#!/usr/bin/env python3
"""P3 隔离部署：默认只准备文件；网络下载、镜像构建及启动分别执行。"""
import argparse
import contextlib
import datetime as dt
import fcntl
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import socket
import secrets
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[3]
ORIGINAL = Path('/data/collab/Projects/gpu')
FRONTEND = ORIGINAL / 'confidential-ai-frontend'
TOOLKIT = ORIGINAL / 'data-sandbox-package'
CACHE = ROOT / '.cache/tee-p3'
RUNTIME = ROOT / '.dev-runtime'
LABEL = 'io.hustnlp.data-sandbox.'
INSTANCES = {'tee-a-center': 196, 'tee-a-client-1': 197, 'tee-a-client-2': 198}
SOURCES = {
    'trustflow': ('trustflow', '13b13e0729f42accd1c0f15bb42c5b57e09fdabe'),
    'teeapps': ('trustflow-teeapps', 'd68428fc4d9ee9ffa6d229a90f052fcfe5560587'),
    'capsule': ('trustflow-capsule-manager', '38e07f14b2efc9311f3383ae8986e13e1447f947'),
    'sdk': ('trustflow-capsule-manager-sdk', 'a4d7389de0402373319cb35700083979293c9ac7'),
}


def run(*args, capture=False, input=None, **kwargs):
    return subprocess.run([str(a) for a in args], check=True, text=True,
                          stdout=subprocess.PIPE if capture else None,
                          input=input, **kwargs).stdout


def git(path, *args):
    return run('git', '-C', path, *args, capture=True).strip()


def atomic(path, value, mode=0o600):
    path = Path(path)
    if path.is_symlink() or not path.resolve().is_relative_to(ROOT.resolve()):
        raise RuntimeError('拒绝向隔离工作树之外写文件')
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, delete=False) as f:
        f.write(value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, indent=2) + '\n')
        temp = Path(f.name)
    temp.chmod(mode)
    temp.replace(path)


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat().replace('+00:00', 'Z')


def guard():
    if ROOT != Path('/data/collab/Projects/gpu-tee-dev-a') or ROOT.is_symlink():
        raise RuntimeError('仅允许既有 A 工作树')
    if run('id', '-un', capture=True).strip() != 'collab' or os.geteuid() == 0:
        raise RuntimeError('必须使用 collab，禁止提权')
    for path, branch in [(ROOT, 'codex/tee-dev-a'), (FRONTEND, 'master')]:
        if git(path, 'branch', '--show-current') != branch:
            raise RuntimeError(f'分支不符合计划：{path}')
    for path in [CACHE, RUNTIME, CACHE / 'toolkit', CACHE / 'sources', CACHE / 'build', CACHE / 'component-build']:
        if not path.resolve().is_relative_to(ROOT) or path.is_symlink():
            raise RuntimeError(f'隔离目录不可指向工作树外：{path}')
    for name in INSTANCES:
        base = RUNTIME / name
        # 仅校验部署入口的挂载根，不遍历 containerd 内部的合法绝对链接。
        for relative in ['', 'tee', 'status', 'kuscia', 'secretpad', 'minio', 'snapshots', 'backups', 'secretpad.env',
                         'kuscia/config', 'kuscia/config/kuscia.yaml', 'kuscia/data', 'kuscia/log',
                         'kuscia/images', 'kuscia/k3s', 'kuscia/containerd',
                         'secretpad/config', 'secretpad/db', 'secretpad/data', 'secretpad/log']:
            child = base / relative
            if child.is_symlink() or not child.resolve().is_relative_to(base.resolve()):
                raise RuntimeError('实例挂载根存在越界链接：' + str(child))


def source_digest(path, excluded=()):
    names = run('git', '-C', path, 'ls-files', '-z', '--cached', '--others', '--exclude-standard', capture=True)
    h = hashlib.sha256()
    for name in sorted(set(names.split('\0')) - {''}):
        if any(name == prefix or name.startswith(prefix + '/') for prefix in excluded):
            continue
        f = path / name
        h.update(name.encode() + b'\0')
        if f.is_symlink():
            h.update(b'link:' + os.readlink(f).encode())
        elif f.is_file():
            h.update(f.read_bytes())
        else:
            h.update(b'missing')
    return h.hexdigest()


def platform_digest():
    # Dockerfile 只打包 Java JAR 和 config/schema；部署脚本与交接文档不进入平台镜像。
    # 完整工作树摘要另行记录，部署脚本修正无需反复构建相同平台。
    return source_digest(ROOT, ('scripts/deploy/tee', 'develop.sh', 'docs/tee-dev-a'))


def toolkit_digest():
    # 只锁定实际复用的六个输入；并行开发的其他 runner 文件不进入本次打包。
    digest = hashlib.sha256()
    for name in ['Dockerfile', 'build.sh', 'data-sandbox.env.example', 'deploy/common/log.sh', 'deploy/common/utils.sh', 'develop.sh']:
        file = TOOLKIT / name
        if file.is_symlink() or not file.is_file():
            raise RuntimeError('工具链输入不是普通文件：' + name)
        digest.update(name.encode() + b'\0' + file.read_bytes())
    return digest.hexdigest()


def source_snapshot(src, dest):
    """复制 Git 可见源码；仅重建指向仓库内普通文件的相对符号链接。"""
    if dest.exists():
        raise RuntimeError(f'暂存目录已存在，不覆盖：{dest}')
    dest.mkdir(parents=True)
    names = run('git', '-C', src, 'ls-files', '-z', '--cached', '--others', '--exclude-standard', capture=True)
    for name in sorted(set(names.split('\0')) - {''}):
        f = src / name
        if f.is_symlink():
            link = Path(os.readlink(f))
            resolved = (f.parent / link).resolve()
            if link.is_absolute() or not resolved.is_relative_to(src.resolve()) or not resolved.is_file():
                raise RuntimeError(f'源码含不安全符号链接：{name}')
            target = dest / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.symlink_to(link)
            continue
        if not f.is_file():
            continue
        target = dest / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(f, target)


def image_info(ref):
    return json.loads(run('docker', 'image', 'inspect', ref, capture=True))[0]


def manifest():
    file = RUNTIME / 'p3-manifest.json'
    return json.loads(file.read_text()) if file.exists() else {'contractVersion': 'tee-contract/1.0', 'images': {}}


def save_manifest(data):
    atomic(RUNTIME / 'p3-manifest.json', data)


def managed(name, kind='container'):
    query = subprocess.run(['docker', kind, 'inspect', name], text=True, capture_output=True)
    if query.returncode:
        return None
    value = json.loads(query.stdout)[0]
    labels = value.get('Labels') if kind == 'network' else value.get('Config', {}).get('Labels')
    labels = labels or {}
    if any(labels.get(LABEL + key) != expected for key, expected in
           [('dev', 'true'), ('dev-owner', 'collab'), ('dev-workspace', str(ROOT))]):
        raise RuntimeError(f'拒绝操作不属于 A 工作树的 {kind}：{name}')
    return value


def port_check(name):
    base = INSTANCES[name] * 100
    ports = {base + n for n in [80, 81, 82, 83, 84, 88]}
    if name == 'tee-a-center':
        ports.add(19685)
    own = {f'data-sandbox-dev-{name}-{suffix}' for suffix in ['kuscia', 'secretpad']}
    ids = run('docker', 'ps', '-aq', capture=True).split()
    mapped = set()
    if ids:
        for value in json.loads(run('docker', 'inspect', *ids, capture=True)):
            for binds in (value.get('HostConfig', {}).get('PortBindings') or {}).values():
                for binding in binds or []:
                    port = int(binding['HostPort'])
                    if port not in ports:
                        continue
                    if value['Name'].lstrip('/') not in own:
                        raise RuntimeError(f'端口 {port} 被其他容器保留')
                    managed(value['Name'].lstrip('/'))
                    if value['State']['Running']:
                        mapped.add(port)
    for port in ports - mapped:
        with socket.socket() as sock:
            sock.bind(('0.0.0.0', port))


def detect(name):
    checks = {'sgx': False, 'tdx': False, 'csv': False}
    detected = True
    try:
        devices = {'sgx': ['/dev/sgx_enclave', '/dev/sgx/enclave'],
                   'tdx': ['/dev/tdx_guest', '/dev/tdx-guest'],
                   'csv': ['/dev/csv-guest', '/dev/csv_guest', '/dev/csv']}
        for kind, paths in devices.items():
            for path in paths:
                try: checks[kind] |= stat.S_ISCHR(Path(path).stat().st_mode)
                except FileNotFoundError: pass
        detected = Path('/dev').is_dir()
    except OSError:
        detected = False
    atomic(RUNTIME / name / 'status/hardware.json',
           {'checkedAt': utc(), 'detectorOk': detected, 'deviceChecks': checks}, 0o644)


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise RuntimeError(f'工具链结构变化，拒绝盲目适配：{old[:70]}')
    return text.replace(old, new, 1)


def prepare():
    """只生成适配脚本和非敏感检测结果，不运行上游入口。"""
    for name in INSTANCES:
        (RUNTIME / name).mkdir(parents=True, exist_ok=True, mode=0o700)
        (RUNTIME / name).chmod(0o700)
        detect(name)
    target = CACHE / 'toolkit'
    target.mkdir(parents=True, exist_ok=True, mode=0o700)
    for name in ['deploy/common/log.sh', 'deploy/common/utils.sh', 'data-sandbox.env.example', 'Dockerfile']:
        dest = target / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(TOOLKIT / name, dest)
    # 使用公开默认配置，不复制原工具链 data-sandbox.env 中的运行凭据。
    shutil.copy2(TOOLKIT / 'data-sandbox.env.example', target / 'data-sandbox.env')
    script = (TOOLKIT / 'develop.sh').read_text()
    script = replace_once(script, 'WORKSPACE_DIR="$(cd "${PACKAGE_DIR}/.." && pwd)"', f'WORKSPACE_DIR="{ROOT}"')
    script = replace_once(script, 'BACKEND_DIR="$(realpath -m "${WORKSPACE_DIR}/confidential-ai")"', 'BACKEND_DIR="$WORKSPACE_DIR"')
    script = replace_once(script, 'FRONTEND_DIR="$(realpath -m "${WORKSPACE_DIR}/confidential-ai-frontend")"', f'FRONTEND_DIR="{FRONTEND}"')
    script = replace_once(script, 'SECRETPAD_IMAGE="data-sandbox-secretpad:dev-${DEV_NAME}"', 'SECRETPAD_IMAGE="${TEE_PLATFORM_IMAGE:?Missing pinned platform image}"')
    # 校验在真实输入仓库执行，不能要求只读前端切换到 A 分支。
    script = replace_once(script, '  local branch\n', '  local branch\n  local expected="$EXPECTED_BRANCH"\n  [ "$repository" != "$FRONTEND_DIR" ] || expected=master\n')
    script = replace_once(script, '[ "$branch" = "$EXPECTED_BRANCH" ]', '[ "$branch" = "$expected" ]')
    # 所有隐式重建和替换由 P3 的显式动作代替。
    start = script.index('build_developer_image() {')
    end = script.index('sampler_source_hash() {', start)
    script = script[:start] + '''build_developer_image() {
  verify_checkout "$BACKEND_DIR"
  verify_checkout "$FRONTEND_DIR"
  verify_managed_image "$SECRETPAD_IMAGE" || exit 1
}

''' + script[end:]
    start = script.index('build_sampler_image() {')
    end = script.index('import_sampler_image() {', start)
    script = script[:start] + '''build_sampler_image() {
  docker image inspect "$SAMPLER_IMAGE" >/dev/null
}

''' + script[end:]
    start = script.index('ensure_sampler_runtime() {')
    end = script.index('start_kuscia() {', start)
    script = script[:start] + '''ensure_sampler_runtime() {
  import_sampler_image
  python3 "$BACKEND_DIR/scripts/deploy/tee/p3.py" register-sampler --name "$DEV_NAME" --tee
}

''' + script[end:]
    # 上游的模型运行器属于 P5/P6，不从复用工具链构建或注册额外业务镜像。
    script, omitted = re.subn(r'(?m)^    ensure_model_runner_runtime[^\n]*\\\n[^\n]*\\\n[^\n]*\n',
        '    # P3 不准备 Python/JAR 业务运行器。\n', script)
    if omitted != 4:
        raise RuntimeError('上游业务运行器调用结构变化，停止隔离适配')
    script = replace_once(script, '      docker rm -f "$KUSCIA_CONTAINER" >/dev/null\n      kuscia_status=""',
                          '      log_error "Kuscia requires an explicitly authorized replacement."\n      exit 1')
    script = replace_once(script, '  if verify_managed_container "$SECRETPAD_CONTAINER"; then\n    docker rm -f "$SECRETPAD_CONTAINER" >/dev/null\n  fi',
                          '  if verify_managed_container "$SECRETPAD_CONTAINER"; then\n    log_error "P3 refuses implicit platform replacement."\n    exit 1\n  fi')
    # 只给中心 Kuscia 发布密钥服务入口，原生 CM 端口不发布。
    script = script.replace('-p "${METRICS_PORT}:9091" \\\n', '-p "${METRICS_PORT}:9091" ${TEE_GATEWAY_PORT_ARGS:-} \\\n')
    script = script.replace('-v "${KUSCIA_CONTAINERD_DIR}:/home/kuscia/containerd" \\\n',
                            '-v "${KUSCIA_CONTAINERD_DIR}:/home/kuscia/containerd" \\\n      -v "${DEV_ROOT}/tee:/home/kuscia/tee" \\\n')
    script = replace_once(script, '    --env-file "$CREDENTIAL_FILE" \\\n',
                          '    --env-file "$CREDENTIAL_FILE" \\\n    -e "TEE_FOUNDATION_PROBE_URL=http://${DEV_PREFIX}-tee-probe:8089/health" \\\n    -v "${DEV_ROOT}/status:/app/tee-status:ro" \\\n')
    script = script.replace('docker run ', 'docker run --pull=never ').replace('docker create ', 'docker create --pull=never ')
    atomic(target / 'develop.sh', script, 0o700)
    data = manifest()
    if data.get('backend_runtime_content') != platform_digest() or data.get('frontend_content') != source_digest(FRONTEND) or data.get('toolkit_content') != toolkit_digest():
        data['images'].pop('platform', None)
    data.update(workspace=str(ROOT), owner='collab', source_mode='working-tree',
                backend_commit=git(ROOT, 'rev-parse', 'HEAD'), backend_content=source_digest(ROOT), backend_runtime_content=platform_digest(),
                frontend_commit=git(FRONTEND, 'rev-parse', 'HEAD'), frontend_content=source_digest(FRONTEND),
                toolkit_content=toolkit_digest(), toolkit_repository_content=source_digest(TOOLKIT), sources=SOURCES)
    save_manifest(data)
    print('隔离适配入口已生成；未构建、下载或启动服务。')


def build_platform():
    prepare()
    data = manifest()
    stamp = data['backend_runtime_content'][:12] + '-' + data['frontend_content'][:8]
    if data['images'].get('platform'):
        checked_image('platform')
        print('平台编译输入未变化，复用已锁定镜像。')
        return
    stage = CACHE / 'build' / stamp
    if stage.exists():
        raise RuntimeError('同版本构建暂存已存在；核查失败原因后显式清理或使用现有镜像，不自动重建')
    source_snapshot(ROOT, stage / 'backend')
    source_snapshot(FRONTEND, stage / 'frontend')
    stage_toolkit = stage / 'toolkit'
    shutil.copytree(CACHE / 'toolkit', stage_toolkit)
    build = (TOOLKIT / 'build.sh').read_text()
    build = replace_once(build, 'BACKEND_DIR="${WORKSPACE_DIR}/confidential-ai"', 'BACKEND_DIR="${WORKSPACE_DIR}/backend"')
    build = replace_once(build, 'FRONTEND_DIR="${WORKSPACE_DIR}/confidential-ai-frontend"', 'FRONTEND_DIR="${WORKSPACE_DIR}/frontend"')
    build = build.replace('maven:3.9.9-eclipse-temurin-17-noble', checked_image('maven'))
    dockerfile = stage_toolkit / 'Dockerfile'
    dockerfile.write_text(dockerfile.read_text().replace('ARG BASE_IMAGE=secretflow-registry.cn-hangzhou.cr.aliyuncs.com/secretflow/secretpad:0.12.0b0', 'ARG BASE_IMAGE=' + checked_image('platform-base')))
    build = build.replace('docker run --rm', 'docker run --pull=never --rm').replace('docker build ', 'docker build --pull=false ')
    atomic(stage_toolkit / 'build.sh', build, 0o700)
    atomic(stage_toolkit / 'artifacts/p3-build-manifest.json', {key: value for key, value in data.items() if key != 'images'})
    dockerfile.write_text(dockerfile.read_text() + '\nCOPY artifacts/p3-build-manifest.json /app/p3-build-manifest.json\n')
    image = 'tee-a-secretpad:p3-' + stamp
    env = dict(os.environ, CI='true', HUSKY='0', DATA_SANDBOX_DEV_IMAGE='true', DATA_SANDBOX_DEV_IMAGE_OWNER='collab',
               DATA_SANDBOX_DEV_IMAGE_WORKSPACE=str(ROOT), SECRETPAD_IMAGE=image)
    # Maven 缓存仅复制，不通过共享写挂载复用。
    cache = stage / '.cache/m2'
    cache.parent.mkdir(parents=True)
    run('cp', '-a', '--reflink=auto', ORIGINAL / '.cache/m2', cache)
    run('pnpm', 'install', '--frozen-lockfile', '--store-dir', CACHE / 'pnpm-store', cwd=stage / 'frontend', env=env)
    run('bash', stage_toolkit / 'build.sh', env=env)
    if platform_digest() != data['backend_runtime_content'] or source_digest(FRONTEND) != data['frontend_content'] or toolkit_digest() != data['toolkit_content']:
        raise RuntimeError('构建期间输入发生变化，禁止启动实例')
    data['images']['platform'] = {'ref': image, 'id': image_info(image)['Id'],
        'backend_content_at_build': data['backend_content'], 'backend_runtime_content': data['backend_runtime_content'],
        'frontend_content': data['frontend_content'], 'toolkit_content': data['toolkit_content']}
    # 复用原算子镜像内容，只增加 A 专属不可变标签，不覆盖共享 latest。
    sampler = image_info('data-sandbox-sampler:latest')
    alias = 'tee-a-sampler:' + sampler['Id'].split(':')[1][:16]
    run('docker', 'tag', sampler['Id'], alias)
    data['images']['sampler'] = {'ref': alias, 'id': sampler['Id']}
    data['built_at'] = utc()
    save_manifest(data)
    print('平台构建完成，三个实例使用同一镜像：' + image)


def checked_image(key):
    item = manifest()['images'].get(key)
    if not item or image_info(item['ref'])['Id'] != item['id']:
        raise RuntimeError(f'镜像尚未准备或摘要变化：{key}')
    return item['ref']


def kube(name, *args, value=None):
    ctr = f'data-sandbox-dev-{name}-kuscia'
    managed(ctr) or (_ for _ in ()).throw(RuntimeError('Kuscia 尚未启动'))
    return run('docker', 'exec', *(['-i'] if value is not None else []), ctr, 'kubectl', *args,
               capture=True, input=json.dumps(value) if value is not None else None)


def register_sampler(name):
    image = checked_image('sampler')
    for app in ['data-sandbox-sampler', 'data-sandbox-sampler-nonet']:
        template = (ROOT / f'scripts/templates/{app}.yaml').read_text()
        template = template.replace('{{.IMAGE_NAME}}', image.rsplit(':', 1)[0]).replace('{{.IMAGE_TAG}}', image.rsplit(':', 1)[1])
        ctr = f'data-sandbox-dev-{name}-kuscia'
        managed(ctr)
        run('docker', 'exec', '-i', ctr, 'kubectl', 'apply', '-f', '-', input=template)


def up(name):
    data = manifest()
    if data.get('backend_runtime_content') != platform_digest() or data.get('frontend_content') != source_digest(FRONTEND) or data.get('toolkit_content') != toolkit_digest():
        raise RuntimeError('源码已变化，现有镜像不能代表当前工作树')
    data['deployment_source_content'] = source_digest(ROOT)
    save_manifest(data)
    platform = checked_image('platform')
    sampler = checked_image('sampler')
    port_check(name)
    detect(name)
    ctr = f'data-sandbox-dev-{name}-secretpad'
    current = managed(ctr)
    if current:
        if current['Image'] == data['images']['platform']['id'] and current['State']['Running']:
            print(f'{name} 已运行相同平台镜像，不替换；底座状态请单独验收。')
            return
        raise RuntimeError('实例已存在且状态或镜像不符；需明确授权后替换，拒绝隐式操作')
    (RUNTIME / name / 'tee').mkdir(exist_ok=True, mode=0o700)
    base = INSTANCES[name] * 100
    env = dict(os.environ, DATA_SANDBOX_DEV_ROOT=str(RUNTIME / name), TEE_PLATFORM_IMAGE=platform, DATA_SANDBOX_DEV_SAMPLER_IMAGE=sampler, DATA_SANDBOX_DEV_KUSCIA_IMAGE=checked_image('kuscia'),
               DATA_SANDBOX_DEV_MINIO_IMAGE=checked_image('minio'),
               TEE_GATEWAY_PORT_ARGS='-p 19685:31888' if name == 'tee-a-center' else '')
    # 独立随机口令只交给上游入口写入本实例 600 凭据文件，不输出到日志。
    password = secrets.token_urlsafe(24) if not (RUNTIME / name / 'secretpad.env').exists() else None
    run('bash', CACHE / 'toolkit/develop.sh', 'up', '--skip-build', '--name', name, '--branch', 'codex/tee-dev-a',
        '--port', base+88, '--gateway-port', base+80, '--internal-port', base+81,
        '--api-http-port', base+82, '--api-grpc-port', base+83, '--metrics-port', base+84,
        '--advertise-host', '222.20.99.38', env=env, input=(password + '\n' + password + '\n') if password else None)


def down(name):
    """仅停止本次所属容器；保留容器、网络、数据库及身份，恢复需单独授权。"""
    containers = [f'data-sandbox-dev-{name}-{suffix}' for suffix in ['tee-probe', 'secretpad', 'minio', 'kuscia']]
    current = [(ctr, managed(ctr)) for ctr in containers]
    for ctr, info in current:
        if info and info['State']['Running']:
            run('docker', 'stop', ctr)
    print(name + ' 已停止；所有持久数据与密钥保留。')


def fetch_sources():
    """此子命令会下载源码，须在确认具体清单后单独执行。"""
    for key, (repo, revision) in SOURCES.items():
        dest = CACHE / 'sources' / key
        if dest.exists():
            if (dest / '.p3-revision').read_text().strip() != revision:
                raise RuntimeError('已存在不同源码版本，拒绝覆盖')
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=dest.parent) as archive:
            url = f'https://codeload.github.com/secretflow/{repo}/tar.gz/{revision}'
            with urllib.request.urlopen(url, timeout=60) as response:
                shutil.copyfileobj(response, archive)
            archive.flush()
            archive.seek(0)
            digest = hashlib.sha256(archive.read()).hexdigest()
            archive.seek(0)
            temp = dest.with_name(key + '.extracting')
            temp.mkdir()
            with tarfile.open(fileobj=archive) as tar:
                for member in tar:
                    relative = Path(*Path(member.name).parts[1:])
                    target = temp / relative
                    if not target.resolve().is_relative_to(temp.resolve()) or member.issym() or member.islnk():
                        raise RuntimeError('源码压缩包含不安全路径或链接')
                    if member.isdir():
                        target.mkdir(parents=True, exist_ok=True)
                    elif member.isfile():
                        target.parent.mkdir(parents=True, exist_ok=True)
                        with tar.extractfile(member) as source, target.open('wb') as output:
                            shutil.copyfileobj(source, output)
                        target.chmod(member.mode & 0o755)
            atomic(temp / '.p3-revision', revision + '\n')
            atomic(temp / '.p3-archive-sha256', digest + '\n')
            temp.rename(dest)
        print(f'{key}: {revision}')


def status():
    for name in INSTANCES:
        state = {}
        for suffix in ['secretpad', 'kuscia', 'minio', 'tee-probe']:
            item = managed(f'data-sandbox-dev-{name}-{suffix}')
            state[suffix] = item['State']['Status'] if item else 'NOT_CREATED'
        print(name, json.dumps(state))


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['prepare', 'status', 'build-platform', 'up', 'down', 'fetch-sources',
        'register-sampler', 'certificates', 'render', 'base-up', 'probe-up', 'register', 'smoke', 'pair',
        'verify-tls', 'verify-native', 'verify-persistence', 'verify-environment', 'verify-isolation', 'verify-repeat', 'lock-image', 'build-components'])
    parser.add_argument('--tee', action='store_true', required=True)
    parser.add_argument('--name', choices=list(INSTANCES), default='tee-a-center')
    parser.add_argument('--image-key')
    parser.add_argument('--image-ref')
    parser.add_argument('--repair-startup', action='store_true', help='明确修复本次 A 底座的启动配置；不用于无故替换健康实例')
    args = parser.parse_args()
    guard()
    CACHE.mkdir(parents=True, exist_ok=True, mode=0o700)
    # register-sampler 是上游入口的同步子调用，不能再次取得同一把排他锁。
    if args.command == 'register-sampler':
        return register_sampler(args.name)
    with (CACHE / 'operation.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.command == 'prepare': prepare()
        elif args.command == 'status': status()
        elif args.command == 'build-platform': build_platform()
        elif args.command == 'up': up(args.name)
        elif args.command == 'down': down(args.name)
        elif args.command == 'fetch-sources': fetch_sources()
        else:
            import foundation
            foundation.dispatch(args)


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, subprocess.CalledProcessError, ValueError, KeyError) as error:
        print(f'P3 停止：{type(error).__name__}: {error}', file=sys.stderr)
        sys.exit(1)
