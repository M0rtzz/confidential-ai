"""固定源码构建入口；不下载源码、不拉取基础镜像，缺少依赖立即停止。"""
import hashlib
import json
import re
from pathlib import Path
import shutil
import shlex

from platform_deploy import ROOT, CACHE, SOURCES, run, atomic, manifest, save_manifest, checked_image, image_info, replace_once
from foundation import labels


def source(key):
    path = CACHE / 'sources' / key
    if not path.exists() or (path / '.p3-revision').read_text().strip() != SOURCES[key][1]:
        raise RuntimeError(f'{key} 固定源码未准备，请先获得源码下载授权')
    return path


def docker_build(key, directory, dockerfile, ref, extra=()):
    known = {value['ref']: value['id'] for value in manifest()['images'].values()}
    for base in re.findall(r'^FROM\s+(\S+)', dockerfile.read_text(), re.MULTILINE | re.IGNORECASE):
        if base not in known or ':latest' in base or image_info(base)['Id'] != known[base]:
            raise RuntimeError('Dockerfile 基础镜像未锁定，停止构建：' + base)
    command = ['docker', 'build', '--pull=false', '--network=host', '-f', str(dockerfile), '-t', ref]
    for name, value in labels().items(): command += ['--label', f'{name}={value}']
    if key in SOURCES:
        command += ['--label', 'org.opencontainers.image.revision=' + SOURCES[key][1]]
    patch_record = directory / 'p3-source-patch.json'
    if patch_record.exists():
        command += ['--label', 'tee.secretflow.dev/source-patch-sha256=' + json.loads(patch_record.read_text())['sha256']]
    command += list(extra) + [str(directory)]
    run(*command)
    data = manifest()
    data['images'][key] = {'ref': ref, 'id': image_info(ref)['Id'],
                           'revision': SOURCES[key][1] if key in SOURCES else SOURCES['sdk'][1],
                           'dockerfile_sha256': hashlib.sha256(dockerfile.read_bytes()).hexdigest()}
    if patch_record.exists():
        data['images'][key]['sourcePatch'] = json.loads(patch_record.read_text())
    save_manifest(data)


def build(key):
    if key not in ['capsule', 'teeapps', 'probe']:
        raise RuntimeError('--image-key 必须指定单个组件 capsule、teeapps 或 probe')
    revision = SOURCES['sdk' if key == 'probe' else key][1]
    distdir = CACHE / 'distdir'
    distdir.mkdir(exist_ok=True)
    dependency_digest = b''.join(f.name.encode() + hashlib.sha256(f.read_bytes()).digest() for f in sorted(distdir.iterdir()) if f.is_file())
    patch = ROOT / 'scripts/deploy/tee/capsule-source-fixes.patch'
    patch_bytes = patch.read_bytes() if key == 'capsule' else b''
    guard_bytes = (ROOT / 'scripts/deploy/tee/cm_source_guard.py').read_bytes() if key == 'capsule' else b''
    cargo_inventory = CACHE / 'cargo-registry/p3-checksums.json'
    cargo_cache_bytes = cargo_inventory.read_bytes() if key == 'capsule' and cargo_inventory.exists() else b''
    recipe = hashlib.sha256(dependency_digest + Path(__file__).read_bytes() + patch_bytes + guard_bytes + cargo_cache_bytes + (ROOT / 'scripts/deploy/tee/probe.py').read_bytes() + (ROOT / 'scripts/deploy/tee/persistence_client.py').read_bytes()).hexdigest()[:10]
    image_tag = revision[:12] + '-' + recipe
    context = CACHE / 'component-build' / (key + '-' + image_tag)
    if context.exists():
        current = manifest()['images'].get(key, {})
        if current.get('ref', '').endswith(':' + image_tag):
            checked_image(key)
            print('相同组件构建已锁定，复用镜像，不重复构建。')
            return
        raise RuntimeError('已有组件构建上下文，不自动覆盖或重复构建；请先核查上次结果')
    bazel = CACHE / 'tools/bazel-6.2.1'
    if key in ['capsule', 'teeapps'] and (not bazel.exists() or hashlib.sha256(bazel.read_bytes()).hexdigest() != 'cdf349dc938b1f11db5a7172269d66e91ce18c0ca134b38bb3997a3e3be782b8'):
        raise RuntimeError('固定 Bazel 6.2.1 尚未通过官方 SHA256 校验')
    if key == 'capsule':
        dev, release = checked_image('capsule-dev'), checked_image('capsule-release')
        cm_source, tf_source = source('capsule'), source('trustflow')
        shutil.copytree(cm_source, context)
        # 修复统一应用于构建副本；原提交快照不改写，所有目标文件记录前后摘要。
        targets = ['capsule-manager/src/server.rs', 'bin/grpc-as/src/main.rs']
        before = {name: hashlib.sha256((context / name).read_bytes()).hexdigest() for name in targets}
        run('patch', '--directory', context, '--strip=1', '--batch', '--forward', '--fuzz=0', '--input', patch)
        from cm_source_guard import validate_dispatch
        dispatch = validate_dispatch((context / targets[0]).read_text())
        if not dispatch['ok']: raise RuntimeError('CM 原生接口分派守卫拒绝构建：' + '; '.join(dispatch['errors']))
        if 'String::from_utf8(plain_text.clone())' in (context / targets[0]).read_text() or 'log::info!("config {:#?}", cfg)' in (context / targets[1]).read_text():
            raise RuntimeError('CM 存在敏感请求或完整配置日志，拒绝构建')
        atomic(context / 'p3-source-patch.json', {'baseRevision': revision,
            'file': patch.name, 'sha256': hashlib.sha256(patch_bytes).hexdigest(),
            'targets': {name: {'beforeSha256': before[name], 'afterSha256': hashlib.sha256((context / name).read_bytes()).hexdigest()} for name in targets},
            'dispatchGuard': dispatch, 'guardSha256': hashlib.sha256(guard_bytes).hexdigest(), 'userApproved': True})
        shutil.copy2(ROOT / 'scripts/deploy/tee/cm_source_guard.py', context / 'script/p3_validate_cm.py')
        cargo_cache = CACHE / 'cargo-registry'
        offline_cargo = bool(cargo_cache_bytes)
        if offline_cargo:
            inventory = json.loads(cargo_cache_bytes)
            if inventory['cargoLockSha256'] != hashlib.sha256((context / 'Cargo.lock').read_bytes()).hexdigest():
                raise RuntimeError('Cargo 缓存的锁文件与源码不同')
            cached = {file.name: file for file in (cargo_cache / 'cache').glob('*/*.crate')}
            for name, digest in inventory['verifiedCrates'].items():
                if name not in cached or hashlib.sha256(cached[name].read_bytes()).hexdigest() != digest:
                    raise RuntimeError('Cargo 缓存损坏：' + name)
            shutil.copytree(cargo_cache, context / 'p3-cargo-registry')
        else:
            # 新工作区可按 Cargo.lock 首次下载；已有校验缓存时强制离线，失败不静默改版本。
            (context / 'p3-cargo-registry').mkdir()
        patch_record = json.loads((context / 'p3-source-patch.json').read_text())
        patch_record['cargoDependencyMode'] = 'verified-offline' if offline_cargo else 'locked-online'
        atomic(context / 'p3-source-patch.json', patch_record)
        # 复制依赖快照，构建期间不允许 install 脚本自行克隆未固定版本。
        shutil.copytree(tf_source, context / 'p3-trustflow')
        installer = context / 'script/install_attestation_lib.sh'
        installer.read_text()
        # 上游安装器存在浮动 git clone。替换为固定源码构建安装器，目标存在性需先核查。
        generation = tf_source / 'trustflow/attestation/generation/wrapper/BUILD.bazel'
        verification = tf_source / 'trustflow/attestation/verification/wrapper/BUILD.bazel'
        if not generation.exists() or not verification.exists():
            raise RuntimeError('固定 TrustFlow 的证明库目标位置与构建适配不符，禁止自动改版本')
        for target in [generation, verification]:
            expected = 'lib' + target.parent.parent.name + '.so'
            if not re.search(r'name\s*=\s*[\"\']' + re.escape(expected) + r'[\"\']', target.read_text()):
                raise RuntimeError('固定源码未声明预期证明库目标：' + expected)
        installer.write_text('''#!/usr/bin/env bash
set -euo pipefail
cd /home/admin/dev/p3-trustflow
bazel build --distdir=/p3-distdir --experimental_downloader_config=/p3-downloader.cfg --jobs=8 -c opt //trustflow/attestation/generation/wrapper:libgeneration.so //trustflow/attestation/verification/wrapper:libverification.so
install -m 755 bazel-bin/trustflow/attestation/generation/wrapper/libgeneration.so /lib/libgeneration.so
install -m 755 bazel-bin/trustflow/attestation/verification/wrapper/libverification.so /lib/libverification.so
''')
        installer.chmod(0o755)
        build_script = context / 'script/build.sh'
        build_text = build_script.read_text().replace('cargo build ', 'cargo build ' + ('--offline ' if offline_cargo else '') + '--locked -j 8 ')
        build_text = replace_once(build_text, 'set -e\n', 'set -e\npython3 "$(dirname "$0")/p3_validate_cm.py" "$(dirname "$0")/../capsule-manager/src/server.rs"\n')
        build_script.write_text(build_text)
        text = (context / 'deployment/Dockerfile').read_text()
        text = text.replace('secretflow/trustedflow-dev-ubuntu22.04:latest', dev)
        text = text.replace('secretflow/trustedflow-release-ubuntu22.04:latest', release)
        text = replace_once(text, 'COPY Cargo.toml ./', 'COPY Cargo.toml ./\nCOPY p3-cargo-registry /root/.cargo/registry\nCOPY p3-trustflow ./p3-trustflow')
        if (context / 'Cargo.lock').exists():
            text = text.replace('COPY Cargo.toml ./', 'COPY Cargo.toml Cargo.lock ./')
        else:
            raise RuntimeError('固定 CM 源码缺少 Cargo.lock，不能声称依赖已锁定；停止并报告版本兼容阻塞')
        text = text.replace('ENV TINI_VERSION v0.19.0\nADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini /tini\nRUN chmod +x /tini\nENTRYPOINT ["/tini", "--"]', 'ENTRYPOINT []')
        text = text.replace('CMD [ "/home/admin/entrypoint.sh" ]', 'CMD ["/home/admin/capsule_manager", "--config_path", "/config/config.yaml", "--tls_config.enable_tls", "true"]')
        text += '\nCOPY p3-source-patch.json /home/admin/p3-source-patch.json\n'
        text = text.replace('WORKDIR /home/admin/dev', 'WORKDIR /home/admin/dev\nCOPY p3-bazel /usr/local/bin/bazel')
        shutil.copy2(bazel, context / 'p3-bazel')
        shutil.copytree(distdir, context / 'p3-distdir')
        text = text.replace('COPY p3-bazel /usr/local/bin/bazel', 'COPY p3-bazel /usr/local/bin/bazel\nCOPY p3-distdir /p3-distdir')
        atomic(context / 'p3-downloader.cfg', 'rewrite github.com/(.*) https://mirror.bazel.build/github.com/$1\nrewrite github.com/(.*)/archive/(.*)\\.tar\\.gz https://codeload.github.com/$1/tar.gz/$2\nrewrite github.com/(.*)/archive/(.*)\\.zip https://codeload.github.com/$1/zip/$2\n')
        text = text.replace('COPY p3-bazel /usr/local/bin/bazel', 'COPY p3-bazel /usr/local/bin/bazel\nCOPY p3-downloader.cfg /p3-downloader.cfg')
        atomic(context / 'Dockerfile.p3', text)
        docker_build(key, context, context / 'Dockerfile.p3', 'tee-a-capsule:' + image_tag, ['--build-arg', 'PLATFORM=sim'])
    elif key == 'teeapps':
        dev, ubuntu = checked_image('teeapps-dev'), checked_image('ubuntu')
        shutil.copytree(source('teeapps'), context)
        text = (context / 'deployment/sim/Dockerfile').read_text()
        text = text.replace('secretflow/trustflow-dev-ubuntu22.04:latest', dev).replace('ubuntu:22.04', ubuntu)
        text = text.replace('WORKDIR /home/admin/dev', 'WORKDIR /home/admin/dev\nCOPY p3-bazel /usr/local/bin/bazel')
        shutil.copy2(bazel, context / 'p3-bazel')
        shutil.copytree(distdir, context / 'p3-distdir')
        text = text.replace('COPY p3-bazel /usr/local/bin/bazel', 'COPY p3-bazel /usr/local/bin/bazel\nCOPY p3-distdir /p3-distdir')
        atomic(context / 'p3-downloader.cfg', 'rewrite github.com/(.*) https://mirror.bazel.build/github.com/$1\nrewrite github.com/(.*)/archive/(.*)\\.tar\\.gz https://codeload.github.com/$1/tar.gz/$2\nrewrite github.com/(.*)/archive/(.*)\\.zip https://codeload.github.com/$1/zip/$2\n')
        text = text.replace('COPY p3-bazel /usr/local/bin/bazel', 'COPY p3-bazel /usr/local/bin/bazel\nCOPY p3-downloader.cfg /p3-downloader.cfg')
        build_script = context / 'scripts/build_sim.sh'
        build_script.write_text(build_script.read_text().replace('build -c opt', 'build --distdir=/p3-distdir --experimental_downloader_config=/p3-downloader.cfg --jobs=8 -c opt'))
        atomic(context / 'Dockerfile.p3', text)
        docker_build(key, context, context / 'Dockerfile.p3', 'tee-a-teeapps:' + image_tag)
    else:
        base = checked_image('python')
        shutil.copytree(source('sdk'), context / 'sdk')
        shutil.copy2(ROOT / 'scripts/deploy/tee/probe.py', context / 'probe.py')
        shutil.copy2(ROOT / 'scripts/deploy/tee/persistence_client.py', context / 'persistence_client.py')
        setup = context / 'sdk/python/setup.py'
        setup.write_text(setup.read_text().replace('0.2.0.dev$$DATE$$', '0.2.0.dev0+g' + revision[:12]))
        child_check = "import runpy; runpy.run_path('/opt/p3/probe.py', run_name='probe_import'); from sdc.capsule_manager_frame import CapsuleManagerFrame"
        preflight = "import os; os.setgroups([]); os.setgid(65534); os.setuid(65534); os.execl('/root/miniconda3/bin/python', 'python', '-c', " + repr(child_check) + ")"
        text = f'''FROM {base}
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ENV PATH=/root/miniconda3/bin:$PATH
COPY sdk/python /opt/sdk
RUN pip install --no-cache-dir cryptography==41.0.7 protobuf==4.25.3 /opt/sdk && pip freeze > /opt/p3-dependencies.txt
RUN python -c "from sdc.capsule_manager_frame import CapsuleManagerFrame; from secretflowapis.v2.sdc.capsule_manager import capsule_manager_pb2_grpc"
# 公开 Python 运行时位于 /root；只开放目录遍历，容器仍按证书持有者 UID 运行。
RUN chmod 0711 /root
COPY --chmod=0644 probe.py persistence_client.py /opt/p3/
RUN chmod 0755 /opt/p3
RUN python -c {shlex.quote(preflight)}
ENTRYPOINT []
CMD ["python", "/opt/p3/probe.py"]
'''
        atomic(context / 'Dockerfile', text)
        docker_build(key, context, context / 'Dockerfile', 'tee-a-probe:' + image_tag)
