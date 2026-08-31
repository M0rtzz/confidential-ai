"""P3 密钥底座、证书、Kuscia 模板与验证动作；所有资源限制在 A 工作树。"""
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import time
import urllib.request

from p3 import (ROOT, CACHE, RUNTIME, INSTANCES, SOURCES, LABEL, run, atomic, utc,
                manifest, save_manifest, checked_image, image_info, managed, kube)

CENTER = RUNTIME / 'tee-a-center/tee'
PKI = CENTER / 'pki'
DOMAIN = 'dev-tee-a-center'
GET_RA = '/secretflowapis.v2.sdc.capsule_manager.CapsuleManager/GetRaCert'


def openssl(*args):
    return run('openssl', *args, capture=True, stderr=subprocess.DEVNULL)


def verify_pair(directory, prefix, ca=None, expired=False):
    key, cert = directory / (prefix + '.key'), directory / (prefix + '.crt')
    key_public = openssl('pkey', '-in', key, '-pubout')
    cert_public = openssl('x509', '-in', cert, '-pubkey', '-noout')
    if key_public.strip() != cert_public.strip():
        raise RuntimeError('已有证书与私钥不匹配，拒绝覆盖')
    if ca is not None and not expired:
        openssl('verify', '-CAfile', ca / 'ca.crt', cert)
    key.chmod(0o600)


def make_ca(directory, cn):
    if directory.is_symlink() or not directory.resolve().is_relative_to(ROOT):
        raise RuntimeError('证书目录越出 A 工作树')
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if (directory / 'ca.key').exists() and (directory / 'ca.crt').exists():
        for name in ['openssl.cnf', 'index.txt', 'serial', 'crlnumber', 'ca.crl', 'newcerts']:
            if not (directory / name).exists():
                raise RuntimeError('已有 CA 状态不完整，拒绝重建')
        verify_pair(directory, 'ca')
        return
    if directory.is_symlink() or not directory.resolve().is_relative_to(ROOT):
        raise RuntimeError('证书目录越出 A 工作树')
    if any(directory.iterdir()):
        raise RuntimeError(f'CA 目录不完整，拒绝覆盖：{directory}')
    openssl('req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-sha256', '-days', '3650',
            '-subj', '/CN=' + cn, '-keyout', directory / 'ca.key', '-out', directory / 'ca.crt',
            '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
    atomic(directory / 'index.txt', '')
    atomic(directory / 'serial', '1000\n')
    atomic(directory / 'crlnumber', '1000\n')
    (directory / 'newcerts').mkdir(mode=0o700)
    (directory / 'ca.key').chmod(0o600)
    atomic(directory / 'openssl.cnf', f'''[ca]
default_ca=local
[local]
dir={directory}
database=$dir/index.txt
new_certs_dir=$dir/newcerts
certificate=$dir/ca.crt
private_key=$dir/ca.key
serial=$dir/serial
crlnumber=$dir/crlnumber
default_md=sha256
default_days=365
default_crl_days=30
policy=policy
unique_subject=no
copy_extensions=copy
[policy]
commonName=supplied
''')
    openssl('ca', '-batch', '-config', directory / 'openssl.cnf', '-gencrl', '-out', directory / 'ca.crl')


def issue(ca, directory, cn, server=False, expired=False):
    if directory.is_symlink() or not directory.resolve().is_relative_to(ROOT):
        raise RuntimeError('证书目录越出 A 工作树')
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if (directory / 'client.key').exists() and (directory / 'client.crt').exists():
        if not (directory / 'ca.crt').exists():
            raise RuntimeError('已有证书信任链缺失，拒绝重新签发')
        verify_pair(directory, 'client', ca, expired)
        return
    if directory.is_symlink() or not directory.resolve().is_relative_to(ROOT):
        raise RuntimeError('证书目录越出 A 工作树')
    if any(directory.iterdir()):
        raise RuntimeError(f'证书目录不完整，拒绝重建身份：{directory}')
    openssl('req', '-new', '-newkey', 'rsa:3072', '-nodes', '-sha256', '-subj', '/CN=' + cn,
            '-keyout', directory / 'client.key', '-out', directory / 'client.csr',
            '-addext', 'basicConstraints=critical,CA:FALSE',
            '-addext', 'keyUsage=critical,digitalSignature,keyEncipherment',
            '-addext', 'extendedKeyUsage=' + ('serverAuth' if server else 'clientAuth'),
            '-addext', 'subjectAltName=DNS:' + cn + (f',DNS:capsule-manager.{DOMAIN}.svc,DNS:capsule-manager.{DOMAIN}.svc.cluster.local,IP:222.20.99.38' if server and cn == 'capsule.tee-a.test' else ''))
    args = ['ca', '-batch', '-notext', '-config', ca / 'openssl.cnf',
            '-in', directory / 'client.csr', '-out', directory / 'client.crt']
    if expired:
        args += ['-startdate', '20200101000000Z', '-enddate', '20200102000000Z']
    openssl(*args)
    shutil.copy2(ca / 'ca.crt', directory / 'ca.crt')
    (directory / 'client.csr').unlink()
    for f in directory.iterdir():
        if f.is_file(): f.chmod(0o600)


def certificates():
    make_ca(PKI / 'external-ca', 'tee-a-external-ca')
    make_ca(PKI / 'upstream-ca', 'tee-a-upstream-ca')
    for name in INSTANCES:
        issue(PKI / 'external-ca', RUNTIME / name / 'tee/identity', name)
        issue(PKI / 'external-ca', RUNTIME / name / 'tee/probe-cert', 'probe-' + name)
    issue(PKI / 'external-ca', CENTER / 'gateway-cert', 'capsule.tee-a.test', server=True)
    issue(PKI / 'upstream-ca', CENTER / 'cm-server-cert', 'capsule-internal.tee-a.test', server=True)
    issue(PKI / 'upstream-ca', CENTER / 'gateway-upstream-cert', 'tee-a-gateway-upstream')
    issue(PKI / 'external-ca', CENTER / 'workload-cert', 'probe-tee-a-workload')
    issue(PKI / 'external-ca', CENTER / 'cm-master-key', 'tee-a-cm-master')
    (CENTER / 'cm-client-ca').mkdir(exist_ok=True)
    shutil.copy2(PKI / 'upstream-ca/ca.crt', CENTER / 'cm-client-ca/ca.crt')
    (CENTER / 'gateway-trust').mkdir(exist_ok=True)
    for f in ['ca.crt', 'ca.crl']:
        shutil.copy2(PKI / 'external-ca' / f, CENTER / 'gateway-trust' / f)
    (CENTER / 'mysql-secrets').mkdir(exist_ok=True, mode=0o700)
    for name in ['root-password', 'password']:
        file = CENTER / 'mysql-secrets' / name
        if not file.exists(): atomic(file, secrets.token_urlsafe(36))
    # 登记只含公开证书指纹；P4 再接入业务权属，不在普通平台保存机构私钥。
    identities = {}
    for name in INSTANCES:
        cert = RUNTIME / name / 'tee/identity/client.crt'
        der = subprocess.check_output(['openssl', 'x509', '-in', str(cert), '-outform', 'DER'])
        identities[name] = {'certificateSha256': hashlib.sha256(der).hexdigest(),
                            'certificatePath': str(cert.relative_to(RUNTIME))}
    registry = CENTER / 'identity-registry.json'
    if registry.exists() and json.loads(registry.read_text()) != identities:
        raise RuntimeError('机构登记与已有证书不一致，拒绝覆盖身份')
    if not registry.exists(): atomic(registry, identities)
    print('独立机构、服务及探测证书已准备；私钥未输出，未写入普通平台目录。')


def lock_image(key, ref):
    allowed = {'capsule-dev', 'capsule-release', 'teeapps-dev', 'ubuntu', 'python', 'mysql', 'gateway', 'maven', 'platform-base', 'kuscia', 'minio'}
    if key not in allowed or not ref or ':latest' in ref or (':' not in ref and '@sha256:' not in ref):
        raise RuntimeError('仅允许锁定明确的基础镜像引用，禁止 latest')
    info = image_info(ref)
    data = manifest()
    data['images'][key] = {'ref': ref, 'id': info['Id'], 'repoDigests': info.get('RepoDigests', [])}
    save_manifest(data)


def labels():
    return {LABEL+'dev': 'true', LABEL+'dev-owner': 'collab', LABEL+'dev-workspace': str(ROOT)}


def kube_labels():
    # Kubernetes 标签值不能包含路径分隔符；归属由工作树路径摘要标识。
    return {'tee.secretflow.dev/owner': 'collab',
            'tee.secretflow.dev/workspace': hashlib.sha256(str(ROOT).encode()).hexdigest()[:32]}


def import_image(name, key):
    ref = checked_image(key)
    ctr = f'data-sandbox-dev-{name}-kuscia'
    managed(ctr) or (_ for _ in ()).throw(RuntimeError('Kuscia 未启动'))
    image_id = manifest()['images'][key]['id']
    if '@sha256:' in ref:
        # Docker save 的归档标签需要稳定名字；保留来源 digest，仅增加 A 专属本地别名。
        alias = 'tee-a-import-' + key + ':' + image_id.split(':')[1][:16]
        existing = subprocess.run(['docker', 'image', 'inspect', alias], capture_output=True, text=True)
        if existing.returncode:
            run('docker', 'tag', image_id, alias)
        elif json.loads(existing.stdout)[0]['Id'] != image_id:
            raise RuntimeError('A 导入别名已指向其他镜像，拒绝覆盖')
        ref = alias
    normalized = ref if '/' in ref else 'docker.io/library/' + ref
    def present():
        values = json.loads(run('docker', 'exec', ctr, '/home/kuscia/bin/crictl', 'images', '-o', 'json', capture=True))['images']
        return any(item['id'] == image_id and normalized in item.get('repoTags', []) for item in values)
    def record():
        data = manifest()
        data['images'][key]['kuscia_ref'] = ref
        save_manifest(data)
    if present():
        record()
        return
    directory = RUNTIME / name / 'kuscia/images'
    with tempfile.NamedTemporaryFile(dir=directory, suffix='.tar') as target:
        run('docker', 'save', '-o', target.name, ref)
        run('docker', 'exec', ctr, '/home/kuscia/bin/ctr', '--address', '/home/kuscia/containerd/run/containerd.sock',
            '-n', 'k8s.io', 'images', 'import', '/home/kuscia/var/images/' + Path(target.name).name)
    # containerd 导入完成后，CRI 镜像索引可能稍后更新；始终比对完整 ID 与实际标签。
    deadline = time.monotonic() + 30
    while not present():
        if time.monotonic() >= deadline: raise RuntimeError('Kuscia 镜像导入完整 ID 或标签不匹配')
        time.sleep(1)
    record()


def runtime_image(key):
    ref = checked_image(key)
    item = manifest()['images'][key]
    ref = item.get('kuscia_ref', ref)
    if image_info(ref)['Id'] != item['id']:
        raise RuntimeError('Kuscia 导入别名的镜像 ID 发生变化')
    return ref


def pod_exec(pod, container, *command):
    """Kuscia 未提供标准 kubelet 日志代理时，按精确 Pod 归属执行 CRI 同步命令。"""
    ctr = 'data-sandbox-dev-tee-a-center-kuscia'
    managed(ctr) or (_ for _ in ()).throw(RuntimeError('中心 Kuscia 不存在'))
    values = json.loads(run('docker', 'exec', ctr, '/home/kuscia/bin/crictl', 'ps', '-o', 'json', capture=True))['containers']
    matched = [item for item in values if item.get('metadata', {}).get('name') == container
        and item.get('labels', {}).get('io.kubernetes.pod.namespace') == DOMAIN
        and item.get('labels', {}).get('io.kubernetes.pod.name') == pod]
    if len(matched) != 1: raise RuntimeError('未找到唯一属于中心 Pod 的运行容器')
    return run('docker', 'exec', ctr, '/home/kuscia/bin/crictl', 'exec', '--sync', matched[0]['id'], *command, capture=True)


def host_volume(name, relative, container_path, read_only=True, directory=True):
    source = CENTER / relative
    if source.is_symlink() or not source.resolve().is_relative_to(CENTER.resolve()):
        raise RuntimeError('底座挂载越出中心实例运行目录')
    return ({'name': name, 'hostPath': {'path': '/home/kuscia/tee/' + relative,
                                     'type': 'Directory' if directory else 'File'}},
            {'name': name, 'mountPath': container_path, 'readOnly': read_only})


def render():
    for key in ['capsule', 'mysql', 'gateway', 'probe', 'teeapps']:
        checked_image(key)
    nodes = json.loads(kube('tee-a-center', 'get', 'nodes', '-l', 'kuscia.secretflow/namespace=' + DOMAIN, '-o', 'json'))['items']
    if len(nodes) != 1 or not any(c['type'] == 'Ready' and c['status'] == 'True' for c in nodes[0].get('status', {}).get('conditions', [])):
        raise RuntimeError('中心 domain 必须对应唯一 READY 节点')
    node_name = nodes[0]['metadata']['name']
    schema = CACHE / 'sources/capsule/capsule-manager/src/storage/sql_storage/cm.sql'
    if not schema.exists(): raise RuntimeError('固定版本 CM schema 尚未准备')
    (CENTER / 'mysql-init').mkdir(exist_ok=True)
    # 初始化 SQL 不含凭据，需要允许容器内 mysql 用户读取；外层中心运行根仍为 700。
    (CENTER / 'mysql-init').chmod(0o755)
    (CENTER / 'mysql-data').mkdir(exist_ok=True)
    shutil.copy2(schema, CENTER / 'mysql-init/01-cm.sql')
    (CENTER / 'mysql-init/01-cm.sql').chmod(0o644)
    password = (CENTER / 'mysql-secrets/password').read_text()
    config = {
        'port': 8888, 'mode': 'simulation', 'scheme': 'RSA',
        'tls_config': {'enable_tls': True, 'server_cert_path': '/cm-server/client.crt',
                       'server_private_key_path': '/cm-server/client.key', 'client_ca_cert_path': '/cm-client-ca'},
        'storage_config': {'storage_backend': 'mysql', 'db_url': 'mysql://capsule@127.0.0.1:3306/capsulemanager', 'password': password},
        'enable_inject_cm_key': True, 'cm_private_key_path': '/cm-master/client.key', 'cm_cert_path': '/cm-master/client.crt',
        'log_config': {'log_dir': '/tmp/cm-logs', 'log_level': 'info', 'enable_console_logger': True},
    }
    # JSON 是 YAML 的子集；字段按固定源码定义，敏感配置只在运行目录。
    atomic(CENTER / 'cm-config.json', config)
    nginx = '''pid /tmp/nginx.pid;
events { worker_connections 256; }
http {
  map_hash_bucket_size 256;
  access_log off;
  error_log /dev/stderr warn;
  client_body_temp_path /tmp/client_body;
  map $ssl_client_s_dn $p3_probe { default 0; ~CN=probe- 1; }
  map "$p3_probe:$uri" $p3_reject { default 0; ~^1: 1; "1:GET_RA" 0; }
  server {
    listen 8443 ssl;
    http2 on;
    server_name capsule.tee-a.test;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_certificate /gateway-cert/client.crt;
    ssl_certificate_key /gateway-cert/client.key;
    ssl_client_certificate /gateway-trust/ca.crt;
    ssl_crl /gateway-trust/ca.crl;
    ssl_verify_client on;
    ssl_verify_depth 2;
    ssl_session_cache off;
    ssl_session_tickets off;
    if ($p3_reject) { return 403; }
    location / {
      grpc_connect_timeout 2s;
      grpc_read_timeout 5s;
      grpc_ssl_verify on;
      grpc_ssl_server_name on;
      grpc_ssl_name capsule-internal.tee-a.test;
      grpc_ssl_trusted_certificate /upstream/ca.crt;
      grpc_ssl_certificate /upstream/client.crt;
      grpc_ssl_certificate_key /upstream/client.key;
      grpc_pass grpcs://127.0.0.1:8888;
    }
  }
}
'''.replace('GET_RA', GET_RA)
    atomic(CENTER / 'nginx.conf', nginx)
    volumes = []
    def mounts(specs):
        result = []
        for params in specs:
            volume, mount = host_volume(*params)
            volumes.append(volume)
            result.append(mount)
        return result
    cm_mounts = mounts([('cm-config', 'cm-config.json', '/config/config.yaml', True, False),
                        ('cm-server', 'cm-server-cert', '/cm-server'),
                        ('cm-master', 'cm-master-key', '/cm-master'),
                        ('cm-client-ca', 'cm-client-ca', '/cm-client-ca')])
    gateway_mounts = mounts([('nginx', 'nginx.conf', '/etc/nginx/nginx.conf', True, False),
                             ('gateway-cert', 'gateway-cert', '/gateway-cert'),
                             ('gateway-trust', 'gateway-trust', '/gateway-trust'),
                             ('upstream', 'gateway-upstream-cert', '/upstream')])
    mysql_mounts = mounts([('mysql', 'mysql-data', '/var/lib/mysql', False),
                           ('mysql-secrets', 'mysql-secrets', '/mysql-secrets'),
                           ('mysql-init', 'mysql-init', '/docker-entrypoint-initdb.d')])
    containers = [
        {'name': 'mysql', 'image': runtime_image('mysql'), 'imagePullPolicy': 'Never', 'volumeMounts': mysql_mounts,
         'env': [{'name': k, 'value': v} for k, v in {'MYSQL_DATABASE': 'capsulemanager', 'MYSQL_USER': 'capsule',
             'MYSQL_PASSWORD_FILE': '/mysql-secrets/password', 'MYSQL_ROOT_PASSWORD_FILE': '/mysql-secrets/root-password'}.items()],
         # 此 Kuscia agent 不支持 Exec 探针；TCP 仅用于 Pod 就绪，业务可用性另由认证原生请求验收。
         'readinessProbe': {'tcpSocket': {'port': 3306}, 'periodSeconds': 5}},
        {'name': 'capsule', 'image': runtime_image('capsule'), 'imagePullPolicy': 'Never', 'volumeMounts': cm_mounts,
         'command': ['/home/admin/capsule_manager'], 'args': ['--config_path', '/config/config.yaml', '--tls_config.enable_tls', 'true'],
         'readinessProbe': {'tcpSocket': {'port': 8888}, 'periodSeconds': 5}},
        {'name': 'gateway', 'image': runtime_image('gateway'), 'imagePullPolicy': 'Never', 'volumeMounts': gateway_mounts,
         'ports': [{'name': 'mtls', 'containerPort': 8443, 'hostPort': 31888, 'protocol': 'TCP'}],
         'command': ['nginx'], 'args': ['-g', 'daemon off;'],
         'readinessProbe': {'tcpSocket': {'port': 8443}, 'periodSeconds': 5}},
    ]
    configured_files = ['cm-config.json', 'nginx.conf', 'mysql-init/01-cm.sql',
        'cm-server-cert/client.crt', 'cm-master-key/client.crt', 'gateway-cert/client.crt',
        'gateway-upstream-cert/client.crt', 'cm-client-ca/ca.crt', 'gateway-trust/ca.crt']
    config_digest = hashlib.sha256(b''.join(name.encode() + b'\0' + (CENTER / name).read_bytes() for name in configured_files)).hexdigest()
    deployment = {'apiVersion': 'apps/v1', 'kind': 'Deployment',
        'metadata': {'name': 'tee-a-capsule', 'namespace': DOMAIN, 'labels': kube_labels()},
        'spec': {'replicas': 1, 'strategy': {'type': 'Recreate'}, 'selector': {'matchLabels': {'app': 'tee-a-capsule'}},
                 'template': {'metadata': {'labels': {'app': 'tee-a-capsule', **kube_labels()},
                                          'annotations': {'tee.secretflow.dev/config-sha256': config_digest}},
                 'spec': {'automountServiceAccountToken': False, 'nodeName': node_name,
                          'nodeSelector': {'kuscia.secretflow/namespace': DOMAIN},
                          'containers': containers, 'volumes': volumes}}}}
    service = {'apiVersion': 'v1', 'kind': 'Service',
        'metadata': {'name': 'capsule-manager', 'namespace': DOMAIN, 'labels': kube_labels()},
        'spec': {'type': 'ClusterIP', 'selector': {'app': 'tee-a-capsule'},
                 'ports': [{'port': 8443, 'targetPort': 8443, 'protocol': 'TCP'}]}}
    atomic(CENTER / 'resources.json', {'apiVersion': 'v1', 'kind': 'List', 'items': [deployment, service]})
    print('中心模板已渲染；CM 原端口与 MySQL 不发布，外部只有19685的mTLS网关。')


def base_up(repair_startup=False):
    blocker = CENTER / 'compatibility-blocker.json'
    blocked = json.loads(blocker.read_text()) if blocker.exists() else {}
    patch_candidate = blocked.get('deploymentStopped') is True
    if patch_candidate:
        patch = manifest()['images']['capsule'].get('sourcePatch', {})
        digest = hashlib.sha256((ROOT / 'scripts/deploy/tee/capsule-source-fixes.patch').read_bytes()).hexdigest()
        if not repair_startup or patch.get('sha256') != digest or patch.get('baseRevision') != SOURCES['capsule'][1] or patch.get('userApproved') is not True or not patch.get('targets') or any(v.get('beforeSha256') == v.get('afterSha256') for v in patch['targets'].values()) or patch.get('dispatchGuard', {}).get('ok') is not True:
            raise RuntimeError('CM 兼容阻塞；仅允许显式启动带已批准且摘要匹配修复的候选镜像')
    def record_start():
        if patch_candidate:
            blocked.update(deploymentStopped=False, resolution='PATCHED_CANDIDATE_PENDING_RUNTIME_ACCEPTANCE',
                candidateImageId=manifest()['images']['capsule']['id'], sourcePatch=patch, checkedAt=utc())
            atomic(blocker, blocked)
    for key in ['capsule', 'mysql', 'gateway']: import_image('tee-a-center', key)
    render()
    file = CENTER / 'resources.json'
    digest = hashlib.sha256(file.read_bytes()).hexdigest()
    marker = CENTER / 'applied.sha256'
    if marker.exists():
        if marker.read_text().strip() != digest:
            existing = json.loads(kube('tee-a-center', 'get', 'deployment', 'tee-a-capsule', '-n', DOMAIN, '-o', 'json'))
            if any(existing['metadata'].get('labels', {}).get(k) != v for k, v in kube_labels().items()):
                raise RuntimeError('底座归属不符，拒绝操作')
            if existing.get('status', {}).get('readyReplicas', 0) > 0 and not repair_startup:
                raise RuntimeError('不替换健康或归属不符的底座；需单独核对配置变化')
            print('应用已核对的 A 底座启动修复；保留私钥与数据库，不改变原平台或旧实例。')
            kube('tee-a-center', 'apply', '-f', '-', value=json.loads(file.read_text()))
            atomic(marker, digest + '\n')
            print(kube('tee-a-center', 'rollout', 'status', 'deployment/tee-a-capsule', '-n', DOMAIN, '--timeout=180s'))
            record_start()
            return
        else:
            print(kube('tee-a-center', 'rollout', 'status', 'deployment/tee-a-capsule', '-n', DOMAIN, '--timeout=30s'))
            print('相同底座配置已应用且就绪，不重启。')
            record_start()
            return
    existing = json.loads(kube('tee-a-center', 'get', 'deployment', '-n', DOMAIN, '-o', 'json'))
    if any(x['metadata']['name'] == 'tee-a-capsule' for x in existing['items']):
        raise RuntimeError('同名底座已存在但没有本次清单，拒绝接管')
    kube('tee-a-center', 'apply', '-f', '-', value=json.loads(file.read_text()))
    atomic(marker, digest + '\n')
    print(kube('tee-a-center', 'rollout', 'status', 'deployment/tee-a-capsule', '-n', DOMAIN, '--timeout=180s'))
    record_start()


def probe_up(name):
    ref = checked_image('probe')
    ctr = f'data-sandbox-dev-{name}-tee-probe'
    current = managed(ctr)
    if current:
        if current['Image'] == image_info(ref)['Id'] and current['State']['Running']: return
        raise RuntimeError('探测器已存在且状态不同，需单独授权替换')
    network = f'data-sandbox-dev-{name}'
    managed(network, 'network') or (_ for _ in ()).throw(RuntimeError('实例网络未创建'))
    command = ['docker', 'run', '-d', '--pull=never', '--name', ctr, '--network', network,
               '--user', f'{os.getuid()}:{os.getgid()}',
               '--restart', 'unless-stopped', '--read-only', '--cap-drop=ALL', '--security-opt', 'no-new-privileges',
               '--tmpfs', '/tmp:rw,noexec,nosuid,size=16m',
               '-e', 'TEE_CAPSULE_ENDPOINT=222.20.99.38:19685',
               '-v', str(RUNTIME / name / 'tee/probe-cert') + ':/certs:ro']
    for k, v in labels().items(): command += ['--label', f'{k}={v}']
    run(*command, ref, 'python', '/opt/p3/probe.py', '--serve')


def secret(name, directory):
    return {'apiVersion': 'v1', 'kind': 'Secret', 'type': 'Opaque',
            'metadata': {'name': name, 'namespace': DOMAIN, 'labels': kube_labels()},
            'data': {key: base64.b64encode((directory / file).read_bytes()).decode() for key, file in
                     [('TEE_CA_PEM', 'ca.crt'), ('TEE_CLIENT_CERT_PEM', 'client.crt'), ('TEE_CLIENT_KEY_PEM', 'client.key')]}}


def appimage(name, key, command):
    ref = checked_image(key)
    image_name, tag = ref.rsplit(':', 1)
    return {'apiVersion': 'kuscia.secretflow/v1alpha1', 'kind': 'AppImage',
        'metadata': {'name': name, 'labels': kube_labels()},
        'spec': {'image': {'name': image_name, 'tag': tag, 'id': manifest()['images'][key]['id']},
                 'configTemplates': {'task-config.conf': '{"task_id":"{{.TASK_ID}}","task_input_config":"{{.TASK_INPUT_CONFIG}}"}'},
                 'deployTemplates': [{'name': 'main', 'replicas': 1, 'spec': {'restartPolicy': 'Never',
                    'containers': [{'name': 'main', 'command': command, 'workingDir': '/tmp', 'imagePullPolicy': 'Never',
                       'envFrom': [{'secretRef': {'name': 'tee-a-probe-cert'}}],
                       'env': [{'name': 'TEE_CAPSULE_ENDPOINT', 'value': '222.20.99.38:19685'}],
                       'configVolumeMounts': [{'mountPath': '/etc/kuscia/task-config.conf', 'subPath': 'task-config.conf'}],
                       'resources': {'requests': {'cpu': '100m', 'memory': '128Mi'}, 'limits': {'cpu': '1', 'memory': '512Mi'}},
                       'securityContext': {'allowPrivilegeEscalation': False, 'capabilities': {'drop': ['ALL']}}}]}}]}}


def register():
    for instance in INSTANCES:
        for key in ['probe', 'teeapps']: import_image(instance, key)
    kube('tee-a-center', 'apply', '-f', '-', value=secret('tee-a-probe-cert', CENTER / 'workload-cert'))
    # 私钥只通过 Secret 引用传递，不写入 AppImage、TaskSpec 或日志。
    probe = appimage('tee-a-foundation-probe', 'probe', ['python', '/opt/p3/probe.py', '--task-config', '/etc/kuscia/task-config.conf'])
    teeapps = appimage('tee-a-official-teeapps-check', 'teeapps', ['/bin/sh', '-ec',
        'umask 077; d=$(mktemp -d /dev/shm/tee-p3.XXXXXX); trap \'rm -rf "$d"\' EXIT; '
        'printf "%s" "$TEE_CLIENT_KEY_PEM" > "$d/client.key"; '
        'printf "%s" "$TEE_CLIENT_CERT_PEM" > "$d/client.crt"; '
        'printf "%s" "$TEE_CA_PEM" > "$d/ca.crt"; '
        'test -s /etc/kuscia/task-config.conf; test -s "$d/client.key"; test -s "$d/client.crt"; test -s "$d/ca.crt"; '
        'rc=0; /home/teeapp/sim/teeapps/main --help > "$d/help" || rc=$?; '
        'test "$rc" -eq 1; grep -q enable_capsule_tls "$d/help"; grep -q entry_task_config_path "$d/help"; printf \'TEEAPPS_HELP_AND_NONEMPTY_MOUNTS_OK\\n\''])
    official = appimage('tee-a-official-teeapps', 'teeapps', ['/bin/sh', '-ec',
        'umask 077; d=$(mktemp -d /dev/shm/tee-p3.XXXXXX); trap \'rm -rf "$d"\' EXIT; '
        'printf "%s" "$TEE_CLIENT_KEY_PEM" > "$d/client.key"; '
        'printf "%s" "$TEE_CLIENT_CERT_PEM" > "$d/client.crt"; '
        'printf "%s" "$TEE_CA_PEM" > "$d/ca.crt"; '
        'for f in client.key client.crt ca.crt; do ln -s "$d/$f" "/host/certs/$f"; done; '
        '/home/teeapp/sim/teeapps/main --plat sim --app_mode kuscia '
        '--entry_task_config_path /etc/kuscia/task-config.conf --data_mesh_endpoint datamesh:8071 '
        '--enable_capsule_tls true --enable_console_logger true '
        '--app_log_path "$d/app.log" --monitor_log_path "$d/monitor.log"'])
    official['spec']['configTemplates']['task-config.conf'] = ('{"task_id":"{{.TASK_ID}}",'
        '"task_input_config":"{{.TASK_INPUT_CONFIG}}","task_cluster_def":"{{.TASK_CLUSTER_DEFINE}}",'
        '"allocated_ports":"{{.ALLOCATED_PORTS}}"}')
    # 官方入口仅登记为底座组件，当前挂载只读探测身份；业务密钥请求会被网关拒绝。
    # 它不接受 tee_task_jws，也不替代 B 后续提供的契约运行时。
    for resource in [probe, teeapps, official]:
        kube('tee-a-center', 'apply', '-f', '-', value=resource)


def record_smoke(app, name):
    job = json.loads(kube('tee-a-center', 'get', 'kusciajob', name, '-n', 'cross-domain', '-o', 'json'))
    task = json.loads(kube('tee-a-center', 'get', 'kusciatask', name + '-task', '-n', 'cross-domain', '-o', 'json'))
    if job.get('status', {}).get('phase') != 'Succeeded' or task.get('status', {}).get('phase') != 'Succeeded' or task['metadata']['labels'].get('kuscia.secretflow/job-uid') != job['metadata']['uid']:
        raise RuntimeError('Job 与实际 Task 的成功状态不一致')
    ctr = 'data-sandbox-dev-tee-a-center-kuscia'
    def cri(*args): return run('docker', 'exec', ctr, '/home/kuscia/bin/crictl', *args, capture=True)
    containers = [c for c in json.loads(cri('ps', '-a', '-o', 'json'))['containers']
        if c.get('metadata', {}).get('name') == 'main' and c.get('labels', {}).get('io.kubernetes.pod.name') == name + '-task-0'
        and c['labels'].get('io.kubernetes.pod.namespace') == DOMAIN]
    if len(containers) != 1: raise RuntimeError('未找到唯一的实际探测容器')
    container = containers[0]
    status = json.loads(cri('inspect', container['id']))['status']
    key = 'probe' if app == 'tee-a-foundation-probe' else 'teeapps'
    if status.get('exitCode') != 0 or container.get('imageRef') != manifest()['images'][key]['id']:
        raise RuntimeError('探测退出码或实际镜像 ID 与锁定清单不一致')
    log = cri('logs', container['id'])
    if app == 'tee-a-foundation-probe':
        result = json.loads(log)
        if result.get('reachable') is not True or result.get('method') != 'CAPSULE_GET_RA_CERT_MTLS' or not result.get('checkedAt'):
            raise RuntimeError('Job 日志未证明实际原生认证调用')
        result = {k: result[k] for k in ['checkedAt', 'reachable', 'method']}
    else:
        if log.strip() != 'TEEAPPS_HELP_AND_NONEMPTY_MOUNTS_OK':
            raise RuntimeError('官方入口及挂载检查日志不符合预期')
        result = {'helpAndNonemptyMounts': True, 'nativeCallVerifiedByThisJob': False}
    file = CENTER / 'job-verification.json'
    evidence = json.loads(file.read_text()) if file.exists() else {}
    evidence[app] = {'checkedAt': utc(), 'job': name, 'jobUid': job['metadata']['uid'],
        'taskUid': task['metadata']['uid'], 'containerId': container['id'], 'imageId': container['imageRef'],
        'exitCode': status['exitCode'], 'logSha256': hashlib.sha256(log.encode()).hexdigest(), 'logEvidence': result}
    atomic(file, evidence)


def smoke():
    for app in ['tee-a-foundation-probe', 'tee-a-official-teeapps-check']:
        name = 'p3-' + secrets.token_hex(5)
        task = {'apiVersion': 'kuscia.secretflow/v1alpha1', 'kind': 'KusciaJob',
            'metadata': {'name': name, 'namespace': 'cross-domain', 'labels': kube_labels()},
            'spec': {'initiator': DOMAIN, 'maxParallelism': 1,
                'tasks': [{'taskID': name + '-task', 'alias': 'p3-probe', 'appImage': app, 'taskInputConfig': '{}', 'scheduleConfig': {'lifecycleSeconds': 120},
                           'parties': [{'domainID': DOMAIN}] }]}}
        kube('tee-a-center', 'apply', '-f', '-', value=task)
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            result = json.loads(kube('tee-a-center', 'get', 'kusciajob', name, '-n', 'cross-domain', '-o', 'json'))
            state = result.get('status', {}).get('phase')
            if state == 'Succeeded': break
            if state in ['Failed', 'Cancelled']: raise RuntimeError(f'{app} 调度探测失败：{name}')
            time.sleep(2)
        else: raise RuntimeError(f'{app} 调度探测超时：{name}')
        record_smoke(app, name)
        print(f'{app} {name} Succeeded；实际容器镜像、退出码和日志已核对。')


def pair():
    """仅配对新实例，身份信息在内存传递，不保存登录 token 或节点私钥。"""
    def api(name, path, payload, token=None):
        port = INSTANCES[name] * 100 + 88
        headers = {'Content-Type': 'application/json'}
        if token: headers['User-Token'] = token
        request = urllib.request.Request(f'http://127.0.0.1:{port}/api/' + path,
            data=json.dumps(payload).encode(), headers=headers)
        with urllib.request.urlopen(request, timeout=20) as response: result = json.load(response)
        if result.get('status', {}).get('code') != 0:
            raise RuntimeError(f'{name} {path} 请求失败，不输出身份响应')
        return result['data']
    sessions = {}
    for name in INSTANCES:
        managed(f'data-sandbox-dev-{name}-secretpad')
        env = dict(line.split('=', 1) for line in (RUNTIME / name / 'secretpad.env').read_text().splitlines() if '=' in line)
        login = api(name, 'login', {'name': env['SECRETPAD_USER_NAME'],
                    'passwordHash': hashlib.sha256(env['SECRETPAD_PASSWORD'].encode()).hexdigest()})
        sessions[name] = login['token']
    invitations = {}
    for name in INSTANCES:
        result = api(name, 'v1alpha1/node/get', {'nodeId': 'dev-' + name}, sessions[name])
        invitations[name] = json.loads(base64.b64decode(result['nodeAuthenticationCode']))
    for client in ['tee-a-client-1', 'tee-a-client-2']:
        for src, dst in [(client, 'tee-a-center'), ('tee-a-center', client)]:
            routes = json.loads(kube(src, 'get', 'clusterdomainroutes', '-o', 'json'))['items']
            if any(x.get('spec', {}).get('source') == 'dev-' + src and x.get('spec', {}).get('destination') == 'dev-' + dst for x in routes):
                continue
            invite = invitations[dst]
            payload = {k: invite[k] for k in ['masterNodeId', 'dstNodeId', 'name', 'certText', 'dstNetAddress']}
            payload.update(mode=1, srcNodeId='dev-' + src, dstInstId=invite['instId'], dstInstName=invite['instName'])
            api(src, 'v1alpha1/p2p/node/create', payload, sessions[src])
    print('两客户端与中心双向配对请求完成；READY 状态仍须实际核验。')


def dispatch(args):
    if args.command == 'base-up': return base_up(args.repair_startup)
    actions = {'certificates': certificates, 'render': render,
               'register': register, 'smoke': smoke, 'pair': pair}
    if args.command in actions: return actions[args.command]()
    if args.command == 'probe-up': return probe_up(args.name)
    if args.command == 'lock-image': return lock_image(args.image_key, args.image_ref)
    if args.command == 'build-components':
        from component_build import build
        return build(args.image_key)
    if args.command in ['verify-tls', 'verify-native', 'verify-persistence', 'verify-environment', 'verify-isolation', 'verify-repeat']:
        from verification import verify
        return verify(args.command)
    raise RuntimeError('未实现的操作')
