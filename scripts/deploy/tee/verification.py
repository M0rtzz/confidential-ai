"""新底座运行验收；任何失败或缺少证据均停止，不接触业务数据。"""
import json
import shutil
import subprocess
import hashlib
import time
import urllib.error
import urllib.request
import os
from pathlib import Path
from datetime import datetime

from platform_deploy import ROOT, ORIGINAL, RUNTIME, INSTANCES, CONTRACT_HOST, run, atomic, kube, checked_image, managed, manifest, utc, domain_id
from foundation import CENTER, PKI, DOMAIN, openssl, issue, make_ca, labels, pod_exec


def verify_tls():
    """全部结论来自实际 gRPC 请求，TLS 握手退出码不作为准入证据。"""
    target = f'{CONTRACT_HOST}:19685'
    kuscia = 'data-sandbox-dev-center-kuscia'
    managed(kuscia) or (_ for _ in ()).throw(RuntimeError('中心实例尚未启动'))
    image = checked_image('probe')
    cases = CENTER / 'acceptance-certs'
    issue(PKI / 'external-ca', cases / 'expired', 'probe-expired', expired=True)
    issue(PKI / 'external-ca', cases / 'revoked', 'probe-revoked')
    make_ca(cases / 'wrong-ca', 'wrong-ca')
    issue(cases / 'wrong-ca', cases / 'wrong', 'probe-wrong')
    # 错误客户端 CA 测试仍信任合法服务端 CA，避免因服务端校验失败产生假阳性。
    shutil.copy2(PKI / 'external-ca/ca.crt', cases / 'wrong/ca.crt')
    index = (PKI / 'external-ca/index.txt').read_text()
    if not any(line.startswith('R\t') and '/CN=probe-revoked' in line for line in index.splitlines()):
        openssl('ca', '-batch', '-config', PKI / 'external-ca/openssl.cnf', '-revoke', cases / 'revoked/client.crt')
    openssl('ca', '-batch', '-config', PKI / 'external-ca/openssl.cnf', '-gencrl', '-out', PKI / 'external-ca/ca.crl')
    shutil.copy2(PKI / 'external-ca/ca.crl', CENTER / 'gateway-trust/ca.crl')
    pods = json.loads(kube('center', 'get', 'pods', '-n', DOMAIN, '-l', 'app=tee-a-capsule', '-o', 'json'))['items']
    if len(pods) != 1: raise RuntimeError('底座 Pod 数量不符')
    pod, address = pods[0]['metadata']['name'], pods[0]['status']['podIP']
    pod_exec(pod, 'gateway', 'nginx', '-s', 'reload')
    valid = RUNTIME / 'center/tee/probe-cert'
    bypass = cases / 'bypass'
    bypass.mkdir(exist_ok=True, mode=0o700)
    for file in ['client.key', 'client.crt']: shutil.copy2(valid / file, bypass / file)
    shutil.copy2(PKI / 'upstream-ca/ca.crt', bypass / 'ca.crt')
    attempts = [('valid', valid, target, []),
        ('missing', valid, target, ['--negative-no-client-certificate']),
        ('wrong', cases / 'wrong', target, []), ('expired', cases / 'expired', target, []),
        ('revoked', cases / 'revoked', target, []),
        ('plaintext', valid, target, ['--negative-plaintext']),
        ('bypass', bypass, address + ':8888', ['--server-name', 'capsule-internal.tee-a.test'])]
    # 观察固定镜像内探测器的真实 RPC 异常；不替换 SDK 请求或成功判据。
    observer = '''import sys,json,grpc
sys.path.insert(0, '/opt/p3')
import probe
from secretflowapis.v2.sdc.capsule_manager import capsule_manager_pb2_grpc as api
original = api.CapsuleManagerStub
observed = {}
class ObservedStub(original):
    def __init__(self, channel):
        super().__init__(channel)
        native = self.GetRaCert
        def invoke(*args, **kwargs):
            try: return native(*args, **kwargs)
            except grpc.RpcError as error:
                observed['code'] = error.code().name
                detail = error.details()
                observed['gatewayCertificateRejected'] = 'status: 400' in detail
                observed['plaintextProtocolRejected'] = 'Trying to connect an http1.x server' in detail
                raise
        self.GetRaCert = invoke
api.CapsuleManagerStub = ObservedStub
flags = sys.argv[1:]
server = flags[flags.index('--server-name') + 1] if '--server-name' in flags else 'capsule.tee-a.test'
result = probe.check('--negative-no-client-certificate' in flags, '--negative-plaintext' in flags, server)
result['transportEvidence'] = observed
print(json.dumps(result))
raise SystemExit(0 if result['reachable'] else 1)
'''
    results = {}
    # 每个负例后立即再发合法请求；连接故障或超时不得当作认证拒绝。
    attempts = [item for attempt in attempts for item in ([attempt] if attempt[0] == 'valid' else [attempt, ('valid-after-' + attempt[0], valid, target, [])])]
    for kind, directory, endpoint, flags in attempts:
        command = ['docker', 'run', '--rm', '--pull=never', '--network', 'container:' + kuscia,
             '--user', f'{os.getuid()}:{os.getgid()}',
             '--read-only', '--cap-drop=ALL', '--security-opt', 'no-new-privileges',
             '-e', 'TEE_CAPSULE_ENDPOINT=' + endpoint, '-v', str(directory) + ':/certs:ro']
        for key, value in labels().items(): command += ['--label', key + '=' + value]
        completed = subprocess.run(command + [image, 'python', '-c', observer] + flags,
                                    text=True, capture_output=True, timeout=20)
        # 导入失败、容器未启动等情况没有合法探测结果，必须失败，不能记为认证拒绝。
        try: result = json.loads(completed.stdout)
        except ValueError: raise RuntimeError('原生探测未执行：' + kind) from None
        if type(result.get('reachable')) is not bool or completed.returncode != (0 if result['reachable'] else 1):
            raise RuntimeError('原生探测结果异常：' + kind)
        if result['reachable'] != kind.startswith('valid'):
            raise RuntimeError('认证准入行为不符：' + kind)
        evidence = result.get('transportEvidence', {})
        if kind in ['missing', 'wrong', 'expired', 'revoked'] and not (evidence.get('code') == 'INTERNAL' and evidence.get('gatewayCertificateRejected') is True):
            raise RuntimeError('未取得网关证书拒绝证据：' + kind)
        if kind == 'plaintext' and not (evidence.get('code') == 'UNAVAILABLE' and evidence.get('plaintextProtocolRejected') is True):
            raise RuntimeError('未取得明文协议拒绝证据')
        if kind == 'bypass' and not (evidence.get('code') == 'UNAVAILABLE' and 'TLSV1_ALERT_UNKNOWN_CA' in completed.stderr):
            raise RuntimeError('未取得原生入口客户端 CA 拒绝证据')
        results[kind] = {'nativeAccepted': result['reachable'], 'checkedAt': result['checkedAt'], 'transportEvidence': evidence}
    atomic(CENTER / 'tls-verification.json', {'checkedAt': utc(), 'results': results})
    print('七项原生请求验收通过：合法证书成功，无证书、错误 CA、过期、吊销、明文及绕过入口均拒绝。')


def verify_native_surface():
    """覆盖原生全部入口的拒绝路径与进程稳定性，不模拟任何业务密钥放行。"""
    cert = CENTER / 'persistence-cert'
    issue(PKI / 'external-ca', cert, 'p3-persistence-client')
    def capsule_state():
        pods = json.loads(kube('center', 'get', 'pods', '-n', DOMAIN, '-l', 'app=tee-a-capsule', '-o', 'json'))['items']
        if len(pods) != 1: raise RuntimeError('CM Pod 数量异常')
        state = next(c for c in pods[0]['status']['containerStatuses'] if c['name'] == 'capsule')
        return pods[0]['metadata']['uid'], state['restartCount']
    before = capsule_state()
    code = '''import json,grpc,secrets
from pathlib import Path
from cryptography import x509
from secretflowapis.v2.sdc.capsule_manager import capsule_manager_pb2 as pb
from secretflowapis.v2.sdc.capsule_manager import capsule_manager_pb2_grpc as api
import os
root=Path('/certs')
creds=grpc.ssl_channel_credentials((root/'ca.crt').read_bytes(),(root/'client.key').read_bytes(),(root/'client.crt').read_bytes())
expected={'GetRaCert','CreateDataKeys','GetDataKeys','DeleteDataKey','GetExportDataKey','RegisterCert','CreateDataPolicy','ListDataPolicy','AddDataRule','DeleteDataPolicy','DeleteDataRule','CreateResultDataKey'}
service=pb.DESCRIPTOR.services_by_name['CapsuleManager']
assert {method.name for method in service.methods} == expected
result={}
with grpc.secure_channel(os.environ['TEE_CAPSULE_ENDPOINT'],creds,options=[('grpc.ssl_target_name_override','capsule.tee-a.test')]) as channel:
 stub=api.CapsuleManagerStub(channel)
 def positive():
  response=stub.GetRaCert(pb.GetRaCertRequest(nonce=secrets.token_hex(32)),timeout=3)
  assert response.status.code == 0
  x509.load_pem_x509_certificate(response.cert.encode())
 positive()
 for method in service.methods:
  if method.name == 'GetRaCert':
   result[method.name]={'nativeReadAccepted':True};continue
  request=getattr(pb,method.input_type.name)()
  response=getattr(stub,method.name)(request,timeout=3)
  assert response.status.code != 0
  positive()
  result[method.name]={'invalidRequestRejected':True,'applicationCode':response.status.code,'positiveControl':True}
print(json.dumps(result))
'''
    command = ['docker', 'run', '--rm', '--pull=never', '--network', 'data-sandbox-dev-center',
        '--user', f'{os.getuid()}:{os.getgid()}', '--read-only', '--cap-drop=ALL', '--security-opt', 'no-new-privileges',
        '-e', f'TEE_CAPSULE_ENDPOINT={CONTRACT_HOST}:19685', '-v', str(cert) + ':/certs:ro']
    for k, v in labels().items(): command += ['--label', k + '=' + v]
    result = subprocess.run(command + [checked_image('probe'), 'python', '-c', code], text=True, capture_output=True, timeout=90)
    if result.returncode:
        raise RuntimeError('全部原生入口回归失败；不将异常堆栈或请求内容输出到日志')
    observed = json.loads(result.stdout)
    if before != capsule_state(): raise RuntimeError('原生入口回归导致 CM 进程或 Pod 重启')
    atomic(CENTER / 'native-surface-verification.json', {'checkedAt': utc(), 'methods': observed,
        'capsuleImageId': manifest()['images']['capsule']['id'], 'processNotRestarted': True,
        'businessKeyReleaseVerified': False})
    print('12 个原生入口回归通过：只读调用成功，其余非法请求明确拒绝；阳性对照成功，CM 未重启。')


def verify_persistence():
    # 合成策略的原生读取会校验使用固定主密钥派生的 HMAC；不代替数据密钥解密验收。
    from time import sleep, monotonic
    case_root = CENTER / 'acceptance-persistence'
    case_root.mkdir(exist_ok=True, mode=0o700)
    cert = CENTER / 'persistence-cert'
    issue(PKI / 'external-ca', cert, 'p3-persistence-client')
    image = checked_image('probe')
    network = 'data-sandbox-dev-center'
    managed(network, 'network') or (_ for _ in ()).throw(RuntimeError('中心网络不存在'))
    def phase(name):
        command = ['docker', 'run', '--rm', '--pull=never', '--network', network,
                   '--user', f'{os.getuid()}:{os.getgid()}',
                   '--add-host', f'capsule.tee-a.test:{CONTRACT_HOST}', '--read-only', '--cap-drop=ALL',
                   '--security-opt', 'no-new-privileges', '-e', 'TEE_CAPSULE_ENDPOINT=capsule.tee-a.test:19685',
                   '-v', str(cert) + ':/certs:ro', '-v', str(case_root) + ':/case']
        for k, v in labels().items(): command += ['--label', k + '=' + v]
        result = subprocess.run(command + [image, 'python', '/opt/p3/persistence_client.py', name],
                                capture_output=True, text=True, timeout=50)
        if result.returncode: raise RuntimeError('合成持久化阶段未通过：' + name)
        value = json.loads(result.stdout)
        if value.get('verified') is not True: raise RuntimeError('合成持久化没有有效证据')
        return value
    before = phase('create')
    old = json.loads(kube('center', 'get', 'pods', '-n', DOMAIN, '-l', 'app=tee-a-capsule', '-o', 'json'))['items']
    kube('center', 'rollout', 'restart', 'deployment/tee-a-capsule', '-n', DOMAIN)
    kube('center', 'rollout', 'status', 'deployment/tee-a-capsule', '-n', DOMAIN, '--timeout=180s')
    new = json.loads(kube('center', 'get', 'pods', '-n', DOMAIN, '-l', 'app=tee-a-capsule', '-o', 'json'))['items']
    if not old or not new or old[0]['metadata']['uid'] == new[0]['metadata']['uid']:
        raise RuntimeError('未观察到实际 Pod 重建')
    deadline = monotonic() + 30
    while True:
        try: after = phase('verify'); break
        except RuntimeError:
            if monotonic() >= deadline: raise
            sleep(2)
    cleanup = phase('cleanup')
    # 合成身份仅用于本轮验收；成功软删除后清理，下一轮不复用已删除的合成策略。
    (case_root / 'case.json').unlink()
    atomic(CENTER / 'persistence-verification.json', {'checkedAt': utc(), 'before': before,
        'after': after, 'cleanup': cleanup, 'oldPodUid': old[0]['metadata']['uid'],
        'newPodUid': new[0]['metadata']['uid'], 'evidence': 'NATIVE_POLICY_HMAC_RESTART_READ'})
    print('合成策略在底座重启后通过原生 HMAC 校验读取，合成规则已软删除；不声称数据密钥解密验收。')


def verify_environment():
    """通过真实会话验证字段与故障降级；故障注入仅作用于 A 中心底座，退出时恢复。"""
    fields = set('contractVersion runtimeMode checkedAt hardwareDetected deviceChecks attestationVerified keyServiceReachable realModeReady blockers'.split())
    sessions, starts, results = {}, {}, {}
    def request(name, path, payload=None, token=None):
        headers = {'Content-Type': 'application/json'}
        if token: headers['User-Token'] = token
        req = urllib.request.Request(f'http://127.0.0.1:{INSTANCES[name] * 100 + 88}/api/' + path,
            data=json.dumps(payload).encode() if payload is not None else None, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            return error.code, json.load(error)
    def environment(name):
        code, body = request(name, 'v1alpha1/tee/environment', token=sessions[name])
        value = body.get('data', {})
        if code != 200 or body.get('status', {}).get('code') != 0 or set(value) != fields:
            raise RuntimeError('环境接口包装或冻结字段不符：' + name)
        if value['contractVersion'] != 'tee-contract/1.0' or value['runtimeMode'] != 'SIMULATION' or value['attestationVerified'] is not False or value['realModeReady'] is not False:
            raise RuntimeError('环境接口错误声明真实 TEE 能力：' + name)
        return value
    for name in INSTANCES:
        starts[name] = managed(f'data-sandbox-dev-{name}-secretpad')['State']['StartedAt']
        env = dict(line.split('=', 1) for line in (RUNTIME / name / 'secretpad.env').read_text().splitlines() if '=' in line)
        # 中心端同时开放数据方与执行方，按契约必须显式选择端；单端实例可省略。
        credentials = {'name': env['SECRETPAD_USER_NAME'],
            'passwordHash': hashlib.sha256(env['SECRETPAD_PASSWORD'].encode()).hexdigest()}
        if name == 'center':
            credentials['endRole'] = 'CENTER'
        code, login = request(name, 'login', credentials)
        if code != 200 or login.get('status', {}).get('code') != 0:
            raise RuntimeError('实例登录验收失败：' + name)
        sessions[name] = login['data']['token']
        code, denied = request(name, 'v1alpha1/tee/environment')
        if code != 401 or denied.get('data', {}).get('errorCode') != 'AUDIT_ACCESS_DENIED':
            raise RuntimeError('环境接口未拒绝无会话访问：' + name)
        value = environment(name)
        if value['keyServiceReachable'] is not True or value['checkedAt'] is None or value['hardwareDetected'] is not False or value['deviceChecks'] != {'sgx': False, 'tdx': False, 'csv': False} or value['blockers'] != ['NO_VERIFIED_HARDWARE_RUNTIME']:
            raise RuntimeError('环境正常态证据不符合当前仿真部署：' + name)
        results[name] = {'login': True, 'unauthenticatedRejected': True, 'environment': value}
    snapshot = RUNTIME / 'center/status/hardware.json'
    saved = snapshot.read_text()
    failures = {}
    def assert_snapshot_fault(value, blocker, expected_time):
        observed = value['checkedAt']
        same_time = observed is None if expected_time is None else observed is not None and datetime.fromisoformat(observed.replace('Z', '+00:00')) == datetime.fromisoformat(expected_time.replace('Z', '+00:00'))
        if value['blockers'] != [blocker, 'NO_VERIFIED_HARDWARE_RUNTIME'] or not same_time or value['keyServiceReachable'] is not True or value['hardwareDetected'] is not False or value['deviceChecks'] != {'sgx': False, 'tdx': False, 'csv': False}:
            raise RuntimeError('检测故障状态不精确，或错误影响密钥服务状态：' + blocker)
    try:
        snapshot.unlink()
        missing = environment('center')
        assert_snapshot_fault(missing, 'HARDWARE_CHECK_UNAVAILABLE', None)
        failures['missing'] = True
        atomic(snapshot, 'malformed', 0o644)
        assert_snapshot_fault(environment('center'), 'HARDWARE_CHECK_UNAVAILABLE', None)
        failures['malformed'] = True
        stale = json.loads(saved); stale['checkedAt'] = '2000-01-01T00:00:00Z'
        atomic(snapshot, stale, 0o644)
        assert_snapshot_fault(environment('center'), 'HARDWARE_CHECK_STALE', stale['checkedAt'])
        failures['stale'] = True
        failed = json.loads(saved); failed['detectorOk'] = False
        atomic(snapshot, failed, 0o644)
        assert_snapshot_fault(environment('center'), 'HARDWARE_CHECK_FAILED', failed['checkedAt'])
        failures['detectorFailed'] = True
    finally:
        atomic(snapshot, saved, 0o644)
    try:
        kube('center', 'scale', 'deployment/tee-a-capsule', '-n', DOMAIN, '--replicas=0')
        kube('center', 'wait', '--for=delete', 'pod', '-n', DOMAIN, '-l', 'app=tee-a-capsule', '--timeout=90s')
        for name in INSTANCES:
            value = environment(name)
            if value['keyServiceReachable'] is not False or value['blockers'] != ['KEY_SERVICE_UNAVAILABLE', 'NO_VERIFIED_HARDWARE_RUNTIME'] or value['checkedAt'] is None or value['hardwareDetected'] is not False or value['deviceChecks'] != {'sgx': False, 'tdx': False, 'csv': False}:
                raise RuntimeError('CM 不可用时环境接口未降级：' + name)
        failures['capsuleUnavailable'] = True
    finally:
        kube('center', 'scale', 'deployment/tee-a-capsule', '-n', DOMAIN, '--replicas=1')
        kube('center', 'rollout', 'status', 'deployment/tee-a-capsule', '-n', DOMAIN, '--timeout=180s')
    deadline = time.monotonic() + 45
    while not all(environment(name)['keyServiceReachable'] is True for name in INSTANCES):
        if time.monotonic() > deadline: raise RuntimeError('底座恢复后原生探测未恢复')
        time.sleep(2)
    for name, started in starts.items():
        if managed(f'data-sandbox-dev-{name}-secretpad')['State']['StartedAt'] != started:
            raise RuntimeError('故障验收期间平台被重启：' + name)
    atomic(CENTER / 'environment-verification.json', {'checkedAt': utc(), 'instances': results,
        'degradation': failures, 'platformsNotRestarted': True})
    print('三实例登录、会话守卫、冻结环境字段及五类故障降级通过；CM 已恢复，平台没有重启。')


def verify_routes():
    domains = {name: domain_id(name) for name in INSTANCES}
    expected = {(domains[client], domains['center']) for client in ['client-a', 'client-b']}
    expected |= {(right, left) for left, right in expected.copy()}
    evidence = {}
    for name in INSTANCES:
        nodes = json.loads(kube(name, 'get', 'nodes', '-o', 'json'))['items']
        if len(nodes) != 1 or not any(c['type'] == 'Ready' and c['status'] == 'True' for c in nodes[0].get('status', {}).get('conditions', [])):
            raise RuntimeError('Kuscia 节点未就绪：' + name)
        items = json.loads(kube(name, 'get', 'clusterdomainroutes', '-o', 'json'))['items']
        pairs = {(r['spec']['source'], r['spec']['destination']) for r in items}
        required = expected if name == 'center' else {pair for pair in expected if domains[name] in pair}
        if pairs != required or len(items) != len(required):
            raise RuntimeError('存在缺失、重复、客户端直连或非本次实例路由：' + name)
        for route in items:
            if not any(c['type'] == 'Ready' and c['status'] == 'True' for c in route.get('status', {}).get('conditions', [])):
                raise RuntimeError('路由未就绪：' + route['metadata']['name'])
        # 只保存必要条件；完整 status 包含动态认证 token，禁止输出或归档。
        evidence[name] = {'node': nodes[0]['metadata']['name'], 'ready': True,
            'routes': [{'source': r['spec']['source'], 'destination': r['spec']['destination'],
                        'ready': True} for r in items]}
    atomic(RUNTIME / 'route-verification.json', {'checkedAt': utc(), 'instances': evidence})


def verify_isolation():
    verify_routes()
    before = json.loads((RUNTIME / 'protection-baseline.json').read_text())['before']
    after = {'repos': {}, 'containers': {}}
    for name in before['repos']:
        path, digest = ORIGINAL / name, hashlib.sha256()
        for relative in subprocess.check_output(['git', '-C', str(path), 'ls-files', '-z']).split(b'\0'):
            if not relative: continue
            file = path / os.fsdecode(relative)
            digest.update(relative + b'\0')
            if file.is_symlink(): digest.update(os.fsencode(os.readlink(file)))
            elif file.is_file(): digest.update(file.read_bytes())
        after['repos'][name] = {'head': run('git', '-C', path, 'rev-parse', 'HEAD', capture=True).strip(),
            'status': run('git', '-C', path, 'status', '--porcelain', capture=True).strip(), 'content': digest.hexdigest()}
    for name in before['containers']:
        value = json.loads(run('docker', 'inspect', name, capture=True))[0]
        after['containers'][name] = {key: value[key] for key in ['Id', 'Image', 'RestartCount']}
        after['containers'][name].update(startedAt=value['State']['StartedAt'], running=value['State']['Running'],
            ports=value['HostConfig']['PortBindings'])
    concurrent = []
    if before != after:
        if before['containers'] != after['containers'] or any(before['repos'][name] != after['repos'][name] for name in ['confidential-ai', 'confidential-ai-frontend']):
            raise RuntimeError('受保护仓库或旧容器变化，停止隔离验收，不自动恢复其他开发者资源')
        old, new = before['repos']['data-sandbox-package'], after['repos']['data-sandbox-package']
        old_status = {line.strip() for line in old['status'].splitlines()}
        new_status = {line.strip() for line in new['status'].splitlines()}
        concurrent = sorted(new_status - old_status)
        observed_paths = {'docker/data-sandbox-runner-lib/runner_common.py', 'docker/build-runner-images.sh',
            'docker/data-sandbox-jar-runner/', 'docker/data-sandbox-python-runner/'}
        if old['head'] != new['head'] or old_status - new_status or not concurrent or any(line.split(maxsplit=1)[1] not in observed_paths for line in concurrent):
            raise RuntimeError('工具链变化超出已观察到的独立 runner 开发范围')
        # 原基线仅 build.sh/develop.sh 有改动；用 HEAD 字节做只读反事实比较，不改磁盘文件。
        # 若恢复摘要等于原基线，则六个实际复用输入及其他受保护文件仍保持原内容。
        path, digest = ORIGINAL / 'data-sandbox-package', hashlib.sha256()
        changed = {line.split(maxsplit=1)[1] for line in concurrent if not line.startswith('?? ')}
        for relative in subprocess.check_output(['git', '-C', str(path), 'ls-files', '-z']).split(b'\0'):
            if not relative: continue
            name, file = os.fsdecode(relative), path / os.fsdecode(relative)
            digest.update(relative + b'\0')
            if name in changed: digest.update(subprocess.check_output(['git', '-C', str(path), 'show', 'HEAD:' + name]))
            elif file.is_symlink(): digest.update(os.fsencode(os.readlink(file)))
            elif file.is_file(): digest.update(file.read_bytes())
        if digest.hexdigest() != old['content']:
            raise RuntimeError('排除并发 runner 改动后，原工具链输入仍与基线不同')
    mounts, images = {}, {}
    for name in INSTANCES:
        for suffix in ['secretpad', 'kuscia', 'minio', 'tee-probe']:
            ctr = f'data-sandbox-dev-{name}-{suffix}'
            value = managed(ctr)
            if not value or not value['State']['Running']: raise RuntimeError('新实例容器未运行：' + ctr)
            for mount in value['Mounts']:
                source = Path(mount.get('Source', '')).resolve()
                allowed = source.is_relative_to(ROOT.resolve()) or source.is_relative_to(RUNTIME.resolve())
                if mount.get('RW') and mount['Type'] != 'tmpfs' and (mount['Type'] != 'bind' or not allowed):
                    raise RuntimeError('存在主源码和运行目录之外的可写挂载：' + ctr)
                if 'docker.sock' in mount.get('Source', ''): raise RuntimeError('新实例不允许挂载 Docker socket')
                if suffix == 'secretpad' and '/tee/' in mount.get('Source', ''):
                    raise RuntimeError('普通平台不允许挂载底座私钥目录')
            mounts[ctr] = [{'source': item.get('Source'), 'destination': item['Destination'], 'rw': item['RW']}
                           for item in value['Mounts']]
            if suffix == 'secretpad': images[name] = value['Image']
            if set(value['NetworkSettings']['Networks']) != {f'data-sandbox-dev-{name}'}:
                raise RuntimeError('新实例连接了非本实例网络：' + ctr)
        if (RUNTIME / name).stat().st_mode & 0o777 != 0o700 or (RUNTIME / name / 'secretpad.env').stat().st_mode & 0o777 != 0o600:
            raise RuntimeError('运行根或登录凭据权限不符：' + name)
    if set(images.values()) != {manifest()['images']['platform']['id']}:
        raise RuntimeError('三实例没有复用同一锁定平台镜像')
    atomic(RUNTIME / 'isolation-verification.json', {'checkedAt': utc(), 'protectedTrackedAndStatusUnchanged': before == after,
        'protectedInputsUnchanged': True, 'concurrentToolkitChanges': concurrent, 'untrackedHistoricalContentsVerified': False,
        'before': before, 'after': after, 'mounts': mounts, 'platformImages': images})
    print('原后端、前端、实际工具链输入及旧六个容器保持原基线；新实例隔离通过。')
    if concurrent: print('原工具链在已观察的 runner 路径出现并发改动，已单列证据；不推断修改者或宣称整个原目录未变。')


def verify_repeat():
    from foundation import certificates, base_up, probe_up, pair
    from platform_deploy import up
    def state():
        containers = {name + '-' + suffix: managed('data-sandbox-dev-' + name + '-' + suffix)['State']['StartedAt']
            for name in INSTANCES for suffix in ['secretpad', 'kuscia', 'minio', 'tee-probe']}
        pods = json.loads(kube('center', 'get', 'pods', '-n', DOMAIN, '-l', 'app=tee-a-capsule', '-o', 'json'))['items']
        containers['capsulePod'] = sorted(p['metadata']['uid'] for p in pods)
        directories = [PKI / ca for ca in ['external-ca', 'upstream-ca']]
        directories += [RUNTIME / name / 'tee' / kind for name in INSTANCES for kind in ['identity', 'probe-cert']]
        directories += [CENTER / kind for kind in ['gateway-cert', 'cm-server-cert', 'gateway-upstream-cert', 'workload-cert', 'cm-master-key']]
        keys = {str(file.relative_to(RUNTIME)): hashlib.sha256(file.read_bytes()).hexdigest()
                for directory in directories for file in directory.glob('*.key')}
        return containers, keys
    before, keys = state()
    certificates()
    for name in INSTANCES: up(name)
    base_up()
    for name in INSTANCES: probe_up(name)
    pair()
    after, after_keys = state()
    if before != after or keys != after_keys:
        raise RuntimeError('重复执行重建了健康容器、Pod 或改变已有私钥')
    atomic(RUNTIME / 'repeat-verification.json', {'checkedAt': utc(), 'privateKeyCount': len(keys),
        'identitiesUnchanged': True, 'healthyContainersAndPodUnchanged': True})
    print('重复执行未改变机构/服务私钥，未重建健康平台、探测器或底座 Pod。')


def verify_release():
    """P4 前置：用一次性合成身份验证数据密钥的真实放行与规则拒绝，结束后删除写入的策略与密钥。"""
    case_root = CENTER / 'acceptance-release'
    case_root.mkdir(exist_ok=True, mode=0o700)
    state = case_root / 'release-pilot.json'
    if state.exists():
        raise RuntimeError('上一轮放行验收未清理，先人工核对再重跑')
    cert = CENTER / 'release-cert'
    issue(PKI / 'external-ca', cert, 'p4-release-client')
    image = checked_image('probe')
    network = 'data-sandbox-dev-center'
    managed(network, 'network') or (_ for _ in ()).throw(RuntimeError('中心网络不存在'))
    script = ROOT / 'scripts/deploy/tee/release_client.py'

    def phase(name):
        command = ['docker', 'run', '--rm', '--pull=never', '--network', network,
                   '--user', f'{os.getuid()}:{os.getgid()}',
                   '--add-host', f'capsule.tee-a.test:{CONTRACT_HOST}', '--read-only', '--cap-drop=ALL',
                   '--security-opt', 'no-new-privileges', '-e', 'TEE_CAPSULE_ENDPOINT=capsule.tee-a.test:19685',
                   '-v', str(cert) + ':/certs:ro', '-v', str(case_root) + ':/case',
                   '-v', str(script) + ':/opt/p4/release_client.py:ro']
        for k, v in labels().items(): command += ['--label', k + '=' + v]
        result = subprocess.run(command + [image, 'python', '/opt/p4/release_client.py', name],
                                capture_output=True, text=True, timeout=180)
        if result.returncode: raise RuntimeError('密钥放行验收阶段未通过：' + name)
        value = json.loads(result.stdout)
        if value.get('allPassed') is not True:
            raise RuntimeError('密钥放行验收存在未通过项：' + name)
        return value

    released = phase('run')
    cleaned = phase('cleanup')
    # 合成身份仅用于本轮验收，成功清理后不保留，下一轮重新生成。
    state.unlink()
    atomic(CENTER / 'release-verification.json', {'checkedAt': utc(), 'released': released, 'cleanup': cleaned,
        'evidence': 'NATIVE_DATA_KEY_RELEASE_AND_POLICY_DENIAL',
        'adapterMustEnforce': ['EMPTY_COLUMN_SET', 'WILDCARD_COLUMN_OR_OPERATOR', 'INITIATOR_IDENTITY'],
        'capsuleUnimplemented': ['RegisterCert/store_public_key', 'get_public_key'],
        'businessKeyReleaseVerified': True})
    print('仿真模式下数据密钥真实放行，越权算子、越权列、非授权方与未知 scope 均被拒绝；合成策略与密钥已删除。')
    print('适配层必须自行拒绝空列集合、通配符授权，并保证发起方身份可信：这三项 CM 不校验。')


def verify_p4():
    """用一份示例数据跑完密钥、加密、登记、放行、解密全链路，并逐项验证拒绝行为。"""
    script = ROOT / 'scripts/deploy/tee/contract_acceptance.py'
    result = subprocess.run(['python3', str(script)], capture_output=True, text=True, timeout=600)
    if result.returncode:
        raise RuntimeError('P4 全链路验收未通过')
    value = json.loads(result.stdout)
    failed = [name for name, check in value['checks'].items() if check is False]
    if failed:
        raise RuntimeError('P4 验收存在未通过项：' + '、'.join(failed))
    denials = sorted({check['errorCode'] for check in value['checks'].values()
                      if isinstance(check, dict) and 'errorCode' in check})
    atomic(CENTER / 'p4-verification.json', {'checkedAt': utc(), 'result': value,
        'evidence': 'END_TO_END_KEY_ISSUE_ENCRYPT_POLICY_RELEASE_DECRYPT',
        'checkCount': len(value['checks']), 'deniedErrorCodes': denials,
        'businessChainVerified': True})
    print(f'P4 全链路通过：{len(value["checks"])} 项检查，示例数据经签发、申领、客户端加密、')
    print('规则登记、资产登记后由签名任务在运行时放行并解密还原，中心端全程只持有密文。')
    print('覆盖的拒绝错误码：' + '、'.join(denials))
    print('授权规则的审批来源、运行镜像摘要、程序结构与结果对象写入端均已逐项校验。')
    print('两个客户端实例经平台间双向 TLS 向中心端申请密钥并登记规则，台账只在中心端；')
    print('三个实例的抽样脱敏产出均加密落盘，跨节点同步送出的字节确认为密文。')


def verify(command):
    if command == 'verify-tls': return verify_tls()
    if command == 'verify-native': return verify_native_surface()
    if command == 'verify-persistence': return verify_persistence()
    if command == 'verify-environment': return verify_environment()
    if command == 'verify-isolation': return verify_isolation()
    if command == 'verify-repeat': return verify_repeat()
    if command == 'verify-release': return verify_release()
    if command == 'verify-p4': return verify_p4()
    raise RuntimeError('未知验证操作')
