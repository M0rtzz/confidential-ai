"""全链路契约验收：用一份示例数据跑完签发、加密、登记、放行、解密，并逐项验证拒绝行为。

示例数据为合成客户表，不涉及任何真实业务数据。脚本使用运行目录中的机构私钥、
可信运行时私钥与任务签名私钥；这些材料只在本进程内存中使用，不输出、不落盘。

规则登记要求「由有效审批生成」，因此验收会在本实例平台库中写入一份合成审批、挂载与
使用管控记录作为来源，跑完即删除；这些记录只用于本验收，不代表真实业务审批。
"""
import base64
import hashlib
import json
import os
import secrets
import subprocess
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4
from zoneinfo import ZoneInfo

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CONTRACT = 'tee-contract/1.0'
ROOT = Path(__file__).resolve().parents[3]
WORKSPACE = Path(os.environ.get(
    'DATA_SANDBOX_WORKSPACE_DIR',
    str(Path(subprocess.run(
        ['git', '-C', str(ROOT), 'rev-parse', '--path-format=absolute', '--git-common-dir'],
        check=True, text=True, stdout=subprocess.PIPE).stdout.strip()).resolve().parent.parent)
)).resolve()
RUNTIME = Path(os.environ.get(
    'DATA_SANDBOX_TEE_RUNTIME_ROOT', str(WORKSPACE / '.dev-runtime'))).resolve()
CENTER = RUNTIME / 'center'
CLIENT = RUNTIME / 'client-a'
PORTS = {'client-a': 19488, 'client-b': 19588, 'center': 19688}
PLATFORM_ZONE = ZoneInfo('Asia/Shanghai')

SAMPLE_COLUMNS = ['age', 'income', 'city', 'id_card']
GRANTED_COLUMNS = ['age', 'income', 'city']
OPERATOR = 'ml.xgboost'
SAMPLE_CSV = ('age,income,city,id_card\n'
              '31,42000,hangzhou,3301...0011\n'
              '45,88000,shanghai,3101...0022\n'
              '27,31000,wuhan,4201...0033\n')


class Failure(Exception):
    pass


def request(path, payload=None, token=None, instance='center'):
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['User-Token'] = token
    req = urllib.request.Request(f'http://127.0.0.1:{PORTS[instance]}/api' + path, headers=headers,
                                 data=json.dumps(payload).encode() if payload is not None else None)
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        return error.code, json.load(error)


def login(end_role=None, instance='center'):
    env = dict(line.split('=', 1) for line in
               (RUNTIME / instance / 'secretpad.env').read_text().splitlines() if '=' in line)
    payload = {'name': env['SECRETPAD_USER_NAME'],
               'passwordHash': hashlib.sha256(env['SECRETPAD_PASSWORD'].encode()).hexdigest()}
    if end_role:
        payload['endRole'] = end_role
    code, body = request('/login', payload, instance=instance)
    if code != 200 or body.get('status', {}).get('code') != 0:
        raise Failure(f'登录失败：{instance} {end_role}')
    return body['data']['token'], body['data']['ownerId']


def expect_ok(name, path, payload, token, instance='center'):
    code, body = request(path, payload, token, instance)
    if code != 200 or body.get('status', {}).get('code') != 0:
        data = body.get('data') or {}
        detail = data.get('errorCode') or body.get('status', {}).get('msg') or f'HTTP {code}'
        raise Failure(f'{name} 应成功但被拒绝：{detail}')
    return body['data']


def expect_denied(name, path, payload, token, error_code, instance='center'):
    code, body = request(path, payload, token, instance)
    actual = body.get('data', {}).get('errorCode')
    if body.get('status', {}).get('code') == 0:
        raise Failure(f'{name} 应被拒绝但成功了')
    if actual != error_code:
        raise Failure(f'{name} 拒绝原因不符：期望 {error_code}，实际 {actual}')
    return {'errorCode': actual, 'httpStatus': code}


def sqlite(instance, statements):
    """在实例平台库上执行语句；库启用 WAL，必须进容器执行。"""
    script = 'pragma busy_timeout=8000;\n' + '\n'.join(statements)
    subprocess.run(['docker', 'exec', '-i', f'data-sandbox-dev-{instance}-secretpad',
                    'sqlite3', '/app/db/secretpad.sqlite'],
                   input=script.encode(), check=True, capture_output=True)


def quote(value):
    return "'" + str(value).replace("'", "''") + "'"


def platform_time(offset_hours):
    moment = datetime.now(PLATFORM_ZONE) + timedelta(hours=offset_hours)
    return moment.replace(microsecond=0, tzinfo=None).isoformat()


def utc_time(offset_seconds):
    moment = datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)
    return moment.replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def install_approval(instance, owner, asset_id, columns, operators, hours=2):
    """写入一份合成的沙箱审批、挂载与使用管控，作为授权规则的来源。

    沙箱记录以 STOPPED 且资源为零写入，不参与调度、不占配额；到期时间取当前之后，
    避免被到期回收任务触及。返回的标识用于跑完后原样删除。
    """
    sandbox_id = 'sbx-p4-' + uuid4().hex[:10]
    approval_id = 'apr-p4-' + uuid4().hex[:10]
    mount_id = 'mnt-p4-' + uuid4().hex[:10]
    control_id = 'ctl-p4-' + uuid4().hex[:10]
    now = platform_time(0)
    until = platform_time(hours)
    payload = json.dumps({'datasetAssetIds': [asset_id], 'teeColumns': columns,
                          'teeOperators': operators, 'teeExpiresAt': utc_time(hours * 3600)},
                         separators=(',', ':'))
    sqlite(instance, [
        'insert into ds_sandbox(id,name,owner_id,project_id,image_id,status,expires_at,network_policy,'
        'cpu_cores,memory_gb,gpu_count,storage_gb,kuscia_job_id,endpoint,last_error,created_by,'
        f'created_at,updated_at,deleted) values({quote(sandbox_id)},{quote("p4 验收沙箱")},'
        f'{quote(owner)},{quote("")},{quote("")},{quote("STOPPED")},{quote(until)},'
        f"{quote('NO_NETWORK')},0,0,0,0,'','','','p4-acceptance',{quote(now)},{quote(now)},0);",
        'insert into ds_sandbox_approval(id,approval_type,sandbox_id,owner_id,submitter,payload_json,'
        'status,current_stage,version,submitted_at,approved_at,completed_at,created_at,updated_at,deleted) '
        f'values({quote(approval_id)},{quote("DATA_CHANGE")},{quote(sandbox_id)},{quote(owner)},'
        f"'p4-acceptance',{quote(payload)},{quote('COMPLETED')},{quote('COMPLETED')},1,"
        f'{quote(now)},{quote(now)},{quote(now)},{quote(now)},{quote(now)},0);',
        'insert into ds_sandbox_dataset_mount(id,sandbox_id,asset_id,asset_version,provider_node_id,'
        f'staging_uri,mount_path,checksum,status,expires_at,created_at,updated_at,deleted) values('
        f'{quote(mount_id)},{quote(sandbox_id)},{quote(asset_id)},1,{quote(owner)},'
        f"'','','',{quote('READY')},{quote(until)},{quote(now)},{quote(now)},0);",
        'insert into ds_sandbox_mount_control(id,sandbox_id,asset_id,allow_use,use_until,version,'
        f'updated_by,updated_at) values({quote(control_id)},{quote(sandbox_id)},{quote(asset_id)},1,'
        f"{quote(until)},1,'p4-acceptance',{quote(now)});",
    ])
    return {'instance': instance, 'sandboxId': sandbox_id, 'approvalId': approval_id,
            'mountId': mount_id, 'controlId': control_id}


def remove_approval(fixture):
    sqlite(fixture['instance'], [
        f'delete from ds_sandbox_mount_control where id={quote(fixture["controlId"])};',
        f'delete from ds_sandbox_dataset_mount where id={quote(fixture["mountId"])};',
        f'delete from ds_sandbox_approval where id={quote(fixture["approvalId"])};',
        f'delete from ds_sandbox where id={quote(fixture["sandboxId"])};',
    ])


def private_key(path):
    return serialization.load_pem_private_key(Path(path).read_bytes(), password=None)


def unwrap(envelope, key_path):
    """信封只有对应私钥能解开；这是密封给已登记接收者的直接证据。"""
    data_key = private_key(key_path).decrypt(base64.b64decode(envelope['wrappedKeyB64']), padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    if len(data_key) != 32:
        raise Failure('数据密钥长度不是 32 字节')
    return data_key


def build_aad(asset_id, asset_version, key_id, key_version):
    # 字段顺序必须与平台一致，AAD 以原始字节参与认证。
    return json.dumps({'contractVersion': CONTRACT, 'assetId': asset_id, 'assetVersion': asset_version,
                       'keyId': key_id, 'keyVersion': key_version}, separators=(',', ':')).encode()


def encrypt(data_key, plaintext, asset_id, asset_version, key_id, key_version):
    nonce = secrets.token_bytes(12)
    aad = build_aad(asset_id, asset_version, key_id, key_version)
    combined = AESGCM(data_key).encrypt(nonce, plaintext, aad)
    ciphertext, tag = combined[:-16], combined[-16:]
    digest = hashlib.sha256(nonce + aad + ciphertext + tag).hexdigest()
    return {'contractVersion': CONTRACT, 'assetId': asset_id, 'assetVersion': asset_version,
            'keyId': key_id, 'keyVersion': key_version, 'algorithm': 'AES-256-GCM',
            'nonceB64': base64.b64encode(nonce).decode(), 'aadB64': base64.b64encode(aad).decode(),
            'ciphertextB64': base64.b64encode(ciphertext).decode(),
            'tagB64': base64.b64encode(tag).decode(), 'ciphertextSha256': digest}


def decrypt(data_key, obj):
    nonce = base64.b64decode(obj['nonceB64'])
    aad = base64.b64decode(obj['aadB64'])
    ciphertext = base64.b64decode(obj['ciphertextB64'])
    tag = base64.b64decode(obj['tagB64'])
    return AESGCM(data_key).decrypt(nonce, ciphertext + tag, aad)


def b64url(value):
    return base64.urlsafe_b64encode(value).decode().rstrip('=')


def runtime_digest():
    """任务声明的运行镜像摘要必须落在部署登记的集合内。"""
    registry = json.loads((CENTER / 'identity-pub/registry.json').read_text())
    digests = registry.get('runtimeImageDigests') or []
    if not digests:
        raise Failure('部署未登记可信运行镜像摘要')
    return digests[0]


def sign_task(payload, kid='center-1', alg='RS256'):
    header = b64url(json.dumps({'alg': alg, 'typ': 'JWS', 'kid': kid}).encode())
    body = b64url(json.dumps(payload).encode())
    signature = private_key(CENTER / 'tee/task-signer/client.key').sign(
        f'{header}.{body}'.encode('ascii'), padding.PKCS1v15(), hashes.SHA256())
    return f'{header}.{body}.{b64url(signature)}'


def task_payload(asset, key, policy, columns, operator, nonce=None, sandbox_id='sandbox-demo',
                 lifetime=240, issued_offset=0, program=None, image_digest=None, plaintext_bytes=None):
    now = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(seconds=issued_offset)
    return {'contractVersion': CONTRACT, 'taskId': 'task-' + uuid4().hex[:12],
            'requestId': uuid4().hex, 'issuer': 'center', 'audience': 'tee-a-runtime',
            'sandboxId': sandbox_id, 'operatorId': operator, 'columns': columns,
            'inputs': [{'assetId': asset['assetId'], 'assetVersion': asset['assetVersion'],
                        'keyId': key['keyId'], 'keyVersion': key['keyVersion'],
                        'policyId': policy['policyId'], 'policyVersion': policy['policyVersion'],
                        'objectId': asset['objectId'], 'ciphertextSha256': asset['ciphertextSha256'],
                        'plaintextBytes': plaintext_bytes or len(SAMPLE_CSV)}],
            'program': program or {'kind': 'BUILTIN', 'objectId': None,
                                   'sha256': hashlib.sha256(b'builtin').hexdigest(), 'parameters': {}},
            'issuedAt': now.isoformat().replace('+00:00', 'Z'),
            'expiresAt': (now + timedelta(seconds=lifetime)).isoformat().replace('+00:00', 'Z'),
            'nonce': nonce or uuid4().hex,
            'outputPolicy': {'reportKinds': ['EVALUATION_METRICS'], 'encryptData': True,
                             'encryptModel': True, 'exportRequiresAllContributors': True},
            'runtimeImageDigest': image_digest or runtime_digest()}


def pem_of(path):
    return Path(path).read_text()


def sqlite_query(instance, statement):
    """只读查询实例平台库；用于直接核对中心端台账，不改写任何业务数据。"""
    result = subprocess.run(['docker', 'exec', '-i', f'data-sandbox-dev-{instance}-secretpad',
                             'sqlite3', '-cmd', '.timeout 8000', '/app/db/secretpad.sqlite'],
                            input=statement.encode(), check=True, capture_output=True)
    return result.stdout.decode().strip()


def cleanup_run_objects(task_ids, instance='center'):
    """删除本次验收自己产生的结果对象。

    只按精确的 task_id 匹配，不按时间或类型批量删除；验收脚本历次运行留下的结果
    对象会淹没链路看板，但清理失败不应让已经通过的验收变成失败，调用方需自行兜住异常。
    """
    ids = [task_id for task_id in task_ids if task_id]
    if not ids:
        return 0
    condition = 'task_id in (' + ', '.join(quote(task_id) for task_id in ids) + ')'
    removed = int(sqlite_query(instance, 'select count(*) from tee_object where '
                               + condition + ' and is_deleted=0;') or 0)
    sqlite(instance, ['update tee_object set is_deleted=1 where ' + condition + ';'])
    return removed


def multipart(field, filename, content, content_type):
    boundary = '----p4' + uuid4().hex
    body = (f'--{boundary}\r\nContent-Disposition: form-data; name="{field}"; '
            f'filename="{filename}"\r\nContent-Type: {content_type}\r\n\r\n').encode()
    body += content + f'\r\n--{boundary}--\r\n'.encode()
    return body, f'multipart/form-data; boundary={boundary}'


def upload_csv(instance, token, filename, content):
    body, content_type = multipart('file', filename, content, 'text/csv')
    req = urllib.request.Request(
        f'http://127.0.0.1:{PORTS[instance]}/api/v1alpha1/data-assets/files/upload',
        data=body, headers={'Content-Type': content_type, 'User-Token': token})
    with urllib.request.urlopen(req, timeout=60) as response:
        payload = json.load(response)
    if payload.get('status', {}).get('code') != 0:
        raise Failure(f'{instance} 上传样例数据失败')
    return payload['data']


def get(path, token, instance):
    req = urllib.request.Request(f'http://127.0.0.1:{PORTS[instance]}/api' + path,
                                 headers={'User-Token': token})
    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        return error.code, json.load(error)


def install_sync_grant(instance, asset_id, requester):
    """写入一份合成的项目授权，使同步下载端点认为请求方已获授权；跑完即删除。"""
    project_id = 'prj-p4-' + uuid4().hex[:10]
    now = platform_time(0)
    sqlite(instance, [
        'insert into project_node(project_id,node_id,is_deleted) values('
        f'{quote(project_id)},{quote(requester)},0);',
        'insert into ds_project_asset(project_id,asset_id,provider_node_id,attached_by,'
        f'attached_at,expires_at,deleted) values({quote(project_id)},{quote(asset_id)},'
        f"{quote(instance)},'p4-acceptance',{quote(now)},'',0);",
    ])
    return {'instance': instance, 'projectId': project_id, 'requester': requester}


def remove_sync_grant(grant):
    sqlite(grant['instance'], [
        f'delete from ds_project_asset where project_id={quote(grant["projectId"])};',
        f'delete from project_node where project_id={quote(grant["projectId"])};',
    ])


def sync_download(instance, token, asset_id, requester):
    """按跨节点同步端点取回这份资产实际会送出的字节。"""
    path = (f'/v1alpha1/data-assets/sync/download?assetId={asset_id}'
            f'&requesterNodeId={requester}')
    req = urllib.request.Request(f'http://127.0.0.1:{PORTS[instance]}/api' + path,
                                 headers={'User-Token': token})
    with urllib.request.urlopen(req, timeout=60) as response:
        return response.read()


def governed_encryption(instance, token, owner, checks, prefix):
    """核对抽样脱敏产出加密落盘，并核对出节点的字节确实是密文。

    走真实页面链路：上传样例 → 提交内置治理任务 → 读取产出资产。要求产出标记为密文、
    存储对象扩展名为 .enc、密钥记在中心端台账；再按同步下载端点取回出节点的字节，
    确认它是本契约的密文封装，且只有向中心端重新申领密钥才能解回原文。
    """
    source = upload_csv(instance, token, 'p4-governed.csv', SAMPLE_CSV.encode())
    detail = expect_ok('提交治理任务', '/v1alpha1/data-governance/tasks/submit', {
        'name': 'p4 加密落盘验收', 'nodeId': source['provider_node_id'],
        'datatableId': source['datatable_id'], 'sourceAssetId': source['id'],
        'sampling': {}, 'masking': []}, token, instance)
    if detail.get('status') != 'SUCCEEDED':
        raise Failure(f'{instance} 治理任务未成功：{detail.get("status")}')
    asset_id = detail['result_datatable_id']

    code, body = get('/v1alpha1/data-assets/detail?id=' + asset_id, token, instance)
    if code != 200 or body.get('status', {}).get('code') != 0:
        raise Failure(f'{instance} 无法读取治理产出资产')
    asset = body['data']
    metadata = asset.get('metadata_json')
    metadata = json.loads(metadata) if isinstance(metadata, str) else (metadata or {})
    if metadata.get('encrypted') is not True:
        raise Failure(f'{instance} 抽样脱敏产出未加密落盘')
    if not str(asset.get('storage_uri', '')).endswith('.enc'):
        raise Failure(f'{instance} 加密产出的存储对象扩展名不符')
    if metadata.get('sha256') == metadata.get('plaintextSha256'):
        raise Failure(f'{instance} 落盘对象与明文同摘要，未真正加密')

    ledger_owner = sqlite_query('center', 'select owner_id from tee_key where key_id='
                                + quote(metadata['keyId']) + ';')
    if ledger_owner != owner:
        raise Failure(f'{instance} 治理产出的密钥未记入中心端台账')

    grant = install_sync_grant(instance, asset_id, 'p4-acceptance-peer')
    try:
        payload = json.loads(sync_download(instance, token, asset_id, grant['requester']))
    finally:
        remove_sync_grant(grant)
    if payload.get('algorithm') != 'AES-256-GCM' or payload.get('contractVersion') != CONTRACT:
        raise Failure(f'{instance} 出节点的字节不是契约密文封装')
    if payload.get('assetId') != asset_id or payload.get('keyId') != metadata['keyId']:
        raise Failure(f'{instance} 出节点密文与登记的资产或密钥不符')

    claimed = expect_ok('重新申领治理产出密钥', '/v1alpha1/tee/keys/claim', {
        'contractVersion': CONTRACT, 'requestId': uuid4().hex, 'assetId': asset_id,
        'assetVersion': '1', 'keyId': metadata['keyId'], 'keyVersion': metadata['keyVersion'],
        'recipientCertPem': pem_of(RUNTIME / instance / 'tee/identity/client.crt')}, token, instance)
    data_key = unwrap(claimed['keyEnvelope'], RUNTIME / instance / 'tee/identity/client.key')
    recovered = decrypt(data_key, payload).decode()
    if recovered.splitlines()[0] != ','.join(SAMPLE_COLUMNS):
        raise Failure(f'{instance} 密文解回的表头与产出不符')
    for city in ['hangzhou', 'shanghai', 'wuhan']:
        if city not in recovered:
            raise Failure(f'{instance} 密文解回的内容缺行')

    checks[prefix] = {'instance': instance, 'assetId': asset_id, 'keyId': metadata['keyId'],
                      'encryptedAtRest': True, 'ciphertextOnlyOnSync': True,
                      'plaintextBytes': metadata.get('plaintextBytes'),
                      'ledgerAtCenter': True}
    return {'assetId': asset_id, 'metadata': metadata}


def client_instance_chain(instance, checks, prefix):
    """在真实客户端实例上跑完「向中心端申请密钥并加密落盘」。

    客户端实例不直连密钥服务，签发、申领与规则登记都经平台间双向 TLS 通道交给中心端；
    机构标识由中心端从客户端证书推导，客户端无法自报。验收要求：
    密钥台账落在中心端、信封只有客户端自己的机构私钥能解开、
    资产登记在本地成密文对象，且运行时接口仍按端角色拒绝。
    """
    token, owner = login(None, instance)
    result = {'instance': instance, 'ownerId': owner}

    # 无会话一律拒绝，且响应保持冻结的契约包装。
    code, body = request('/v1alpha1/tee/keys', instance=instance)
    if code != 401 or body.get('data', {}).get('errorCode') != 'AUDIT_ACCESS_DENIED':
        raise Failure(f'{instance} 未认证访问未被拒绝')
    result['sessionGuard'] = True

    asset_id = 'demo-client-' + uuid4().hex[:8]
    issued = expect_ok('客户端申请密钥', '/v1alpha1/tee/keys/issue', {
        'contractVersion': CONTRACT, 'requestId': uuid4().hex,
        'assetId': asset_id, 'assetVersion': '1'}, token, instance)
    result['keyId'] = issued['keyId']

    # 台账唯一在中心端：中心库里必须有这条记录，且归属为客户端机构。
    ledger_owner = sqlite_query('center',
                                'select owner_id from tee_key where key_id='
                                + quote(issued['keyId']) + ';')
    if ledger_owner != owner:
        raise Failure(f'{instance} 的密钥未记入中心端台账')
    result['ledgerAtCenter'] = True

    claimed = expect_ok('客户端申领密钥', '/v1alpha1/tee/keys/claim', {
        'contractVersion': CONTRACT, 'requestId': uuid4().hex, 'assetId': asset_id,
        'assetVersion': '1', 'keyId': issued['keyId'], 'keyVersion': issued['keyVersion'],
        'recipientCertPem': pem_of(RUNTIME / instance / 'tee/identity/client.crt')}, token, instance)
    data_key = unwrap(claimed['keyEnvelope'], RUNTIME / instance / 'tee/identity/client.key')
    result['envelopeOpensWithOwnKey'] = True

    # 别的机构证书拿不到这把密钥。
    result['foreignRecipientDenied'] = expect_denied(
        '客户端用他方证书申领', '/v1alpha1/tee/keys/claim', {
            'contractVersion': CONTRACT, 'requestId': uuid4().hex, 'assetId': asset_id,
            'assetVersion': '1', 'keyId': issued['keyId'], 'keyVersion': issued['keyVersion'],
            'recipientCertPem': pem_of(CENTER / 'tee/identity/client.crt')},
        token, 'ASSET_OWNER_MISMATCH', instance)

    # 规则由中心端按审批核验：审批写在中心库，客户端只发起登记。
    fixture = install_approval('center', owner, asset_id, SAMPLE_COLUMNS, [OPERATOR])
    try:
        policy = expect_ok('客户端登记授权规则', '/v1alpha1/tee/policies/register', {
            'contractVersion': CONTRACT, 'requestId': uuid4().hex,
            'policy': {'contractVersion': CONTRACT, 'policyId': '', 'policyVersion': '',
                       'assetId': asset_id, 'assetVersion': '1', 'ownerId': owner,
                       'sandboxId': fixture['sandboxId'], 'columns': GRANTED_COLUMNS,
                       'operators': [OPERATOR], 'expiresAt': utc_time(3600),
                       'reportKinds': ['EVALUATION_METRICS']}}, token, instance)
        result['policyId'] = policy['policyId']

        encrypted = encrypt(data_key, SAMPLE_CSV.encode(), asset_id, '1',
                            issued['keyId'], issued['keyVersion'])
        asset = expect_ok('客户端登记密文资产', '/v1alpha1/tee/assets/register', {
            'contractVersion': CONTRACT, 'requestId': uuid4().hex, 'ownerId': owner,
            'schema': SAMPLE_COLUMNS, 'encryptedObject': encrypted,
            'policyId': policy['policyId'], 'policyVersion': policy['policyVersion']}, token, instance)
        result['objectId'] = asset['objectId']

        # 超出审批范围的规则仍然被中心端拒绝，委派不会放宽任何判定。
        result['policyBeyondApprovalDenied'] = expect_denied(
            '客户端登记越权规则', '/v1alpha1/tee/policies/register', {
                'contractVersion': CONTRACT, 'requestId': uuid4().hex,
                'policy': {'contractVersion': CONTRACT, 'policyId': '', 'policyVersion': '',
                           'assetId': asset_id, 'assetVersion': '1', 'ownerId': owner,
                           'sandboxId': fixture['sandboxId'], 'columns': GRANTED_COLUMNS,
                           'operators': ['ml.dnn'], 'expiresAt': utc_time(3600),
                           'reportKinds': ['EVALUATION_METRICS']}},
            token, 'POLICY_DENIED', instance)
    finally:
        remove_approval(fixture)

    # 客户端不承担运行时职责，运行时接口按端角色拒绝。
    result['runtimeDenied'] = expect_denied(
        '客户端调用运行时放行', '/v1alpha1/tee/runtime/release', {
            'contractVersion': CONTRACT, 'requestId': uuid4().hex, 'taskJws': 'x.y.z',
            'attestationEvidence': None, 'recipientCertPem': ''},
        token, 'END_ROLE_DENIED', instance)

    # 环境接口在客户端同样如实标注仿真，不出现夸大表述。
    code, body = request('/v1alpha1/tee/environment', token=token, instance=instance)
    environment = body['data']
    if environment['runtimeMode'] != 'SIMULATION' or environment['attestationVerified'] is not False \
            or environment['realModeReady'] is not False:
        raise Failure(f'{instance} 环境接口未如实标注仿真模式')
    result['environmentHonest'] = True

    # 抽样脱敏产出在客户端同样加密落盘，密钥同样来自中心端。
    governed = governed_encryption(instance, token, owner, checks, prefix + 'Governed')
    result['governedAssetId'] = governed['assetId']
    checks[prefix] = result


def run():
    checks = {}
    client_token, owner = login('CLIENT')
    center_token, _ = login('CENTER')
    asset_id = 'demo-customers-' + uuid4().hex[:8]
    institution_cert = pem_of(CENTER / 'tee/identity/client.crt')
    foreign_cert = pem_of(CLIENT / 'tee/identity/client.crt')
    workload_cert = pem_of(CENTER / 'tee/workload-cert/client.crt')
    fixture = install_approval('center', owner, asset_id, SAMPLE_COLUMNS, [OPERATOR])
    sandbox_id = fixture['sandboxId']

    try:
        # 1 签发密钥
        issued = expect_ok('密钥签发', '/v1alpha1/tee/keys/issue', {
            'contractVersion': CONTRACT, 'requestId': uuid4().hex,
            'assetId': asset_id, 'assetVersion': '1'}, client_token)
        checks['keyIssued'] = issued['state'] == 'ACTIVE'

        # 2 申领并解开信封，得到数据密钥
        claim_request = {'contractVersion': CONTRACT, 'requestId': uuid4().hex, 'assetId': asset_id,
                         'assetVersion': '1', 'keyId': issued['keyId'], 'keyVersion': issued['keyVersion'],
                         'recipientCertPem': institution_cert}
        claimed = expect_ok('密钥申领', '/v1alpha1/tee/keys/claim', claim_request, client_token)
        data_key = unwrap(claimed['keyEnvelope'], CENTER / 'tee/identity/client.key')
        checks['keyClaimedAndUnwrapped'] = True

        # 3 本地加密示例数据
        encrypted = encrypt(data_key, SAMPLE_CSV.encode(), asset_id, '1',
                            issued['keyId'], issued['keyVersion'])
        checks['clientSideEncrypted'] = True

        # 4 登记授权规则
        policy_body = {'contractVersion': CONTRACT, 'policyId': None, 'policyVersion': None,
                       'assetId': asset_id, 'assetVersion': '1', 'ownerId': owner,
                       'sandboxId': sandbox_id, 'columns': GRANTED_COLUMNS, 'operators': [OPERATOR],
                       'expiresAt': utc_time(3600), 'reportKinds': ['EVALUATION_METRICS']}
        policy = expect_ok('规则登记', '/v1alpha1/tee/policies/register', {
            'contractVersion': CONTRACT, 'requestId': uuid4().hex, 'policy': policy_body}, client_token)
        checks['policyRegistered'] = policy['state'] == 'ACTIVE'

        # 5 登记密文资产
        asset = expect_ok('资产登记', '/v1alpha1/tee/assets/register', {
            'contractVersion': CONTRACT, 'requestId': uuid4().hex, 'ownerId': owner,
            'schema': SAMPLE_COLUMNS, 'encryptedObject': encrypted,
            'policyId': policy['policyId'], 'policyVersion': policy['policyVersion']}, client_token)
        asset['ciphertextSha256'] = encrypted['ciphertextSha256']
        checks['assetRegistered'] = True

        # 6 中心端只拿得到密文
        code, stored = request(f'/v1alpha1/tee/objects/{asset["objectId"]}', token=client_token)
        if code != 200 or stored['data']['ciphertextB64'] != encrypted['ciphertextB64']:
            raise Failure('中心端存储的对象与提交的密文不一致')
        if SAMPLE_CSV.split('\n')[1] in json.dumps(stored):
            raise Failure('中心端对象响应中出现了明文数据行')
        checks['centerHoldsOnlyCiphertext'] = True

        # 7 运行时按签名任务放行，解密还原示例数据
        task = task_payload(asset, issued, policy, GRANTED_COLUMNS, OPERATOR, sandbox_id=sandbox_id)
        released = expect_ok('运行时放行', '/v1alpha1/tee/runtime/release', {
            'contractVersion': CONTRACT, 'requestId': uuid4().hex, 'taskJws': sign_task(task),
            'attestationEvidence': None, 'recipientCertPem': workload_cert}, center_token)
        runtime_key = unwrap(released['keyEnvelopes'][0], CENTER / 'tee/workload-cert/client.key')
        recovered = decrypt(runtime_key, encrypted).decode()
        if recovered != SAMPLE_CSV:
            raise Failure('运行时解密结果与原始示例数据不一致')
        checks['runtimeReleasedAndDecrypted'] = True
        checks['simulationNotClaimingAttestation'] = (
            released['runtimeMode'] == 'SIMULATION' and released['attestationVerified'] is False)

        def release_denied(name, payload_task, error, evidence=None, recipient=None, signer=None):
            return expect_denied(name, '/v1alpha1/tee/runtime/release', {
                'contractVersion': CONTRACT, 'requestId': uuid4().hex,
                'taskJws': signer(payload_task) if signer else sign_task(payload_task),
                'attestationEvidence': evidence,
                'recipientCertPem': recipient or workload_cert}, center_token, error)

        def task_for(columns=None, operator=OPERATOR, **kwargs):
            return task_payload(asset, issued, policy, columns or GRANTED_COLUMNS, operator,
                                sandbox_id=sandbox_id, **kwargs)

        # 8 越权算子被拒
        checks['deniedUnauthorizedOperator'] = release_denied(
            '越权算子', task_for(operator='ml.dnn'), 'POLICY_DENIED')

        # 9 越权列被拒；拒绝原因不含列的数据内容
        code, body = request('/v1alpha1/tee/runtime/release', {
            'contractVersion': CONTRACT, 'requestId': uuid4().hex,
            'taskJws': sign_task(task_for(columns=GRANTED_COLUMNS + ['id_card'])),
            'attestationEvidence': None, 'recipientCertPem': workload_cert}, center_token)
        if body.get('data', {}).get('errorCode') != 'POLICY_DENIED':
            raise Failure('越权列未被按 POLICY_DENIED 拒绝')
        if any(row.split(',')[3] in json.dumps(body) for row in SAMPLE_CSV.splitlines()[1:]):
            raise Failure('拒绝响应中出现了列的数据内容')
        checks['deniedUnauthorizedColumn'] = {'errorCode': 'POLICY_DENIED', 'httpStatus': code,
                                              'noColumnDataInReason': True}

        # 10 非登记的可信运行时被拒
        checks['deniedForeignRecipient'] = release_denied(
            '伪造接收者', task_for(), 'TASK_SIGNATURE_INVALID', recipient=institution_cert)

        # 11 重放同一 nonce
        checks['deniedReplayedNonce'] = release_denied(
            'nonce 重放', task_for(nonce=task['nonce']), 'TASK_REPLAYED')

        # 12 幂等：相同请求标识不同内容
        conflict_id = uuid4().hex
        expect_ok('幂等首次', '/v1alpha1/tee/keys/issue', {
            'contractVersion': CONTRACT, 'requestId': conflict_id,
            'assetId': asset_id, 'assetVersion': '1'}, client_token)
        checks['deniedRequestIdConflict'] = expect_denied(
            '幂等冲突', '/v1alpha1/tee/keys/issue', {
                'contractVersion': CONTRACT, 'requestId': conflict_id,
                'assetId': asset_id, 'assetVersion': '2'}, client_token, 'REQUEST_ID_CONFLICT')

        # 13 通配符与空集合授权被拒
        checks['deniedWildcardPolicy'] = expect_denied(
            '通配符授权', '/v1alpha1/tee/policies/register', {
                'contractVersion': CONTRACT, 'requestId': uuid4().hex,
                'policy': dict(policy_body, columns=['*'])}, client_token, 'POLICY_DENIED')
        checks['deniedEmptyPolicy'] = expect_denied(
            '空授权集合', '/v1alpha1/tee/policies/register', {
                'contractVersion': CONTRACT, 'requestId': uuid4().hex,
                'policy': dict(policy_body, columns=[])}, client_token, 'POLICY_DENIED')

        # 14 端角色越权
        checks['deniedEndRole'] = expect_denied(
            '端角色越权', '/v1alpha1/tee/keys/issue', {
                'contractVersion': CONTRACT, 'requestId': uuid4().hex,
                'assetId': asset_id, 'assetVersion': '3'}, center_token, 'END_ROLE_DENIED')

        # 15 台账可查且不含密钥材料
        code, ledger = request('/v1alpha1/tee/keys', token=client_token)
        if code != 200 or not ledger['data']['items']:
            raise Failure('密钥台账为空')
        if 'wrappedKeyB64' in json.dumps(ledger) or 'dataKey' in json.dumps(ledger):
            raise Failure('台账返回了密钥材料')
        checks['ledgerWithoutKeyMaterial'] = True

        # 16 跨节点同步只给密文
        code, sync = request(f'/v1alpha1/data-assets/sync/download?assetId={asset_id}', token=client_token)
        body = json.dumps(sync)
        if SAMPLE_CSV.splitlines()[1] in body or 'id_card' in body:
            raise Failure('跨节点同步响应中出现了明文数据行')
        checks['syncServesNoPlaintext'] = True

        # 17 换一个机构的证书申领同一份数据的密钥
        checks['deniedForeignInstitutionClaim'] = expect_denied(
            '他机构证书申领', '/v1alpha1/tee/keys/claim',
            dict(claim_request, requestId=uuid4().hex, recipientCertPem=foreign_cert),
            client_token, 'ASSET_OWNER_MISMATCH')

        # 18 冒充其他机构登记规则
        checks['deniedForeignOwnerPolicy'] = expect_denied(
            '冒充机构登记规则', '/v1alpha1/tee/policies/register', {
                'contractVersion': CONTRACT, 'requestId': uuid4().hex,
                'policy': dict(policy_body, ownerId=owner + '-other')},
            client_token, 'ASSET_OWNER_MISMATCH')

        # 19 申领时资产绑定不符
        checks['deniedClaimAssetMismatch'] = expect_denied(
            '申领资产不符', '/v1alpha1/tee/keys/claim',
            dict(claim_request, requestId=uuid4().hex, assetId=asset_id + '-other'),
            client_token, 'DATA_INTEGRITY_FAILED')

        # 20 规则没有审批来源
        checks['deniedPolicyWithoutApproval'] = expect_denied(
            '无审批来源', '/v1alpha1/tee/policies/register', {
                'contractVersion': CONTRACT, 'requestId': uuid4().hex,
                'policy': dict(policy_body, sandboxId='sbx-not-approved')},
            client_token, 'POLICY_DENIED')

        # 21 授权列超出审批批准范围
        checks['deniedPolicyBeyondApproval'] = expect_denied(
            '超出审批列范围', '/v1alpha1/tee/policies/register', {
                'contractVersion': CONTRACT, 'requestId': uuid4().hex,
                'policy': dict(policy_body, columns=GRANTED_COLUMNS + ['salary'])},
            client_token, 'POLICY_DENIED')

        # 22 有效期超过审批批准的期限
        checks['deniedPolicyBeyondDeadline'] = expect_denied(
            '超出审批期限', '/v1alpha1/tee/policies/register', {
                'contractVersion': CONTRACT, 'requestId': uuid4().hex,
                'policy': dict(policy_body, expiresAt=utc_time(30 * 24 * 3600))},
            client_token, 'POLICY_DENIED')

        # 23 篡改密文与篡改 AAD
        tampered = dict(encrypted, ciphertextB64=base64.b64encode(
            base64.b64decode(encrypted['ciphertextB64'])[:-1] + b'\x00').decode())
        checks['deniedTamperedCiphertext'] = expect_denied(
            '篡改密文', '/v1alpha1/tee/assets/register', {
                'contractVersion': CONTRACT, 'requestId': uuid4().hex, 'ownerId': owner,
                'schema': SAMPLE_COLUMNS, 'encryptedObject': tampered,
                'policyId': policy['policyId'], 'policyVersion': policy['policyVersion']},
            client_token, 'DATA_INTEGRITY_FAILED')
        forged_aad = build_aad(asset_id, '9', issued['keyId'], issued['keyVersion'])
        swapped = dict(encrypted, aadB64=base64.b64encode(forged_aad).decode())
        swapped['ciphertextSha256'] = hashlib.sha256(
            base64.b64decode(swapped['nonceB64']) + forged_aad
            + base64.b64decode(swapped['ciphertextB64'])
            + base64.b64decode(swapped['tagB64'])).hexdigest()
        checks['deniedTamperedAad'] = expect_denied(
            '篡改 AAD', '/v1alpha1/tee/assets/register', {
                'contractVersion': CONTRACT, 'requestId': uuid4().hex, 'ownerId': owner,
                'schema': SAMPLE_COLUMNS, 'encryptedObject': swapped,
                'policyId': policy['policyId'], 'policyVersion': policy['policyVersion']},
            client_token, 'DATA_INTEGRITY_FAILED')

        # 24 任务时效：已过期与有效期超过契约上限
        checks['deniedExpiredTask'] = release_denied(
            '过期任务', task_for(lifetime=60, issued_offset=-600), 'TASK_EXPIRED')
        checks['deniedTaskLifetimeTooLong'] = release_denied(
            '有效期超上限', task_for(lifetime=600), 'CONTRACT_INVALID')

        # 25 签名不可信：未知 kid 与非 RS256
        checks['deniedUnknownKid'] = release_denied(
            '未知 kid', task_for(), 'TASK_SIGNATURE_INVALID',
            signer=lambda payload: sign_task(payload, kid='center-unknown'))
        checks['deniedNonRs256'] = release_denied(
            '非 RS256', task_for(), 'TASK_SIGNATURE_INVALID',
            signer=lambda payload: sign_task(payload, alg='HS256'))

        # 26 运行镜像摘要未登记
        checks['deniedUnregisteredImageDigest'] = release_denied(
            '未登记镜像摘要', task_for(image_digest='sha256:' + '0' * 64), 'TASK_SIGNATURE_INVALID')

        # 27 程序引用结构不符契约
        checks['deniedProgramShape'] = release_denied(
            'BUILTIN 携带程序对象', task_for(program={
                'kind': 'BUILTIN', 'objectId': 'obj-x',
                'sha256': hashlib.sha256(b'builtin').hexdigest(), 'parameters': {}}),
            'CONTRACT_INVALID')

        # 28 仿真部署不接受硬件证明证据
        checks['deniedAttestationInSimulation'] = release_denied(
            '仿真下提交证明', task_for(), 'REAL_MODE_UNAVAILABLE', evidence='c3ludGhldGlj')

        # 29 输入明文总量超契约上限
        checks['deniedOversizedInput'] = release_denied(
            '输入超限', task_for(plaintext_bytes=300 * 1024 * 1024), 'PAYLOAD_TOO_LARGE')

        # 30 契约版本不匹配
        checks['deniedContractVersion'] = expect_denied(
            '契约版本不符', '/v1alpha1/tee/keys/issue', {
                'contractVersion': 'tee-contract/9.9', 'requestId': uuid4().hex,
                'assetId': asset_id, 'assetVersion': '1'}, client_token, 'CONTRACT_INVALID')

        # 31 结果密钥：DATA 可申领，REPORT 不需要结果密钥
        result_task = task_for()
        result_task_jws = sign_task(result_task)
        expect_ok('结果任务放行', '/v1alpha1/tee/runtime/release', {
            'contractVersion': CONTRACT, 'requestId': uuid4().hex, 'taskJws': result_task_jws,
            'attestationEvidence': None, 'recipientCertPem': workload_cert}, center_token)
        result_id = 'res-' + uuid4().hex[:10]
        output = expect_ok('结果密钥申领', '/v1alpha1/tee/runtime/output-key', {
            'contractVersion': CONTRACT, 'requestId': uuid4().hex, 'taskJws': result_task_jws,
            'resultId': result_id, 'resultKind': 'DATA',
            'recipientCertPem': workload_cert}, center_token)
        result_key = unwrap(output['keyEnvelope'], CENTER / 'tee/workload-cert/client.key')
        checks['outputKeyIssuedAndUnwrapped'] = len(result_key) == 32
        checks['deniedReportOutputKey'] = expect_denied(
            '报告申领结果密钥', '/v1alpha1/tee/runtime/output-key', {
                'contractVersion': CONTRACT, 'requestId': uuid4().hex, 'taskJws': sign_task(task_for()),
                'resultId': 'res-' + uuid4().hex[:10], 'resultKind': 'REPORT',
                'recipientCertPem': workload_cert}, center_token, 'CONTRACT_INVALID')

        # 32 运行时写回结果对象；存储与读回都是密文
        result_object = encrypt(result_key, b'metric,value\nauc,0.91\n', result_id, 1,
                                output['keyEnvelope']['keyId'],
                                output['keyEnvelope']['keyVersion'])
        written = expect_ok('结果对象写入', '/v1alpha1/tee/objects', {
            'contractVersion': CONTRACT, 'requestId': uuid4().hex, 'taskId': result_task['taskId'],
            'resultId': result_id, 'resultKind': 'DATA', 'contributors': [owner],
            'encryptedObject': result_object}, center_token)
        code, read_back = request(f'/v1alpha1/tee/objects/{written["objectId"]}', token=center_token)
        if code != 200 or read_back['data']['ciphertextB64'] != result_object['ciphertextB64']:
            raise Failure('结果对象读回与写入的密文不一致')
        if 'auc' in base64.b64decode(read_back['data']['ciphertextB64']).decode('latin-1'):
            raise Failure('结果对象存储的不是密文')
        checks['resultObjectStoredAsCiphertext'] = {'objectId': written['objectId'],
                                                    'exportState': written['exportState']}

        # 33 结果标识不得改挂到其他任务
        checks['deniedResultBoundToOtherTask'] = expect_denied(
            '结果改挂其他任务', '/v1alpha1/tee/objects', {
                'contractVersion': CONTRACT, 'requestId': uuid4().hex,
                'taskId': 'task-' + uuid4().hex[:12], 'resultId': result_id, 'resultKind': 'DATA',
                'contributors': [owner], 'encryptedObject': result_object},
            center_token, 'POLICY_DENIED')

        # 34 数据方不得写入结果对象
        checks['deniedClientWritesResultObject'] = expect_denied(
            '数据方写结果对象', '/v1alpha1/tee/objects', {
                'contractVersion': CONTRACT, 'requestId': uuid4().hex,
                'taskId': result_task['taskId'], 'resultId': 'res-' + uuid4().hex[:10],
                'resultKind': 'DATA', 'contributors': [owner], 'encryptedObject': result_object},
            client_token, 'END_ROLE_DENIED')

        # 35 吊销后立即算不动
        expect_ok('吊销密钥', '/v1alpha1/tee/keys/revoke', {
            'contractVersion': CONTRACT, 'requestId': uuid4().hex, 'keyId': issued['keyId'],
            'keyVersion': issued['keyVersion'], 'reason': 'p4 acceptance'}, client_token)
        checks['deniedAfterRevoke'] = release_denied('吊销后放行', task_for(), 'KEY_REVOKED')
    finally:
        remove_approval(fixture)

    # 36 中心实例的抽样脱敏产出加密落盘
    governed_encryption('center', client_token, owner, checks, 'centerGoverned')

    # 37 两个客户端实例：向中心端申请密钥、登记规则、加密落盘，端角色与环境如实标注
    client_instance_chain('client-a', checks, 'clientInstance1')
    client_instance_chain('client-b', checks, 'clientInstance2')

    return {'assetId': asset_id, 'keyId': issued['keyId'], 'policyId': policy['policyId'],
            'objectId': asset['objectId'], 'sampleBytes': len(SAMPLE_CSV),
            'grantedColumns': GRANTED_COLUMNS, 'operator': OPERATOR,
            'approvalId': fixture['approvalId'], 'checks': checks}


if __name__ == '__main__':
    try:
        print(json.dumps(run(), ensure_ascii=False))
    except Failure as failure:
        raise SystemExit('P4 全链路验收失败：' + str(failure))
    except Exception as error:
        # 异常内容可能带证书或请求正文，只输出类别。
        raise SystemExit('P4 全链路验收异常：' + type(error).__name__)
