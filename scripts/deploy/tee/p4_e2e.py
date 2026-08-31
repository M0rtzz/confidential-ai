"""P4 全链路验收：用一份示例数据跑完签发、加密、登记、放行、解密，并逐项验证拒绝行为。

示例数据为合成客户表，不涉及任何真实业务数据。脚本使用运行目录中的机构私钥、
可信运行时私钥与任务签名私钥；这些材料只在本进程内存中使用，不输出、不落盘。
"""
import base64
import hashlib
import json
import secrets
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CONTRACT = 'tee-contract/1.0'
RUNTIME = Path('/data/collab/Projects/gpu-tee-dev-a/.dev-runtime')
CENTER = RUNTIME / 'tee-a-center'
BASE = 'http://127.0.0.1:19688/api'

SAMPLE_COLUMNS = ['age', 'income', 'city', 'id_card']
GRANTED_COLUMNS = ['age', 'income', 'city']
OPERATOR = 'ml.xgboost'
SAMPLE_CSV = ('age,income,city,id_card\n'
              '31,42000,hangzhou,3301...0011\n'
              '45,88000,shanghai,3101...0022\n'
              '27,31000,wuhan,4201...0033\n')


class Failure(Exception):
    pass


def request(path, payload=None, token=None):
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['User-Token'] = token
    req = urllib.request.Request(BASE + path, headers=headers,
                                 data=json.dumps(payload).encode() if payload is not None else None)
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        return error.code, json.load(error)


def login(end_role):
    env = dict(line.split('=', 1) for line in
               (CENTER / 'secretpad.env').read_text().splitlines() if '=' in line)
    code, body = request('/login', {'name': env['SECRETPAD_USER_NAME'],
                                    'passwordHash': hashlib.sha256(env['SECRETPAD_PASSWORD'].encode()).hexdigest(),
                                    'endRole': end_role})
    if code != 200 or body.get('status', {}).get('code') != 0:
        raise Failure('登录失败：' + end_role)
    return body['data']['token'], body['data']['ownerId']


def expect_ok(name, path, payload, token):
    code, body = request(path, payload, token)
    if code != 200 or body.get('status', {}).get('code') != 0:
        raise Failure(f'{name} 应成功但被拒绝：{body.get("data", {}).get("errorCode")}')
    return body['data']


def expect_denied(name, path, payload, token, error_code):
    code, body = request(path, payload, token)
    actual = body.get('data', {}).get('errorCode')
    if body.get('status', {}).get('code') == 0:
        raise Failure(f'{name} 应被拒绝但成功了')
    if actual != error_code:
        raise Failure(f'{name} 拒绝原因不符：期望 {error_code}，实际 {actual}')
    return {'errorCode': actual, 'httpStatus': code}


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


def sign_task(payload):
    header = b64url(json.dumps({'alg': 'RS256', 'typ': 'JWS', 'kid': 'tee-a-center-1'}).encode())
    body = b64url(json.dumps(payload).encode())
    signature = private_key(CENTER / 'tee/task-signer/client.key').sign(
        f'{header}.{body}'.encode('ascii'), padding.PKCS1v15(), hashes.SHA256())
    return f'{header}.{body}.{b64url(signature)}'


def task_payload(asset, key, policy, columns, operator, nonce=None):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    return {'contractVersion': CONTRACT, 'taskId': 'task-' + uuid4().hex[:12],
            'requestId': uuid4().hex, 'issuer': 'tee-a-center', 'audience': 'tee-a-runtime',
            'sandboxId': 'sandbox-demo', 'operatorId': operator, 'columns': columns,
            'inputs': [{'assetId': asset['assetId'], 'assetVersion': asset['assetVersion'],
                        'keyId': key['keyId'], 'keyVersion': key['keyVersion'],
                        'policyId': policy['policyId'], 'policyVersion': policy['policyVersion'],
                        'objectId': asset['objectId'], 'ciphertextSha256': asset['ciphertextSha256'],
                        'plaintextBytes': len(SAMPLE_CSV)}],
            'program': {'kind': 'BUILTIN', 'objectId': None,
                        'sha256': hashlib.sha256(b'builtin').hexdigest(), 'parameters': '{}'},
            'issuedAt': now.isoformat().replace('+00:00', 'Z'),
            'expiresAt': (now + timedelta(seconds=240)).isoformat().replace('+00:00', 'Z'),
            'nonce': nonce or uuid4().hex,
            'outputPolicy': {'reportKinds': ['EVALUATION_METRICS'], 'encryptData': True,
                             'encryptModel': True, 'exportRequiresAllContributors': True},
            'runtimeImageDigest': 'sha256:' + hashlib.sha256(b'runtime').hexdigest()}


def pem_of(path):
    return Path(path).read_text()


def run():
    checks = {}
    client_token, owner = login('CLIENT')
    center_token, _ = login('CENTER')
    asset_id = 'demo-customers-' + uuid4().hex[:8]
    institution_cert = pem_of(CENTER / 'tee/identity/client.crt')
    workload_cert = pem_of(CENTER / 'tee/workload-cert/client.crt')

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
                   'sandboxId': 'sandbox-demo', 'columns': GRANTED_COLUMNS, 'operators': [OPERATOR],
                   'expiresAt': (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat().replace('+00:00', 'Z'),
                   'reportKinds': ['EVALUATION_METRICS']}
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
    task = task_payload(asset, issued, policy, GRANTED_COLUMNS, OPERATOR)
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

    # 8 越权算子被拒
    denied = task_payload(asset, issued, policy, GRANTED_COLUMNS, 'ml.dnn')
    checks['deniedUnauthorizedOperator'] = expect_denied(
        '越权算子', '/v1alpha1/tee/runtime/release', {
            'contractVersion': CONTRACT, 'requestId': uuid4().hex, 'taskJws': sign_task(denied),
            'attestationEvidence': None, 'recipientCertPem': workload_cert},
        center_token, 'POLICY_DENIED')

    # 9 越权列被拒
    denied = task_payload(asset, issued, policy, GRANTED_COLUMNS + ['id_card'], OPERATOR)
    checks['deniedUnauthorizedColumn'] = expect_denied(
        '越权列', '/v1alpha1/tee/runtime/release', {
            'contractVersion': CONTRACT, 'requestId': uuid4().hex, 'taskJws': sign_task(denied),
            'attestationEvidence': None, 'recipientCertPem': workload_cert},
        center_token, 'POLICY_DENIED')

    # 10 非登记的可信运行时被拒
    checks['deniedForeignRecipient'] = expect_denied(
        '伪造接收者', '/v1alpha1/tee/runtime/release', {
            'contractVersion': CONTRACT, 'requestId': uuid4().hex,
            'taskJws': sign_task(task_payload(asset, issued, policy, GRANTED_COLUMNS, OPERATOR)),
            'attestationEvidence': None, 'recipientCertPem': institution_cert},
        center_token, 'TASK_SIGNATURE_INVALID')

    # 11 重放同一 nonce
    replay = task_payload(asset, issued, policy, GRANTED_COLUMNS, OPERATOR, nonce=task['nonce'])
    checks['deniedReplayedNonce'] = expect_denied(
        'nonce 重放', '/v1alpha1/tee/runtime/release', {
            'contractVersion': CONTRACT, 'requestId': uuid4().hex, 'taskJws': sign_task(replay),
            'attestationEvidence': None, 'recipientCertPem': workload_cert},
        center_token, 'TASK_REPLAYED')

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

    # 16 跨节点同步只给密文：已登记为密文资产的数据不再以明文出节点
    code, sync = request(f'/v1alpha1/data-assets/sync/download?assetId={asset_id}', token=client_token)
    body = json.dumps(sync)
    first_row = SAMPLE_CSV.splitlines()[1]
    if first_row in body or 'id_card' in body:
        raise Failure('跨节点同步响应中出现了明文数据行')
    checks['syncServesNoPlaintext'] = True

    # 17 吊销后立即算不动
    expect_ok('吊销密钥', '/v1alpha1/tee/keys/revoke', {
        'contractVersion': CONTRACT, 'requestId': uuid4().hex, 'keyId': issued['keyId'],
        'keyVersion': issued['keyVersion'], 'reason': 'p4 acceptance'}, client_token)
    revoked_task = task_payload(asset, issued, policy, GRANTED_COLUMNS, OPERATOR)
    checks['deniedAfterRevoke'] = expect_denied(
        '吊销后放行', '/v1alpha1/tee/runtime/release', {
            'contractVersion': CONTRACT, 'requestId': uuid4().hex, 'taskJws': sign_task(revoked_task),
            'attestationEvidence': None, 'recipientCertPem': workload_cert},
        center_token, 'KEY_REVOKED')

    return {'assetId': asset_id, 'keyId': issued['keyId'], 'policyId': policy['policyId'],
            'objectId': asset['objectId'], 'sampleBytes': len(SAMPLE_CSV),
            'grantedColumns': GRANTED_COLUMNS, 'operator': OPERATOR, 'checks': checks}


if __name__ == '__main__':
    try:
        print(json.dumps(run(), ensure_ascii=False))
    except Failure as failure:
        raise SystemExit('P4 全链路验收失败：' + str(failure))
    except Exception as error:
        # 异常内容可能带证书或请求正文，只输出类别。
        raise SystemExit('P4 全链路验收异常：' + type(error).__name__)
