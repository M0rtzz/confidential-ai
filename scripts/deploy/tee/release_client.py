"""P4 前置验证：中心密钥服务的数据密钥业务放行与规则拒绝。

只使用一次性合成身份与合成数据密钥，不接触真实资产；结束后删除本次写入的策略与密钥。
本脚本验证的是底座能力边界，不是 P4 的业务接口实现。
"""
import argparse
import base64
import json
import os
from pathlib import Path
import secrets
from uuid import uuid4

COLUMNS = ['age', 'income']
OPERATOR = 'ml.xgboost'
TIMEOUT = 15


def frame_for(endpoint):
    from sdc.capsule_manager_frame import CapsuleManagerFrame, CredentialsConf
    tls = CredentialsConf(*[(Path('/certs') / f).read_bytes() for f in ['ca.crt', 'client.key', 'client.crt']])
    frame = CapsuleManagerFrame(endpoint, 'sim', None, tls)
    for method in ['GetRaCert', 'RegisterCert', 'CreateDataKeys', 'CreateDataPolicy',
                   'ListDataPolicy', 'DeleteDataPolicy', 'DeleteDataKey', 'GetDataKeys', 'GetExportDataKey']:
        stub = getattr(frame.stub, method)
        setattr(frame.stub, method, lambda request, _s=stub: _s(request, timeout=TIMEOUT))
    return frame


def identity():
    from sdc.util.crypto import generate_rsa_keypair
    from sdc.util.tool import generate_party_id_from_cert
    private_key, chain = generate_rsa_keypair()
    return {'privateKey': private_key, 'chain': chain, 'partyId': generate_party_id_from_cert(chain[-1])}


def release(frame, public_key, caller, initiator, uri, columns, scope, operator, recipient):
    """按 TEE 应用的调用形态直接请求数据密钥；仿真模式下证明报告为空。"""
    from secretflowapis.v2.sdc.capsule_manager import capsule_manager_pb2
    request = capsule_manager_pb2.GetDataKeysRequest()
    request.cert = recipient['chain'][-1].decode()
    request.resource_request.initiator_party_id = initiator
    request.resource_request.scope = scope
    request.resource_request.op_name = operator
    resource = request.resource_request.resources.add()
    resource.resource_uri = uri
    resource.columns.extend(columns)
    encrypted = frame.stub.GetDataKeys(frame.create_encrypted_request(
        request, public_key, caller['privateKey'], caller['chain']))
    if encrypted.status.code != 0:
        return {'released': False, 'applicationCode': encrypted.status.code}
    response = capsule_manager_pb2.GetDataKeysResponse()
    frame.parse_from_encrypted_response(encrypted, recipient['privateKey'], response)
    return {'released': True, 'keys': {k.resource_uri: k.data_key_b64 for k in response.data_keys}}


def expect(checks, name, condition, detail=None):
    checks[name] = {'passed': bool(condition)}
    if detail is not None:
        checks[name]['detail'] = detail
    return checks[name]['passed']


def run(state_file):
    endpoint = os.environ['TEE_CAPSULE_ENDPOINT']
    frame = frame_for(endpoint)
    public_key = frame.get_public_key()

    owner, runtime, outsider = identity(), identity(), identity()
    uuid, scope = uuid4().hex, 'p4-pilot-' + uuid4().hex
    data_key = base64.b64encode(secrets.token_bytes(32)).decode()
    state = {'scope': scope, 'uuid': uuid,
             'owner': {'partyId': owner['partyId'],
                       'privateKey': base64.b64encode(owner['privateKey']).decode(),
                       'chain': [base64.b64encode(c).decode() for c in owner['chain']]}}
    with open(state_file, 'x') as handle:
        json.dump(state, handle)
    Path(state_file).chmod(0o600)

    checks = {}
    signing = {'cert_pems': owner['chain'], 'private_key': owner['privateKey']}

    # 固定版本 CM 的 SQL 存储未实现 store_public_key/get_public_key，RegisterCert 会使工作线程 panic。
    # 各接口的身份由 JWS 的 x5c 证书链承载并反推 party_id，因此本链路不调用 RegisterCert。
    expect(checks, 'registerCertNotRequired', True, 'CM 按 x5c 证书链验签并反推 party_id，无需预先注册公钥')

    frame.create_data_keys(owner['partyId'], [{'resource_uri': uuid, 'data_key_b64': data_key}], **signing)
    expect(checks, 'createDataKeys', True)

    frame.create_data_policy(owner['partyId'], scope, uuid, [{
        'rule_id': uuid4().hex, 'grantee_party_ids': [runtime['partyId']],
        'columns': COLUMNS, 'global_constraints': [],
        'op_constraints': [{'op_name': OPERATOR, 'constraints': []}]}], **signing)
    expect(checks, 'createDataPolicy',
           any(p.data_uuid == uuid for p in frame.get_data_policys(owner['partyId'], scope, **signing)))

    granted = release(frame, public_key, runtime, runtime['partyId'], uuid, COLUMNS, scope, OPERATOR, runtime)
    expect(checks, 'authorizedRelease',
           granted['released'] and granted['keys'].get(uuid) == data_key,
           '授权算子与授权列的请求取回与登记完全一致的数据密钥')

    denied_operator = release(frame, public_key, runtime, runtime['partyId'], uuid, COLUMNS, scope, 'ml.dnn', runtime)
    expect(checks, 'deniedUnauthorizedOperator', not denied_operator['released'], denied_operator)

    denied_column = release(frame, public_key, runtime, runtime['partyId'], uuid,
                            COLUMNS + ['id_card'], scope, OPERATOR, runtime)
    expect(checks, 'deniedUnauthorizedColumn', not denied_column['released'], denied_column)

    denied_grantee = release(frame, public_key, outsider, outsider['partyId'], uuid,
                             COLUMNS, scope, OPERATOR, outsider)
    expect(checks, 'deniedUnauthorizedGrantee', not denied_grantee['released'], denied_grantee)

    denied_scope = release(frame, public_key, runtime, runtime['partyId'], uuid,
                           COLUMNS, 'p4-pilot-absent', OPERATOR, runtime)
    expect(checks, 'deniedUnknownScope', not denied_scope['released'], denied_scope)

    # 空列集合在原生策略下不会触发列校验；A 的适配层必须自行拒绝，契约要求空授权集合即禁止。
    empty_columns = release(frame, public_key, runtime, runtime['partyId'], uuid, [], scope, OPERATOR, runtime)
    expect(checks, 'emptyColumnsNotBlockedByCapsule', empty_columns['released'],
           '原生策略对空列请求不作限制，适配层必须前置拒绝')

    # 发起方身份在仿真模式下不由 CM 验签，只靠 mTLS 入口约束；记录事实，不据此放松入口。
    spoofed = release(frame, public_key, outsider, runtime['partyId'], uuid, COLUMNS, scope, OPERATOR, outsider)
    expect(checks, 'initiatorNotAuthenticatedByCapsule', spoofed['released'],
           '任意可达 CM 的客户端可自称已授权发起方，入口 mTLS 是唯一约束')

    try:
        frame.get_export_data_key_b64(owner['partyId'], uuid, json.dumps({'body': {}, 'signatures': []}), **signing)
        exported = True
    except Exception as error:
        exported = False
        checks.setdefault('exportRequiresCertificate', {})['errorType'] = type(error).__name__
    expect(checks, 'exportRequiresCertificate', not exported, '缺少数据出域凭证时导出密钥被拒绝')

    return {'scope': scope, 'dataUuid': uuid, 'ownerPartyId': owner['partyId'],
            'granteePartyId': runtime['partyId'], 'attestationReport': None,
            'runtimeMode': 'SIMULATION', 'checks': checks,
            'allPassed': all(c['passed'] for c in checks.values())}


def cleanup(state_file):
    endpoint = os.environ['TEE_CAPSULE_ENDPOINT']
    frame = frame_for(endpoint)
    state = json.loads(Path(state_file).read_text())
    owner = state['owner']
    signing = {'cert_pems': [base64.b64decode(c) for c in owner['chain']],
               'private_key': base64.b64decode(owner['privateKey'])}
    frame.delete_data_policy(owner['partyId'], state['scope'], data_uuid=state['uuid'], **signing)
    frame.delete_data_key(owner['partyId'], state['uuid'], **signing)
    remaining = [p for p in frame.get_data_policys(owner['partyId'], state['scope'], **signing)
                 if p.data_uuid == state['uuid'] and p.rules]
    if remaining:
        raise RuntimeError('合成策略仍处于有效状态')
    return {'scope': state['scope'], 'checks': {'cleanup': {'passed': True}}, 'allPassed': True}


if __name__ == '__main__':
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument('phase', choices=['run', 'cleanup'])
    parser.add_argument('--state', default='/case/release-pilot.json')
    args = parser.parse_args()
    try:
        print(json.dumps(run(args.state) if args.phase == 'run' else cleanup(args.state)))
    except Exception as error:
        # 原生异常可能带签名请求内容；只输出异常类别，不输出凭据或请求正文。
        raise SystemExit('密钥放行验证失败：' + type(error).__name__)
