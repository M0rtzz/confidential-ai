"""仅用于合成策略的持久化验收，不提供业务密钥接口。"""
import argparse
import base64
from functools import partial
import json
import os
from pathlib import Path
from uuid import uuid4

from sdc.capsule_manager_frame import CapsuleManagerFrame, CredentialsConf
from sdc.util.crypto import generate_rsa_keypair
from sdc.util.tool import generate_party_id_from_cert
from secretflowapis.v2.sdc.capsule_manager import capsule_manager_pb2


def execute(phase):
    root = Path('/case')
    file = root / 'case.json'
    if phase == 'create' and not file.exists():
        private_key, chain = generate_rsa_keypair()
        owner = generate_party_id_from_cert(chain[-1])
        case = {'owner': owner, 'privateKey': base64.b64encode(private_key).decode(),
                'chain': [base64.b64encode(c).decode() for c in chain],
                'scope': 'p3-' + uuid4().hex, 'uuid': uuid4().hex,
                'rule': {'rule_id': uuid4().hex, 'grantee_party_ids': [owner], 'columns': ['synthetic'],
                         'op_constraints': [{'op_name': 'p3_persistence_probe', 'constraints': []}],
                         'global_constraints': []}}
        with file.open('x') as output: json.dump(case, output)
        file.chmod(0o600)
    case = json.loads(file.read_text())
    tls = CredentialsConf(*[(Path('/certs') / f).read_bytes() for f in ['ca.crt', 'client.key', 'client.crt']])
    frame = CapsuleManagerFrame(os.environ['TEE_CAPSULE_ENDPOINT'], 'sim', None, tls)
    for method in ['GetRaCert', 'CreateDataPolicy', 'ListDataPolicy', 'DeleteDataPolicy']:
        setattr(frame.stub, method, partial(getattr(frame.stub, method), timeout=10))
    args = {'owner_party_id': case['owner'], 'cert_pems': [base64.b64decode(c) for c in case['chain']],
            'private_key': base64.b64decode(case['privateKey']), 'scope': case['scope']}
    expected = capsule_manager_pb2.Policy(data_uuid=case['uuid'], rules=[case['rule']])
    found = [p for p in frame.get_data_policys(**args) if p.data_uuid == case['uuid']]
    if phase == 'create' and not found:
        frame.create_data_policy(data_uuid=case['uuid'], rules=[case['rule']], **args)
        found = [p for p in frame.get_data_policys(**args) if p.data_uuid == case['uuid']]
    if phase != 'cleanup' and (len(found) != 1 or found[0] != expected):
        raise RuntimeError('原生策略读取与合成记录不一致')
    if phase == 'cleanup':
        frame.delete_data_policy(data_uuid=case['uuid'], **args)
        if any(p.data_uuid == case['uuid'] and p.rules for p in frame.get_data_policys(**args)):
            raise RuntimeError('合成规则仍处于有效状态')
    print(json.dumps({'phase': phase, 'verified': True, 'scope': case['scope']}))


if __name__ == '__main__':
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument('phase', choices=['create', 'verify', 'cleanup'])
    try:
        execute(parser.parse_args().phase)
    except Exception as error:
        # 原生异常可能含签名请求；只输出异常类别，不输出凭据或请求正文。
        raise SystemExit('合成持久化验收失败：' + type(error).__name__)
