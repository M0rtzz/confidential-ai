#!/usr/bin/env python3
"""使用与主平台已登记文件摘要一致的现有测试素材；独立测试身份和测试审批。"""
import hashlib
import json
import sqlite3
from uuid import uuid4
import deep_learning_acceptance as check
from contract_acceptance import CONTRACT, CENTER, expect_ok, login, quote, utc_time, platform_time

EVIDENCE = check.WORKSPACE / 'evidence/deep-learning-existing-data.json'
INPUT = check.WORKSPACE / 'evidence/existing-credit-sample.csv'
EXPECTED_SHA = '978eae81d248f744089684d90de610ac1b201922d3a046724f79f19270c1e98a'
COLUMNS = ['age', 'income', 'tenure_months', 'is_default']
OPERATORS = check.OPERATORS + ['preprocessing.standardize']

def prepare(token, owner):
    data = INPUT.read_bytes()
    if hashlib.sha256(data).hexdigest() != EXPECTED_SHA:
        raise RuntimeError('现有测试文件摘要与已核实资产不一致')
    asset_id = 'asset-dl-existing-' + uuid4().hex[:10]
    fixture = check.contract.install_approval('center', owner, asset_id, COLUMNS, OPERATORS, hours=6)
    env = dict(line.split('=', 1) for line in (CENTER / 'secretpad.env').read_text().splitlines() if '=' in line)
    project = 'project-dl-' + uuid4().hex[:10]
    node = check.fixture_api.scalar('select node_id from node where inst_id=' + quote(owner) + ' and is_deleted=0 limit 1;')
    now = platform_time(0)
    metadata = json.dumps({'encrypted': True, 'plaintextBytes': len(data), 'contentType': 'text/csv', 'sourceSha256': EXPECTED_SHA})
    schema = json.dumps([{'name': c, 'type': 'float' if c == 'income' else 'int'} for c in COLUMNS])
    check.sql('center', [
        'insert into project(project_id,name,compute_mode,compute_func,owner_id) values('
        + ','.join(map(quote, [project, '深度学习现有测试素材验收', 'tee', 'ALL', owner])) + ');',
        'insert into project_node(project_id,node_id,is_deleted) values(' + quote(project) + ',' + quote(node) + ',0);',
        'update ds_sandbox set project_id=' + quote(project) + ',name=' + quote('现有信贷样本验收')
        + ',created_by=' + quote(env['SECRETPAD_USER_NAME']) + ' where id=' + quote(fixture['sandboxId']) + ';',
        'insert into ds_data_asset(id,name,provider_node_id,processor_node_id,ingestion_type,modality,data_stage,'
        'source_asset_id,datatable_id,storage_uri,metadata_json,created_by,created_at,updated_at,version,status,deleted) values('
        + ','.join(map(quote, [asset_id, '客户端A-信贷样本.csv', owner, owner, 'UPLOAD', 'TABULAR', 'PROCESSED', '',
                              'p6_input', '', metadata, env['SECRETPAD_USER_NAME'], now, now])) + ",1,'ACTIVE',0);",
        'insert into ds_sandbox_data_dir(id,sandbox_id,kind,asset_id,table_name,name,modality,row_count,columns_json,source,created_at,updated_at,deleted) values('
        + ','.join(map(quote, ['dir-dl-' + uuid4().hex[:10], fixture['sandboxId'], 'MOUNT', asset_id,
                              'p6_input', '现有信贷样本', 'TABULAR'])) + ',400,'
        + ','.join(map(quote, [schema, 'LOCAL', now, now])) + ',0);'])
    directory = CENTER / 'secretpad/data/sandbox-db' / fixture['sandboxId']
    directory.mkdir(mode=0o700, exist_ok=False)
    # 控制面只建空表和元数据；原始行经加密接口提供给 TEE。
    with sqlite3.connect(directory / 'sandbox_data.db') as db:
        db.execute('create table p6_input(age integer,income real,tenure_months integer,is_default integer)')
        db.execute('create table _sandbox_manifest(table_name text primary key,asset_id text,name text,kind text,source text,row_count integer)')
        db.execute('insert into _sandbox_manifest values(?,?,?,?,?,?)', ('p6_input', asset_id, '现有信贷样本', 'MOUNT', 'LOCAL', 400))
    issued = expect_ok('现有样本密钥签发', '/v1alpha1/tee/keys/issue', {
        'contractVersion': CONTRACT, 'requestId': uuid4().hex, 'assetId': asset_id, 'assetVersion': '1'}, token)
    claimed = expect_ok('现有样本加密密钥申领', '/v1alpha1/tee/keys/claim', {
        'contractVersion': CONTRACT, 'requestId': uuid4().hex, 'assetId': asset_id, 'assetVersion': '1',
        'keyId': issued['keyId'], 'keyVersion': issued['keyVersion'],
        'recipientCertPem': check.contract.pem_of(CENTER / 'tee/identity/client.crt')}, token)
    key = check.contract.unwrap(claimed['keyEnvelope'], CENTER / 'tee/identity/client.key')
    encrypted = check.current_encrypt(key, data, asset_id, issued['keyId'], issued['keyVersion'])
    policy = expect_ok('测试规则登记', '/v1alpha1/tee/policies/register', {
        'contractVersion': CONTRACT, 'requestId': uuid4().hex, 'policy': {'contractVersion': CONTRACT,
        'policyId': '', 'policyVersion': '', 'assetId': asset_id, 'assetVersion': '1', 'ownerId': owner,
        'sandboxId': fixture['sandboxId'], 'columns': COLUMNS, 'operators': OPERATORS,
        'expiresAt': utc_time(5 * 3600), 'reportKinds': ['EVALUATION_METRICS']}}, token)
    expect_ok('现有样本密文登记', '/v1alpha1/tee/assets/register', {
        'contractVersion': CONTRACT, 'requestId': uuid4().hex, 'ownerId': owner, 'schema': COLUMNS,
        'encryptedObject': encrypted, 'policyId': policy['policyId'], 'policyVersion': policy['policyVersion']}, token)
    return {'sourceName': '客户端A-信贷样本.csv', 'sourceAssetId': 'asset-04a366fedf23',
            'sourceSha256': EXPECTED_SHA, 'rows': 400, 'syntheticApproval': True,
            'runtimeMode': 'SIMULATION', 'attestationVerified': False, 'fixture': fixture, 'cases': []}

def main():
    token, owner = login('CLIENT')
    state = json.loads(EVIDENCE.read_text()) if EVIDENCE.exists() else prepare(token, owner)
    EVIDENCE.write_text(json.dumps(state, ensure_ascii=False, indent=2) + '\n')
    for kind in ['cnn', 'rnn', 'lstm', 'dnn']:
        if any(c['kind'] == kind for c in state['cases']):
            continue
        result = check.run_case(token, state['fixture'], kind, 'classification',
                                features=['age', 'income', 'tenure_months'], label='is_default',
                                samples=400, preprocess=kind == 'cnn')
        state['cases'].append(result)
        EVIDENCE.write_text(json.dumps(state, ensure_ascii=False, indent=2) + '\n')
    state['status'] = 'PASSED'
    EVIDENCE.write_text(json.dumps(state, ensure_ascii=False, indent=2) + '\n')
    print('现有 400 行测试素材的四种分类训练和报告通过，包含标准化到 CNN 链路。', flush=True)

if __name__ == '__main__':
    main()
