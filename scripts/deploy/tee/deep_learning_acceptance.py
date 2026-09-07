#!/usr/bin/env python3
"""专属测试中心的深度学习验收；仅生成合成数据和合成审批，不读取主环境数据。"""
import csv
import io
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from uuid import uuid4
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[3]
WORKSPACE = ROOT.parent
if WORKSPACE != Path('/data/collab/Projects/gpu-deep-learning-20260907'):
    raise SystemExit('验收仅允许在专属服务器工作树执行')
os.environ.update(DATA_SANDBOX_TEE_PROFILE='deep-learning',
                  DATA_SANDBOX_WORKSPACE_DIR=str(WORKSPACE),
                  DATA_SANDBOX_TEE_RUNTIME_ROOT=str(WORKSPACE / '.dev-runtime'))
import contract_acceptance as contract

# 复用现有合成夹具的业务请求；显式绑定唯一测试端口和数据库容器。
contract.PORTS = {'center': 21687}
CONTAINER = 'data-sandbox-dev-dl-center-secretpad'

def sql(instance, statements):
    if instance != 'center':
        raise RuntimeError('仅允许专属测试中心')
    subprocess.run(['docker', 'exec', '-i', CONTAINER, 'sqlite3', '/app/db/secretpad.sqlite'],
                   input=('pragma busy_timeout=8000;\n' + '\n'.join(statements)).encode(),
                   check=True, capture_output=True)

contract.sqlite = sql
import p6_acceptance as fixture_api
fixture_api.SECRETPAD = CONTAINER
fixture_api.KUSCIA = 'data-sandbox-dev-dl-center-kuscia'
from p5_acceptance import current_encrypt
from contract_acceptance import (CONTRACT, CENTER, expect_ok, login, quote, utc_time)

EVIDENCE = WORKSPACE / 'evidence/deep-learning-acceptance.json'
COLUMNS = ['age', 'income', 'label', 'city', 'private_note']
OPERATORS = ['ml.' + kind for kind in ['dnn', 'cnn', 'rnn', 'lstm']]

def get(path, token, **query):
    code, body = contract.request(path + '?' + urlencode(query), token=token)
    if code != 200 or body.get('status', {}).get('code') != 0:
        raise RuntimeError('接口读取失败：' + str(body.get('status')))
    return body['data']

def persist(state):
    temporary = EVIDENCE.with_suffix('.tmp')
    temporary.write_text(json.dumps(state, ensure_ascii=False, indent=2) + '\n')
    temporary.replace(EVIDENCE)

def prepare(token, owner):
    stream = io.StringIO()
    writer = csv.writer(stream)
    writer.writerow(COLUMNS)
    for index in range(96):
        age = 20 + index % 64
        writer.writerow([age, 20000 + age * 1000, int(age >= 48), 'test-city', 'synthetic-only'])
    fixture_api.SAMPLE_CSV = stream.getvalue()
    asset_id = 'asset-dl-' + uuid4().hex[:12]
    fixture = contract.install_approval('center', owner, asset_id, COLUMNS, OPERATORS, hours=6)
    env = dict(line.split('=', 1) for line in (CENTER / 'secretpad.env').read_text().splitlines() if '=' in line)
    sql('center', ['update ds_sandbox set name=' + quote('深度学习合成数据验收')
                   + ',created_by=' + quote(env['SECRETPAD_USER_NAME'])
                   + ' where id=' + quote(fixture['sandboxId']) + ';'])
    issued = expect_ok('密钥签发', '/v1alpha1/tee/keys/issue', {
        'contractVersion': CONTRACT, 'requestId': uuid4().hex, 'assetId': asset_id, 'assetVersion': '1'}, token)
    claimed = expect_ok('合成数据加密密钥申领', '/v1alpha1/tee/keys/claim', {
        'contractVersion': CONTRACT, 'requestId': uuid4().hex, 'assetId': asset_id, 'assetVersion': '1',
        'keyId': issued['keyId'], 'keyVersion': issued['keyVersion'],
        'recipientCertPem': contract.pem_of(CENTER / 'tee/identity/client.crt')}, token)
    key = contract.unwrap(claimed['keyEnvelope'], CENTER / 'tee/identity/client.key')
    encrypted = current_encrypt(key, stream.getvalue().encode(), asset_id, issued['keyId'], issued['keyVersion'])
    policy = expect_ok('合成夹具授权规则登记', '/v1alpha1/tee/policies/register', {
        'contractVersion': CONTRACT, 'requestId': uuid4().hex,
        'policy': {'contractVersion': CONTRACT, 'policyId': '', 'policyVersion': '', 'assetId': asset_id,
                   'assetVersion': '1', 'ownerId': owner, 'sandboxId': fixture['sandboxId'],
                   'columns': ['age', 'income', 'label'], 'operators': OPERATORS,
                   'expiresAt': utc_time(5 * 3600), 'reportKinds': ['EVALUATION_METRICS']}}, token)
    expect_ok('密文资产登记', '/v1alpha1/tee/assets/register', {
        'contractVersion': CONTRACT, 'requestId': uuid4().hex, 'ownerId': owner, 'schema': COLUMNS,
        'encryptedObject': encrypted, 'policyId': policy['policyId'], 'policyVersion': policy['policyVersion']}, token)
    fixture_api.install_platform_fixture(owner, asset_id, fixture)
    sql('center', ["update ds_sandbox_data_dir set name='深度学习合成输入',row_count=96 where sandbox_id="
                   + quote(fixture['sandboxId']) + ';'])
    return {'syntheticData': True, 'syntheticApproval': True, 'runtimeMode': 'SIMULATION',
            'attestationVerified': False, 'fixture': fixture, 'cases': []}

def run_case(token, fixture, kind, task, features=None, label=None, samples=96, preprocess=False):
    name = kind.upper() + (' 分类' if task == 'classification' else ' 回归')
    params = {'features': ['age', 'income'] if task == 'classification' else ['age'],
              'label': 'label' if task == 'classification' else 'income', 'task': task}
    if features is not None:
        params['features'] = features
    if label is not None:
        params['label'] = label
    if kind != 'dnn':
        params.update(epochs=50, learning_rate=0.001)
    graph = {'nodes': [
        {'id': 'input', 'data': {'componentCode': 'data.table', 'name': '合成输入',
                               'params': {'table': fixture_api.SOURCE_TABLE}}, 'position': {'x': 60, 'y': 80}},
        {'id': 'train', 'data': {'componentCode': 'ml.' + kind, 'name': name, 'params': params},
         'position': {'x': 360, 'y': 80}}], 'edges': [{'source': 'input', 'target': 'train'}]}
    if preprocess:
        graph['nodes'].append({'id': 'scale', 'data': {'componentCode': 'preprocessing.standardize',
            'name': '标准化', 'params': {'columns': params['features'], 'method': 'zscore'}},
            'position': {'x': 320, 'y': 80}})
        graph['nodes'][1]['position']['x'] = 580
        graph['edges'] = [{'source': 'input', 'target': 'scale'}, {'source': 'scale', 'target': 'train'}]
    canvas = expect_ok('保存画布', '/v1alpha1/data-compute/canvases/save', {
        'sandboxId': fixture['sandboxId'], 'name': '深度学习验收 ' + name,
        'graph': graph, 'snapshot': False}, token)
    started = expect_ok('运行画布', '/v1alpha1/data-compute/canvas/run', {'canvasId': canvas['id'], 'mode': 'ALL'}, token)
    result = {'kind': kind, 'task': task, 'canvasId': canvas['id'], 'runId': started['id'],
              'features': params['features'], 'label': params['label'], 'preprocess': preprocess}
    print('START ' + json.dumps(result), flush=True)
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        status = fixture_api.scalar('select status from ds_compute_run where id=' + quote(started['id']) + ';')
        if status in fixture_api.TERMINAL:
            if status != 'SUCCEEDED':
                detail = fixture_api.scalar('select component_code,status,error_message from ds_compute_node_run where run_id=' + quote(started['id']) + ';')
                raise RuntimeError('画布失败：' + detail)
            break
        time.sleep(3)
    else:
        raise RuntimeError('画布运行超时')
    output = get('/v1alpha1/data-compute/canvas/node/output', token, canvasId=canvas['id'], nodeId='train', runId=started['id'])
    objects = output.get('encryptedOutputs', [])
    assert {item['kind'] for item in objects} >= {'DATA', 'MODEL'}, output
    assert output.get('rows') in (None, []) and output.get('attestationVerified') is False
    result['encryptedOutputs'] = [{k: item.get(k) for k in ('kind', 'objectId', 'sizeBytes', 'ciphertextSha256')} for item in objects]
    saved = expect_ok('保存模型', '/v1alpha1/data-compute/canvas/models/save', {
        'canvasId': canvas['id'], 'nodeId': 'train', 'name': name + ' 验收模型'}, token)
    result['canvasModelId'] = saved['id']
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        report = get('/v1alpha1/data-compute/canvas/models/report', token, canvasModelId=saved['id'])
        evaluation = report.get('evaluation', {})
        if evaluation.get('status') == 'AVAILABLE':
            assert evaluation.get('source') == 'TRUSTED_TRAINING_EVALUATION', evaluation
            metrics = evaluation.get('metrics', {})
            assert metrics.get('samples') == samples, metrics
            assert ('accuracy' if task == 'classification' else 'rmse') in metrics, metrics
            result['evaluation'] = evaluation
            result['status'] = 'PASSED'
            print('PASS ' + kind + ' ' + task, flush=True)
            return result
        if evaluation.get('status') not in ('RUNNING', 'PENDING'):
            raise RuntimeError('报告不可用：' + json.dumps(evaluation, ensure_ascii=False))
        time.sleep(4)
    raise RuntimeError('报告生成超时')

def main():
    token, owner = login('CLIENT')
    state = json.loads(EVIDENCE.read_text()) if EVIDENCE.exists() else prepare(token, owner)
    persist(state)
    for kind in ['cnn', 'rnn', 'lstm', 'dnn']:
        for task in ['classification', 'regression']:
            if any(c['kind'] == kind and c['task'] == task for c in state['cases']):
                continue
            state['cases'].append(run_case(token, state['fixture'], kind, task))
            persist(state)
    state['status'] = 'PASSED'
    persist(state)
    print('八项画布训练、加密权重登记和训练集报告验收通过。', flush=True)

if __name__ == '__main__':
    main()
