#!/usr/bin/env python3
"""独立测试中心的单节点运行、非法标签和未授权算子回归。"""
import json
import time
import deep_learning_acceptance as a
from contract_acceptance import expect_ok, login, quote


def wait(run_id, expected):
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        status = a.fixture_api.scalar('select status from ds_compute_run where id=' + quote(run_id) + ';')
        if status in a.fixture_api.TERMINAL:
            if status != expected:
                raise RuntimeError('运行状态不符：' + status)
            active = a.fixture_api.scalar("select count(*) from ds_compute_node_run where status in ('PENDING','RUNNING') and run_id=" + quote(run_id) + ';')
            if active != '0':
                raise RuntimeError('终态画布仍有未收敛节点')
            return
        time.sleep(3)
    raise RuntimeError('运行超时')


def main():
    token, _ = login('CLIENT')
    state = json.loads(a.EVIDENCE.read_text())
    single = state['cases'][0]
    started = expect_ok('CNN 单节点重跑', '/v1alpha1/data-compute/canvas/run', {
        'canvasId': single['canvasId'], 'mode': 'SINGLE', 'nodeId': 'train', 'nodeIds': ['train']}, token)
    wait(started['id'], 'SUCCEEDED')
    result = {'singleNode': {'runId': started['id'], 'status': 'PASSED'}, 'negative': []}
    for label, operator, target in [('非法二分类标签', 'ml.cnn', 'income'), ('未授权训练算子', 'ml.knn', 'label')]:
        graph = {'nodes': [
            {'id': 'input', 'data': {'componentCode': 'data.table', 'params': {'table': 'p6_input'}}},
            {'id': 'train', 'data': {'componentCode': operator,
                                   'params': {'features': ['age'], 'label': target, 'task': 'classification'}}}],
            'edges': [{'source': 'input', 'target': 'train'}]}
        canvas = expect_ok('保存拒绝场景', '/v1alpha1/data-compute/canvases/save', {
            'sandboxId': state['fixture']['sandboxId'], 'name': '负向验收 ' + label,
            'graph': graph, 'snapshot': False}, token)
        run = expect_ok('提交拒绝场景', '/v1alpha1/data-compute/canvas/run', {'canvasId': canvas['id'], 'mode': 'ALL'}, token)
        wait(run['id'], 'FAILED')
        row = a.fixture_api.scalar("select error_message,coalesce(model_id,'') from ds_compute_node_run where node_id='train' and run_id=" + quote(run['id']) + ';')
        if row.rsplit('|', 1)[-1]:
            raise RuntimeError('失败训练登记了模型')
        result['negative'].append({'name': label, 'runId': run['id'], 'status': 'PASSED', 'error': row.rsplit('|', 1)[0]})
    (a.EVIDENCE.parent / 'deep-learning-negative-acceptance.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print('CNN 单节点重跑通过；非法标签和未授权算子均失败收敛，未登记空模型。', flush=True)

if __name__ == '__main__':
    main()
