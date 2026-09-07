#!/usr/bin/env python3
"""通过正式导出审批取回信封，在独立接收进程解封并复算预测与报告指标。"""
import hashlib
import json
import subprocess
import tempfile
from uuid import uuid4
from pathlib import Path

import deep_learning_acceptance as acceptance
from contract_acceptance import CONTRACT, CENTER, expect_ok, login, pem_of, utc_time
from p7_acceptance import _action

RECEIVER = '''
import java.nio.file.*;
import com.fasterxml.jackson.databind.*;
import org.secretflow.secretpad.web.service.tee.*;
class ExportReceiver {
    public static void main(String[] args) throws Exception {
        ObjectMapper mapper = new ObjectMapper().findAndRegisterModules();
        JsonNode payload = mapper.readTree(Path.of("/receiver/payload.json").toFile());
        var exported = mapper.treeToValue(payload.get("exported"), TeeExportService.ExportResult.class);
        var object = mapper.treeToValue(payload.get("object"), TeeCrypto.EncryptedObject.class);
        byte[] data = new TeeInstitutionKey("/identity").decryptExport(exported, object, mapper);
        System.out.write(data);
    }
}
'''

def receive(token, item, export_id):
    exported = expect_ok('取回已批准的导出信封', '/v1alpha1/tee/results/' + item['resultId'] + '/export', {
        'contractVersion': CONTRACT, 'requestId': uuid4().hex, 'exportId': export_id,
        'recipientCertPem': pem_of(CENTER / 'tee/identity/client.crt')}, token)
    code, body = acceptance.contract.request('/v1alpha1/tee/objects/' + item['objectId'], token=token)
    if code != 200 or body.get('status', {}).get('code') != 0:
        raise RuntimeError('已批准密文对象读取失败')
    platform = json.loads((acceptance.WORKSPACE / '.dev-runtime/p3-manifest.json').read_text())['images']['platform']['ref']
    stamp = platform.split(':p3-', 1)[1]
    jar = acceptance.ROOT / '.cache/tee-p3/build' / stamp / 'backend/target/secretpad.jar'
    with tempfile.TemporaryDirectory(prefix='dl-receiver-', dir=acceptance.EVIDENCE.parent) as directory:
        path = Path(directory)
        (path / 'ExportReceiver.java').write_text(RECEIVER)
        (path / 'payload.json').write_text(json.dumps({'exported': exported, 'object': body['data']}))
        result = subprocess.run(['docker', 'run', '--pull=never', '--rm', '--network', 'none',
            '--read-only', '--tmpfs', '/tmp:rw,size=1g', '--cpus', '2', '--memory', '2g',
            '-v', str(jar) + ':/platform.jar:ro', '-v', str(path) + ':/receiver:ro',
            '-v', str(CENTER / 'tee/identity') + ':/identity:ro', '--entrypoint', 'sh',
            'tee-a-base-maven:4f726ce43075', '-c', 'cd /tmp && jar xf /platform.jar && java -cp "/tmp/BOOT-INF/classes:/tmp/BOOT-INF/lib/*" /receiver/ExportReceiver.java'],
            check=True, capture_output=True)
        return result.stdout

VERIFY = r'''
import io,json,joblib,numpy as np,pandas as pd
from pathlib import Path
from sklearn.metrics import accuracy_score,mean_squared_error
root=Path('/evidence')
state=json.loads((root/'deep-learning-acceptance.json').read_text())
results=[]
for case in state['cases']:
    stem=case['kind']+'-'+case['task']
    model=joblib.load(root/'weights'/(stem+'.pkl'))
    frame=pd.read_csv(root/'weights'/(stem+'.csv'))
    features=['age','income'] if case['task']=='classification' else ['age']
    predicted=model.predict(frame[features])
    np.testing.assert_allclose(predicted,frame['pred'],rtol=1e-5,atol=1e-5)
    metrics=case['evaluation']['metrics']
    if case['task']=='classification':
        metric=accuracy_score(frame['label'],predicted)
        np.testing.assert_allclose(metric,metrics['accuracy'],rtol=1e-6,atol=1e-6)
        np.testing.assert_allclose(model.predict_proba(frame[features])[:,1],frame['pred_prob'],rtol=1e-5,atol=1e-6)
    else:
        metric=float(np.sqrt(mean_squared_error(frame['income'],predicted)))
        np.testing.assert_allclose(metric,metrics['rmse'],rtol=1e-5,atol=1e-5)
    results.append({'kind':case['kind'],'task':case['task'],'reloadMatches':True,'reportMatches':True})
print(json.dumps(results))
'''

def main():
    state = json.loads(acceptance.EVIDENCE.read_text())
    if state.get('status') != 'PASSED' or not state.get('syntheticData'):
        raise RuntimeError('须先完成合成画布验收')
    token, _ = login('CLIENT')
    directory = acceptance.EVIDENCE.parent / 'weights'
    directory.mkdir(mode=0o700, exist_ok=True)
    exports = []
    for case in state['cases']:
        output = acceptance.get('/v1alpha1/data-compute/canvas/node/output', token,
                                canvasId=case['canvasId'], nodeId='train', runId=case['runId'])
        for item in output['encryptedOutputs']:
            if item['kind'] not in ('DATA', 'MODEL'):
                continue
            mine = acceptance.get('/v1alpha1/tee/exports/mine', token)
            view = next((v for v in mine['items'] if v['resultId'] == item['resultId']
                         and v['status'] == 'APPROVED' and v.get('canDownload')), None)
            if view is None:
                view = expect_ok('申请合成数据导出', '/v1alpha1/tee/exports', {
                    'contractVersion': CONTRACT, 'requestId': uuid4().hex, 'resultId': item['resultId'],
                    'recipientCertPem': pem_of(CENTER / 'tee/identity/client.crt'),
                    'exportUntil': utc_time(3600), 'purpose': '独立测试环境的合成权重重载与指标复算'}, token)
            approved = view if view['status'] == 'APPROVED' else _action(
                'center', token, view['exportId'], 'APPROVE', '专属测试环境的合成数据验收')
            if approved.get('status') != 'APPROVED':
                raise RuntimeError('合成数据导出尚未完成全部供数方审批')
            data = receive(token, item, view['exportId'])
            name = item['resultId'] + ('.pkl' if item['kind'] == 'MODEL' else '.csv')
            if len(data) == 0:
                raise RuntimeError('下载产物为空')
            suffix = '.pkl' if item['kind'] == 'MODEL' else '.csv'
            path = directory / (case['kind'] + '-' + case['task'] + suffix)
            path.write_bytes(data)
            path.chmod(0o600)
            exports.append({'kind': case['kind'], 'task': case['task'], 'objectKind': item['kind'],
                            'exportId': view['exportId'], 'downloadName': name, 'bytes': len(data),
                            'sha256': hashlib.sha256(data).hexdigest()})
    checked = subprocess.run(['docker', 'run', '--pull=never', '--rm', '--network', 'none',
                              '--cpus', '2', '--memory', '4g', '--read-only', '--tmpfs', '/tmp:rw,size=256m',
                              '-v', str(acceptance.EVIDENCE.parent) + ':/evidence:ro',
                              '-e', 'OPENBLAS_NUM_THREADS=1', '-e', 'OMP_NUM_THREADS=1',
                              '--entrypoint', 'python', 'data-sandbox-dl-runtime:20260907', '-c', VERIFY],
                             check=True, text=True, capture_output=True)
    result = {'status': 'PASSED', 'syntheticData': True, 'receiver': 'TeeInstitutionKey.decryptExport',
              'centerPlaintextDownload': False, 'downloads': exports,
              'verification': json.loads(checked.stdout)}
    (acceptance.EVIDENCE.parent / 'deep-learning-export-acceptance.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print('八个模型通过正式导出、独立进程权重重载和报告复算。', flush=True)

if __name__ == '__main__':
    main()
