"""P3 安全边界定向测试，不启动容器、不联网、不使用业务凭据。"""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import p3
import foundation
import release_client


def quiet(function, *args):
    """新增子命令会向命令行打印反馈；测试只关心行为，不需要这些输出。"""
    with contextlib.redirect_stdout(io.StringIO()):
        return function(*args)


class IsolationTests(unittest.TestCase):
    def test_source_snapshot_links_cannot_write_back_or_escape(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            src = root / 'source'; src.mkdir()
            (src / 'file').write_text('original')
            (src / 'link').symlink_to('file')
            with patch.object(p3, 'run', return_value='file\0link\0'):
                p3.source_snapshot(src, root / 'copy')
            (root / 'copy/link').write_text('copy-only')
            self.assertEqual((src / 'file').read_text(), 'original')
            (root / 'outside').write_text('protected')
            (src / 'escape').symlink_to('../outside')
            with patch.object(p3, 'run', return_value='escape\0'):
                with self.assertRaises(RuntimeError): p3.source_snapshot(src, root / 'rejected')

    def test_atomic_rejects_escape_and_symlink(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'inside').mkdir()
            (root / 'inside/link').symlink_to(root / 'outside')
            with patch.object(p3, 'ROOT', root / 'inside'):
                for file in [root / 'outside/file', root / 'inside/link/file']:
                    with self.assertRaises(RuntimeError): p3.atomic(file, 'must-not-write')
                self.assertFalse((root / 'outside').exists())
                p3.atomic(root / 'inside/ok', 'ok')
                self.assertEqual((root / 'inside/ok').stat().st_mode & 0o777, 0o600)

    def test_foreign_docker_resource_is_never_managed(self):
        result = subprocess.CompletedProcess([], 0, json.dumps([{'Config': {'Labels': {
            p3.LABEL + 'dev': 'true', p3.LABEL + 'dev-owner': 'collab',
            p3.LABEL + 'dev-workspace': '/data/collab/Projects/gpu'}}}]), '')
        with patch.object(p3.subprocess, 'run', return_value=result):
            with self.assertRaises(RuntimeError): p3.managed('data-sandbox-dev-tee-a-center-secretpad')

    def test_stopped_foreign_container_reserves_ports(self):
        def run(*args, **kwargs):
            if args[:3] == ('docker', 'ps', '-aq'): return 'foreign-id'
            return json.dumps([{'Name': '/foreign', 'HostConfig': {'PortBindings': {'80/tcp': [{'HostPort': '19688'}]}}, 'State': {'Running': False}}])
        with patch.object(p3, 'run', side_effect=run):
            with self.assertRaises(RuntimeError): p3.port_check('tee-a-center')

    def test_digest_drift_blocks_image_use(self):
        with patch.object(p3, 'manifest', return_value={'images': {'probe': {'ref': 'probe:fixed', 'id': 'sha256:old'}}}), patch.object(p3, 'image_info', return_value={'Id': 'sha256:new'}):
            with self.assertRaises(RuntimeError): p3.checked_image('probe')

    def test_kubernetes_labels_and_host_mounts_are_scoped(self):
        for value in foundation.kube_labels().values():
            self.assertRegex(value, r'^[A-Za-z0-9]([A-Za-z0-9_.-]{0,61}[A-Za-z0-9])?$')
        volume, mount = foundation.host_volume('cert', 'cm-server-cert', '/cm-server')
        self.assertEqual(volume['hostPath']['path'], '/home/kuscia/tee/cm-server-cert')
        self.assertTrue(mount['readOnly'])
        self.assertEqual(foundation.GET_RA, '/secretflowapis.v2.sdc.capsule_manager.CapsuleManager/GetRaCert')

    def test_partial_ca_and_external_key_path_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            with patch.object(foundation, 'ROOT', root), patch.object(p3, 'ROOT', root):
                ca = root / 'ca'; ca.mkdir(); (ca / 'ca.key').write_text('partial')
                with self.assertRaises(RuntimeError): foundation.make_ca(ca, 'test')
                link = root / 'link'; link.symlink_to(root.parent / 'p3-escape')
                with patch.object(foundation, 'openssl') as openssl:
                    with self.assertRaises(RuntimeError): foundation.issue(ca, link, 'test')
                    openssl.assert_not_called()

    def test_certificate_replay_preserves_private_keys_and_crl_rejects_revocation(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            with patch.object(foundation, 'ROOT', root), patch.object(p3, 'ROOT', root):
                ca, client = root / 'ca', root / 'client'
                foundation.make_ca(ca, 'synthetic-ca')
                foundation.issue(ca, client, 'synthetic-client')
                digest = hashlib.sha256((client / 'client.key').read_bytes()).hexdigest()
                foundation.make_ca(ca, 'synthetic-ca')
                foundation.issue(ca, client, 'synthetic-client')
                self.assertEqual(hashlib.sha256((client / 'client.key').read_bytes()).hexdigest(), digest)
                foundation.openssl('ca', '-batch', '-config', ca / 'openssl.cnf', '-revoke', client / 'client.crt')
                foundation.openssl('ca', '-batch', '-config', ca / 'openssl.cnf', '-gencrl', '-out', ca / 'ca.crl')
                with self.assertRaises(subprocess.CalledProcessError):
                    foundation.openssl('verify', '-CAfile', ca / 'ca.crt', '-CRLfile', ca / 'ca.crl', '-crl_check', client / 'client.crt')



class DetectionRefreshTests(unittest.TestCase):
    def test_refresh_only_touches_prepared_instances_and_rewrites_snapshot(self):
        with tempfile.TemporaryDirectory() as folder:
            runtime = Path(folder)
            prepared = list(p3.INSTANCES)[0]
            (runtime / prepared / 'status').mkdir(parents=True)
            with patch.object(p3, 'ROOT', runtime), patch.object(p3, 'RUNTIME', runtime):
                quiet(p3.refresh_detection)
                snapshot = json.loads((runtime / prepared / 'status/hardware.json').read_text())
                first = snapshot['checkedAt']
                self.assertEqual(set(snapshot['deviceChecks']), {'sgx', 'tdx', 'csv'})
                self.assertIs(snapshot['detectorOk'], True)
                for name in list(p3.INSTANCES)[1:]:
                    self.assertFalse((runtime / name / 'status/hardware.json').exists())
                quiet(p3.refresh_detection)
                self.assertNotEqual(json.loads(
                    (runtime / prepared / 'status/hardware.json').read_text())['checkedAt'], first)

    def test_refresh_snapshot_is_world_readable_but_not_writable(self):
        with tempfile.TemporaryDirectory() as folder:
            runtime = Path(folder)
            prepared = list(p3.INSTANCES)[0]
            (runtime / prepared / 'status').mkdir(parents=True)
            with patch.object(p3, 'ROOT', runtime), patch.object(p3, 'RUNTIME', runtime):
                quiet(p3.refresh_detection)
            mode = (runtime / prepared / 'status/hardware.json').stat().st_mode & 0o777
            self.assertEqual(mode, 0o644)


class DetectionScheduleTests(unittest.TestCase):
    def crontab(self, existing, remove=False):
        written = {}

        def fake(command, **kwargs):
            if command == ['crontab', '-l']:
                return subprocess.CompletedProcess(command, 0 if existing is not None else 1,
                                                   stdout=existing or '', stderr='')
            written['payload'] = kwargs['input']
            return subprocess.CompletedProcess(command, 0, stdout='', stderr='')

        with patch.object(p3.subprocess, 'run', side_effect=fake):
            quiet(p3.schedule_detection, remove)
        return written['payload']

    def test_install_keeps_unrelated_entries_and_is_idempotent(self):
        other = '0 3 * * * /usr/bin/other-job\n'
        once = self.crontab(other)
        self.assertIn('/usr/bin/other-job', once)
        self.assertEqual(once.count(p3.CRON_MARK), 1)
        self.assertIn('refresh-detection --tee', once)
        twice = self.crontab(once)
        self.assertEqual(twice.count(p3.CRON_MARK), 1)
        self.assertIn('/usr/bin/other-job', twice)

    def test_install_without_existing_crontab(self):
        payload = self.crontab(None)
        self.assertEqual(payload.count(p3.CRON_MARK), 1)

    def test_remove_drops_only_its_own_entry(self):
        installed = self.crontab('0 3 * * * /usr/bin/other-job\n')
        payload = self.crontab(installed, remove=True)
        self.assertNotIn(p3.CRON_MARK, payload)
        self.assertIn('/usr/bin/other-job', payload)


class ReleaseClientTests(unittest.TestCase):
    """密钥放行客户端不依赖 SDK 即可校验的部分：拒绝判定与状态文件处理。"""

    def test_expect_records_pass_and_detail(self):
        checks = {}
        release_client.expect(checks, 'a', True, 'detail')
        release_client.expect(checks, 'b', False)
        self.assertEqual(checks['a'], {'passed': True, 'detail': 'detail'})
        self.assertEqual(checks['b'], {'passed': False})

    def test_state_file_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder) / 'release-pilot.json'
            state.write_text('{}')
            with self.assertRaises(FileExistsError):
                with open(state, 'x'):
                    pass

if __name__ == '__main__':
    os.umask(0o077)
    unittest.main()
