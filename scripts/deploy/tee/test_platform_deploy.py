"""部署与契约验收的安全边界定向测试，不启动容器、不联网、不使用业务凭据。"""
import base64
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

import platform_deploy as deploy
import foundation
import key_adapter
import p5_runtime
import contract_acceptance as acceptance
import release_client


def quiet(function, *args):
    """新增子命令会向命令行打印反馈；测试只关心行为，不需要这些输出。"""
    with contextlib.redirect_stdout(io.StringIO()):
        return function(*args)


class IsolationTests(unittest.TestCase):
    def test_migrated_domain_and_routes_preserve_credentials(self):
        with tempfile.TemporaryDirectory() as folder:
            runtime = Path(folder)
            instance = runtime / 'client-a'
            (instance / 'kuscia/config').mkdir(parents=True)
            (instance / 'kuscia/config/kuscia.yaml').write_text('mode: autonomy\ndomainID: dev-gpu-a\n')
            credentials = instance / 'secretpad.env'
            credentials.write_text(
                'NODE_ID=old\nKUSCIA_API_ADDRESS=old:8083\n'
                'SECRETPAD_PASSWORD=keep-me\nMINIO_ROOT_USER=keep-user\n')
            with patch.object(deploy, 'ROOT', runtime), patch.object(deploy, 'RUNTIME', runtime):
                domain = deploy.domain_id('client-a')
                deploy.refresh_runtime_credentials('client-a', domain)
            values = dict(line.split('=', 1) for line in credentials.read_text().splitlines())
            self.assertEqual(domain, 'dev-gpu-a')
            self.assertEqual(values['NODE_ID'], 'dev-gpu-a')
            self.assertEqual(values['KUSCIA_API_ADDRESS'], 'data-sandbox-dev-client-a-kuscia:8083')
            self.assertEqual(values['KUSCIA_GW_ADDRESS'], 'data-sandbox-dev-client-a-kuscia:80')
            self.assertEqual(values['SECRETPAD_DATA_ASSETS_MINIO_ENDPOINT'],
                             'http://data-sandbox-dev-client-a-minio:9000')
            self.assertEqual(values['SECRETPAD_PASSWORD'], 'keep-me')
            self.assertEqual(values['MINIO_ROOT_USER'], 'keep-user')
            self.assertEqual(credentials.stat().st_mode & 0o777, 0o600)

    def test_invalid_migrated_domain_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            runtime = Path(folder)
            (runtime / 'center/kuscia/config').mkdir(parents=True)
            (runtime / 'center/kuscia/config/kuscia.yaml').write_text('domainID: ../escape\n')
            with patch.object(deploy, 'RUNTIME', runtime):
                with self.assertRaises(RuntimeError):
                    deploy.domain_id('center')

    def test_source_snapshot_links_cannot_write_back_or_escape(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            src = root / 'source'; src.mkdir()
            (src / 'file').write_text('original')
            (src / 'link').symlink_to('file')
            with patch.object(deploy, 'run', return_value='file\0link\0'):
                deploy.source_snapshot(src, root / 'copy')
            (root / 'copy/link').write_text('copy-only')
            self.assertEqual((src / 'file').read_text(), 'original')
            (root / 'outside').write_text('protected')
            (src / 'escape').symlink_to('../outside')
            with patch.object(deploy, 'run', return_value='escape\0'):
                with self.assertRaises(RuntimeError): deploy.source_snapshot(src, root / 'rejected')

    def test_atomic_rejects_escape_and_symlink(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'inside').mkdir()
            (root / 'inside/link').symlink_to(root / 'outside')
            with patch.object(deploy, 'ROOT', root / 'inside'):
                for file in [root / 'outside/file', root / 'inside/link/file']:
                    with self.assertRaises(RuntimeError): deploy.atomic(file, 'must-not-write')
                self.assertFalse((root / 'outside').exists())
                deploy.atomic(root / 'inside/ok', 'ok')
                self.assertEqual((root / 'inside/ok').stat().st_mode & 0o777, 0o600)

    def test_foreign_docker_resource_is_never_managed(self):
        result = subprocess.CompletedProcess([], 0, json.dumps([{'Config': {'Labels': {
            deploy.LABEL + 'dev': 'true', deploy.LABEL + 'dev-owner': 'collab',
            deploy.LABEL + 'dev-workspace': '/data/collab/Projects/gpu'}}}]), '')
        with patch.object(deploy.subprocess, 'run', return_value=result):
            with self.assertRaises(RuntimeError): deploy.managed('data-sandbox-dev-center-secretpad')

    def test_stopped_foreign_container_does_not_reserve_ports(self):
        def run(*args, **kwargs):
            if args[:3] == ('docker', 'ps', '-aq'): return 'foreign-id'
            return json.dumps([{'Name': '/foreign', 'HostConfig': {'PortBindings': {'80/tcp': [{'HostPort': '19688'}]}}, 'State': {'Running': False}}])
        with patch.object(deploy, 'run', side_effect=run):
            deploy.port_check('center')

    def test_digest_drift_blocks_image_use(self):
        with patch.object(deploy, 'manifest', return_value={'images': {'probe': {'ref': 'probe:fixed', 'id': 'sha256:old'}}}), patch.object(deploy, 'image_info', return_value={'Id': 'sha256:new'}):
            with self.assertRaises(RuntimeError): deploy.checked_image('probe')

    def test_platform_image_cannot_borrow_fresh_top_level_inputs(self):
        inputs = {'backend_runtime_content': 'backend-new', 'frontend_content': 'frontend-new',
                  'toolkit_content': 'toolkit-new'}
        manifest = dict(inputs, images={'platform': {
            'backend_runtime_content': 'backend-new', 'frontend_content': 'frontend-new',
            'toolkit_content': 'toolkit-old'}})
        self.assertFalse(deploy.platform_image_matches(manifest, inputs))
        manifest['images']['platform']['toolkit_content'] = 'toolkit-new'
        self.assertTrue(deploy.platform_image_matches(manifest, inputs))

    def test_platform_stamp_changes_with_toolkit_input(self):
        data = {'backend_runtime_content': 'b' * 64, 'frontend_content': 'f' * 64,
                'toolkit_content': 'a' * 64}
        first = deploy.platform_stamp(data)
        data['toolkit_content'] = 'c' * 64
        self.assertNotEqual(first, deploy.platform_stamp(data))

    def test_kubernetes_labels_and_host_mounts_are_scoped(self):
        for value in foundation.kube_labels().values():
            self.assertRegex(value, r'^[A-Za-z0-9]([A-Za-z0-9_.-]{0,61}[A-Za-z0-9])?$')
        volume, mount = foundation.host_volume('cert', 'cm-server-cert', '/cm-server')
        self.assertEqual(volume['hostPath']['path'], '/home/kuscia/tee/cm-server-cert')
        self.assertTrue(mount['readOnly'])
        self.assertEqual(foundation.GET_RA, '/secretflowapis.v2.sdc.capsule_manager.CapsuleManager/GetRaCert')

    def test_kubernetes_ownership_migration_requires_manifest_and_explicit_repair(self):
        legacy = '/data/collab/Projects/gpu-tee-dev-a'
        labels = {'tee.secretflow.dev/owner': 'collab',
                  'tee.secretflow.dev/workspace': hashlib.sha256(legacy.encode()).hexdigest()[:32]}
        with patch.object(foundation, 'manifest', return_value={
                'migratedFrom': {'workspace': legacy}}):
            self.assertFalse(foundation.kube_labels_owned_or_migrated(labels))
            self.assertTrue(foundation.kube_labels_owned_or_migrated(labels, True))
        with patch.object(foundation, 'manifest', return_value={}):
            self.assertFalse(foundation.kube_labels_owned_or_migrated(labels, True))

    def test_partial_ca_and_external_key_path_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            with patch.object(foundation, 'ROOT', root), patch.object(foundation, 'RUNTIME', root), \
                    patch.object(deploy, 'ROOT', root), patch.object(deploy, 'RUNTIME', root):
                ca = root / 'ca'; ca.mkdir(); (ca / 'ca.key').write_text('partial')
                with self.assertRaises(RuntimeError): foundation.make_ca(ca, 'test')
                link = root / 'link'; link.symlink_to(root.parent / 'deploy-escape')
                with patch.object(foundation, 'openssl') as openssl:
                    with self.assertRaises(RuntimeError): foundation.issue(ca, link, 'test')
                    openssl.assert_not_called()

    def test_certificate_replay_preserves_private_keys_and_crl_rejects_revocation(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            with patch.object(foundation, 'ROOT', root), patch.object(foundation, 'RUNTIME', root), \
                    patch.object(deploy, 'ROOT', root), patch.object(deploy, 'RUNTIME', root):
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
            prepared = list(deploy.INSTANCES)[0]
            (runtime / prepared / 'status').mkdir(parents=True)
            with patch.object(deploy, 'ROOT', runtime), patch.object(deploy, 'RUNTIME', runtime):
                quiet(deploy.refresh_detection)
                snapshot = json.loads((runtime / prepared / 'status/hardware.json').read_text())
                first = snapshot['checkedAt']
                self.assertEqual(set(snapshot['deviceChecks']), {'sgx', 'tdx', 'csv'})
                self.assertIs(snapshot['detectorOk'], True)
                for name in list(deploy.INSTANCES)[1:]:
                    self.assertFalse((runtime / name / 'status/hardware.json').exists())
                quiet(deploy.refresh_detection)
                self.assertNotEqual(json.loads(
                    (runtime / prepared / 'status/hardware.json').read_text())['checkedAt'], first)

    def test_refresh_snapshot_is_world_readable_but_not_writable(self):
        with tempfile.TemporaryDirectory() as folder:
            runtime = Path(folder)
            prepared = list(deploy.INSTANCES)[0]
            (runtime / prepared / 'status').mkdir(parents=True)
            with patch.object(deploy, 'ROOT', runtime), patch.object(deploy, 'RUNTIME', runtime):
                quiet(deploy.refresh_detection)
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

        with patch.object(deploy.subprocess, 'run', side_effect=fake):
            quiet(deploy.schedule_detection, remove)
        return written['payload']

    def test_install_keeps_unrelated_entries_and_is_idempotent(self):
        other = '0 3 * * * /usr/bin/other-job\n'
        once = self.crontab(other)
        self.assertIn('/usr/bin/other-job', once)
        self.assertEqual(once.count(deploy.CRON_MARK), 1)
        self.assertIn('refresh-detection --tee', once)
        twice = self.crontab(once)
        self.assertEqual(twice.count(deploy.CRON_MARK), 1)
        self.assertIn('/usr/bin/other-job', twice)

    def test_install_without_existing_crontab(self):
        payload = self.crontab(None)
        self.assertEqual(payload.count(deploy.CRON_MARK), 1)

    def test_remove_drops_only_its_own_entry(self):
        installed = self.crontab('0 3 * * * /usr/bin/other-job\n')
        payload = self.crontab(installed, remove=True)
        self.assertNotIn(deploy.CRON_MARK, payload)
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


class KeyAdapterTests(unittest.TestCase):
    """适配服务是三条底座不校验边界的第二道拦截，空集合与通配符必须在此再拒一次。"""

    def test_empty_and_wildcard_grant_sets_are_rejected(self):
        for values in ([], None, 'age'):
            with self.assertRaises(key_adapter.AdapterError) as raised:
                key_adapter.check_names(values, '列')
            self.assertEqual('POLICY_DENIED' if values in ([], None) else 'POLICY_DENIED',
                             raised.exception.code)
        with self.assertRaises(key_adapter.AdapterError) as raised:
            key_adapter.check_names(['age', '*'], '列')
        self.assertEqual('POLICY_DENIED', raised.exception.code)

    def test_blank_name_is_contract_invalid(self):
        with self.assertRaises(key_adapter.AdapterError) as raised:
            key_adapter.check_names(['age', '  '], '列')
        self.assertEqual('CONTRACT_INVALID', raised.exception.code)

    def test_valid_grant_set_passes(self):
        self.assertIsNone(key_adapter.check_names(['age', 'income'], '列'))

    def test_required_field_must_be_non_blank_string(self):
        for body in ({}, {'scope': ''}, {'scope': 3}):
            with self.assertRaises(key_adapter.AdapterError) as raised:
                key_adapter.require(body, 'scope')
            self.assertEqual('CONTRACT_INVALID', raised.exception.code)
        self.assertEqual('s1', key_adapter.require({'scope': 's1'}, 'scope'))

    def test_recipient_must_be_rsa_2048_or_stronger(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        import datetime as dt
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'ec-recipient')])
        now = dt.datetime.now(dt.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now).not_valid_after(now + dt.timedelta(days=1))
                .sign(key, hashes.SHA256()))
        with self.assertRaises(key_adapter.AdapterError) as raised:
            key_adapter.seal_to_recipient(base64.b64encode(b'k' * 32).decode(),
                                          cert.public_bytes(serialization.Encoding.PEM))
        self.assertEqual('CONTRACT_INVALID', raised.exception.code)


class AcceptanceFixtureTests(unittest.TestCase):
    """验收脚本写入平台库的合成审批必须能被原样删除，且时间取值不会立刻过期。"""

    def test_sql_literals_escape_quotes(self):
        self.assertEqual("'it''s'", acceptance.quote("it's"))

    def test_platform_time_is_naive_local_and_ahead(self):
        value = acceptance.platform_time(2)
        self.assertNotIn('+', value)
        self.assertGreater(value, acceptance.platform_time(0))

    def test_utc_time_is_rfc3339_zulu(self):
        self.assertTrue(acceptance.utc_time(60).endswith('Z'))

    def test_fixture_install_and_remove_are_symmetric(self):
        statements = []
        original = acceptance.sqlite
        acceptance.sqlite = lambda instance, script: statements.append((instance, script))
        try:
            fixture = acceptance.install_approval('center', 'inst-a', 'asset-1',
                                              ['age'], ['ml.xgboost'])
            acceptance.remove_approval(fixture)
        finally:
            acceptance.sqlite = original
        inserted = ' '.join(statements[0][1])
        deleted = ' '.join(statements[1][1])
        for table in ('ds_sandbox', 'ds_sandbox_approval', 'ds_sandbox_dataset_mount',
                      'ds_sandbox_mount_control'):
            self.assertIn(table, inserted)
            self.assertIn(table, deleted)
        # 合成沙箱不参与调度：无 Kuscia Job、资源为零、状态为 STOPPED。
        self.assertIn("'STOPPED'", inserted)
        self.assertIn("'COMPLETED'", inserted)


class IdentityPublishTests(unittest.TestCase):
    """机构条目只有平台起来后才能取到；重新发布不得把它们抹掉。"""

    def test_existing_owner_entries_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            names = list(foundation.INSTANCES)
            for name in names:
                target = root / name / 'identity-pub'
                target.mkdir(parents=True)
                (target / 'registry.json').write_text(json.dumps({
                    'taskSigningCertificates': {},
                    name: {'certificateSha256': 'aa'},
                    'ownerof' + name: {'certificateSha256': 'aa', 'instance': name}}))
            with patch.object(foundation, 'RUNTIME', root):
                entries = foundation.published_owner_entries()
        for name in names:
            self.assertIn('ownerof' + name, entries)
        self.assertNotIn(names[0], entries)

    def test_entries_without_known_instance_are_ignored(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            name = list(foundation.INSTANCES)[0]
            target = root / name / 'identity-pub'
            target.mkdir(parents=True)
            (target / 'registry.json').write_text(json.dumps({
                'stray': {'certificateSha256': 'aa', 'instance': 'not-an-instance'}}))
            with patch.object(foundation, 'RUNTIME', root):
                self.assertEqual({}, foundation.published_owner_entries())

    def test_owner_map_is_the_source_of_truth_for_aliases(self):
        with tempfile.TemporaryDirectory() as directory:
            center = Path(directory) / 'center'
            center.mkdir()
            # atomic 只允许写隔离工作树内，测试目录同时替换 ROOT 才能落盘。
            with patch.object(deploy, 'ROOT', Path(directory)), \
                    patch.object(foundation, 'OWNER_MAP', center / 'owner-map.json'):
                names = list(foundation.INSTANCES)
                foundation.save_owner_map({names[0]: 'ownera'})
                self.assertEqual({names[0]: 'ownera'}, foundation.owner_map())
                # 重复保存同一映射是幂等的，映射变化则拒绝覆盖既有机构身份。
                foundation.save_owner_map({names[0]: 'ownera'})
                with self.assertRaises(RuntimeError):
                    foundation.save_owner_map({names[0]: 'someone-else'})

    def test_owner_map_ignores_unknown_instances(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / 'owner-map.json'
            file.write_text(json.dumps({'not-an-instance': 'x', list(foundation.INSTANCES)[0]: 'ok'}))
            with patch.object(foundation, 'OWNER_MAP', file):
                self.assertEqual({list(foundation.INSTANCES)[0]: 'ok'}, foundation.owner_map())

    def test_legacy_identity_names_keep_certificate_and_owner(self):
        current = {
            'center': {'certificateSha256': 'center-cert', 'certificatePath': 'center/new'},
            'client-a': {'certificateSha256': 'a-cert', 'certificatePath': 'client-a/new'},
            'client-b': {'certificateSha256': 'b-cert', 'certificatePath': 'client-b/new'},
        }
        legacy = {
            'tee-a-center': {'certificateSha256': 'center-cert', 'certificatePath': 'old/center'},
            'tee-a-client-1': {'certificateSha256': 'a-cert', 'certificatePath': 'old/a'},
            'tee-a-client-2': {'certificateSha256': 'b-cert', 'certificatePath': 'old/b'},
        }
        self.assertTrue(foundation.identity_registry_matches(legacy, current))
        legacy['tee-a-client-2']['certificateSha256'] = 'changed'
        self.assertFalse(foundation.identity_registry_matches(legacy, current))
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / 'owner-map.json'
            file.write_text(json.dumps({'tee-a-center': 'owner-center',
                                        'tee-a-client-1': 'owner-a',
                                        'tee-a-client-2': 'owner-b'}))
            with patch.object(foundation, 'OWNER_MAP', file):
                self.assertEqual({'center': 'owner-center', 'client-a': 'owner-a',
                                  'client-b': 'owner-b'}, foundation.owner_map())

    def test_legacy_owner_map_switches_clients_once_but_keeps_center(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            file = root / 'owner-map.json'
            file.write_text(json.dumps({'tee-a-center': 'center-old',
                                        'tee-a-client-1': 'synthetic-a',
                                        'tee-a-client-2': 'synthetic-b'}))
            migrated = {'center': 'center-old', 'client-a': 'real-a', 'client-b': 'real-b'}
            with patch.object(deploy, 'ROOT', root), patch.object(foundation, 'OWNER_MAP', file):
                self.assertEqual(migrated, foundation.save_owner_map(migrated))
                self.assertEqual(migrated, json.loads(file.read_text()))
                with self.assertRaises(RuntimeError):
                    foundation.save_owner_map(dict(migrated, **{'client-a': 'changed'}))

    def test_legacy_owner_map_cannot_replace_center(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            file = root / 'owner-map.json'
            file.write_text(json.dumps({'tee-a-center': 'center-old',
                                        'tee-a-client-1': 'synthetic-a',
                                        'tee-a-client-2': 'synthetic-b'}))
            with patch.object(deploy, 'ROOT', root), patch.object(foundation, 'OWNER_MAP', file):
                with self.assertRaises(RuntimeError):
                    foundation.save_owner_map({'center': 'center-new', 'client-a': 'real-a',
                                               'client-b': 'real-b'})

    def test_runtime_image_digests_come_from_locked_manifest(self):
        with patch.object(foundation, 'manifest', lambda: {'images': {
                'teeapps': {'id': 'sha256:aa'}, 'probe': {'id': 'sha256:bb'},
                'mysql': {'id': 'sha256:cc'}}}):
            self.assertEqual(['sha256:aa', 'sha256:bb'], foundation.runtime_image_digests())

    def test_runtime_contract_identity_is_center_only(self):
        with tempfile.TemporaryDirectory() as directory:
            center = Path(directory) / 'center/tee'
            certificate = center / 'runtime-contract-client/client.crt'
            certificate.parent.mkdir(parents=True)
            certificate.write_text('certificate')
            with patch.object(foundation, 'CENTER', center), \
                    patch.object(foundation, 'owner_map', lambda: {'center': 'inst-center'}), \
                    patch.object(foundation.subprocess, 'check_output', return_value=b'runtime-der'):
                entries = foundation.runtime_contract_certificates()
            self.assertEqual({'inst-center'}, set(entries.values()))
            self.assertEqual(64, len(next(iter(entries))))



class CrossInstanceChannelTests(unittest.TestCase):
    """平台间契约通道的部署配置：身份登记、端口占用与容器挂载。"""

    def test_only_registered_instances_get_a_contract_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory)
            certificates = {}
            for name in deploy.INSTANCES:
                target = runtime / name / 'tee/contract-client'
                target.mkdir(parents=True)
                (target / 'client.crt').write_bytes(b'cert-' + name.encode())
                certificates[name] = b'der-' + name.encode()

            def der(command):
                for name in deploy.INSTANCES:
                    if name in ' '.join(str(item) for item in command):
                        return certificates[name]
                raise AssertionError('未知证书路径')

            owners = {'center': 'inst-center', 'client-a': 'inst-client-1'}
            with patch.object(foundation, 'RUNTIME', runtime), \
                    patch.object(foundation.subprocess, 'check_output', side_effect=der), \
                    patch.object(foundation, 'owner_map', lambda: {}):
                entries = foundation.contract_client_certificates(owners)
            # 没有机构标识的实例不进登记：证书通过 CA 校验也不会自动获得机构身份。
            self.assertEqual(2, len(entries))
            self.assertEqual({'inst-center', 'inst-client-1'}, set(entries.values()))
            for fingerprint in entries:
                self.assertEqual(64, len(fingerprint))

    def test_contract_port_is_reserved_on_the_center(self):
        def run(*args, **kwargs):
            if args[:3] == ('docker', 'ps', '-aq'):
                return 'foreign-id'
            return json.dumps([{'Name': '/foreign', 'HostConfig': {'PortBindings': {
                '8443/tcp': [{'HostPort': str(deploy.CONTRACT_PORT)}]}}, 'State': {'Running': False}}])
        with patch.object(deploy, 'run', side_effect=run):
            deploy.port_check('center')

    def test_contract_server_certificate_covers_the_published_address(self):
        names = foundation.subject_alt_names(foundation.CONTRACT_SERVER_CN, True)
        self.assertIn('IP:222.20.99.38', names)
        # 客户端证书不追加可路由地址，避免把入口地址写进调用方身份。
        self.assertEqual('', foundation.subject_alt_names('contract-client-a', False))

    def test_only_the_center_publishes_the_contract_entry(self):
        source = Path(deploy.__file__).read_text()
        self.assertIn("TEE_CONTRACT_PORT_ARGS='-p 19686:8443' if name == 'center' else ''", source)
        self.assertIn("TEE_CONTRACT_CENTER_URL='' if name == 'center' else CONTRACT_CENTER_URL", source)
        # 三个实例都要挂载本机构私钥与调用方证书，中心端另挂服务端证书。
        for mount in ['/app/tee-contract-client:ro', '/app/tee-identity-key:ro',
                      '${TEE_CONTRACT_SERVER_MOUNT:-}']:
            self.assertIn(mount, source)

    def test_isolation_allows_only_explicit_read_only_identity_mounts(self):
        source = Path(acceptance.__file__).with_name('verification.py').read_text()
        for destination in ['/app/tee-adapter-client', '/app/tee-contract-client',
                            '/app/tee-identity-key', '/app/tee-contract-server']:
            self.assertIn(destination, source)
        self.assertIn("if mount.get('RW') or mount.get('Destination') not in allowed_identity_mounts", source)

    def test_p5_identity_directory_remains_traversable(self):
        source = Path(p5_runtime.__file__).read_text()
        self.assertIn("runtime-contract-client/client.crt", source)
        self.assertIn("runtime-contract-client/client.key", source)
        self.assertIn('chmod 700 "$d" "$d/trust"', source)
        self.assertIn('stat -f -c %T /dev/shm', source)
        self.assertIn('chmod o+rx / /usr /usr/local /usr/lib /usr/lib64 /opt /opt/java /opt/data-sandbox; chmod -R o+rX /usr/local /usr/lib /usr/lib64 /opt/java/openjdk /opt/data-sandbox', source)
        self.assertNotIn('chmod 600 "$d"/* "$d/trust/center-1.pem"', source)
        # This Kuscia AppImage CRD does not expose Pod volumes. The runtime
        # deliberately uses the OCI-provided /dev/shm tmpfs instead.
        self.assertNotIn("'volumeMounts'", source)
        self.assertNotIn("['spec']['volumes']", source)


class ToolkitIntegrationTests(unittest.TestCase):
    """主工作区直接读取共享工具链，并以摘要发现并发变化。"""

    @contextlib.contextmanager
    def workspace(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shared = root / 'shared'
            for name in deploy.TOOLKIT_INPUTS:
                file = shared / name
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text('原始 ' + name + '\n')
            with patch.object(deploy, 'ROOT', root), patch.object(deploy, 'TOOLKIT', shared), \
                    patch.object(deploy, 'CACHE', root / 'cache'), \
                    patch.object(deploy, 'TOOLKIT_PIN', root / 'cache/toolkit-pin'):
                yield shared

    def test_shared_changes_are_visible_to_the_digest(self):
        with self.workspace() as shared:
            before = deploy.toolkit_digest()
            (shared / 'develop.sh').write_text('他人改动\n')
            self.assertNotEqual(before, deploy.toolkit_digest())
            self.assertEqual(deploy.shared_toolkit_digest(), deploy.toolkit_digest())

    def test_sync_is_a_read_only_compatibility_command(self):
        with self.workspace() as shared:
            before = {name: (shared / name).read_bytes() for name in deploy.TOOLKIT_INPUTS}
            quiet(deploy.sync_toolkit)
            self.assertEqual(deploy.shared_toolkit_digest(), deploy.toolkit_digest())
            for name, content in before.items():
                self.assertEqual(content, (shared / name).read_bytes())

    def test_toolkit_source_is_always_the_shared_worktree(self):
        with self.workspace() as shared:
            self.assertEqual(shared, deploy.toolkit_source())
            self.assertFalse((deploy.TOOLKIT_PIN / 'pin.json').exists())

    def test_runner_digest_ignores_generated_bytecode(self):
        with self.workspace() as shared:
            runner = shared / deploy.TOOLKIT_DIR_INPUTS[0]
            runner.mkdir(parents=True)
            (runner / 'start.py').write_text('print("ok")\n')
            before = deploy.toolkit_digest()
            generated = runner / '__pycache__'; generated.mkdir()
            (generated / 'start.cpython-310.pyc').write_bytes(b'generated')
            self.assertEqual(before, deploy.toolkit_digest())

if __name__ == '__main__':
    os.umask(0o077)
    unittest.main()
