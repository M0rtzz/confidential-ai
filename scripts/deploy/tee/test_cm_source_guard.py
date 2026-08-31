import json
from pathlib import Path
import subprocess
import sys
import unittest

from cm_source_guard import EXPECTED_METHODS, validate_dispatch


SOURCE_PATH = Path(__file__).with_name("cm-audit-source") / "server.rs"
if not SOURCE_PATH.exists():
    SOURCE_PATH = Path(__file__).resolve().parents[3] / ".cache/tee-p3/sources/capsule/capsule-manager/src/server.rs"


class CMSourceGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SOURCE_PATH.read_text(encoding="utf-8")

    def repaired_source(self):
        old = "        self.delete_data_policy(request).await"
        new = "        self.delete_data_policy_impl(request).await"
        self.assertEqual(self.source.count(old), 1)
        return self.source.replace(old, new)

    def test_original_fixture_is_rejected_for_recursive_dispatch(self):
        result = validate_dispatch(self.source)
        self.assertFalse(result["ok"])
        self.assertEqual(result["interface_count"], 12)
        self.assertIn("delete_data_policy", " ".join(result["errors"]))

    def test_one_line_repair_passes_and_reports_the_contract(self):
        result = validate_dispatch(self.repaired_source())
        self.assertTrue(result["ok"], result["errors"])
        self.assertEqual(result["interface_names"], list(EXPECTED_METHODS))
        self.assertEqual(result["trait_methods"], result["impl_methods"])
        self.assertEqual(result["trait_method_count"], 12)
        self.assertEqual(result["impl_method_count"], 12)
        json.dumps(result)

    def test_missing_impl_method_is_rejected(self):
        method = """    async fn delete_data_rule(
        &self,
        request: &capsule_manager::EncryptedRequest,
    ) -> AuthResult<capsule_manager::EncryptedResponse> {
        self.delete_data_rule_impl(request).await
    }

"""
        source = self.repaired_source()
        self.assertEqual(source.count(method), 1)
        result = validate_dispatch(source.replace(method, ""))
        self.assertFalse(result["ok"])
        self.assertIn("固定 CM 契约", " ".join(result["errors"]))

    def test_duplicate_impl_method_is_rejected(self):
        method = """    async fn delete_data_rule(
        &self,
        request: &capsule_manager::EncryptedRequest,
    ) -> AuthResult<capsule_manager::EncryptedResponse> {
        self.delete_data_rule_impl(request).await
    }

"""
        source = self.repaired_source()
        insertion = source.rfind("\n}")
        result = validate_dispatch(source[:insertion] + "\n" + method + source[insertion:])
        self.assertFalse(result["ok"])
        self.assertIn("重复", " ".join(result["errors"]))

    def test_wrong_other_impl_and_recursive_dispatch_are_rejected(self):
        source = self.repaired_source().replace(
            "self.delete_data_policy_impl(request).await",
            "self.delete_data_rule_impl(request).await",
        )
        result = validate_dispatch(source)
        self.assertFalse(result["ok"])
        self.assertIn("delete_data_policy", " ".join(result["errors"]))

        recursive = self.repaired_source().replace(
            "self.delete_data_policy_impl(request).await",
            "self.delete_data_policy(request).await",
        )
        self.assertFalse(validate_dispatch(recursive)["ok"])

    def test_comments_and_whitespace_are_ignored_without_broad_string_matching(self):
        source = self.repaired_source().replace(
            "self.delete_data_policy_impl(request).await",
            "self /* async fn fake() {} */ . delete_data_policy_impl( /* fake */ request ) . await",
        )
        source += "\n/* impl CapsuleManagerService for CapsuleManagerImpl { async fn fake() {} } */\n"
        result = validate_dispatch(source)
        self.assertTrue(result["ok"], result["errors"])

    def test_parse_failure_is_fail_closed(self):
        result = validate_dispatch(self.repaired_source() + "\n/* unterminated")
        self.assertFalse(result["ok"])
        self.assertTrue(any("解析失败" in error for error in result["errors"]))

    def test_cli_returns_json_and_nonzero_for_original_fixture(self):
        completed = subprocess.run(
            [sys.executable, str(Path(__file__).with_name("cm_source_guard.py")), str(SOURCE_PATH)],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 1)
        result = json.loads(completed.stdout)
        self.assertFalse(result["ok"])


if __name__ == "__main__":
    unittest.main()
