-- 树报告与显式历史授权；原训练和密文对象不改写。
CREATE TABLE IF NOT EXISTS ds_model_tree_report (
 id TEXT PRIMARY KEY, model_object_id TEXT NOT NULL, tree_index INTEGER NOT NULL,
 policy_fingerprint TEXT NOT NULL, task_id TEXT NOT NULL, status TEXT NOT NULL,
 content_json TEXT, error_message TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_model_tree_report_object ON ds_model_tree_report(model_object_id,tree_index);
CREATE TABLE IF NOT EXISTS ds_model_report_grant (
 id TEXT PRIMARY KEY, model_object_id TEXT NOT NULL, source_policy_id TEXT NOT NULL,
 source_policy_version TEXT NOT NULL, owner_id TEXT NOT NULL, status TEXT NOT NULL,
 expires_at TEXT NOT NULL, authorization_basis TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ds_model_report_setting (id TEXT PRIMARY KEY, value TEXT NOT NULL);
INSERT OR IGNORE INTO ds_model_report_setting(id,value)
 VALUES('standard_reports_since',strftime('%Y-%m-%dT%H:%M:%fZ','now'));
