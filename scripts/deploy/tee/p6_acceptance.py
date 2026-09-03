#!/usr/bin/env python3
"""通过平台四类入口完成 P6 真实验收，并保存可复核证据。"""
import base64
import hashlib
import json
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote as urlquote
from uuid import uuid4

from contract_acceptance import (CONTRACT, CENTER, Failure, cleanup_run_objects,
                                 expect_ok, install_approval,
                                 login, pem_of, platform_time, quote, remove_approval,
                                 request, sqlite, unwrap, utc_time)
from p5_acceptance import (ALL_COLUMNS, GRANTED_COLUMNS, current_encrypt,
                           decode_jws)
from platform_deploy import atomic, manifest


KUSCIA = "data-sandbox-dev-center-kuscia"
SECRETPAD = "data-sandbox-dev-center-secretpad"
SOURCE_TABLE = "p6_input"
SAMPLE_CSV = """age,income,label,city,private_note
31,42000,0,hangzhou,private-a
45,88000,1,shanghai,private-b
27,31000,0,wuhan,private-c
52,99000,1,beijing,private-d
"""
OPERATORS = ["sql.query", "python.execute", "jar.execute", "preprocessing.standardize"]
TERMINAL = {"SUCCEEDED", "FAILED", "CANCELLED"}


def scalar(statement):
    result = subprocess.run(
        ["docker", "exec", "-i", SECRETPAD, "sqlite3", "/app/db/secretpad.sqlite"],
        input=(".timeout 8000\n" + statement + "\n").encode(), check=True,
        stdout=subprocess.PIPE).stdout.decode().strip()
    return result


def task_row(task_id):
    raw = scalar(
        "select json_object('id',id,'status',status,'jobId',kuscia_job_id,"
        "'jws',tee_task_jws,'requestId',tee_request_id,'nonce',tee_nonce,"
        "'dispatchStatus',tee_dispatch_status,'preview',result_preview,"
        "'error',error_message,'retryCount',retry_count) from ds_dev_task where id="
        + quote(task_id) + ";")
    if not raw:
        raise Failure("P6 平台任务记录不存在")
    return json.loads(raw)


def wait_task(task_id, expected="SUCCEEDED", timeout=600):
    deadline = time.monotonic() + timeout
    row = task_row(task_id)
    while row["status"] not in TERMINAL and time.monotonic() < deadline:
        time.sleep(2)
        row = task_row(task_id)
    if row["status"] != expected:
        raise Failure(f"P6 任务 {task_id} 期望 {expected}，实际 {row['status']}：{row['error']}")
    return row


def kube_job(job_id):
    output = subprocess.run(
        ["docker", "exec", KUSCIA, "kubectl", "get", "kusciajobs", "-A", "-o", "json"],
        check=True, text=True,
        stdout=subprocess.PIPE).stdout
    matches = [item for item in json.loads(output).get("items", [])
               if item.get("metadata", {}).get("name") == job_id]
    if len(matches) != 1:
        raise Failure("P6 Kuscia Job 不存在或不唯一：" + job_id)
    return matches[0]


def receipt(task_id):
    raw = scalar("select receipt_jws from tee_runtime_task where task_id=" + quote(task_id)
                 + " and receipt_verified=1;")
    if not raw:
        raise Failure("P6 任务缺少已验签回执")
    return decode_jws(raw)


def parse_instant(value):
    normalized = re.sub(r"(\.\d{6})\d+(?=Z|[+-]\d\d:\d\d$)", r"\1", value)
    return datetime.fromisoformat(normalized.replace("Z", "+00:00"))


def validate_task(label, row, expected_kind, expected_operator):
    if not row["jobId"] or not row["jws"]:
        raise Failure(label + " 未保存 Kuscia Job 或 JWS")
    job = row.get("capturedJob") or kube_job(row["jobId"])
    tasks = job.get("spec", {}).get("tasks", [])
    if len(tasks) != 1:
        raise Failure(label + " 未保持一任务一 Job")
    config = tasks[0].get("taskInputConfig")
    if isinstance(config, str):
        config = json.loads(config)
    if not isinstance(config, dict) or set(config) != {"tee_task_jws"}:
        raise Failure(label + " Job 输入字段不唯一")
    compact = config["tee_task_jws"]
    if compact != row["jws"] or any(value in compact for value in
                                     ("input_csv_b64", "sandbox_db_b64", "private-a")):
        raise Failure(label + " Job 含明文输入或 JWS 绑定不一致")
    parts = compact.split(".")
    if len(parts) != 3 or any("=" in part for part in parts):
        raise Failure(label + " 不是无填充 Compact JWS")
    header = json.loads(base64.urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4)))
    payload = decode_jws(compact)
    if header.get("alg") != "RS256" or header.get("typ") != "JWS":
        raise Failure(label + " JWS 头不符合冻结契约")
    if payload.get("program", {}).get("kind") != expected_kind \
            or payload.get("operatorId") != expected_operator:
        raise Failure(label + " 程序类型或算子绑定不符")
    issued = parse_instant(payload["issuedAt"])
    expires = parse_instant(payload["expiresAt"])
    if not 0 < (expires - issued).total_seconds() <= 300:
        raise Failure(label + " 任务有效期超出 5 分钟")
    if payload.get("columns") != GRANTED_COLUMNS or len(payload.get("inputs", [])) != 1:
        raise Failure(label + " 输入列或密文资产绑定不符")
    if payload.get("runtimeImageDigest") != manifest()["images"]["runtime"]["id"]:
        raise Failure(label + " 运行镜像摘要漂移")
    program = payload["program"]
    if expected_kind != "BUILTIN":
        registered = scalar("select ciphertext_sha256 from tee_object where object_id="
                            + quote(program["objectId"]) + ";")
        if registered != program["sha256"]:
            raise Failure(label + " 程序对象摘要不一致")
    signed_receipt = receipt(row["id"])
    if signed_receipt.get("status") != "SUCCEEDED" \
            or signed_receipt.get("runtimeMode") != "SIMULATION" \
            or signed_receipt.get("attestationVerified") is not False:
        raise Failure(label + " 回执状态或 Simulation 边界不符")
    encrypted = [item for item in signed_receipt.get("outputs", [])
                 if item.get("kind") in ("DATA", "MODEL")]
    if not encrypted or any(item.get("encrypted") is not True
                            or item.get("exportState") != "PENDING_APPROVAL" for item in encrypted):
        raise Failure(label + " DATA/MODEL 未保持密文待审批")
    preview = json.loads(row.get("preview") or "{}")
    if preview.get("attestationVerified") is not False \
            or any(item.get("exportState") != "PENDING_APPROVAL"
                   for item in preview.get("encryptedOutputs", [])):
        raise Failure(label + " 平台结果映射不符合密文输出约束")
    return {"taskId": row["id"], "jobId": row["jobId"],
            "requestId": payload["requestId"], "nonce": payload["nonce"],
            "jwsSha256": hashlib.sha256(compact.encode()).hexdigest(),
            "program": program, "operatorId": payload["operatorId"],
            "columns": payload["columns"], "input": payload["inputs"][0],
            "outputPolicy": payload["outputPolicy"],
            "jobInputKeys": sorted(config), "receiptVerified": True,
            "runtimeMode": "SIMULATION", "attestationVerified": False,
            "encryptedOutputKinds": sorted(item["kind"] for item in encrypted),
            "legacyPlaintextFieldsPresent": False}


def submit_task(token, fixture, exec_type, **extra):
    payload = {"sandboxId": fixture["sandboxId"], "sourceTable": SOURCE_TABLE,
               "assetId": fixture["assetId"], "mountId": fixture["mountId"],
               "runMode": "DEV", "execType": exec_type,
               "name": "P6 " + exec_type + " 验收", "params": {}}
    payload.update(extra)
    data = expect_ok("P6 " + exec_type + " 提交", "/v1alpha1/data-dev/tasks/submit-sandbox",
                     payload, token)
    submitted = task_row(data["id"])
    job = kube_job(submitted["jobId"])
    completed = wait_task(data["id"])
    completed["capturedJob"] = job
    return completed


def build_jar():
    source = """import java.nio.file.*;public class P6Copy{public static void main(String[]a)throws Exception{Path i=null,o=null;for(int x=0;x<a.length-1;x++){if(a[x].equals(\"--input\"))i=Path.of(a[++x]);else if(a[x].equals(\"--output\"))o=Path.of(a[++x]);}if(i==null||o==null)throw new IllegalArgumentException();Files.copy(i,o);}}"""
    with tempfile.TemporaryDirectory(prefix="p6-jar-") as directory:
        root = Path(directory)
        (root / "P6Copy.java").write_text(source, encoding="utf-8")
        subprocess.run(["javac", "P6Copy.java"], cwd=root, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["jar", "--create", "--file", "p6.jar", "--main-class", "P6Copy",
                        "P6Copy.class"], cwd=root, check=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
        return base64.b64encode((root / "p6.jar").read_bytes()).decode()


def install_platform_fixture(owner, asset_id, fixture):
    project_id = "project-p6-" + uuid4().hex[:10]
    now = platform_time(0)
    platform_node = scalar("select node_id from node where inst_id=" + quote(owner)
                           + " and is_deleted=0 limit 1;")
    if not platform_node:
        raise Failure("P6 验收机构没有对应的平台节点")
    metadata = json.dumps({"encrypted": True, "plaintextBytes": len(SAMPLE_CSV.encode()),
                           "contentType": "text/csv"}, separators=(",", ":"))
    columns = json.dumps([{"name": item, "type": "string"} for item in ALL_COLUMNS],
                         separators=(",", ":"))
    sqlite("center", [
        "insert into project(project_id,name,compute_mode,compute_func,owner_id) values("
        f"{quote(project_id)},{quote('P6 验收项目')},'tee','ALL',{quote(owner)});",
        "insert into project_node(project_id,node_id,is_deleted) values("
        f"{quote(project_id)},{quote(platform_node)},0);",
        f"update ds_sandbox set project_id={quote(project_id)} where id={quote(fixture['sandboxId'])};",
        "insert into ds_data_asset(id,name,provider_node_id,processor_node_id,ingestion_type,modality,"
        "data_stage,source_asset_id,datatable_id,storage_uri,metadata_json,created_by,created_at,updated_at,"
        "version,status,deleted) values("
        f"{quote(asset_id)},{quote('P6 合成密文资产')},{quote(owner)},{quote(owner)},'UPLOAD','TABULAR',"
        f"'PROCESSED','',{quote(SOURCE_TABLE)},'',{quote(metadata)},'p6-acceptance',{quote(now)},"
        f"{quote(now)},1,'ACTIVE',0);",
        "insert into ds_sandbox_data_dir(id,sandbox_id,kind,asset_id,table_name,name,modality,row_count,"
        "columns_json,source,created_at,updated_at,deleted) values("
        f"{quote('dir-p6-' + uuid4().hex[:10])},{quote(fixture['sandboxId'])},'MOUNT',{quote(asset_id)},"
        f"{quote(SOURCE_TABLE)},{quote('P6 输入')},'TABULAR',4,{quote(columns)},'LOCAL',"
        f"{quote(now)},{quote(now)},0);"
    ])
    db_dir = CENTER / "secretpad/data/sandbox-db" / fixture["sandboxId"]
    db_dir.mkdir(parents=True, exist_ok=False)
    db_path = db_dir / "sandbox_data.db"
    connection = sqlite3.connect(db_path)
    try:
        connection.execute("create table p6_input(age text,income text,label text,city text,private_note text)")
        rows = [line.split(",") for line in SAMPLE_CSV.strip().splitlines()[1:]]
        connection.executemany("insert into p6_input values(?,?,?,?,?)", rows)
        connection.execute("create table _sandbox_manifest(table_name text primary key,asset_id text,"
                           "name text,kind text,source text,row_count integer)")
        connection.execute("insert into _sandbox_manifest values(?,?,?,?,?,?)",
                           (SOURCE_TABLE, asset_id, "P6 输入", "MOUNT", "LOCAL", len(rows)))
        connection.commit()
    finally:
        connection.close()
    fixture.update({"assetId": asset_id, "projectId": project_id, "dbDir": str(db_dir)})


def cleanup_platform_fixture(fixture):
    sandbox_id = fixture["sandboxId"]
    project_id = fixture.get("projectId", "")
    asset_id = fixture.get("assetId", "")
    sqlite("center", [
        "delete from ds_compute_node_run where sandbox_id=" + quote(sandbox_id) + ";",
        "delete from ds_compute_run where sandbox_id=" + quote(sandbox_id) + ";",
        "delete from ds_compute_canvas_version where canvas_id in (select id from ds_compute_canvas where sandbox_id="
        + quote(sandbox_id) + ");",
        "delete from ds_compute_canvas where sandbox_id=" + quote(sandbox_id) + ";",
        "delete from ds_sandbox_data_dir where sandbox_id=" + quote(sandbox_id) + ";",
        "delete from ds_data_asset where id=" + quote(asset_id) + ";",
        "delete from project_node where project_id=" + quote(project_id) + ";",
        "delete from project where project_id=" + quote(project_id) + ";"
    ])
    path = Path(fixture.get("dbDir", ""))
    expected = (CENTER / "secretpad/data/sandbox-db" / sandbox_id).resolve()
    if path and path.resolve() == expected and expected.is_dir():
        shutil.rmtree(expected)


def canvas_task(token, fixture):
    graph = {"nodes": [
        {"id": "p6-node-1", "data": {"componentCode": "data.table", "name": "数据资源",
                                     "params": {"table": SOURCE_TABLE}}, "position": {"x": 40, "y": 40}},
        {"id": "p6-node-2", "data": {"componentCode": "preprocessing.standardize", "name": "标准化",
                                     "params": {"columns": ["age", "income"], "method": "zscore"}},
         "position": {"x": 320, "y": 40}}],
        "edges": [{"source": "p6-node-1", "target": "p6-node-2"}]}
    canvas = expect_ok("P6 画布保存", "/v1alpha1/data-compute/canvases/save",
                       {"sandboxId": fixture["sandboxId"], "name": "P6 TEE 验收画布",
                        "graph": graph, "snapshot": False}, token)
    started = expect_ok("P6 画布运行", "/v1alpha1/data-compute/canvas/run",
                        {"canvasId": canvas["id"], "mode": "ALL"}, token)
    deadline = time.monotonic() + 360
    run_id = started["id"]
    task_id = ""
    job = None
    while time.monotonic() < deadline:
        if not task_id:
            task_id = scalar("select id from ds_dev_task where sandbox_id="
                             + quote(fixture["sandboxId"])
                             + " and channel='tee:canvas' and deleted=0 order by created_at desc limit 1;")
        if task_id and job is None:
            submitted = task_row(task_id)
            if submitted["jobId"]:
                try:
                    job = kube_job(submitted["jobId"])
                except Failure:
                    pass
        raw = scalar("select status from ds_compute_run where id=" + quote(run_id) + ";")
        if raw in TERMINAL:
            if raw != "SUCCEEDED":
                raise Failure("P6 画布运行失败：" + raw)
            break
        time.sleep(2)
    else:
        raise Failure("P6 画布运行超时")
    linked_task = scalar("select task_id from ds_compute_node_run where run_id=" + quote(run_id)
                         + " and component_code='preprocessing.standardize';")
    if linked_task != task_id:
        raise Failure("P6 画布节点与捕获的 TEE 任务绑定不一致")
    row = wait_task(task_id)
    if job is None:
        raise Failure("P6 画布任务未能在删除前捕获 Kuscia Job")
    row["capturedJob"] = job
    evidence = validate_task("可视化建模", row, "BUILTIN", "preprocessing.standardize")
    code, body = request("/v1alpha1/data-compute/canvas/node/output?canvasId="
                         + urlquote(canvas["id"]) + "&nodeId=p6-node-2&runId=" + urlquote(run_id),
                         token=token)
    output = body.get("data", {})
    encrypted_outputs = output.get("encryptedOutputs", []) if isinstance(output, dict) else []
    if code != 200 or body.get("status", {}).get("code") != 0 or not isinstance(output, dict) \
            or output.get("available") is not False \
            or output.get("runtimeMode") != "SIMULATION" \
            or output.get("attestationVerified") is not False \
            or output.get("exportState") != "PENDING_APPROVAL" \
            or output.get("rows") or not encrypted_outputs \
            or any(item.get("exportState") != "PENDING_APPROVAL" for item in encrypted_outputs):
        raise Failure("P6 画布节点输出暴露明文或缺少密文标记")
    evidence.update({"canvasId": canvas["id"], "runId": run_id,
                     "nodeId": "p6-node-2", "plaintextPreview": False})
    return evidence


def run():
    token, owner = login("CLIENT")
    asset_id = "asset-p6-" + uuid4().hex[:12]
    fixture = install_approval("center", owner, asset_id, ALL_COLUMNS, OPERATORS)
    env = dict(line.split("=", 1) for line in
               (CENTER / "secretpad.env").read_text().splitlines() if "=" in line)
    sqlite("center", ["update ds_sandbox set created_by="
                      + quote(env["SECRETPAD_USER_NAME"])
                      + " where id=" + quote(fixture["sandboxId"]) + ";"])
    fixture["assetId"] = asset_id
    checks = {}
    try:
        issued = expect_ok("P6 密钥签发", "/v1alpha1/tee/keys/issue", {
            "contractVersion": CONTRACT, "requestId": uuid4().hex,
            "assetId": asset_id, "assetVersion": "1"}, token)
        claimed = expect_ok("P6 密钥申领", "/v1alpha1/tee/keys/claim", {
            "contractVersion": CONTRACT, "requestId": uuid4().hex,
            "assetId": asset_id, "assetVersion": "1", "keyId": issued["keyId"],
            "keyVersion": issued["keyVersion"],
            "recipientCertPem": pem_of(CENTER / "tee/identity/client.crt")}, token)
        data_key = unwrap(claimed["keyEnvelope"], CENTER / "tee/identity/client.key")
        encrypted = current_encrypt(data_key, SAMPLE_CSV.encode(), asset_id,
                                    issued["keyId"], issued["keyVersion"])
        policy = expect_ok("P6 规则登记", "/v1alpha1/tee/policies/register", {
            "contractVersion": CONTRACT, "requestId": uuid4().hex,
            "policy": {"contractVersion": CONTRACT, "policyId": "", "policyVersion": "",
                       "assetId": asset_id, "assetVersion": "1", "ownerId": owner,
                       "sandboxId": fixture["sandboxId"], "columns": GRANTED_COLUMNS,
                       "operators": OPERATORS, "expiresAt": utc_time(3600),
                       "reportKinds": ["EVALUATION_METRICS"]}}, token)
        expect_ok("P6 密文资产登记", "/v1alpha1/tee/assets/register", {
            "contractVersion": CONTRACT, "requestId": uuid4().hex, "ownerId": owner,
            "schema": ALL_COLUMNS, "encryptedObject": encrypted,
            "policyId": policy["policyId"], "policyVersion": policy["policyVersion"]}, token)
        install_platform_fixture(owner, asset_id, fixture)

        sql_row = submit_task(token, fixture, "SQL",
                              script="SELECT age,income,label FROM p6_input")
        checks["sql"] = validate_task("SQL", sql_row, "SQL", "sql.query")
        python = """import argparse,shutil\np=argparse.ArgumentParser();p.add_argument('--input');p.add_argument('--output');p.add_argument('--params');a=p.parse_args();shutil.copyfile(a.input,a.output)\n"""
        py_row = submit_task(token, fixture, "PYTHON", script=python)
        checks["python"] = validate_task("Python", py_row, "PYTHON", "python.execute")
        jar_row = submit_task(token, fixture, "JAR", jar=build_jar())
        checks["jar"] = validate_task("JAR", jar_row, "JAR", "jar.execute")
        checks["canvas"] = canvas_task(token, fixture)

        # 未登记资产必须在 Job 创建前失败，证明 TEE 失败不会回退旧执行器。
        denied = expect_ok("P6 非密文资产提交", "/v1alpha1/data-dev/tasks/submit-sandbox", {
            "sandboxId": fixture["sandboxId"], "sourceTable": SOURCE_TABLE,
            "assetId": "plain-p6-" + uuid4().hex[:8], "mountId": fixture["mountId"],
            "runMode": "DEV", "execType": "SQL", "script": "SELECT age FROM p6_input",
            "name": "P6 非密文拒绝", "params": {}}, token)
        denied_row = wait_task(denied["id"], "FAILED", 30)
        if denied_row["jobId"] or denied_row["jws"]:
            raise Failure("非密文资产失败后仍创建了 TEE/旧执行 Job")
        checks["nonEncryptedDenied"] = {"taskId": denied_row["id"], "jobCreated": False,
                                         "legacyFallback": False, "status": "FAILED"}

        nonces = [checks[name]["nonce"] for name in ("sql", "python", "jar", "canvas")]
        if len(set(nonces)) != len(nonces):
            raise Failure("P6 新任务复用了 nonce")
        p5_path = CENTER / "tee/p5-acceptance.json"
        if not p5_path.is_file():
            raise Failure("缺少 P5 负向场景验收证据")
        p5 = json.loads(p5_path.read_text())
        required_negative = {"denied", "replay", "tamper", "timeout", "revoked"}
        if not required_negative.issubset(p5.get("checks", {})):
            raise Failure("P5 负向场景证据不完整")
        evidence = {"status": "P6_ACCEPTED", "contractVersion": CONTRACT,
                    "checkedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    "sourceCommit": subprocess.run(["git", "rev-parse", "HEAD"], check=True,
                                                   text=True, stdout=subprocess.PIPE).stdout.strip(),
                    "platformImageId": manifest()["images"]["platform"]["id"],
                    "runtimeImageId": manifest()["images"]["runtime"]["id"],
                    "runtimeMode": "SIMULATION", "attestationVerified": False,
                    "realModeReady": False, "checks": checks,
                    "negativeEvidence": {name: p5["checks"][name] for name in sorted(required_negative)}}
        atomic(CENTER / "tee/p6-acceptance.json", evidence, 0o600)
        return evidence
    finally:
        try:
            removed = cleanup_run_objects([checks.get(name, {}).get("taskId")
                                           for name in ("sql", "python", "jar", "canvas")])
            if removed:
                print(f"P6 已清理本次运行产生的 {removed} 个结果对象", file=sys.stderr)
        except (subprocess.CalledProcessError, OSError, ValueError) as error:
            print(f"P6 结果对象清理失败，需人工处理：{type(error).__name__}: {error}", file=sys.stderr)
        if fixture.get("projectId"):
            cleanup_platform_fixture(fixture)
        remove_approval(fixture)


if __name__ == "__main__":
    try:
        result = run()
        print(json.dumps({"status": result["status"], "sourceCommit": result["sourceCommit"],
                          "checks": sorted(result["checks"])}, ensure_ascii=False))
    except Failure as failure:
        raise SystemExit("P6 真实验收失败：" + str(failure))
    except Exception as error:
        frame = traceback.extract_tb(error.__traceback__)[-1]
        raise SystemExit("P6 真实验收异常：" + type(error).__name__ + ": " + str(error)
                         + f" ({Path(frame.filename).name}:{frame.lineno})")
