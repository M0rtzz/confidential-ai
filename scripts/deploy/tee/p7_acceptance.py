#!/usr/bin/env python3
"""P7 真实验收：密文结果导出审批、跨机构投票与信封取回。

脚本只使用运行目录中已登记的合成身份和证书，数据由本脚本在内存中生成。
结果任务通过真实 Kuscia AppImage 执行，导出工单通过 client-a/client-b 的会话
接口委派到中心端。任何未被接口真实证明的场景都会写入缺口并以非成功状态退出。
"""
import json
import hashlib
import ssl
import subprocess
import time
import traceback
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4
import urllib.error
import urllib.request

from contract_acceptance import (CONTRACT, CENTER, RUNTIME, Failure, decrypt, encrypt,
                                 expect_denied, expect_ok, login, pem_of, platform_time,
                                 quote, request, sign_task, sqlite, sqlite_query, unwrap,
                                 utc_time)
from p5_acceptance import APPIMAGE, apply_job, builtin_digest, receipt, wait_job
from platform_deploy import atomic, manifest


CONTRACT_PORT = 19686
CLIENT_A = "client-a"
CLIENT_B = "client-b"
REPORT_OPERATOR = "report.feature_importance"
STANDARDIZE_OPERATOR = "preprocessing.standardize"
GRANTED_COLUMNS = ["age", "income", "label"]
ALL_COLUMNS = GRANTED_COLUMNS + ["city", "private_note"]
REPORT_KINDS = ["FEATURE_IMPORTANCE"]
SAMPLE_A = """age,income,label,city,private_note
31,42000,0,hangzhou,private-a
45,88000,1,shanghai,private-b
27,31000,0,wuhan,private-c
""".encode()
SAMPLE_B = """age,income,label,city,private_note
52,99000,1,beijing,private-d
36,61000,0,nanjing,private-e
41,73000,1,shenzhen,private-f
""".encode()
EXPECTED_DATA = """age,income,label
-0.35267280792929934,-0.3858286853723962,0
1.1285529853737568,1.1354387026673376,1
-0.7758801774444583,-0.7496100172949413,0
""".encode()
EXPECTED_MODEL = json.dumps({
    "op": "standardize", "method": "zscore", "scaler": {
        "age": {"mean": 34.333333333333336, "std": 9.451631252505218},
        "income": {"mean": 53666.666666666664, "std": 30237.945256470935},
    },
}).encode()


def _common_approval(asset_ids, provider_nodes, operators, sandbox_owner, hours=2):
    """安装一份覆盖两个机构资产的合成审批，两个资产共用同一沙箱。"""
    sandbox_id = "sbx-p7-" + uuid4().hex[:10]
    approval_id = "apr-p7-" + uuid4().hex[:10]
    now = platform_time(0)
    until = platform_time(hours)
    tee_until = utc_time(hours * 3600)
    payload = json.dumps({"datasetAssetIds": asset_ids, "teeColumns": ALL_COLUMNS,
                          "teeOperators": operators, "teeExpiresAt": tee_until},
                         separators=(",", ":"))
    statements = [
        "insert into ds_sandbox(id,name,owner_id,project_id,image_id,status,expires_at,network_policy,"
        "cpu_cores,memory_gb,gpu_count,storage_gb,kuscia_job_id,endpoint,last_error,created_by,"
        f"created_at,updated_at,deleted) values({quote(sandbox_id)},{quote('P7 合成双机构沙箱')},"
        f"{quote(sandbox_owner)},'','','STOPPED',{quote(until)},'NO_NETWORK',0,0,0,0,'','','',"
        f"'p7-acceptance',{quote(now)},{quote(now)},0);",
        "insert into ds_sandbox_approval(id,approval_type,sandbox_id,owner_id,submitter,payload_json,"
        "status,current_stage,version,submitted_at,approved_at,completed_at,created_at,updated_at,deleted) "
        f"values({quote(approval_id)},'DATA_CHANGE',{quote(sandbox_id)},{quote(sandbox_owner)},"
        f"'p7-acceptance',{quote(payload)},'COMPLETED','COMPLETED',1,{quote(now)},{quote(now)},"
        f"{quote(now)},{quote(now)},{quote(now)},0);"
    ]
    for asset_id, provider_node in zip(asset_ids, provider_nodes):
        mount_id = "mnt-p7-" + uuid4().hex[:10]
        control_id = "ctl-p7-" + uuid4().hex[:10]
        statements.extend([
            "insert into ds_sandbox_dataset_mount(id,sandbox_id,asset_id,asset_version,provider_node_id,"
            f"staging_uri,mount_path,checksum,status,expires_at,created_at,updated_at,deleted) values("
            f"{quote(mount_id)},{quote(sandbox_id)},{quote(asset_id)},1,{quote(provider_node)},'','','','READY',"
            f"{quote(until)},{quote(now)},{quote(now)},0);",
            "insert into ds_sandbox_mount_control(id,sandbox_id,asset_id,allow_use,use_until,version,"
            f"updated_by,updated_at) values({quote(control_id)},{quote(sandbox_id)},{quote(asset_id)},1,"
            f"{quote(until)},1,'p7-acceptance',{quote(now)});"
        ])
    sqlite("center", statements)
    return {"sandboxId": sandbox_id, "approvalId": approval_id,
            "assetIds": list(asset_ids), "taskIds": [], "exportIds": [],
            "resultIds": [], "reportObjectIds": []}


def _provider_nodes(owners):
    """从中心节点台账解析真实 provider node，禁止用资产标识替代节点标识。"""
    nodes = []
    for owner in owners:
        node_id = sqlite_query(
            "center", "select node_id from node where inst_id=" + quote(owner)
            + " and is_deleted=0 order by node_id limit 1;")
        if not node_id:
            raise Failure("P7 机构没有可用的 provider node：" + owner)
        nodes.append(node_id)
    return nodes


def _contract_request(path, payload=None, instance=CLIENT_A):
    """通过真实贡献方的合同 mTLS 身份访问中心对象接口。"""
    cert_root = RUNTIME / instance / "tee/contract-client"
    ca_path = CENTER / "tee/pki/contract-ca/ca.crt"
    cert_path = cert_root / "client.crt"
    key_path = cert_root / "client.key"
    if not all(path.exists() for path in (ca_path, cert_path, key_path)):
        raise Failure("P7 缺少合同 mTLS 材料：" + instance)
    context = ssl.create_default_context(cafile=str(ca_path))
    context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    headers = {"Content-Type": "application/json"}
    request_data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request("https://127.0.0.1:" + str(CONTRACT_PORT) + "/api" + path,
                                 headers=headers, data=request_data)
    try:
        with urllib.request.urlopen(req, context=context, timeout=30) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        return error.code, json.load(error)


def _remove_common_approval(fixture):
    """只删除本次验收写入的审批、挂载和沙箱记录。"""
    asset_ids = ",".join(quote(item) for item in fixture["assetIds"])
    statements = ["pragma busy_timeout=8000;"]
    if fixture["exportIds"]:
        export_ids = ",".join(quote(item) for item in fixture["exportIds"])
        statements.extend([
            f"delete from tee_export_vote where export_id in ({export_ids});",
            f"delete from tee_export_request where export_id in ({export_ids});",
        ])
    if fixture["reportObjectIds"]:
        object_ids = ",".join(quote(item) for item in fixture["reportObjectIds"])
        statements.append(f"delete from tee_object where object_id in ({object_ids});")
    if fixture["taskIds"]:
        task_ids = ",".join(quote(item) for item in fixture["taskIds"])
        statements.extend([
            f"delete from tee_object where task_id in ({task_ids});",
            f"delete from tee_runtime_task where task_id in ({task_ids});",
            f"delete from tee_nonce where task_id in ({task_ids});",
        ])
    if fixture["resultIds"]:
        result_ids = ",".join(quote(item) for item in fixture["resultIds"])
        statements.append(f"delete from tee_key where asset_id in ({result_ids});")
    statements.extend([
        f"delete from tee_object where asset_id in ({asset_ids});",
        f"delete from tee_key where asset_id in ({asset_ids});",
        f"delete from tee_policy where asset_id in ({asset_ids});",
        f"delete from tee_asset where asset_id in ({asset_ids});",
        f"delete from ds_sandbox_mount_control where sandbox_id={quote(fixture['sandboxId'])};",
        f"delete from ds_sandbox_dataset_mount where sandbox_id={quote(fixture['sandboxId'])};",
        f"delete from ds_sandbox_approval where id={quote(fixture['approvalId'])};",
        f"delete from ds_sandbox where id={quote(fixture['sandboxId'])};",
    ])
    sqlite("center", statements)


def _register_asset(instance, token, owner, asset_id, plaintext, sandbox_id, operators):
    issued = expect_ok("P7 密钥签发 " + instance, "/v1alpha1/tee/keys/issue", {
        "contractVersion": CONTRACT, "requestId": uuid4().hex,
        "assetId": asset_id, "assetVersion": "1"}, token, instance)
    cert = pem_of(RUNTIME / instance / "tee/identity/client.crt")
    claimed = expect_ok("P7 密钥申领 " + instance, "/v1alpha1/tee/keys/claim", {
        "contractVersion": CONTRACT, "requestId": uuid4().hex,
        "assetId": asset_id, "assetVersion": "1", "keyId": issued["keyId"],
        "keyVersion": issued["keyVersion"], "recipientCertPem": cert}, token, instance)
    data_key = unwrap(claimed["keyEnvelope"], RUNTIME / instance / "tee/identity/client.key")
    encrypted = encrypt(data_key, plaintext, asset_id, 1, issued["keyId"], issued["keyVersion"])
    policy = expect_ok("P7 规则登记 " + instance, "/v1alpha1/tee/policies/register", {
        "contractVersion": CONTRACT, "requestId": uuid4().hex,
        "policy": {"contractVersion": CONTRACT, "policyId": None, "policyVersion": None,
                    "assetId": asset_id, "assetVersion": "1", "ownerId": owner,
                    "sandboxId": sandbox_id, "columns": GRANTED_COLUMNS,
                    "operators": operators, "expiresAt": utc_time(3600),
                    "reportKinds": REPORT_KINDS}}, token, instance)
    register_request = {
        "contractVersion": CONTRACT, "requestId": uuid4().hex, "ownerId": owner,
        "schema": ALL_COLUMNS, "encryptedObject": encrypted,
        "policyId": policy["policyId"], "policyVersion": policy["policyVersion"]}
    code, body = _contract_request("/v1alpha1/tee/assets/register", register_request, instance)
    if code != 200 or body.get("status", {}).get("code") != 0:
        error_code = (body.get("data") or {}).get("errorCode", "HTTP_" + str(code))
        raise Failure("P7 密文资产登记 " + instance + " 应成功但被拒绝：" + error_code)
    registered = body["data"]
    return {"instance": instance, "ownerId": owner, "assetId": asset_id,
            "assetVersion": 1, "objectId": registered["objectId"],
            "keyId": issued["keyId"], "keyVersion": int(issued["keyVersion"]),
            "policyId": policy["policyId"], "policyVersion": int(policy["policyVersion"]),
            "plaintext": plaintext, "encrypted": encrypted}


def _task(inputs, sandbox_id, operator=STANDARDIZE_OPERATOR, parameters=None,
          report_kinds=None):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    payload_inputs = [{"assetId": item["assetId"], "assetVersion": item["assetVersion"],
                       "keyId": item["keyId"], "keyVersion": item["keyVersion"],
                       "policyId": item["policyId"], "policyVersion": item["policyVersion"],
                       "objectId": item["objectId"],
                       "ciphertextSha256": item["encrypted"]["ciphertextSha256"],
                       "plaintextBytes": len(item["plaintext"])} for item in inputs]
    params = parameters or {"op": operator, "method": "zscore", "columns": ["age", "income"]}
    return {"contractVersion": CONTRACT, "taskId": "task-p7-" + uuid4().hex[:16],
            "requestId": uuid4().hex, "issuer": "center", "audience": "tee-a-runtime",
            "sandboxId": sandbox_id, "operatorId": operator, "columns": GRANTED_COLUMNS,
            "inputs": payload_inputs,
            "program": {"kind": "BUILTIN", "objectId": None,
                         "sha256": builtin_digest(), "parameters": params},
            "issuedAt": now.isoformat().replace("+00:00", "Z"),
            "expiresAt": (now + timedelta(seconds=240)).isoformat().replace("+00:00", "Z"),
            "nonce": uuid4().hex,
            "outputPolicy": {"reportKinds": report_kinds or [], "encryptData": True,
                             "encryptModel": True, "exportRequiresAllContributors": True},
            "runtimeImageDigest": manifest()["images"]["runtime"]["id"]}


def _run_task(inputs, sandbox_id, operator=STANDARDIZE_OPERATOR, parameters=None,
              report_kinds=None, fixture=None):
    task = _task(inputs, sandbox_id, operator, parameters, report_kinds)
    compact = sign_task(task)
    job, kuscia_task, task_id = apply_job(task, compact, APPIMAGE)
    if fixture is not None:
        fixture["taskIds"].append(task_id)
    result = wait_job(job, kuscia_task, True)
    payload = receipt(task_id)
    if payload.get("status") != "SUCCEEDED" or payload.get("runtimeMode") != "SIMULATION" \
            or payload.get("attestationVerified") is not False:
        raise Failure("P7 任务回执状态或 Simulation 边界不符")
    if fixture is not None:
        fixture["resultIds"].extend(
            item["resultId"] for item in payload.get("outputs", [])
            if item.get("kind") in ("DATA", "MODEL") and item.get("resultId"))
    return {"task": task, "compact": compact, "taskId": task_id, "job": job,
            "wait": result, "receipt": payload}


def _check_result_outputs(run_result, contributors, contributor, require_model=True):
    outputs = [item for item in run_result["receipt"].get("outputs", [])
               if item.get("kind") in ("DATA", "MODEL")]
    if not outputs or (require_model and not any(item.get("kind") == "MODEL" for item in outputs)):
        raise Failure("P7 真实任务没有产生预期 DATA/MODEL 输出")
    expected = set(contributors)
    for item in outputs:
        if item.get("encrypted") is not True or item.get("exportState") != "PENDING_APPROVAL" \
                or set(item.get("contributors") or []) != expected:
            raise Failure("P7 结果未保持密文待审批或贡献方集合不符")
        code, body = _contract_request("/v1alpha1/tee/objects/" + item["objectId"],
                                       instance=contributor["instance"])
        if code != 200 or body.get("status", {}).get("code") != 0:
            raise Failure("P7 无法通过真实贡献方读取密文结果")
        stored = body.get("data") or {}
        if stored.get("ciphertextSha256") != item.get("ciphertextSha256") \
                or stored.get("ciphertextB64") is None:
            raise Failure("P7 结果对象摘要或密文载荷不一致")
    return outputs


def _create_export(instance, token, result_id, cert=None, fixture=None, request_id=None):
    exported = expect_ok("P7 建立导出工单", "/v1alpha1/tee/exports", {
        "contractVersion": CONTRACT, "requestId": request_id or uuid4().hex,
        "resultId": result_id, "recipientCertPem": cert or ""}, token, instance)
    if fixture is not None:
        fixture["exportIds"].append(exported["exportId"])
    return exported


def _install_report_object_fixture(fixture, task_id, result_id, owner, asset_id):
    """为报告导出拒绝场景安装最小对象台账。

    当前运行时报告只进入已验签回执，不落 tee_object，也不会生成可供导出入口
    使用的 resultId。因此这里仅用真实报告 taskId 绑定一个受控、无密文本体的
    REPORT 行，以便真实执行 kind 门禁；该行在 finally 中删除，不能作为报告出域
    成功证据。
    """
    object_id = "obj-p7-report-" + uuid4().hex[:16]
    contributors = json.dumps([owner], separators=(",", ":"))
    sqlite("center", [
        "insert into tee_object(object_id,kind,owner_id,asset_id,task_id,result_id,key_id,"
        "key_version,ciphertext_sha256,size_bytes,contributors_json,export_state,is_deleted) "
        f"values({quote(object_id)},'REPORT',{quote(owner)},{quote(asset_id)},"
        f"{quote(task_id)},{quote(result_id)},'','1',{quote('0' * 64)},0,"
        f"{quote(contributors)},'PENDING_APPROVAL',0);"
    ])
    fixture["reportObjectIds"].append(object_id)
    return {"objectId": object_id, "resultId": result_id, "taskId": task_id,
            "ownerId": owner, "fixtureOnly": True}


def _action(instance, token, export_id, action, comment=""):
    return expect_ok("P7 投票 " + action, "/v1alpha1/tee/exports/" + export_id + "/action", {
        "contractVersion": CONTRACT, "action": action, "comment": comment}, token, instance)


def _approve_both(view, auth):
    export_id = view["exportId"]
    first = _action(CLIENT_A, auth[CLIENT_A]["token"], export_id, "APPROVE")
    second = _action(CLIENT_B, auth[CLIENT_B]["token"], export_id, "APPROVE")
    if second.get("status") != "APPROVED" \
            or {item.get("status") for item in second.get("votes", [])} != {"APPROVED"}:
        raise Failure("P7 双方投票后工单没有批准")
    return {"afterA": first, "afterB": second}


def _export(instance, token, result_id, cert):
    return expect_ok("P7 取回导出信封", "/v1alpha1/tee/results/" + result_id + "/export", {
        "contractVersion": CONTRACT, "requestId": uuid4().hex,
        "recipientCertPem": cert}, token, instance)


def _decrypt_export(exported, object_id, contributor):
    try:
        expires_at = datetime.fromisoformat(exported["expiresAt"].replace("Z", "+00:00"))
    except (KeyError, TypeError, ValueError) as failure:
        raise Failure("P7 导出信封缺少有效到期时刻") from failure
    if datetime.now(timezone.utc) >= expires_at:
        raise Failure("EXPORT_NOT_APPROVED: 导出信封已过期，请重新取回")
    code, body = _contract_request("/v1alpha1/tee/objects/" + object_id,
                                   instance=contributor["instance"])
    if code != 200 or body.get("status", {}).get("code") != 0:
        raise Failure("P7 导出后真实贡献方无法读取密文对象")
    recovered = decrypt(unwrap(exported["keyEnvelope"], contributor["keyPath"]), body["data"])
    if not recovered:
        raise Failure("P7 解封后得到空明文")
    # AES-GCM 解密已经对导出的密文字节执行认证，摘要只用于证据留存。
    return recovered


def _result_key_owner(key_id, key_version):
    return sqlite_query("center", "select owner_id from tee_key where key_id="
                        + quote(key_id) + " and key_version=" + quote(key_version) + ";")


def _revoke_result_key(output, auth):
    owner = _result_key_owner(output["keyId"], output["keyVersion"])
    runtime_identity = auth["center"]
    if owner != runtime_identity["ownerId"]:
        raise Failure("P7 结果密钥所有者与运行时 CLIENT 身份不一致，不能伪造吊销")
    expect_ok("P7 吊销结果密钥", "/v1alpha1/tee/keys/revoke", {
        "contractVersion": CONTRACT, "requestId": uuid4().hex,
        "keyId": output["keyId"], "keyVersion": output["keyVersion"],
        "reason": "p7 acceptance"}, runtime_identity["token"], runtime_identity["instance"])
    return owner


def _tamper_object_digest(object_id, original):
    tampered = "0" * 64 if original != "0" * 64 else "1" * 64
    sqlite("center", ["update tee_object set ciphertext_sha256=" + quote(tampered)
                       + " where object_id=" + quote(object_id) + ";"])
    return tampered


def _restore_object_digest(object_id, original):
    sqlite("center", ["update tee_object set ciphertext_sha256=" + quote(original)
                       + " where object_id=" + quote(object_id) + ";"])


def run():
    auth = {}
    for instance in (CLIENT_A, CLIENT_B):
        token, owner = login("CLIENT", instance)
        auth[instance] = {"instance": instance, "token": token, "ownerId": owner,
                          "cert": pem_of(RUNTIME / instance / "tee/identity/client.crt"),
                          "keyPath": RUNTIME / instance / "tee/identity/client.key"}
    center_token, center_owner = login("CLIENT", "center")
    runtime_token, _ = login("CENTER", "center")
    auth["center"] = {"instance": "center", "token": center_token, "ownerId": center_owner,
                      "cert": pem_of(CENTER / "tee/identity/client.crt"),
                      "keyPath": CENTER / "tee/identity/client.key"}
    if len({auth[CLIENT_A]["ownerId"], auth[CLIENT_B]["ownerId"]}) != 2:
        raise Failure("P7 client-a/client-b 没有解析为两个不同机构")

    asset_ids = ["asset-p7-a-" + uuid4().hex[:10], "asset-p7-b-" + uuid4().hex[:10]]
    contributor_owners = [auth[CLIENT_A]["ownerId"], auth[CLIENT_B]["ownerId"]]
    operators = [STANDARDIZE_OPERATOR, REPORT_OPERATOR]
    provider_nodes = _provider_nodes(contributor_owners)
    center_node = sqlite_query(
        "center", "select node_id from node where inst_id=" + quote(center_owner)
        + " and is_deleted=0 order by node_id limit 1;")
    if not center_node:
        raise Failure("P7 无法解析中心实例 nodeId")
    fixture = _common_approval(asset_ids, provider_nodes, operators, center_node)
    assets = []
    gaps = []
    checks = {}
    try:
        assets.append(_register_asset(CLIENT_A, auth[CLIENT_A]["token"], auth[CLIENT_A]["ownerId"],
                                      asset_ids[0], SAMPLE_A, fixture["sandboxId"], operators))
        assets.append(_register_asset(CLIENT_B, auth[CLIENT_B]["token"], auth[CLIENT_B]["ownerId"],
                                      asset_ids[1], SAMPLE_B, fixture["sandboxId"], operators))
        contributors = [auth[CLIENT_A]["ownerId"], auth[CLIENT_B]["ownerId"]]

        # 场景 1、10：同一份双机构真实任务分别验收 DATA 与 MODEL 导出链路。
        main_run = _run_task(assets, fixture["sandboxId"], fixture=fixture)
        main_outputs = _check_result_outputs(main_run, contributors, auth[CLIENT_A])
        data_output = next(item for item in main_outputs if item["kind"] == "DATA")
        model_output = next(item for item in main_outputs if item["kind"] == "MODEL")
        create_request_id = uuid4().hex
        view = _create_export(CLIENT_A, auth[CLIENT_A]["token"], data_output["resultId"],
                              auth[CLIENT_A]["cert"], fixture, create_request_id)
        checks["requestIdConflictDenied"] = expect_denied(
            "P7 requestId 内容冲突", "/v1alpha1/tee/exports", {
                "contractVersion": CONTRACT, "requestId": create_request_id,
                "resultId": model_output["resultId"],
                "recipientCertPem": auth[CLIENT_A]["cert"]},
            auth[CLIENT_A]["token"], "REQUEST_ID_CONFLICT", CLIENT_A)
        pending_code, pending_body = request(
            "/v1alpha1/tee/exports/pending", token=auth[CLIENT_B]["token"], instance=CLIENT_B)
        if pending_code != 200 or pending_body.get("status", {}).get("code") != 0:
            raise Failure("P7 B 待办列表 GET 调用失败")
        pending = pending_body["data"]
        if view["exportId"] not in {item["exportId"] for item in pending["items"]}:
            raise Failure("P7 client-b 未通过薄委派看到待投票工单")
        _approve_both(view, auth)
        exported = _export(CLIENT_A, auth[CLIENT_A]["token"], data_output["resultId"], auth[CLIENT_A]["cert"])
        if exported.get("objectId") != data_output["objectId"]:
            raise Failure("P7 DATA 导出对象标识变化")
        data_plaintext = _decrypt_export(exported, data_output["objectId"], auth[CLIENT_A])
        if data_plaintext != EXPECTED_DATA:
            raise Failure("P7 DATA 解密结果与锁定 TEE 算子的逐字节预期不符")
        checks["approvedData"] = {"exportId": view["exportId"], "objectId": data_output["objectId"],
                                   "contributors": contributors, "decrypted": True,
                                   "ciphertextSha256": data_output["ciphertextSha256"],
                                   "plaintextSha256": hashlib.sha256(data_plaintext).hexdigest(),
                                   "fullPlaintextByteMatch": True}

        model_view = _create_export(CLIENT_A, auth[CLIENT_A]["token"], model_output["resultId"],
                                    auth[CLIENT_A]["cert"], fixture)
        _approve_both(model_view, auth)
        model_export = _export(CLIENT_A, auth[CLIENT_A]["token"], model_output["resultId"], auth[CLIENT_A]["cert"])
        model_plaintext = _decrypt_export(model_export, model_output["objectId"], auth[CLIENT_A])
        if model_plaintext != EXPECTED_MODEL:
            raise Failure("P7 MODEL 解密结果与锁定 TEE 算子的逐字节预期不符")
        model = json.loads(model_plaintext)
        if model.get("op") != "standardize" or model.get("method") != "zscore":
            raise Failure("P7 MODEL 解密结果与 TEE 算子不符")
        checks["approvedModel"] = {"exportId": model_view["exportId"], "objectId": model_output["objectId"],
                                    "decrypted": True, "modelOperation": model.get("op"),
                                    "fullPlaintextByteMatch": True}

        # 场景 2：仅发起方投票，真实取回必须拒绝。
        partial_run = _run_task(assets, fixture["sandboxId"], fixture=fixture)
        partial_output = next(item for item in _check_result_outputs(partial_run, contributors, auth[CLIENT_A])
                              if item["kind"] == "DATA")
        partial_view = _create_export(CLIENT_A, auth[CLIENT_A]["token"], partial_output["resultId"],
                                      auth[CLIENT_A]["cert"], fixture)
        _action(CLIENT_A, auth[CLIENT_A]["token"], partial_view["exportId"], "APPROVE")
        checks["singleVoteDenied"] = expect_denied(
            "P7 只投一票取回", "/v1alpha1/tee/results/" + partial_output["resultId"] + "/export", {
                "contractVersion": CONTRACT, "requestId": uuid4().hex,
                "recipientCertPem": auth[CLIENT_A]["cert"]}, auth[CLIENT_A]["token"],
            "EXPORT_NOT_APPROVED", CLIENT_A)

        # 场景 3：一方拒绝，工单应终止且取回继续拒绝。
        reject_run = _run_task(assets, fixture["sandboxId"], fixture=fixture)
        reject_output = next(item for item in _check_result_outputs(reject_run, contributors, auth[CLIENT_A])
                             if item["kind"] == "DATA")
        reject_view = _create_export(CLIENT_A, auth[CLIENT_A]["token"], reject_output["resultId"],
                                     auth[CLIENT_A]["cert"], fixture)
        rejected = _action(CLIENT_B, auth[CLIENT_B]["token"], reject_view["exportId"], "REJECT", "P7 验收拒绝")
        if rejected.get("status") != "REJECTED":
            raise Failure("P7 拒绝投票后工单未变为 REJECTED")
        checks["rejectedVoteDenied"] = expect_denied(
            "P7 拒绝工单取回", "/v1alpha1/tee/results/" + reject_output["resultId"] + "/export", {
                "contractVersion": CONTRACT, "requestId": uuid4().hex,
                "recipientCertPem": auth[CLIENT_A]["cert"]}, auth[CLIENT_A]["token"],
            "EXPORT_NOT_APPROVED", CLIENT_A)

        # 撤回后工单不可继续使用，投票与撤回由中心端单例串行裁决。
        cancel_run = _run_task(assets, fixture["sandboxId"], fixture=fixture)
        cancel_output = next(item for item in _check_result_outputs(
            cancel_run, contributors, auth[CLIENT_A]) if item["kind"] == "DATA")
        cancel_view = _create_export(CLIENT_A, auth[CLIENT_A]["token"],
                                     cancel_output["resultId"], auth[CLIENT_A]["cert"], fixture)
        cancelled = expect_ok("P7 撤回导出工单",
                              "/v1alpha1/tee/exports/" + cancel_view["exportId"] + "/cancel",
                              {"contractVersion": CONTRACT}, auth[CLIENT_A]["token"], CLIENT_A)
        if cancelled.get("status") != "CANCELLED":
            raise Failure("P7 工单撤回后状态不为 CANCELLED")
        checks["cancelledDenied"] = expect_denied(
            "P7 撤回后取回", "/v1alpha1/tee/results/" + cancel_output["resultId"] + "/export", {
                "contractVersion": CONTRACT, "requestId": uuid4().hex,
                "recipientCertPem": auth[CLIENT_A]["cert"]}, auth[CLIENT_A]["token"],
            "EXPORT_NOT_APPROVED", CLIENT_A)

        # 场景 4：批准后吊销结果密钥；取回必须返回 KEY_REVOKED。
        revoke_run = _run_task(assets, fixture["sandboxId"], fixture=fixture)
        revoke_output = next(item for item in _check_result_outputs(revoke_run, contributors, auth[CLIENT_A])
                             if item["kind"] == "DATA")
        revoke_view = _create_export(CLIENT_A, auth[CLIENT_A]["token"], revoke_output["resultId"],
                                     auth[CLIENT_A]["cert"], fixture)
        _approve_both(revoke_view, auth)
        revoked_owner = _revoke_result_key(revoke_output, auth)
        checks["revokedKeyDenied"] = expect_denied(
            "P7 吊销结果密钥后取回", "/v1alpha1/tee/results/" + revoke_output["resultId"] + "/export", {
                "contractVersion": CONTRACT, "requestId": uuid4().hex,
                "recipientCertPem": auth[CLIENT_A]["cert"]}, auth[CLIENT_A]["token"],
            "KEY_REVOKED", CLIENT_A)
        checks["revokedKeyDenied"]["keyOwner"] = revoked_owner

        # 场景 5：只篡改权威摘要，不篡改密文文件；门禁应返回 DATA_INTEGRITY_FAILED。
        tamper_run = _run_task(assets, fixture["sandboxId"], fixture=fixture)
        tamper_output = next(item for item in _check_result_outputs(tamper_run, contributors, auth[CLIENT_A])
                             if item["kind"] == "DATA")
        tamper_view = _create_export(CLIENT_A, auth[CLIENT_A]["token"], tamper_output["resultId"],
                                     auth[CLIENT_A]["cert"], fixture)
        _approve_both(tamper_view, auth)
        original_digest = tamper_output["ciphertextSha256"]
        _tamper_object_digest(tamper_output["objectId"], original_digest)
        try:
            checks["tamperedDigestDenied"] = expect_denied(
                "P7 篡改结果摘要后取回", "/v1alpha1/tee/results/" + tamper_output["resultId"] + "/export", {
                    "contractVersion": CONTRACT, "requestId": uuid4().hex,
                    "recipientCertPem": auth[CLIENT_A]["cert"]}, auth[CLIENT_A]["token"],
                "DATA_INTEGRITY_FAILED", CLIENT_A)
        finally:
            _restore_object_digest(tamper_output["objectId"], original_digest)

        # 批准后原任务任一授权过期，中心端重新校验必须拒绝取回。
        policy_run = _run_task(assets, fixture["sandboxId"], fixture=fixture)
        policy_output = next(item for item in _check_result_outputs(
            policy_run, contributors, auth[CLIENT_A]) if item["kind"] == "DATA")
        policy_view = _create_export(CLIENT_A, auth[CLIENT_A]["token"],
                                     policy_output["resultId"], auth[CLIENT_A]["cert"], fixture)
        _approve_both(policy_view, auth)
        policy_id, policy_version = assets[0]["policyId"], assets[0]["policyVersion"]
        original_expiry = sqlite_query(
            "center", "select expires_at from tee_policy where policy_id=" + quote(policy_id)
            + " and policy_version=" + quote(policy_version) + ";")
        sqlite("center", ["update tee_policy set expires_at=" + quote(utc_time(-60))
                           + " where policy_id=" + quote(policy_id)
                           + " and policy_version=" + quote(policy_version) + ";"])
        try:
            checks["expiredPolicyDenied"] = expect_denied(
                "P7 授权过期后取回", "/v1alpha1/tee/results/" + policy_output["resultId"] + "/export", {
                    "contractVersion": CONTRACT, "requestId": uuid4().hex,
                    "recipientCertPem": auth[CLIENT_A]["cert"]}, auth[CLIENT_A]["token"],
                "POLICY_DENIED", CLIENT_A)
        finally:
            sqlite("center", ["update tee_policy set expires_at=" + quote(original_expiry)
                               + " where policy_id=" + quote(policy_id)
                               + " and policy_version=" + quote(policy_version) + ";"])

        # 场景 6：中心端 CLIENT 会话作为非贡献机构发起，真实身份应被拒绝。
        checks["nonContributorDenied"] = expect_denied(
            "P7 非贡献机构建单", "/v1alpha1/tee/exports", {
                "contractVersion": CONTRACT, "requestId": uuid4().hex,
                "resultId": data_output["resultId"], "recipientCertPem": auth["center"]["cert"]},
            center_token, "AUDIT_ACCESS_DENIED", "center")

        # 场景 7、11：报告由真实 TEE 回执返回明文，导出工单入口显式拒绝。
        report_run = _run_task([assets[0]], fixture["sandboxId"], REPORT_OPERATOR,
                               {"op": REPORT_OPERATOR, "columns": ["age", "income"]}, REPORT_KINDS,
                               fixture)
        reports = [item for item in report_run["receipt"].get("outputs", []) if item.get("kind") == "REPORT"]
        if not reports or any(item.get("encrypted") is not False or not item.get("content") for item in reports):
            raise Failure("P7 报告结果未按契约以明文回执返回")
        # 报告回执没有 resultId；用真实报告 taskId 生成稳定标识，并绑定受控台账行。
        report_result_id = "report-" + report_run["taskId"]
        report_fixture = _install_report_object_fixture(
            fixture, report_run["taskId"], report_result_id, auth[CLIENT_A]["ownerId"], asset_ids[0])
        checks["reportExportDenied"] = expect_denied(
            "P7 REPORT 建单", "/v1alpha1/tee/exports", {
                "contractVersion": CONTRACT, "requestId": uuid4().hex,
                "resultId": report_result_id, "recipientCertPem": auth[CLIENT_A]["cert"]},
            auth[CLIENT_A]["token"], "CONTRACT_INVALID", CLIENT_A)
        checks["reportPlaintext"] = {"reportKinds": [item.get("reportKind") for item in reports],
                                      "encrypted": False, "approvalEntry": False,
                                      "reportTaskId": report_run["taskId"],
                                      "reportResultId": report_result_id,
                                      "fixtureOnly": report_fixture["fixtureOnly"]}

        # 场景 8：请求方提交另一机构证书，建单前即被拒绝。
        checks["foreignRecipientDenied"] = expect_denied(
            "P7 他方证书建单", "/v1alpha1/tee/exports", {
                "contractVersion": CONTRACT, "requestId": uuid4().hex,
                "resultId": data_output["resultId"], "recipientCertPem": auth[CLIENT_B]["cert"]},
            auth[CLIENT_A]["token"], "ASSET_OWNER_MISMATCH", CLIENT_A)

        # 运行时身份不得调用数据方的导出裁决接口。
        checks["runtimeExportDenied"] = expect_denied(
            "P7 运行时越权建立导出工单", "/v1alpha1/tee/exports", {
                "contractVersion": CONTRACT, "requestId": uuid4().hex,
                "resultId": data_output["resultId"],
                "recipientCertPem": auth[CLIENT_A]["cert"]},
            runtime_token, "END_ROLE_DENIED", "center")

        # 场景 9：接收机构统一解封入口按中心端 expiresAt 拒绝旧信封；工单可重新取回。
        expires_at = exported.get("expiresAt", "")
        try:
            expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            ttl = (expiry - datetime.now(timezone.utc)).total_seconds()
        except (TypeError, ValueError):
            ttl = -1
        if not 0 < ttl <= 300:
            raise Failure("P7 导出信封有效期字段不在 5 分钟内")
        time.sleep(max(0, ttl + 1))
        try:
            _decrypt_export(exported, data_output["objectId"], auth[CLIENT_A])
            raise Failure("P7 超过五分钟的旧信封仍可通过统一解封入口使用")
        except Failure as failure:
            if "EXPORT_NOT_APPROVED" not in str(failure):
                raise
        refreshed = _export(CLIENT_A, auth[CLIENT_A]["token"], data_output["resultId"],
                            auth[CLIENT_A]["cert"])
        refreshed_plaintext = _decrypt_export(refreshed, data_output["objectId"], auth[CLIENT_A])
        if hashlib.sha256(refreshed_plaintext).hexdigest() != hashlib.sha256(data_plaintext).hexdigest():
            raise Failure("P7 重新取回信封后的结果明文发生变化")
        checks["envelopeExpiry"] = {"expiresAt": expires_at, "ttlSecondsAtCheck": round(ttl, 3),
                                     "expiredEnvelopeDenied": True,
                                     "refreshedEnvelopeUsable": True}

        evidence = {"status": "P7_INCOMPLETE" if gaps else "P7_ACCEPTED",
                    "contractVersion": CONTRACT,
                    "checkedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    "sourceCommit": subprocess.run(["git", "rev-parse", "HEAD"], check=True,
                                                   text=True, stdout=subprocess.PIPE).stdout.strip(),
                    "platformImageId": manifest()["images"]["platform"]["id"],
                    "runtimeImageId": manifest()["images"]["runtime"]["id"],
                    "runtimeMode": "SIMULATION", "attestationVerified": False,
                    "realModeReady": False, "checks": checks, "gaps": gaps}
        atomic(CENTER / "tee/p7-acceptance.json", evidence, 0o600)
        return evidence
    finally:
        _remove_common_approval(fixture)


if __name__ == "__main__":
    try:
        result = run()
        print(json.dumps({"status": result["status"], "sourceCommit": result["sourceCommit"],
                          "checks": sorted(result["checks"]), "gaps": result["gaps"]},
                         ensure_ascii=False))
        if result["gaps"]:
            raise SystemExit(2)
    except Failure as failure:
        raise SystemExit("P7 真实验收失败：" + str(failure))
    except Exception as error:
        frame = traceback.extract_tb(error.__traceback__)[-1]
        raise SystemExit("P7 真实验收异常：" + type(error).__name__ + ": " + str(error)
                         + f" ({Path(frame.filename).name}:{frame.lineno})")
