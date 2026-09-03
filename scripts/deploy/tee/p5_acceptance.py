#!/usr/bin/env python3
"""Real P5 acceptance through Kuscia and the registered trusted AppImage.

Only synthetic rows are used. Private keys are read from the managed runtime
directories in memory and are never printed or copied into the evidence file.
"""
import base64
import copy
import hashlib
import json
import secrets
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from contract_acceptance import (CONTRACT, CENTER, RUNTIME, Failure, cleanup_run_assets,
                                 cleanup_run_objects,
                                 decrypt, expect_ok, install_approval, login, pem_of,
                                 private_key, remove_approval, request, sign_task,
                                 unwrap, utc_time)
from foundation import DOMAIN, kube_labels
from platform_deploy import LABEL, atomic, manifest


KUSCIA = "data-sandbox-dev-center-kuscia"
APPIMAGE = "tee-b-data-sandbox-runtime"
TIMEOUT_APPIMAGE = "tee-b-data-sandbox-runtime-timeout-test"
SUCCESS_OPERATOR = "preprocessing.standardize"
TIMEOUT_OPERATOR = "ml.xgboost"
GRANTED_COLUMNS = ["age", "income", "label"]
ALL_COLUMNS = GRANTED_COLUMNS + ["city", "private_note"]
SAMPLE_CSV = """age,income,label,city,private_note
31,42000,0,hangzhou,private-a
45,88000,1,shanghai,private-b
27,31000,0,wuhan,private-c
52,99000,1,beijing,private-d
36,61000,0,nanjing,private-e
41,73000,1,shenzhen,private-f
29,39000,0,changsha,private-g
48,92000,1,suzhou,private-h
33,51000,0,ningbo,private-i
44,84000,1,hefei,private-j
"""


def _verify_kuscia():
    value = json.loads(subprocess.run(
        ["docker", "container", "inspect", KUSCIA], check=True, text=True,
        stdout=subprocess.PIPE).stdout)[0]
    labels = value.get("Config", {}).get("Labels") or {}
    expected = {LABEL + "dev": "true", LABEL + "dev-owner": "collab",
                LABEL + "dev-workspace": "/data/collab/Projects/gpu/confidential-ai"}
    if any(labels.get(key) != item for key, item in expected.items()):
        raise Failure("中心 Kuscia 资源身份不符")


def kube(*args, value=None):
    _verify_kuscia()
    command = ["docker", "exec"] + (["-i"] if value is not None else []) + [
        KUSCIA, "kubectl", *args]
    result = subprocess.run(command, check=True, text=True,
                            input=json.dumps(value) if value is not None else None,
                            stdout=subprocess.PIPE)
    return result.stdout


def cri(*args):
    _verify_kuscia()
    return subprocess.run(["docker", "exec", KUSCIA,
                           "/home/kuscia/bin/crictl", *args], check=True,
                          text=True, stderr=subprocess.STDOUT, stdout=subprocess.PIPE).stdout


def current_encrypt(key, plaintext, asset_id, key_id, key_version):
    nonce = secrets.token_bytes(12)
    aad = json.dumps({"assetId": asset_id, "assetVersion": 1,
                      "keyId": key_id, "keyVersion": int(key_version)},
                     separators=(",", ":")).encode()
    sealed = AESGCM(key).encrypt(nonce, plaintext, aad)
    ciphertext, tag = sealed[:-16], sealed[-16:]
    return {"contractVersion": CONTRACT, "assetId": asset_id, "assetVersion": 1,
            "keyId": key_id, "keyVersion": int(key_version),
            "algorithm": "AES-256-GCM", "nonceB64": base64.b64encode(nonce).decode(),
            "aadB64": base64.b64encode(aad).decode(),
            "ciphertextB64": base64.b64encode(ciphertext).decode(),
            "tagB64": base64.b64encode(tag).decode(),
            "ciphertextSha256": hashlib.sha256(nonce + aad + ciphertext + tag).hexdigest()}


def builtin_digest():
    image = manifest()["images"]["runtime"]["ref"]
    output = subprocess.run(["docker", "run", "--pull=never", "--rm",
                             "--entrypoint", "sha256sum", image,
                             "/opt/data-sandbox/modeling_ops.py"], check=True,
                            text=True, stdout=subprocess.PIPE).stdout
    return output.split()[0]


def task(asset, issued, policy, sandbox_id, operator, parameters, digest,
         nonce=None, image_digest=None):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    return {"contractVersion": CONTRACT,
            "taskId": "task-p5-" + uuid4().hex[:16], "requestId": uuid4().hex,
            "issuer": "center", "audience": "tee-a-runtime", "sandboxId": sandbox_id,
            "operatorId": operator, "columns": GRANTED_COLUMNS,
            "inputs": [{"assetId": asset["assetId"],
                        "assetVersion": int(asset["assetVersion"]),
                        "keyId": issued["keyId"], "keyVersion": int(issued["keyVersion"]),
                        "policyId": policy["policyId"],
                        "policyVersion": int(policy["policyVersion"]),
                        "objectId": asset["objectId"],
                        "ciphertextSha256": asset["ciphertextSha256"],
                        "plaintextBytes": len(SAMPLE_CSV.encode())}],
            "program": {"kind": "BUILTIN", "objectId": None,
                        "sha256": digest, "parameters": parameters},
            "issuedAt": now.isoformat().replace("+00:00", "Z"),
            "expiresAt": (now + timedelta(seconds=240)).isoformat().replace("+00:00", "Z"),
            "nonce": nonce or uuid4().hex,
            "outputPolicy": {"reportKinds": [], "encryptData": True,
                             "encryptModel": True,
                             "exportRequiresAllContributors": True},
            "runtimeImageDigest": image_digest or manifest()["images"]["runtime"]["id"]}


def apply_job(task_payload, compact, appimage=APPIMAGE):
    name = "p5-" + uuid4().hex[:12]
    value = {"apiVersion": "kuscia.secretflow/v1alpha1", "kind": "KusciaJob",
             "metadata": {"name": name, "namespace": "cross-domain",
                          "labels": kube_labels()},
             "spec": {"initiator": DOMAIN, "maxParallelism": 1,
                      "tasks": [{"taskID": name + "-task", "alias": "p5-runtime",
                                 "appImage": appimage,
                                 "taskInputConfig": json.dumps(
                                     {"tee_task_jws": compact}, separators=(",", ":")),
                                 "scheduleConfig": {"lifecycleSeconds": 180},
                                 "parties": [{"domainID": DOMAIN}]}]}}
    kube("apply", "-f", "-", value=value)
    return name, value["spec"]["tasks"][0]["taskID"], task_payload["taskId"]


def wait_job(name, task_id, succeeded, timeout=600):
    deadline = time.monotonic() + timeout
    phase = None
    while time.monotonic() < deadline:
        job = json.loads(kube("get", "kusciajob", name, "-n", "cross-domain", "-o", "json"))
        phase = job.get("status", {}).get("phase")
        if phase in ("Succeeded", "Failed", "Cancelled"):
            break
        time.sleep(2)
    expected = "Succeeded" if succeeded else "Failed"
    if phase != expected:
        raise Failure(f"KusciaJob {name} 期望 {expected}，实际 {phase}")
    containers = [item for item in json.loads(cri("ps", "-a", "-o", "json")).get("containers", [])
                  if item.get("metadata", {}).get("name") == "main"
                  and item.get("labels", {}).get("io.kubernetes.pod.name") == task_id + "-0"
                  and item.get("labels", {}).get("io.kubernetes.pod.namespace") == DOMAIN]
    if len(containers) != 1:
        raise Failure("未找到唯一 P5 Runner 容器")
    container = containers[0]
    status = json.loads(cri("inspect", container["id"]))["status"]
    log = cri("logs", container["id"])
    if container.get("imageRef") != manifest()["images"]["runtime"]["id"]:
        raise Failure("P5 实际容器镜像摘要与锁定值不同")
    if succeeded and status.get("exitCode") != 0:
        raise Failure("P5 成功任务容器退出码非零")
    if not succeeded and status.get("exitCode") == 0:
        raise Failure("P5 负向任务容器未失败")
    return {"phase": phase, "exitCode": status.get("exitCode"),
            "imageId": container.get("imageRef"), "log": log}


def log_error_code(log):
    for line in reversed(log.splitlines()):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and value.get("errorCode"):
            return value["errorCode"], value.get("message", "")
    raise Failure("P5 失败容器没有安全错误码")


def decode_jws(compact):
    payload = compact.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def receipt(task_id):
    output = subprocess.run(["docker", "exec", "-i",
                             "data-sandbox-dev-center-secretpad", "sqlite3",
                             "/app/db/secretpad.sqlite"], input=(
        "select receipt_jws from tee_runtime_task where task_id='" +
        task_id.replace("'", "''") + "' and receipt_verified=1;\n").encode(),
        check=True, stdout=subprocess.PIPE).stdout.decode().strip()
    if not output:
        raise Failure("P5 任务没有已验签回执")
    return decode_jws(output)


def install_timeout_appimage():
    current = json.loads(kube("get", "appimage", APPIMAGE, "-o", "json"))
    value = {"apiVersion": current["apiVersion"], "kind": current["kind"],
             "metadata": {"name": TIMEOUT_APPIMAGE, "labels": kube_labels()},
             "spec": copy.deepcopy(current["spec"])}
    env = value["spec"]["deployTemplates"][0]["spec"]["containers"][0]["env"]
    for item in env:
        if item.get("name") == "TEE_TASK_TIMEOUT_SECONDS":
            item["value"] = "1"
            break
    else:
        raise Failure("P5 AppImage 缺少超时配置")
    kube("apply", "-f", "-", value=value)


def run():
    _verify_kuscia()
    client_token, owner = login("CLIENT")
    asset_id = "asset-p5-" + uuid4().hex[:12]
    fixture = install_approval("center", owner, asset_id, ALL_COLUMNS,
                               [SUCCESS_OPERATOR, TIMEOUT_OPERATOR])
    checks = {}
    try:
        issued = expect_ok("P5 密钥签发", "/v1alpha1/tee/keys/issue", {
            "contractVersion": CONTRACT, "requestId": uuid4().hex,
            "assetId": asset_id, "assetVersion": "1"}, client_token)
        claimed = expect_ok("P5 密钥申领", "/v1alpha1/tee/keys/claim", {
            "contractVersion": CONTRACT, "requestId": uuid4().hex,
            "assetId": asset_id, "assetVersion": "1", "keyId": issued["keyId"],
            "keyVersion": issued["keyVersion"],
            "recipientCertPem": pem_of(CENTER / "tee/identity/client.crt")}, client_token)
        key = unwrap(claimed["keyEnvelope"], CENTER / "tee/identity/client.key")
        encrypted = current_encrypt(key, SAMPLE_CSV.encode(), asset_id,
                                    issued["keyId"], issued["keyVersion"])
        policy = expect_ok("P5 规则登记", "/v1alpha1/tee/policies/register", {
            "contractVersion": CONTRACT, "requestId": uuid4().hex,
            "policy": {"contractVersion": CONTRACT, "policyId": "", "policyVersion": "",
                       "assetId": asset_id, "assetVersion": "1", "ownerId": owner,
                       "sandboxId": fixture["sandboxId"], "columns": GRANTED_COLUMNS,
                       "operators": [SUCCESS_OPERATOR, TIMEOUT_OPERATOR],
                       "expiresAt": utc_time(3600), "reportKinds": ["EVALUATION_METRICS"]}},
            client_token)
        asset = expect_ok("P5 密文资产登记", "/v1alpha1/tee/assets/register", {
            "contractVersion": CONTRACT, "requestId": uuid4().hex, "ownerId": owner,
            "schema": ALL_COLUMNS, "encryptedObject": encrypted,
            "policyId": policy["policyId"], "policyVersion": policy["policyVersion"]},
            client_token)
        asset["ciphertextSha256"] = encrypted["ciphertextSha256"]
        digest = builtin_digest()

        successful = task(asset, issued, policy, fixture["sandboxId"], SUCCESS_OPERATOR,
                          {"op": SUCCESS_OPERATOR, "method": "zscore",
                           "columns": ["age", "income"]}, digest)
        successful_jws = sign_task(successful)
        job, kuscia_task, contract_task = apply_job(successful, successful_jws)
        result = wait_job(job, kuscia_task, True)
        success_receipt = receipt(contract_task)
        if success_receipt.get("status") != "SUCCEEDED" or not success_receipt.get("outputs"):
            raise Failure("P5 成功回执状态或输出为空")
        decrypted_kinds = []
        for output in success_receipt["outputs"]:
            if output.get("encrypted") is not True:
                raise Failure("P5 数据/模型输出未加密")
            code, body = request("/v1alpha1/tee/objects/" + output["objectId"],
                                 token=client_token)
            if code != 200 or body.get("status", {}).get("code") != 0:
                raise Failure("P5 无法读取密文结果")
            envelope = body["data"]
            result_claim = expect_ok("P5 结果密钥申领", "/v1alpha1/tee/keys/claim", {
                "contractVersion": CONTRACT, "requestId": uuid4().hex,
                "assetId": output["resultId"], "assetVersion": "1",
                "keyId": output["keyId"], "keyVersion": str(output["keyVersion"]),
                "recipientCertPem": pem_of(CENTER / "tee/identity/client.crt")}, client_token)
            result_key = unwrap(result_claim["keyEnvelope"], CENTER / "tee/identity/client.key")
            plaintext = decrypt(result_key, envelope)
            if output["kind"] == "DATA":
                header = plaintext.decode().splitlines()[0].split(",")
                if header != GRANTED_COLUMNS or "private-" in plaintext.decode() or "city" in header:
                    raise Failure("P5 列过滤或 DATA 解密结果不符")
            elif output["kind"] == "MODEL":
                model = json.loads(plaintext)
                if model.get("op") != "standardize":
                    raise Failure("P5 预处理模型内容不符")
            else:
                raise Failure("P5 成功任务产生未知输出类型")
            decrypted_kinds.append(output["kind"])
        checks["success"] = {"job": job, "taskId": contract_task,
                             "phase": result["phase"], "receiptVerified": True,
                             "outputKinds": sorted(decrypted_kinds),
                             "encryptedOutputs": True, "columnFilterVerified": True,
                             "tmpfsGateEnforced": True}

        denied = task(asset, issued, policy, fixture["sandboxId"], "ml.dnn",
                      {"op": "ml.dnn", "label": "label",
                       "features": ["age", "income"]}, digest)
        job, kuscia_task, _ = apply_job(denied, sign_task(denied))
        failed = wait_job(job, kuscia_task, False)
        code, _ = log_error_code(failed["log"])
        if code != "POLICY_DENIED":
            raise Failure("P5 越权任务拒绝码不符")
        checks["denied"] = {"job": job, "errorCode": code}

        replayed = task(asset, issued, policy, fixture["sandboxId"], SUCCESS_OPERATOR,
                        {"op": SUCCESS_OPERATOR}, digest, nonce=successful["nonce"])
        job, kuscia_task, _ = apply_job(replayed, sign_task(replayed))
        failed = wait_job(job, kuscia_task, False)
        code, _ = log_error_code(failed["log"])
        if code != "TASK_REPLAYED":
            raise Failure("P5 重放拒绝码不符")
        checks["replay"] = {"job": job, "errorCode": code}

        tampered = task(asset, issued, policy, fixture["sandboxId"], SUCCESS_OPERATOR,
                        {"op": SUCCESS_OPERATOR}, digest)
        compact = sign_task(tampered)
        parts = compact.split(".")
        body = decode_jws(compact)
        body["operatorId"] = "ml.dnn"
        parts[1] = base64.urlsafe_b64encode(json.dumps(body).encode()).decode().rstrip("=")
        job, kuscia_task, _ = apply_job(tampered, ".".join(parts))
        failed = wait_job(job, kuscia_task, False)
        code, _ = log_error_code(failed["log"])
        if code != "TASK_SIGNATURE_INVALID":
            raise Failure("P5 篡改任务拒绝码不符")
        checks["tamper"] = {"job": job, "errorCode": code}

        install_timeout_appimage()
        timeout_task = task(asset, issued, policy, fixture["sandboxId"], TIMEOUT_OPERATOR,
                            {"op": TIMEOUT_OPERATOR, "label": "label",
                             "features": ["age", "income"], "n_estimators": 1000000,
                             "max_depth": 10}, digest)
        job, kuscia_task, timeout_contract_task = apply_job(
            timeout_task, sign_task(timeout_task), TIMEOUT_APPIMAGE)
        failed = wait_job(job, kuscia_task, False)
        code, message = log_error_code(failed["log"])
        timeout_receipt = receipt(timeout_contract_task)
        if code != "CONTRACT_INVALID" or "timed out" not in message \
                or timeout_receipt.get("status") != "FAILED" \
                or timeout_receipt.get("errorCode") != "CONTRACT_INVALID":
            raise Failure("P5 超时终止或失败回执不符")
        checks["timeout"] = {"job": job, "errorCode": code,
                             "failedReceiptVerified": True, "processGroupKilled": True}

        expect_ok("P5 密钥吊销", "/v1alpha1/tee/keys/revoke", {
            "contractVersion": CONTRACT, "requestId": uuid4().hex,
            "keyId": issued["keyId"], "keyVersion": issued["keyVersion"],
            "reason": "p5 acceptance"}, client_token)
        revoked = task(asset, issued, policy, fixture["sandboxId"], SUCCESS_OPERATOR,
                       {"op": SUCCESS_OPERATOR}, digest)
        job, kuscia_task, _ = apply_job(revoked, sign_task(revoked))
        failed = wait_job(job, kuscia_task, False)
        code, _ = log_error_code(failed["log"])
        if code != "KEY_REVOKED":
            raise Failure("P5 吊销后拒绝码不符")
        checks["revoked"] = {"job": job, "errorCode": code}

        evidence = {"contractVersion": CONTRACT,
                    "checkedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    "runtimeImageId": manifest()["images"]["runtime"]["id"],
                    "appImage": APPIMAGE, "checks": checks}
        atomic(CENTER / "tee/p5-acceptance.json", evidence, 0o600)
        return evidence
    finally:
        try:
            removed = cleanup_run_objects([checks.get("success", {}).get("taskId")])
            keys = cleanup_run_assets([asset_id])
            if removed or keys:
                print(f"P5 已清理本次运行产生的 {removed} 个结果对象与 {keys} 把密钥", file=sys.stderr)
        except (subprocess.CalledProcessError, OSError, ValueError) as error:
            print(f"P5 结果对象清理失败，需人工处理：{type(error).__name__}: {error}", file=sys.stderr)
        remove_approval(fixture)


if __name__ == "__main__":
    try:
        result = run()
        print(json.dumps({"status": "P5_ACCEPTED", "runtimeImageId": result["runtimeImageId"],
                          "checks": result["checks"]}, ensure_ascii=False))
    except Failure as failure:
        raise SystemExit("P5 真实验收失败：" + str(failure))
    except Exception as error:
        raise SystemExit("P5 真实验收异常：" + type(error).__name__)
