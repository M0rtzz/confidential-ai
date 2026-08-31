#!/usr/bin/env python3
"""中心密钥适配服务：把 Capsule Manager 的原生协议收敛在一处，只对平台暴露最小内部接口。

平台通过双向 TLS 调用本服务，本服务持有中心密钥服务身份并按原生协议访问 CM。
数据密钥的明文只在本进程内存中短暂存在，出站一律是接收者证书公钥密封后的结果。
业务鉴权由平台契约层负责；本服务只做与底座能力相关的纵深防御。
"""
import argparse
import base64
import json
import os
import secrets
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from uuid import uuid4

# 托管作用域与算子由部署固定，不接受请求参数；用于密钥服务取回自己托管的数据密钥。
ESCROW_SCOPE = 'tee-escrow'
ESCROW_OPERATOR = 'tee.escrow'
WHOLE_OBJECT = 'tee.whole-object'
# CM 把 '*' 视为放开全部列或全部算子；契约不支持通配符，本服务一律拒绝。
WILDCARD = '*'
MAX_BODY = 256 * 1024
TIMEOUT = 15


class AdapterError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


class Capsule:
    """CM 会话；证书与私钥只从挂载路径读取，不接受请求传入。"""

    def __init__(self, endpoint, cert_dir):
        from sdc.capsule_manager_frame import CapsuleManagerFrame, CredentialsConf
        from sdc.util.tool import generate_party_id_from_cert
        conf = CredentialsConf(*[(Path(cert_dir) / f).read_bytes()
                                 for f in ['ca.crt', 'client.key', 'client.crt']])
        self.frame = CapsuleManagerFrame(endpoint, 'sim', None, conf)
        # 访问 CM 的传输身份同时作为中心密钥服务在 CM 中的签名身份，只有一份私钥。
        self.private_key = (Path(cert_dir) / 'client.key').read_bytes()
        self.chain = [(Path(cert_dir) / 'client.crt').read_bytes()]
        self.party_id = generate_party_id_from_cert(self.chain[-1])
        self.lock = threading.Lock()

    @property
    def signing(self):
        return {'cert_pems': self.chain, 'private_key': self.private_key}

    def public_key(self):
        with self.lock:
            return self.frame.get_public_key()

    def create_key(self, resource_uri):
        data_key = base64.b64encode(secrets.token_bytes(32)).decode()
        with self.lock:
            self.frame.create_data_keys(self.party_id,
                                        [{'resource_uri': resource_uri, 'data_key_b64': data_key}], **self.signing)
        # 明文密钥不返回给调用方，也不落盘；后续取用一律经 CM 重新申领。
        del data_key

    def create_policy(self, resource_uri, scope, rules):
        with self.lock:
            self.frame.create_data_policy(self.party_id, scope, resource_uri, rules, **self.signing)

    def delete_policy(self, resource_uri, scope):
        with self.lock:
            self.frame.delete_data_policy(self.party_id, scope, data_uuid=resource_uri, **self.signing)

    def delete_key(self, resource_uri):
        with self.lock:
            self.frame.delete_data_key(self.party_id, resource_uri, **self.signing)

    def party_of(self, cert_pem):
        from sdc.util.tool import generate_party_id_from_cert
        return generate_party_id_from_cert(cert_pem)

    def policy_scopes(self, resource_uri, scopes):
        found = []
        for scope in scopes:
            with self.lock:
                policies = self.frame.get_data_policys(self.party_id, scope, **self.signing)
            if any(p.data_uuid == resource_uri and p.rules for p in policies):
                found.append(scope)
        return found

    def fetch_key(self, resource_uri, scope, initiator, operator, columns):
        """按业务规则向 CM 申领数据密钥；规则不满足时由 CM 拒绝。"""
        from secretflowapis.v2.sdc.capsule_manager import capsule_manager_pb2
        request = capsule_manager_pb2.GetDataKeysRequest()
        request.cert = self.chain[-1].decode()
        request.resource_request.initiator_party_id = initiator
        request.resource_request.scope = scope
        request.resource_request.op_name = operator
        resource = request.resource_request.resources.add()
        resource.resource_uri = resource_uri
        resource.columns.extend(columns)
        with self.lock:
            encrypted = self.frame.stub.GetDataKeys(self.frame.create_encrypted_request(
                request, self.frame.get_public_key(), self.private_key, self.chain), timeout=TIMEOUT)
            if encrypted.status.code != 0:
                raise AdapterError('POLICY_DENIED', '密钥服务按规则拒绝放行')
            response = capsule_manager_pb2.GetDataKeysResponse()
            self.frame.parse_from_encrypted_response(encrypted, self.private_key, response)
        for key in response.data_keys:
            if key.resource_uri == resource_uri:
                return key.data_key_b64
        raise AdapterError('KEY_NOT_FOUND', '密钥服务未返回该资源的数据密钥')


def seal_to_recipient(data_key_b64, recipient_cert_pem):
    """按契约以 RSA-OAEP-256 密封数据密钥；公钥只取自已认证的接收者证书。"""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    certificate = x509.load_pem_x509_certificate(recipient_cert_pem)
    public_key = certificate.public_key()
    if not isinstance(public_key, rsa.RSAPublicKey) or public_key.key_size < 2048:
        raise AdapterError('CONTRACT_INVALID', '接收者证书必须为至少 2048 位的 RSA 公钥')
    wrapped = public_key.encrypt(base64.b64decode(data_key_b64), padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    digest = hashes.Hash(hashes.SHA256())
    digest.update(certificate.public_bytes(serialization.Encoding.DER))
    return base64.b64encode(wrapped).decode(), digest.finalize().hex()


def check_names(values, kind):
    """契约要求精确匹配：空集合即禁止，且不接受通配符。"""
    if not isinstance(values, list) or not values:
        raise AdapterError('POLICY_DENIED', f'{kind}授权集合为空，按契约禁止')
    for value in values:
        if not isinstance(value, str) or not value.strip():
            raise AdapterError('CONTRACT_INVALID', f'{kind}名称无效')
        if value == WILDCARD:
            raise AdapterError('POLICY_DENIED', f'{kind}不支持通配符授权')


class Service:
    def __init__(self, capsule):
        self.capsule = capsule

    def issue(self, body):
        resource_uri = require(body, 'resourceUri')
        self.capsule.create_key(resource_uri)
        self.capsule.create_policy(resource_uri, ESCROW_SCOPE, [{
            'rule_id': uuid4().hex, 'grantee_party_ids': [self.capsule.party_id],
            'columns': [WHOLE_OBJECT], 'global_constraints': [],
            'op_constraints': [{'op_name': ESCROW_OPERATOR, 'constraints': []}]}])
        return {'resourceUri': resource_uri, 'servicePartyId': self.capsule.party_id}

    def escrow_seal(self, body):
        """所有者为加密自己的数据申领密钥；走密钥服务的托管作用域。"""
        resource_uri = require(body, 'resourceUri')
        recipient = base64.b64decode(require(body, 'recipientCertPemB64'))
        data_key = self.capsule.fetch_key(resource_uri, ESCROW_SCOPE, self.capsule.party_id,
                                          ESCROW_OPERATOR, [WHOLE_OBJECT])
        wrapped, fingerprint = seal_to_recipient(data_key, recipient)
        return {'wrappedKeyB64': wrapped, 'recipientCertSha256': fingerprint}

    def release_seal(self, body):
        """运行时按签名任务申领输入密钥；发起方、算子与列交给 CM 按业务规则校验。"""
        resource_uri = require(body, 'resourceUri')
        columns = body.get('columns')
        check_names(columns, '列')
        operator = require(body, 'operator')
        check_names([operator], '算子')
        recipient = base64.b64decode(require(body, 'recipientCertPemB64'))
        initiator = self.capsule.party_of(base64.b64decode(require(body, 'initiatorCertPemB64')))
        data_key = self.capsule.fetch_key(resource_uri, require(body, 'scope'), initiator, operator, columns)
        wrapped, fingerprint = seal_to_recipient(data_key, recipient)
        return {'wrappedKeyB64': wrapped, 'recipientCertSha256': fingerprint}

    def register_policy(self, body):
        resource_uri = require(body, 'resourceUri')
        scope = require(body, 'scope')
        rules = body.get('rules')
        if not isinstance(rules, list) or not rules:
            raise AdapterError('POLICY_DENIED', '授权规则为空，按契约禁止')
        prepared = []
        for rule in rules:
            certs = rule.get('granteeCertsB64')
            check_names(certs, '被授权方')
            grantees = [self.capsule.party_of(base64.b64decode(cert)) for cert in certs]
            columns = rule.get('columns')
            check_names(columns, '列')
            operators = rule.get('operators')
            check_names(operators, '算子')
            prepared.append({'rule_id': uuid4().hex, 'grantee_party_ids': grantees,
                             'columns': columns, 'global_constraints': [],
                             'op_constraints': [{'op_name': op, 'constraints': []} for op in operators]})
        self.capsule.create_policy(resource_uri, scope, prepared)
        return {'resourceUri': resource_uri, 'scope': scope, 'ruleCount': len(prepared)}

    def revoke(self, body):
        """吊销后续申领：删除业务规则与托管规则，再删除数据密钥本身。"""
        resource_uri = require(body, 'resourceUri')
        scopes = body.get('scopes') or []
        for scope in list(scopes) + [ESCROW_SCOPE]:
            try:
                self.capsule.delete_policy(resource_uri, scope)
            except Exception:
                # 规则可能已不存在；吊销以数据密钥删除为准，不因重复删除失败。
                pass
        self.capsule.delete_key(resource_uri)
        remaining = self.capsule.policy_scopes(resource_uri, list(scopes) + [ESCROW_SCOPE])
        return {'resourceUri': resource_uri, 'revoked': True, 'remainingScopes': remaining}

    def health(self, _body=None):
        return {'servicePartyId': self.capsule.party_id, 'keyServiceReachable': bool(self.capsule.public_key())}


def require(body, field):
    value = body.get(field)
    if not isinstance(value, str) or not value.strip():
        raise AdapterError('CONTRACT_INVALID', f'缺少必填字段 {field}')
    return value


def handler_for(service):
    routes = {'/v1/keys/issue': service.issue, '/v1/keys/escrow-seal': service.escrow_seal,
              '/v1/keys/release-seal': service.release_seal, '/v1/policies/register': service.register_policy,
              '/v1/keys/revoke': service.revoke}

    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def reply(self, status, payload):
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path != '/v1/health':
                return self.reply(404, {'errorCode': 'NOT_FOUND'})
            try:
                self.reply(200, service.health())
            except Exception:
                self.reply(503, {'errorCode': 'KEY_SERVICE_UNAVAILABLE'})

        def do_POST(self):
            action = routes.get(self.path)
            if action is None:
                return self.reply(404, {'errorCode': 'NOT_FOUND'})
            length = int(self.headers.get('Content-Length') or 0)
            if length <= 0 or length > MAX_BODY:
                return self.reply(413, {'errorCode': 'PAYLOAD_TOO_LARGE'})
            try:
                body = json.loads(self.rfile.read(length))
                if not isinstance(body, dict):
                    raise AdapterError('CONTRACT_INVALID', '请求体必须是对象')
                self.reply(200, action(body))
            except AdapterError as error:
                self.reply(200, {'errorCode': error.code, 'message': error.message})
            except Exception as error:
                # 原生异常可能带签名请求正文或证书内容，只返回类别。
                self.reply(503, {'errorCode': 'KEY_SERVICE_UNAVAILABLE', 'message': type(error).__name__})

        def log_message(self, *args):
            pass

    return Handler


def serve(port, cert_dir, endpoint, server_dir):
    capsule = Capsule(endpoint, cert_dir)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(Path(server_dir) / 'client.crt'), str(Path(server_dir) / 'client.key'))
    context.load_verify_locations(str(Path(server_dir) / 'ca.crt'))
    # 平台必须持有本服务信任的客户端证书；不提供无认证入口。
    context.verify_mode = ssl.CERT_REQUIRED
    server = ThreadingHTTPServer(('0.0.0.0', port), handler_for(Service(capsule)))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == '__main__':
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=8090)
    parser.add_argument('--cert-dir', default='/certs')
    parser.add_argument('--server-dir', default='/server')
    args = parser.parse_args()
    serve(args.port, args.cert_dir, os.environ['TEE_CAPSULE_ENDPOINT'], args.server_dir)
