#!/usr/bin/env python3
"""独立低权限探测器；仅调用原生 GetRaCert，不生成或申请数据密钥。"""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import secrets


def pem(name, filename):
    value = os.environ.get(name)
    return value.encode() if value else (Path(os.environ.get('TEE_CERT_DIR', '/certs')) / filename).read_bytes()


def check(no_client_certificate=False, plaintext=False, server_name="capsule.tee-a.test"):
    import grpc
    from cryptography import x509
    from secretflowapis.v2.sdc.capsule_manager import capsule_manager_pb2, capsule_manager_pb2_grpc
    response = {'checkedAt': dt.datetime.now(dt.timezone.utc).isoformat(),
                'reachable': False, 'method': 'CAPSULE_GET_RA_CERT_MTLS'}
    try:
        credentials = grpc.ssl_channel_credentials(
            root_certificates=pem('TEE_CA_PEM', 'ca.crt'),
            private_key=None if no_client_certificate else pem('TEE_CLIENT_KEY_PEM', 'client.key'),
            certificate_chain=None if no_client_certificate else pem('TEE_CLIENT_CERT_PEM', 'client.crt'))
        target = os.environ['TEE_CAPSULE_ENDPOINT']
        # server_name 由部署者固定，用于容器服务名与证书 SAN 的对应，不接受请求参数。
        options = [('grpc.ssl_target_name_override', server_name)]
        connection = grpc.insecure_channel(target) if plaintext else grpc.secure_channel(target, credentials, options=options)
        with connection as channel:
            stub = capsule_manager_pb2_grpc.CapsuleManagerStub(channel)
            result = stub.GetRaCert(capsule_manager_pb2.GetRaCertRequest(nonce=secrets.token_hex(32)), timeout=2)
            if result.status.code != 0 or not result.cert:
                raise ValueError('原生接口未返回证书')
            x509.load_pem_x509_certificate(result.cert.encode())
        response['reachable'] = True
    except Exception:
        # 异常内容可能包含内部地址及证书信息，不向平台返回原始异常。
        response['errorCode'] = 'KEY_SERVICE_UNAVAILABLE'
    return response


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != '/health':
            self.send_error(404)
            return
        value = check()
        body = json.dumps(value).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--serve', action='store_true')
    parser.add_argument('--task-config')
    parser.add_argument('--negative-no-client-certificate', action='store_true')
    parser.add_argument('--negative-plaintext', action='store_true')
    parser.add_argument('--server-name', default='capsule.tee-a.test')
    args = parser.parse_args()
    if args.task_config:
        with open(args.task_config) as source:
            config = json.load(source)
        if not config.get('task_id'):
            raise SystemExit('调度配置未挂载')
    if args.serve:
        if args.negative_no_client_certificate or args.negative_plaintext or args.server_name != 'capsule.tee-a.test':
            parser.error('健康服务禁止使用否定测试参数')
        ThreadingHTTPServer(('0.0.0.0', 8089), Handler).serve_forever()
    else:
        result = check(args.negative_no_client_certificate, args.negative_plaintext, args.server_name)
        print(json.dumps(result))
        raise SystemExit(0 if result['reachable'] else 1)
