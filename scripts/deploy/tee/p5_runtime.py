#!/usr/bin/env python3
"""P5 Python trusted runtime image import and Kuscia AppImage registration."""
import base64
import hashlib
import json
from pathlib import Path

from platform_deploy import RUNTIME, CONTRACT_CENTER_URL, atomic, checked_image, manifest, run
from foundation import DOMAIN, import_image, kube, kube_labels, runtime_image


SECRET_NAME = 'tee-b-runtime-identity'
APPIMAGE_NAME = 'tee-b-data-sandbox-runtime'


def _b64(value):
    return base64.b64encode(value if isinstance(value, bytes) else value.encode()).decode()


def _read(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(RUNTIME.resolve()):
        raise RuntimeError('P5 身份文件不存在或越出运行目录')
    return path.read_bytes()


def register():
    """Import the locked image, publish file-backed identities, and apply one AppImage."""
    import_image('center', 'runtime')
    image = runtime_image('runtime')
    image_id = manifest()['images']['runtime']['id']
    center = RUNTIME / 'center/tee'
    signer_public = run('openssl', 'x509', '-in', center / 'task-signer/client.crt',
                        '-pubkey', '-noout', capture=True)
    values = {
        'TEE_API_CA_PEM': _read(center / 'runtime-contract-client/ca.crt'),
        'TEE_API_CLIENT_CERT_PEM': _read(center / 'runtime-contract-client/client.crt'),
        'TEE_API_CLIENT_KEY_PEM': _read(center / 'runtime-contract-client/client.key'),
        'TEE_WORKLOAD_CERT_PEM': _read(center / 'workload-cert/client.crt'),
        'TEE_WORKLOAD_PRIVATE_KEY_PEM': _read(center / 'workload-cert/client.key'),
        'TEE_TASK_SIGNER_PUBLIC_KEY_PEM': signer_public.encode(),
    }
    secret = {'apiVersion': 'v1', 'kind': 'Secret', 'type': 'Opaque',
        'metadata': {'name': SECRET_NAME, 'namespace': DOMAIN, 'labels': kube_labels()},
        'data': {key: _b64(value) for key, value in values.items()}}
    kube('center', 'apply', '-f', '-', value=secret)

    command = ['/bin/sh', '-ec',
        'umask 077; chmod o+rx / /usr /usr/local /usr/lib /usr/lib64 /opt /opt/java /opt/data-sandbox; chmod -R o+rX /usr/local /usr/lib /usr/lib64 /opt/java/openjdk /opt/data-sandbox; d=$(mktemp -d /dev/shm/tee-p5.XXXXXX); trap \'rm -rf "$d"\' EXIT; '
        'test "$(stat -f -c %T /dev/shm)" = tmpfs; '
        'printf "%s" "$TEE_API_CA_PEM" > "$d/api-ca.crt"; '
        'printf "%s" "$TEE_API_CLIENT_CERT_PEM" > "$d/api-client.crt"; '
        'printf "%s" "$TEE_API_CLIENT_KEY_PEM" > "$d/api-client.key"; '
        'printf "%s" "$TEE_WORKLOAD_CERT_PEM" > "$d/workload.crt"; '
        'printf "%s" "$TEE_WORKLOAD_PRIVATE_KEY_PEM" > "$d/workload.key"; '
        'mkdir "$d/trust"; printf "%s" "$TEE_TASK_SIGNER_PUBLIC_KEY_PEM" > "$d/trust/center-1.pem"; '
        'chmod 700 "$d" "$d/trust"; chmod 600 "$d"/*.crt "$d"/*.key "$d/trust/center-1.pem"; '
        'export TEE_API_CA_FILE="$d/api-ca.crt" TEE_API_CLIENT_CERT="$d/api-client.crt" '
        'TEE_API_CLIENT_KEY="$d/api-client.key" TEE_WORKLOAD_CERT="$d/workload.crt" '
        'TEE_WORKLOAD_PRIVATE_KEY="$d/workload.key" TEE_ISSUER_TRUST_DIR="$d/trust"; '
        'exec python /app/runtime_main.py']
    appimage = {'apiVersion': 'kuscia.secretflow/v1alpha1', 'kind': 'AppImage',
        'metadata': {'name': APPIMAGE_NAME, 'labels': kube_labels()},
        'spec': {'image': {'name': image.rsplit(':', 1)[0], 'tag': image.rsplit(':', 1)[1],
                           'id': image_id},
                 'configTemplates': {'tee-conf.json':
                     '{"task_id":"{{.TASK_ID}}","task_input_config":"{{.TASK_INPUT_CONFIG}}"}'},
                 'deployTemplates': [{'name': 'main', 'replicas': 1, 'spec': {
                     'restartPolicy': 'Never',
                     'containers': [{'name': 'main', 'command': command, 'workingDir': '/app',
                         'imagePullPolicy': 'Never',
                         'envFrom': [{'secretRef': {'name': SECRET_NAME}}],
                         'env': [
                             {'name': 'TEE_API_BASE', 'value': CONTRACT_CENTER_URL + '/api/v1alpha1/tee'},
                             {'name': 'TEE_AUDIENCE', 'value': 'tee-a-runtime'},
                             {'name': 'TEE_RUNTIME_IMAGE_DIGEST', 'value': image_id},
                             {'name': 'TEE_TASK_CONFIG', 'value': '/etc/kuscia/tee-conf.json'},
                             {'name': 'TEE_TASK_TIMEOUT_SECONDS', 'value': '1800'}],
                         'configVolumeMounts': [{'mountPath': '/etc/kuscia/tee-conf.json',
                                                'subPath': 'tee-conf.json'}],
                         'resources': {'requests': {'cpu': '500m', 'memory': '1Gi'},
                                       'limits': {'cpu': '4', 'memory': '8Gi'}},
                         'securityContext': {'runAsUser': 0, 'runAsGroup': 0,
                             'allowPrivilegeEscalation': False,
                             'capabilities': {'drop': ['ALL'],
                                              'add': ['CHOWN', 'SETUID', 'SETGID']}}}]}}]}}
    kube('center', 'apply', '-f', '-', value=appimage)
    evidence = {'contractVersion': 'tee-contract/1.0', 'appImage': APPIMAGE_NAME,
                'imageRef': image, 'imageId': image_id,
                'appImageSha256': hashlib.sha256(
                    json.dumps(appimage, sort_keys=True, separators=(',', ':')).encode()).hexdigest()}
    atomic(RUNTIME / 'center/tee/p5-runtime-registration.json', evidence, 0o600)
    print(f'{APPIMAGE_NAME} 已登记，镜像摘要 {image_id}；私钥仅来自 Kuscia Secret。')
