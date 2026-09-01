"""恢复上游仓库改名前的固定 DCAP 归档，仅接受原始 SHA256 完全一致的结果。"""
import fcntl
import gzip
import hashlib
import subprocess
import urllib.request

from platform_deploy import CACHE, guard, manifest, save_manifest

EXPECTED = 'a71bba80f8da53ce2877f4c2bd2d1713ab97acc4a3e7987d82d7430cda2d8fb1'
RENAMED = '3a69a687f2222433addd25dfe6e54a6ca164fcbf4c3dec5ad9e8b155c5bb98cb'
URL = 'https://codeload.github.com/intel/confidential-computing.tee.dcap/tar.gz/refs/tags/DCAP_1.20'


def restore():
    target = CACHE / 'distdir/DCAP_1.20.tar.gz'
    if target.is_symlink() or not target.resolve().is_relative_to(CACHE.resolve()):
        raise RuntimeError('DCAP 缓存路径越出隔离目录')
    if target.exists():
        if hashlib.sha256(target.read_bytes()).hexdigest() != EXPECTED:
            raise RuntimeError('已有 DCAP 归档与固定校验值不符，拒绝覆盖')
    else:
        with urllib.request.urlopen(URL, timeout=60) as response:
            raw = response.read(32 * 1024 * 1024)
        if hashlib.sha256(raw).hexdigest() != RENAMED:
            raise RuntimeError('上游归档再次变化，停止恢复，不修改校验值')
        tar, out, offset = gzip.decompress(raw), bytearray(), 0
        renamed = b'confidential-computing.tee.dcap-DCAP_1.20'
        original = b'SGXDataCenterAttestationPrimitives-DCAP_1.20'
        while offset < len(tar):
            header = bytearray(tar[offset:offset + 512])
            if not any(header):
                out.extend(tar[offset:]); break
            size = int(header[124:136].rstrip(b'\0 '), 8)
            extent = 512 + ((size + 511) // 512) * 512
            if header[156:157] == b'x':
                raise RuntimeError('出现未验证的扩展路径格式，停止恢复')
            name = bytes(header[:100]).split(b'\0')[0]
            prefix = bytes(header[345:500]).split(b'\0')[0]
            path = prefix + b'/' + name if prefix else name
            if path.startswith(renamed + b'/'):
                path = original + path[len(renamed):]
                header[:100], header[345:500] = b'\0' * 100, b'\0' * 155
                if len(path) > 100:
                    end = min(len(path) - int(path.endswith(b'/')), 155)
                    plen = path.rfind(b'/', 0, end)
                    if plen <= 0 or len(path) - plen - 1 > 100:
                        raise RuntimeError('恢复路径不满足 Git USTAR 格式')
                    header[345:345 + plen] = path[:plen]
                    path = path[plen + 1:]
                header[:len(path)] = path
                header[148:156] = b' ' * 8
                header[148:156] = ('%07o' % sum(header)).encode() + b'\0'
            out.extend(header)
            out.extend(tar[offset + 512:offset + extent])
            offset += extent
        result = subprocess.run(['gzip', '-n', '-6', '-c'], input=out, capture_output=True, check=True).stdout
        if hashlib.sha256(result).hexdigest() != EXPECTED:
            raise RuntimeError('未恢复原始归档 SHA256，不保存结果')
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(result)
        target.chmod(0o600)
    data = manifest()
    data.setdefault('build_dependencies', {})['dcap_1_20'] = {
        'sha256': EXPECTED, 'renamed_archive_sha256': RENAMED, 'source_url': URL,
        'commit': '621a0850fccf531a8d8131f9293a760925f55730',
        'recovery': 'ORIGINAL_PREFIX_AND_GZIP_EXACT_SHA256'}
    save_manifest(data)
    print('DCAP_1.20 原始归档 SHA256 校验通过；未修改固定源码的校验值。')


if __name__ == '__main__':
    guard()
    with (CACHE / 'operation.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        restore()
