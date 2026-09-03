#!/usr/bin/env python3
"""P8 真实验收：端身份固定声明与可信执行链路只读接口。

全部检查都打在运行中的三个实例上，不构造任何合成数据，也不执行任何写操作。
聚合接口的返回值与实例平台库的直接查询逐项对照，任何对不上的项都会记入缺口
并以非成功状态退出。解绑校验只读取前置检查结果，不调用删除路由接口。
"""
import hashlib
import json
import sys
import traceback
import urllib.error
import urllib.request
from pathlib import Path

from contract_acceptance import PORTS, RUNTIME, Failure, login, request, sqlite_query

CENTER = 'center'
CLIENT_A = 'client-a'
CLIENT_B = 'client-b'
CLIENTS = [CLIENT_A, CLIENT_B]
INSTANCES = [CENTER, CLIENT_A, CLIENT_B]
CENTER_SEGMENTS = ['KEY_ISSUE', 'DATA_ENCRYPT', 'POLICY_CHECK', 'ATTESTATION', 'TEE_EXEC', 'EGRESS']
CLIENT_SEGMENTS = ['KEY_ISSUE', 'DATA_ENCRYPT', 'ATTESTATION', 'EGRESS']
OBJECT_LIMIT = 200


def get(path, token=None, instance=CENTER):
    """信任链接口全部是 GET；request 在 payload 为 None 时发的就是 GET。"""
    return request(path, None, token, instance)


def data_of(name, path, token, instance):
    code, body = get(path, token, instance)
    if code != 200 or body.get('status', {}).get('code') != 0:
        detail = body.get('status', {}).get('msg') or f'HTTP {code}'
        raise Failure(f'{name} 应成功但被拒绝：{detail}')
    return body['data']


def denied(name, path, token, instance):
    code, body = get(path, token, instance)
    if code == 200 and body.get('status', {}).get('code') == 0:
        raise Failure(f'{name} 应被拒绝但成功了')
    return body


def sign_in(end_role, instance):
    """登录并返回完整响应；端身份要从登录响应里读，login() 只回传令牌与机构。"""
    env = dict(line.split('=', 1) for line in
               (Path(RUNTIME) / instance / 'secretpad.env').read_text().splitlines() if '=' in line)
    payload = {'name': env['SECRETPAD_USER_NAME'],
               'passwordHash': hashlib.sha256(env['SECRETPAD_PASSWORD'].encode()).hexdigest()}
    if end_role:
        payload['endRole'] = end_role
    return request('/login', payload, instance=instance)


def sessions():
    """端身份解析：不带 endRole 登录应各自解析为本实例声明的首项。"""
    checks = {}
    tokens = {}
    owners = {}
    for instance in INSTANCES:
        expected = 'CENTER' if instance == CENTER else 'CLIENT'
        code, body = sign_in(None, instance)
        if code != 200 or body.get('status', {}).get('code') != 0:
            raise Failure(f'{instance} 不带端参数登录失败：{body.get("status")}')
        if body['data'].get('endRole') != expected:
            raise Failure(f'{instance} 默认端身份应为 {expected}，实际 {body["data"].get("endRole")}')
        tokens[instance] = body['data']['token']
        owners[instance] = body['data']['ownerId']
    checks['defaultEndRole'] = {instance: ('CENTER' if instance == CENTER else 'CLIENT')
                                for instance in INSTANCES}

    code, body = sign_in('CENTER', CLIENT_A)
    if code == 200 and body.get('status', {}).get('code') == 0:
        raise Failure('客户端不应接受 CENTER 端身份')
    if 'END_ROLE_DENIED' not in str(body.get('status', {}).get('msg')):
        raise Failure(f'客户端拒绝 CENTER 应给出 END_ROLE_DENIED，实际 {body.get("status")}')
    checks['clientCenterLoginDenied'] = True

    # 中心端保留 CLIENT 能力供 P5/P6 验收脚本使用，这条不能被本次改动收走。
    code, body = sign_in('CLIENT', CENTER)
    if code != 200 or body.get('status', {}).get('code') != 0:
        raise Failure(f'中心端显式以 CLIENT 登录应仍然可用：{body.get("status")}')
    checks['centerClientLoginStillWorks'] = True
    return checks, tokens, owners


def instance_endpoint():
    """/instance 免登录：不带 User-Token 也应返回本实例端身份。"""
    result = {}
    for instance in INSTANCES:
        url = f'http://127.0.0.1:{PORTS[instance]}/api/v1alpha1/data-sandbox/instance'
        with urllib.request.urlopen(urllib.request.Request(url), timeout=30) as response:
            body = json.load(response)
        if body.get('status', {}).get('code') != 0:
            raise Failure(f'{instance} 免登录实例接口失败：{body.get("status")}')
        role = body['data']['endRole']
        expected = 'CENTER' if instance == CENTER else 'CLIENT'
        if role != expected:
            raise Failure(f'{instance} 实例接口端身份应为 {expected}，实际 {role}')
        result[instance] = role
    return result


def segments(tokens):
    """中心端六段齐全，客户端只有四段且不含规则校验与执行两段。"""
    summary = data_of('中心端链路概况', '/v1alpha1/data-sandbox/trust-chain/summary',
                      tokens[CENTER], CENTER)
    keys = [segment['key'] for segment in summary['segments']]
    if keys != CENTER_SEGMENTS:
        raise Failure(f'中心端链路应为六段 {CENTER_SEGMENTS}，实际 {keys}')
    if summary['environment']['runtimeMode'] != 'SIMULATION':
        raise Failure('环境应如实显示为仿真模式')
    attestation = next(item for item in summary['segments'] if item['key'] == 'ATTESTATION')
    if attestation['state'] != 'WARN':
        raise Failure(f'仿真模式下环境认证段应为 WARN，实际 {attestation["state"]}')
    for instance in CLIENTS:
        view = data_of(f'{instance} 链路概况', '/v1alpha1/data-sandbox/trust-chain/summary',
                       tokens[instance], instance)
        client_keys = [segment['key'] for segment in view['segments']]
        if client_keys != CLIENT_SEGMENTS:
            raise Failure(f'{instance} 链路应为四段 {CLIENT_SEGMENTS}，实际 {client_keys}')
    return {'center': keys, 'client': CLIENT_SEGMENTS}


def ledger_matches(tokens):
    """聚合数值与库内直接查询一致；接口有上限，比较时对齐同一上限。"""
    keys = data_of('密钥台账', '/v1alpha1/data-sandbox/trust-chain/keys', tokens[CENTER], CENTER)
    in_db = int(sqlite_query(CENTER, 'select count(*) from tee_key where is_deleted=0;') or 0)
    if len(keys['items']) != min(in_db, OBJECT_LIMIT):
        raise Failure(f'密钥台账 {len(keys["items"])} 条与库内 {in_db} 条不一致')
    objects = data_of('密文资产', '/v1alpha1/data-sandbox/trust-chain/objects',
                      tokens[CENTER], CENTER)
    objects_in_db = int(sqlite_query(
        CENTER, "select count(*) from tee_object where is_deleted=0 and kind in ('DATA','MODEL');") or 0)
    listed = [item for item in objects['items'] if item['kind'] in ('DATA', 'MODEL')]
    if len(listed) != min(objects_in_db, OBJECT_LIMIT):
        raise Failure(f'密文对象 {len(listed)} 条与库内 {objects_in_db} 条不一致')
    return {'keys': len(keys['items']), 'objects': len(listed)}


def preview(tokens, owners):
    """密文预览定长返回，且只对贡献机构与中心端开放。"""
    objects = data_of('密文资产', '/v1alpha1/data-sandbox/trust-chain/objects',
                      tokens[CENTER], CENTER)['items']
    target = next((item for item in objects if item['kind'] in ('DATA', 'MODEL')), None)
    if target is None:
        raise Failure('中心端没有可供预览的密文结果对象')
    view = data_of('密文预览', f'/v1alpha1/data-sandbox/trust-chain/objects/{target["objectId"]}/preview',
                   tokens[CENTER], CENTER)
    if view['previewBytes'] > 256 or len(view['hex']) > 512:
        raise Failure(f'密文预览超出定长上限：{view["previewBytes"]} 字节')
    outsider = next((instance for instance in CLIENTS
                     if owners[instance] not in target.get('contributors', [])), None)
    if outsider is None:
        return {'objectId': target['objectId'], 'previewBytes': view['previewBytes'],
                'foreignDenied': 'skipped'}
    denied(f'{outsider} 预览非本机构贡献的密文',
           f'/v1alpha1/data-sandbox/trust-chain/objects/{target["objectId"]}/preview',
           tokens[outsider], outsider)
    return {'objectId': target['objectId'], 'previewBytes': view['previewBytes'],
            'foreignDenied': outsider}


def client_empty(tokens):
    """客户端拿不到中心端台账，对应接口返回空集合而不是报错。"""
    for instance in CLIENTS:
        policies = data_of(f'{instance} 授权规则', '/v1alpha1/data-sandbox/trust-chain/policies',
                           tokens[instance], instance)
        if policies['items'] or policies['recent']:
            raise Failure(f'{instance} 不应留存中心端的规则台账与审计')
        tasks = data_of(f'{instance} 执行记录', '/v1alpha1/data-sandbox/trust-chain/tasks',
                        tokens[instance], instance)
        if tasks['items']:
            raise Failure(f'{instance} 不应留存中心端的执行记录')
    return True


def unbind(tokens):
    """解绑前置校验四项齐全；当前环境客户端有生效密钥与密文结果，应判定为不可解绑。"""
    result = {}
    for instance in CLIENTS:
        view = data_of(f'{instance} 解绑前置检查',
                       '/v1alpha1/data-sandbox/trust-chain/unbind-check', tokens[instance], instance)
        keys = [blocker['key'] for blocker in view['blockers']]
        if keys != ['ACTIVE_KEY', 'OPEN_EXPORT', 'LIVE_OBJECT', 'RUNNING_JOB']:
            raise Failure(f'{instance} 解绑校验项不完整：{keys}')
        if view['clean'] or not any(blocker['count'] > 0 for blocker in view['blockers']):
            raise Failure(f'{instance} 仍有未清理的数据关联，不应判定为可解绑')
        result[instance] = {blocker['key']: blocker['count'] for blocker in view['blockers']}
    return result


def peers(tokens, owners):
    """星形拓扑：客户端只有中心端一个对端，中心端持有两个客户端机构。"""
    for instance in CLIENTS:
        view = data_of(f'{instance} 对端连接', '/v1alpha1/data-sandbox/trust-chain/peer',
                       tokens[instance], instance)
        if not view['bound'] or len(view['peers']) != 1:
            raise Failure(f'{instance} 应恰好接入一个中心端，实际 {len(view["peers"])} 个')
        if view['peers'][0]['ownerId'] != owners[CENTER]:
            raise Failure(f'{instance} 的对端应为中心端 {owners[CENTER]}，'
                          f'实际 {view["peers"][0]["ownerId"]}')
    center_view = data_of('中心端对端连接', '/v1alpha1/data-sandbox/trust-chain/peer',
                          tokens[CENTER], CENTER)
    listed = {peer['ownerId'] for peer in center_view['peers']}
    for instance in CLIENTS:
        if owners[instance] not in listed:
            raise Failure(f'中心端对端列表缺少 {instance} 机构 {owners[instance]}')
    for peer in center_view['peers']:
        if peer['contractChannelReachable'] is not None:
            raise Failure('中心端不外呼契约通道，可达性应为空')
    return {'clients': sorted(listed)}


def end_guard():
    """回归保护：新接口没有绕开既有的端守卫。"""
    token, _ = login('CENTER', CENTER)
    body = denied('中心端以 CENTER 会话读取导出工单', '/v1alpha1/tee/exports/mine', token, CENTER)
    code = (body.get('data') or {}).get('errorCode') or body.get('status', {}).get('msg')
    if 'END_ROLE_DENIED' not in str(code):
        raise Failure(f'端守卫应返回 END_ROLE_DENIED，实际 {code}')
    return True


def main():
    checks = {}
    gaps = []
    try:
        session_checks, tokens, owners = sessions()
        checks.update(session_checks)
        checks['instanceEndpoint'] = instance_endpoint()
        checks['segments'] = segments(tokens)
        checks['ledgerMatchesDatabase'] = ledger_matches(tokens)
        checks['ciphertextPreview'] = preview(tokens, owners)
        checks['clientKeepsNoCenterLedger'] = client_empty(tokens)
        checks['unbindBlocked'] = unbind(tokens)
        checks['peerTopology'] = peers(tokens, owners)
        checks['endRoleGuardIntact'] = end_guard()
    except Failure as failure:
        gaps.append(str(failure))
    except (OSError, ValueError, KeyError, urllib.error.URLError) as error:
        gaps.append(f'{type(error).__name__}: {error}')
        traceback.print_exc()
    status = 'P8_ACCEPTED' if not gaps else 'P8_REJECTED'
    print(json.dumps({'status': status, 'checks': checks, 'gaps': gaps},
                     ensure_ascii=False, sort_keys=True))
    return 0 if not gaps else 1


if __name__ == '__main__':
    sys.exit(main())
