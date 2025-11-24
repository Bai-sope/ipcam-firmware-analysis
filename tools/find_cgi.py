#!/usr/bin/env python3
"""
提取 Web CGI 接口清单

思路：
  1. 找到 web 目录下的 cgi-bin
  2. 列出所有可执行文件
  3. 从二进制里提取可能的参数名（getenv / get_param 的字符串引用）
  4. 判断每个 CGI 是否校验 cookie（简单启发式：搜索 "cookie" 字符串）

用法:
  python3 find_cgi.py <squashfs-root 目录>
"""
import os
import re
import sys
import subprocess

# 常见的参数名提取模式：从二进制里找连续的短字符串
PARAM_HINT = re.compile(rb'^[a-z][a-z0-9_]{2,30}$')


def find_cgi_dir(root):
    """在文件系统里定位 cgi-bin 目录"""
    candidates = []
    for dirpath, dirnames, _ in os.walk(root):
        if os.path.basename(dirpath).lower() in ('cgi-bin', 'cgi'):
            candidates.append(dirpath)
    return candidates


def extract_strings(path, min_len=4):
    """提取二进制里的可打印字符串"""
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except (OSError, PermissionError):
        return []

    # 用正则切分可打印序列
    pattern = re.compile(rb'[\x20-\x7e]{%d,}' % min_len)
    return [m.group().decode('ascii', 'ignore') for m in pattern.finditer(data)]


def guess_params(strings):
    """从字符串里猜参数名"""
    params = set()
    for s in strings:
        if PARAM_HINT.match(s.encode('ascii', 'ignore')):
            params.add(s)
    # 过滤掉明显的非参数词
    blacklist = {
        'true', 'false', 'null', 'none', 'error', 'success', 'failed',
        'application', 'text', 'html', 'json', 'xml', 'content', 'type',
        'length', 'charset', 'encoding', 'accept', 'connection'
    }
    return sorted(p for p in params if p not in blacklist)


def has_auth_check(strings):
    """判断是否包含 cookie / session 相关字符串"""
    keywords = ('cookie', 'Cookie', 'COOKIE', 'session', 'Session', 'token', 'auth')
    return any(any(k in s for k in keywords) for s in strings)


def main():
    if len(sys.argv) < 2:
        print(f'用法: {sys.argv[0]} <squashfs-root 目录>')
        sys.exit(1)

    root = sys.argv[1]
    if not os.path.isdir(root):
        print(f'[!] 目录不存在: {root}')
        sys.exit(1)

    cgi_dirs = find_cgi_dir(root)
    if not cgi_dirs:
        print('[!] 未找到 cgi-bin 目录')
        sys.exit(1)

    print(f'[*] 找到 {len(cgi_dirs)} 个 CGI 目录')
    print()

    total = 0
    no_auth = []

    for cgi_dir in cgi_dirs:
        rel = os.path.relpath(cgi_dir, root)
        print(f'[DIR] {rel}')
        print('-' * 70)

        for fn in sorted(os.listdir(cgi_dir)):
            path = os.path.join(cgi_dir, fn)
            if not os.path.isfile(path):
                continue

            total += 1
            strings = extract_strings(path)
            params = guess_params(strings)
            auth = has_auth_check(strings)

            mark = '  ' if auth else '⚠️'
            print(f'{mark} {fn}')
            print(f'     大小: {os.path.getsize(path)} bytes')
            print(f'     鉴权: {"有 cookie/session 检查" if auth else "未发现鉴权字符串"}')
            if params:
                print(f'     可能参数: {", ".join(params[:12])}')
            print()

            if not auth:
                no_auth.append(fn)

        print()

    print('=' * 70)
    print(f'[*] CGI 总数: {total}')
    print(f'[*] 疑似无鉴权: {len(no_auth)}')
    if no_auth:
        print()
        print('[!] 以下接口未发现鉴权检查，建议手工验证:')
        for n in no_auth:
            print(f'    - {n}')
        print()
        print('    验证方法：不带 cookie 直接请求，看是否返回正常数据。')


if __name__ == '__main__':
    main()
