#!/usr/bin/env python3
"""
扫描文件系统中的硬编码凭据

思路：
  1. 遍历所有文本类文件（.conf/.ini/.sh/.cgi 等）
  2. 用正则匹配常见的凭据字段
  3. 额外检查 base64 编码的可疑字符串

用法:
  python3 scan_strings.py <squashfs-root 目录>
"""
import os
import re
import sys
import base64
import binascii

# 常见的凭据字段名
CRED_PATTERNS = [
    re.compile(r'(?i)(password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key)\s*[=:]\s*(\S+)'),
    re.compile(r'(?i)(username|user|login|account)\s*[=:]\s*(\S+)'),
    re.compile(r'(?i)(root_password|admin_password)\s*[=:]\s*(\S+)'),
]

# 需要扫描的文本扩展名
TEXT_EXTS = {
    '.conf', '.cfg', '.ini', '.sh', '.cgi', '.txt', '.json',
    '.xml', '.properties', '.env', '.yml', '.yaml', ''
}

# 跳过的二进制目录
SKIP_DIRS = {'/lib', '/usr/lib', '/lib64'}

# 可能出现的 base64 字符串（长度 >= 8，只含 base64 字符集）
B64_PATTERN = re.compile(r'^[A-Za-z0-9+/]{8,}={0,2}$')


def is_text_file(path, max_size=2 * 1024 * 1024):
    """粗略判断是否文本文件"""
    try:
        if os.path.getsize(path) > max_size:
            return False
        with open(path, 'rb') as f:
            chunk = f.read(4096)
        # 含 NUL 字节基本是二进制
        return b'\x00' not in chunk
    except (OSError, PermissionError):
        return False


def try_b64_decode(s):
    """尝试 base64 解码，返回可读结果或 None"""
    if not B64_PATTERN.match(s):
        return None
    try:
        raw = base64.b64decode(s, validate=True)
        # 解出来必须是可打印 ASCII
        if len(raw) < 3:
            return None
        text = raw.decode('ascii')
        if all(32 <= ord(c) < 127 for c in text):
            return text
    except (binascii.Error, UnicodeDecodeError, ValueError):
        pass
    return None


def scan_file(path):
    """扫描单个文件，返回命中列表"""
    hits = []
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for lineno, line in enumerate(f, 1):
                line = line.rstrip('\n')

                # 1. 直接匹配凭据字段
                for pat in CRED_PATTERNS:
                    m = pat.search(line)
                    if m:
                        hits.append({
                            'type': 'credential',
                            'line': lineno,
                            'key': m.group(1),
                            'value': m.group(2),
                            'raw': line.strip()[:120]
                        })

                # 2. 检查 base64 编码的值
                for token in re.findall(r'[A-Za-z0-9+/]{8,}={0,2}', line):
                    decoded = try_b64_decode(token)
                    if decoded:
                        hits.append({
                            'type': 'base64',
                            'line': lineno,
                            'value': token,
                            'decoded': decoded,
                            'raw': line.strip()[:120]
                        })
    except (OSError, PermissionError):
        pass
    return hits


def main():
    if len(sys.argv) < 2:
        print(f'用法: {sys.argv[0]} <squashfs-root 目录>')
        sys.exit(1)

    root = sys.argv[1]
    if not os.path.isdir(root):
        print(f'[!] 目录不存在: {root}')
        sys.exit(1)

    print(f'[*] 扫描目录: {root}')
    print('=' * 70)

    total_hits = 0
    scanned = 0

    for dirpath, dirnames, filenames in os.walk(root):
        # 跳过库目录
        if any(dirpath.startswith(root + d) for d in SKIP_DIRS):
            continue

        for fn in filenames:
            path = os.path.join(dirpath, fn)
            ext = os.path.splitext(fn)[1].lower()

            if ext not in TEXT_EXTS:
                continue
            if not is_text_file(path):
                continue

            scanned += 1
            hits = scan_file(path)
            if hits:
                rel = os.path.relpath(path, root)
                print(f'\n[FILE] {rel}')
                for h in hits:
                    if h['type'] == 'credential':
                        print(f"  L{h['line']:<5} [凭据] {h['key']} = {h['value']}")
                    else:
                        print(f"  L{h['line']:<5} [base64] {h['value']} -> \"{h['decoded']}\"")
                total_hits += len(hits)

    print()
    print('=' * 70)
    print(f'[*] 扫描文件数: {scanned}')
    print(f'[*] 命中总数:   {total_hits}')

    if total_hits > 0:
        print()
        print('[!] 建议：逐一确认这些凭据是否为出厂默认值，')
        print('    如果是，说明所有同型号设备共享同一口令，属于高危问题。')


if __name__ == '__main__':
    main()
