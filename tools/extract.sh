#!/bin/bash
# 固件解包脚本
# 用法: ./extract.sh <firmware.bin>

set -e

if [ $# -lt 1 ]; then
    echo "用法: $0 <firmware.bin>"
    exit 1
fi

FW="$1"

if [ ! -f "$FW" ]; then
    echo "[!] 文件不存在: $FW"
    exit 1
fi

echo "[*] 文件信息"
ls -lh "$FW"
echo

echo "[*] 第一步：识别固件结构"
binwalk "$FW"
echo

echo "[*] 第二步：解包（需要 root 权限处理特殊文件）"
if [ "$(id -u)" -ne 0 ]; then
    echo "[!] 建议用 sudo 运行，否则可能解不出设备节点"
fi
binwalk -e --run-as=root "$FW"
echo

# 找到解包目录
EXTRACT_DIR="_${FW}.extracted"
if [ ! -d "$EXTRACT_DIR" ]; then
    echo "[!] 解包目录不存在: $EXTRACT_DIR"
    echo "    可能是 binwalk 版本问题，尝试手动指定偏移"
    exit 1
fi

ROOTFS="$EXTRACT_DIR/squashfs-root"
if [ ! -d "$ROOTFS" ]; then
    echo "[!] 未找到 squashfs-root，尝试查找其他文件系统"
    find "$EXTRACT_DIR" -maxdepth 2 -type d -name "*root*" 2>/dev/null
    exit 1
fi

echo "[*] 第三步：文件系统概览"
echo "    路径: $ROOTFS"
echo "    大小: $(du -sh "$ROOTFS" | cut -f1)"
echo
echo "    顶层目录:"
ls -1 "$ROOTFS" | head -20 | sed 's/^/      /'
echo

echo "[*] 第四步：架构识别"
for f in "$ROOTFS/bin/busybox" "$ROOTFS/usr/sbin/ipcamd"; do
    if [ -f "$f" ]; then
        echo "    $f:"
        file "$f" | sed 's/^/      /'
    fi
done
echo

echo "[+] 完成。下一步："
echo "    python3 tools/scan_strings.py $ROOTFS"
echo "    python3 tools/find_cgi.py $ROOTFS"
