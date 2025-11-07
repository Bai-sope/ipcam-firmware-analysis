# IP 摄像机固件安全分析

对一款家用 IP 摄像机固件做静态与动态分析，梳理攻击面、验证命令注入漏洞，并给出加固建议。

> ⚠️ 说明：本文档涉及的设备型号已隐去，测试样本为自购二手设备，分析全程在隔离网络内进行，未对任何在线设备发起测试。

## 背景

家用 IP 摄像机是 IoT 设备中漏洞最密集的品类之一。厂商为压缩成本，常在固件里保留调试接口、硬编码凭据，且长期不更新。

本项目作为物联网安全方向的入门研究，目标是完整走一遍固件分析的流程：**提取 → 仿真 → 逆向 → 验证 → 加固建议**。

## 环境

| 工具 | 版本 | 用途 |
|---|---|---|
| binwalk | 2.3.4 | 固件解包、文件系统识别 |
| FirmAE | 1.0 | 全系统仿真（MIPS） |
| QEMU | 7.2 | 单程序仿真 |
| Ghidra | 10.4 | 静态反编译 |
| IDA Pro | 7.7 | 辅助静态分析 |
| gdb-multiarch + pwndbg | - | 动态调试 |
| pwntools | 4.11 | PoC 编写 |
| UART (CH340) | - | 硬件调试口接入 |

## 分析流程

```
固件获取 → binwalk 解包 → 文件系统分析 → 架构识别
    ↓
FirmAE 仿真 → Web 服务复现 → 攻击面梳理
    ↓
静态逆向（Ghidra）→ 定位危险函数 → 构造 PoC → 动态验证
    ↓
输出报告 + 加固建议
```

## 关键发现

| # | 问题 | 风险等级 | 状态 |
|---|---|---|---|
| 1 | bootloader 阶段存在未鉴权 telnet 服务 | 高 | 已确认 |
| 2 | Web CGI 接口存在命令注入 | 高 | 已确认（PoC） |
| 3 | 配置文件硬编码 root 口令 | 中 | 已确认 |
| 4 | 固件使用固定密钥签名，可重打包 | 中 | 疑似，未进一步验证 |

## 目录结构

```
ipcam-firmware-analysis/
├── report/
│   └── analysis-report.md     完整分析报告（核心产出）
├── tools/
│   ├── extract.sh             一键解包脚本
│   ├── scan_strings.py        批量搜硬编码凭据
│   └── find_cgi.py            提取 CGI 接口清单
├── poc/
│   └── cmd_injection.py       命令注入 PoC（针对仿真环境）
└── images/
    └── README.md              截图说明（实物照片不放仓库）
```

## 快速开始

### 1. 解包固件

```bash
chmod +x tools/extract.sh
./tools/extract.sh firmware.bin
```

输出在 `./_firmware.bin.extracted/squashfs-root/`

### 2. 扫描硬编码凭据

```bash
python3 tools/scan_strings.py ./_firmware.bin.extracted/squashfs-root
```

### 3. 提取 CGI 接口

```bash
python3 tools/find_cgi.py ./_firmware.bin.extracted/squashfs-root
```

### 4. 仿真（需要 FirmAE）

```bash
cd FirmAE
sudo ./run.sh -r mips ./firmware.bin
```

仿真成功后 Web 服务监听在 `http://127.0.0.1:80`

### 5. 验证 PoC

```bash
python3 poc/cmd_injection.py --target http://127.0.0.1 --cmd "id"
```

## 踩过的坑

1. **binwalk 解不出 Squashfs**
   固件前 1MB 是 bootloader + kernel，直接 binwalk 会漏掉后段。加 `-e` 参数并手动指定偏移（用 `binwalk firmware.bin` 先看魔数位置）后成功。

2. **FirmAE 仿真启动失败，卡在 `init`**
   报错 `can't open /dev/nvram`。原因是固件依赖 NVRAM 存储配置，而 QEMU 没有对应设备。
   解决：FirmAE 会自动创建假的 NVRAM 文件，但需要手动在 `scratch/` 目录下补一个 `nvram.ini`，填入最小默认值（如 `lan_ip=192.168.1.1`）。

3. **UART 接线后没有输出**
   一开始把 TX/RX 接反了，且波特率猜错。正确做法：先量电压确认 VCC/GND，用示波器看 TX 引脚的波形估算波特率，常见是 115200 或 57600。接反时不会烧板子，只是没输出。

4. **Ghidra 反编译 MIPS 代码变量名全是 `undefined4`**
   需要先导入固件里的符号表（如果有）。没有符号表时，靠函数调用约定（MIPS o32：参数在 $a0-$a3）手工标注，工作量很大。优先看字符串引用（`Search → For Strings`）再交叉引用，效率高得多。

5. **CGI 程序是静态链接的，无法用 QEMU 单跑**
   静态链接 + uClibc，直接 `qemu-mips` 会报 `no such file`。改用 `qemu-mips -L ./lib ./cgi-bin/xxx` 指定库路径，或者干脆用 FirmAE 全系统仿真。

## 加固建议

针对发现的问题，给出以下建议（已整理进报告）：

1. **关闭 bootloader 阶段的 telnet**，或至少要求认证
2. **CGI 参数做白名单校验**，禁止拼接进 `system()` / `popen()`
3. **移除硬编码凭据**，首次启动强制用户设置口令
4. **启用固件签名校验**，防止重打包
5. **建立固件更新通道**，及时修复已知漏洞

## 免责声明

本项目仅用于安全研究与教学。所有测试均在本地隔离环境完成，未对任何真实在线设备发起攻击。请勿将相关技术用于未授权的测试。
