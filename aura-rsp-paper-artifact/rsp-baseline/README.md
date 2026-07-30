# OpenEUICC + osmo-smdpp 最小 RSP Baseline

这是一个用于 AURA-RSP 后续研究的**标准 Consumer eSIM RSP 对照组**。它不修改 OpenEUICC、lpac 或 osmo-smdpp 的认证协议，仅使用私有测试 PKI 和软件化 eUICC 客户端，完成可重复的 ES9+、BPP 下载/解密与安装结果通知闭环。

## 1. 已验证到什么程度

已通过：

- WSL2 Ubuntu 24.04 上部署 `osmo-smdpp`，以 HTTPS 提供 SM-DP+。
- 生成匹配的测试 CI、DP TLS、DP Auth、DP PB、EUM 和 eUICC 证书/密钥。
- 准备测试 UPP/profile 和 activation code。
- 根据 activation code 直接发现并连接 SM-DP+，不依赖 SM-DS。
- 完成 `initiateAuthentication`、`authenticateClient`、`getBoundProfilePackage`。
- 解密 BPP，得到 UPP、ISD-P 和 Store Metadata。
- 使用测试 eUICC 密钥签名并提交安装结果通知，服务端返回 HTTP 204。
- 编译 WSL 命令行 LPA 核心 lpac，包含 PC/SC 和 curl 驱动。
- 编译 OpenEUICC privileged/unprivileged 两个 debug APK。

没有连接实体测试 eUICC、PC/SC 读卡器或 Android 设备，因此**没有验证 ES10 APDU 实际写卡**。普通量产 eUICC 通常也不会信任本项目的私有测试 CI；硬件闭环需要使用支持测试 PKI、且证书链与本项目匹配的测试 eUICC。

## 2. 最小架构

```text
activation code
      |
      v
软件 eUICC/ES9+ 客户端 ---- HTTPS ----> osmo-smdpp
      |                                    |
      | eUICC/EUM 测试证书                 | DP TLS/Auth/PB 测试证书
      |                                    |
      +---- BPP 下载、解密、结果通知 <------+

实体扩展路径：
OpenEUICC(Android) / lpac(WSL) -> ES10 APDU -> 匹配测试 eUICC
```

这里的“发现”采用 activation code 中的 SM-DP+ 地址进行直接发现；SM-DS 被有意省略。EUM 也未部署为在线服务，只保留协议所需的 EUM→eUICC 测试证书链。这样简化了生态组件，但没有替换 ES9+/ES8+ 认证消息。

## 3. 项目目录

```text
rsp-baseline/
├── config/
│   ├── baseline.env              # 域名、端口、matching ID、activation code
│   └── activation-code.txt
├── docs/
│   └── TEST_REPORT.md            # 已验证证据和未覆盖边界
├── scripts/
│   ├── bootstrap_sources.sh      # 获取并锁定上游源码
│   ├── install_deps.sh           # Ubuntu/Python 依赖
│   ├── install_android_sdk.sh    # 官方 Android SDK/NDK
│   ├── generate_test_pki.py      # 生成私有测试证书链
│   ├── build_lpac.sh
│   ├── build_openeuicc.sh
│   ├── start_smdpp.sh
│   ├── stop_smdpp.sh
│   ├── run_software_demo.sh      # 完整软件 RSP 闭环
│   ├── check_baseline.sh
│   └── run_all.sh
├── third_party/
│   ├── openeuicc/
│   ├── lpac/
│   └── pysim/                    # osmo-smdpp、示例 UPP、ES9+ 客户端
├── build/lpac/
├── runtime/software-euicc-output/
├── logs/
├── requirements-rsp.lock
└── VERSIONS.md
```

`logs/`、`runtime/`、生成证书中的私钥都只用于本地测试，不应提交或用于生产。

## 4. 从零安装

先在 Windows 打开 Ubuntu，进入项目：

```bash
cd "/path/to/aura-rsp-paper-artifact/rsp-baseline"
chmod +x scripts/*.sh scripts/*.py
```

### 4.1 固定源码

当前目录已经含有固定版本源码。全新复制且 `third_party` 为空时运行：

```bash
./scripts/bootstrap_sources.sh
```

具体 commit 见 `VERSIONS.md`。

### 4.2 Ubuntu 与 Python 依赖

```bash
./scripts/install_deps.sh
```

默认 Python 环境位于：

```text
/home/niaodan/.venvs/rsp-baseline
```

如需换位置：

```bash
export RSP_BASELINE_VENV="$HOME/.venvs/rsp-baseline"
```

### 4.3 Android SDK 与 OpenEUICC

```bash
./scripts/install_android_sdk.sh
./scripts/build_openeuicc.sh
```

安装内容包括 Android 31/32/34/35、Build Tools 35.0.0、Platform Tools 和 NDK `26.1.10909125`。APK 输出：

```text
third_party/openeuicc/app/build/outputs/apk/debug/app-debug.apk
third_party/openeuicc/app-unpriv/build/outputs/apk/debug/app-unpriv-debug.apk
```

`app-debug.apk` 是需要系统权限/特权部署条件的完整 OpenEUICC；一般测试手机应先评估 `app-unpriv-debug.apk`，但它仍要求设备向应用暴露可用的 eUICC/OMAPI 接口。仅安装 APK 不等于设备允许第三方 LPA 管理内置 eSIM。

## 5. 运行可复现 baseline

### 5.1 一键运行

```bash
cd "/path/to/aura-rsp-paper-artifact/rsp-baseline"
./scripts/run_all.sh
```

脚本会在测试 PKI 缺失时生成它，然后构建 lpac、启动 SM-DP+、执行软件闭环并验证 TLS/下载证据。成功时最后应看到：

```text
SOFTWARE_RSP_BASELINE_PASS
INSTALL_NOTIFICATION_PASS transactionId=... iccid=8949449999999990007f
TLS_VERIFY_OK
ES9P_DOWNLOAD_EVIDENCE_OK
RSP_BASELINE_ALL_PASS
```

### 5.2 分步运行

```bash
./scripts/generate_test_pki.py
./scripts/build_lpac.sh
./scripts/start_smdpp.sh
./scripts/run_software_demo.sh
./scripts/check_baseline.sh
```

停止服务：

```bash
./scripts/stop_smdpp.sh
```

SM-DP+ 监听：

```text
https://testsmdpplus1.example.com:443
```

activation code：

```text
LPA:1$testsmdpplus1.example.com$TS48V2-SAIP2-1-NOBERTLV-UNIQUE
```

注意：在 shell 中必须使用单引号包住 activation code，否则 `$` 会被当成变量展开。

## 6. 协议证据

客户端日志：

```text
logs/es9p-client.log
```

服务端日志：

```text
logs/osmo-smdpp.log
```

解密结果：

```text
runtime/software-euicc-output/8949449999999990007f.upp.der
runtime/software-euicc-output/8949449999999990007f.isdp.der
runtime/software-euicc-output/8949449999999990007f.smr.der
```

测试脚本检查以下链路：

1. TLS 证书由私有测试 CI 验证通过。
2. `initiateAuthentication` 返回 transaction ID 和服务端签名材料。
3. `authenticateClient` 接收 eUICC/EUM 测试证书链和签名。
4. `getBoundProfilePackage` 返回与该事务和 eUICC 绑定的 BPP。
5. 客户端解密并保存 UPP/ISD-P/SMR。
6. 客户端提交签名安装结果，`handleNotification` 返回 HTTP 204。

`contrib/es9p_client.py` 是 Osmocom 提供的研究测试客户端，不是完整合规测试套件；其源码中仍有部分服务端签名/transaction ID 校验 TODO。因此本 demo 证明最小标准消息流和密码材料可互操作，不宣称通过 GSMA 认证。

## 7. 接入实体测试 eUICC

先确认 WSL 能看到 PC/SC 读卡器：

```bash
sudo systemctl enable --now pcscd
pcsc_scan
```

确认测试卡的 CI 公钥标识与本项目测试 PKI 匹配后：

```bash
LPAC="build/lpac/src/lpac"
export LPAC_APDU=pcsc
export LPAC_HTTP=curl
export CURL_CA_BUNDLE="$PWD/third_party/pysim/smdpp-data/generated/CertificateIssuer/CERT_CI_ECDSA_NIST.pem"

"$LPAC" chip info
"$LPAC" profile download -a 'LPA:1$testsmdpplus1.example.com$TS48V2-SAIP2-1-NOBERTLV-UNIQUE'
"$LPAC" profile list
```

只有在上述下载完成且 `profile list` 出现 ICCID 后，才能声称实体 ES10 写卡成功。OpenEUICC 设备侧使用同一个 activation code。

## 8. 常见问题

### `SCardEstablishContext ... 8010006A`

WSL 没有可用的 PC/SC 服务或读卡器。这不代表 lpac 编译失败。先启动 `pcscd`，再检查 USB 读卡器是否已被 Windows/WSL 正确暴露。

### 普通量产 eUICC 拒绝认证

本项目使用私有测试 CI。量产卡的信任锚通常不同，应换成支持 SGP.26/测试 PKI 的卡，并重新生成与卡内 CI 配置匹配的 DP/EUM/eUICC 材料；不要通过关闭证书验证伪造“成功”。

### 端口 443 被占用

```bash
sudo ss -ltnp 'sport = :443'
./scripts/stop_smdpp.sh
```

关闭冲突服务后再启动；若改端口，需要同步修改 `config/baseline.env` 和访问方式。

### 域名无法解析

启动脚本会确保 `/etc/hosts` 存在：

```text
127.0.0.1 testsmdpplus1.example.com
```

可用以下命令检查：

```bash
getent hosts testsmdpplus1.example.com
```

### 代理导致本地 HTTPS 请求失败

`common.sh` 会将测试域名、`127.0.0.1` 和 `localhost` 加入 `NO_PROXY/no_proxy`。若手工运行客户端，也要保留这些例外。

### lpac 报 CMake `CMP0177`

Ubuntu 24.04 自带 CMake 3.28 不理解该策略。本项目在隔离的 Python 环境中锁定 CMake 4.4，`build_lpac.sh` 会优先使用它。

### Gradle/Android SDK 报版本或 XML 警告

当前固定组合已经成功构建。关于 manifest namespace、Gradle 9 不兼容或 SDK XML 的信息均为上游/工具链警告，不是本次 debug APK 构建失败。真正失败时运行：

```bash
./scripts/build_openeuicc.sh
```

并从第一条 `FAILURE`/`error` 开始排查。

### 测试 TLS 证书过期

上游证书生成器的旧 TLS 截止时间已经过期。本项目包装器只把本地测试 TLS 证书截止日期延长到 2035 年；没有改认证协议代码。重新运行：

```bash
./scripts/generate_test_pki.py
```

## 9. AURA-RSP 后续研究边界

该目录应保留为不变的 baseline。后续 AURA-RSP 建议在独立分支/目录中引入方案，并至少对照：

- 握手消息数和端到端时延；
- 证书/签名/匿名凭证的字节开销；
- SM-DP+ 与 LPA/eUICC 计算开销；
- 重放、关联、冒充和撤销场景；
- profile 下载成功率及错误码分布。

不要直接覆盖本目录的测试证书、消息日志或成功标记，否则会失去可复现实验对照。
