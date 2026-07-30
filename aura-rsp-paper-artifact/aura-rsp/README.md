# AURA-RSP v14 Profile 下载仿真

本目录在不修改 `../rsp-baseline/` 源码和配置的前提下，实现论文
《AURA_RSP_BBSplus_Iac_PRaddr_最终定稿版_v14》的下载主链研究原型。

当前已实现：

- EUM 对隐藏 `x` 的 BBS+ 盲签设备凭证 `Cred_D`；
- MNO/Reseller 对隐藏 `(x, η, d)` 的 BBS+ 盲签操作票据 `Tok_op`；
- 同一 Fiat-Shamir 上下文中的组合证明 `Π_auth`：
  - 两份 BBS+ 凭证共享同一个隐藏 `x`；
  - `v = g_v^η`；
  - `lph = H_lph(pid_h || salt_p)^x`；
  - `c = d + γk mod q`；
- 一次性 Ed25519 会话签名 `τ_auth`；
- 由独立测试证书认证的 Privacy Relay；
- SM-DP+ 服务器认证、`Bind_t` 和能力绑定；
- P-256 ECDHE、HKDF-SHA256、AES-256-GCM profile 加密下载；
- 基于 `K_mac` 的 InstallReceipt；
- 相同认证消息的幂等重传；
- 同一票据不同有效认证消息的双花检测，以及由两组 `(γ,c)` 恢复 `k`；
- 与 EUM 追踪表联查测试 EID；
- 标准 RSP 与 AURA-RSP 的同机、同 profile 重复计时。

未实现 enable、disable、delete、reinstall 等后续生命周期操作。

## 1. 实验边界

这是软件 eUICC 仿真。长期秘密 `x` 保存在 `runtime/device.json`，用于证明协议与
密码构造可以运行，不代表真实 eUICC 安全域已经支持 BLS12-381 配对或能安全保存
这些材料。

Profile “安装完成”采用以下证据：

1. 软件 eUICC 成功完成匿名认证和密钥协商；
2. AES-GCM 解密成功；
3. 解密 profile 与标准 baseline 使用的 DER fixture 逐字节一致；
4. 客户端使用 `K_mac` 产生 InstallReceipt；
5. SM-DP+ 验证 HMAC 后记录 `installed`。

没有实体 eUICC，因此不执行 ES10 APDU 写卡。

## 2. 目录

```text
aura-rsp/
├── config/aura.json
├── src/aura_rsp/
│   ├── bbs.py                 # BBS+ 与盲签
│   ├── proof.py               # Π_auth 组合证明
│   ├── bootstrap.py           # 测试 PKI、Cred_D 和初始票据
│   ├── ticket.py              # 新 Tok_op 盲签发行
│   ├── client.py              # 软件 eUICC/LPA 侧
│   ├── relay.py               # Privacy Relay
│   ├── server.py              # AURA SM-DP+
│   ├── benchmark.py
│   └── validation_report.py
├── scripts/
├── runtime/                   # 运行时密钥、数据库和下载产物
├── logs/
└── results/
```

## 3. 安装

在 WSL2 Ubuntu 中执行：

```bash
cd /path/to/aura-rsp-paper-artifact/aura-rsp
chmod +x scripts/*.sh
./scripts/install_deps.sh
```

固定依赖：

- Python 3.12；
- `py-ecc==8.0.0`；
- `cryptography==49.0.0`；
- `requests==2.34.2`。

## 4. 一键运行

```bash
cd /path/to/aura-rsp-paper-artifact/aura-rsp
./scripts/run_all.sh
```

成功标志：

```text
AURA_CRYPTO_SELFTEST_PASS
AURA_RSP_DOWNLOAD_PASS
AURA_PROFILE_DOWNLOAD_EVIDENCE_OK
AURA_RSP_ALL_PASS
```

下载产物：

```text
runtime/software-euicc-output/
  TS48V2-SAIP2-1-NOBERTLV-UNIQUE.aura.upp.der
```

激活码形式：

```text
LPA:1$127.0.0.1:9444$TS48V2-SAIP2-1-NOBERTLV-UNIQUE
```

其中 9444 是 Privacy Relay，9443 是只接受 PR 测试客户端证书的 AURA SM-DP+。

## 5. 协议阶段

### 离线设备注册

`bootstrap.py` 生成 `x`，EUM 只收到包含隐藏 `x` 的 BBS+ commitment 及其知识证明。
EUM 生成 `r_tr` 和：

```text
k = H_tr(EID || r_tr) mod q
```

并保存：

```text
L_tr[k] = (EID, r_tr)
```

随后盲签 `(x,k,cred_exp)`。

### 离线操作票据

`ticket.py` 为每次正常下载生成新 `I_ac、η、d`。MNO 看到公开票据字段和盲签
commitment，不收到隐藏的 `x、η、d` 明文。

票据发行不计入在线 RSP 性能测量。

### 在线四阶段

1. `initiateAuthentication`
   - LPA 经 PR 发送 `N_U` 和能力；
   - SM-DP+ 从 mTLS 客户端证书得到观察到的 `PRaddr`；
   - 返回签名的 `I_t、N_S、N_U、sid、serverOID、PRaddr、cap`。
2. `authenticateClient`
   - 发送 `ctx_t、τ_auth、Π_auth`；
   - SM-DP+ 验证两份 BBS+ 凭证、共享 `x` 及三个附加关系；
   - 检查 nullifier 并签发 `Bind_t`。
3. `getBoundProfilePackage`
   - 一次性密钥签名 ECDHE 请求；
   - `ctx_K` 绑定 `Bind_t`、双方临时密钥和能力；
   - HKDF 分离 `K_enc/K_mac`；
   - AES-GCM 返回 profile。
4. `handleNotification`
   - 软件安装完成后生成 HMAC InstallReceipt；
   - 服务端验证后记录安装成功。

## 6. 安全测试

```bash
./scripts/test_aura.sh
```

覆盖：

- 正常匿名认证与下载；
- 同一认证消息重传返回缓存；
- 修改组合证明响应后拒绝；
- 替换 `Bind_t` 后拒绝；
- 同一个 `Tok_op` 生成不同有效认证消息时识别双花；
- 使用两个 `c=d+γk` 响应恢复 `k`；
- 使用 EUM 追踪表恢复测试 EID；
- 下载 profile 与 baseline fixture 逐字节比较。

机器可读报告：

```text
results/validation-report.json
```

## 7. 性能测试

确保标准 baseline 的 osmo-smdpp 正在运行，然后执行：

```bash
./scripts/benchmark.sh 10
```

计时口径：

- 同一 WSL2 主机；
- 同一 12,207 字节 profile；
- 1 次预热，10 次正式测量；
- 服务启动时间不计入；
- TLS、客户端进程、协议密码计算、下载通知和产物校验计入；
- AURA 离线票据发行不计入。

报告：

```text
results/latest-benchmark.json
results/latest-benchmark.md
```

当前机器的正式结果：

| 指标 | 标准 RSP | AURA-RSP |
|---|---:|---:|
| 平均端到端墙钟时间 | 1527.437 ms | 2962.844 ms |
| 中位数 | 1529.952 ms | 2963.424 ms |
| P95 | 1537.802 ms | 2980.237 ms |
| 标准差 | 11.347 ms | 10.954 ms |

AURA 平均增加 1435.407 ms，为标准 RSP 的 1.940 倍，即约增加 93.97%。

AURA 内部在线协议平均 2529.483 ms：

- `Π_auth` 生成：1238.506 ms；
- `Π_auth` 验证：1147.001 ms；
- profile 服务器侧 ECDHE/HKDF/AEAD：约 1 ms；
- profile 客户端 AES-GCM 解密：约 0.1 ms。

说明：PR 累计转发时间包含等待 SM-DP+ 完成证明验证的时间，不能再与证明验证时间
直接相加。

## 8. 研究注意事项

- `bbs.py` 和 `proof.py` 是基于 `py-ecc` 的研究参考实现，没有经过独立密码审计。
- BBS+ 参数、消息顺序、域分离字符串和规范编码已在代码中固定；论文实验必须引用
  对应 commit/归档版本。
- Python 配对性能不能代表优化后的 Rust/C 或真实安全芯片性能。
- baseline 的 pySim 软件客户端本身带有若干上游 TODO，因此此次比较是两个研究 demo
  的端到端工程耗时对比，不是 GSMA 合规认证结果。
- 真正验证“秘密始终位于 eUICC”需要可编程 test-eUICC/JavaCard 或厂商安全域接口。
