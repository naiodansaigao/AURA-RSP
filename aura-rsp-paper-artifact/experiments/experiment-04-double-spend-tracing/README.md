# 实验4：票据双花、重放识别与条件追踪

本目录是完全独立的 AURA-RSP 差分实验，不修改：

- `rsp-baseline/`
- `aura-rsp/`
- 实验1、实验2、实验3

实验真实调用现有 AURA-RSP 的 BBS+ 凭证与票据、匿名证明验证、`UsedNullifier`
数据库分流、双花追踪公式、EUM 追踪索引、`Bind_t`、P-256 ECDHE、HKDF、
AES-GCM Profile 下载和安装通知代码。Standard RSP 部分只做稳定身份可见性对照。

## 一条命令运行

在 WSL2 Ubuntu 中执行：

```bash
cd /path/to/aura-rsp-paper-artifact/experiments/experiment-04-double-spend-tracing
bash ./run_demo.sh
```

默认依次打印中文和英文结果。也可以只显示一种语言：

```bash
bash ./run_demo.sh --lang zh
bash ./run_demo.sh --lang en
```

机器可读取的单行 JSON：

```bash
bash ./run_demo.sh --machine-json
```

## 三个子实验

### 4A 正常单次使用

设备使用一张新票据完成一次匿名认证、Profile 解密、摘要核验和安装通知。
预期只有一条 `UsedNullifier`，没有追踪记录，公开认证转录中没有 EID。

### 4B 完全相同报文重传

攻击代理保存首次认证请求的规范化字节，并逐字节重放。服务器重新验证证明后，
通过相同 `auth_hash` 识别精确重传，返回原缓存 `Bind_t` 并设置
`replayed=true`。实验检查只有一次 Profile 交付、一次业务执行和零追踪。

### 4C 真正双花

恶意 eUICC 测试夹具明确绕过 `LocalTicketLog`，复用同一票据的 `eta,d`，
在两个不同服务器上下文和不同 `opid` 下生成两份真实有效证明。两份证明具有：

- 相同 `nu`；
- 不同 `gamma`；
- 不同 `c`；
- 都能通过现有 `verify_auth_proof`。

服务端拒绝第二次业务执行，并计算：

```text
k = (c - c') * (gamma - gamma')^(-1) mod q
```

随后用隔离的 EUM 追踪索引 `L_tr[k]` 恢复违规设备 EID。

## 关键输出

运行结果位于 `results/latest/`：

```text
results/latest/
├── summary.json
├── summary.csv
├── summary.md
├── raw/
│   ├── events.jsonl
│   ├── events.csv
│   ├── aura-server-4a.jsonl
│   ├── aura-server-4b.jsonl
│   ├── aura-server-4c.jsonl
│   ├── 4a-auth-request.json
│   ├── 4b-auth-original.canonical.json
│   ├── 4b-auth-replay.canonical.json
│   ├── 4c-first-auth.json
│   └── 4c-second-auth.json
├── evidence/
│   ├── assertions.json
│   ├── database-4a.json
│   ├── database-4b.json
│   ├── database-4c.json
│   └── 4a-downloaded-profile.der
└── paper/
    ├── figure-1-scenario-outcomes-zh.svg
    ├── figure-1-scenario-outcomes-en.svg
    ├── figure-2-replay-double-spend-flow-zh.svg
    ├── figure-2-replay-double-spend-flow-en.svg
    ├── table-1-double-spend-results-zh.csv
    ├── table-1-double-spend-results-en.csv
    ├── captions-and-analysis-zh.txt
    └── captions-and-analysis-en.txt
```

论文中最直接使用的四个指标是：

- `trace_success`
- `recovered_eid_matches_malicious_device`
- `false_trace_count`
- `business_execution_count`

## 如何理解 Standard 对照

Standard RSP 从第一次正常 eUICC 认证起就可以看到 EID、eUICC 证书或稳定指纹，
因此不存在“平时匿名、违规后才追踪”的状态区分。这是标准身份认证的预期行为，
本实验不把它描述为消息完整性漏洞。

## 实验边界

- EUM 查询在本 demo 中由隔离的本地 `eum-trace.sqlite` 模拟，验证的是追踪触发条件、
  恢复公式和正确性；生产系统应拆成独立 EUM 服务和最小权限查询接口。
- 固定种子控制场景、上下文标签和测试材料；BBS+/P-256/Ed25519 的临时随机数仍使用
  密码学安全随机源，所以原始证明字节和耗时每次会变化，机器安全结论应保持一致。
- 本实验不测试生命周期状态机，也不把纯阻断型 DoS 纳入安全失败。
