# 实验7：跨服务器移植

本目录是独立实验，不修改 Standard RSP baseline，也不重写 AURA-RSP。实验捕获
设备针对 SM-DP+-A 生成的认证请求，再尝试把它移植到 SM-DP+-B。

## 一键运行

在 WSL2 Ubuntu 中执行：

```bash
cd /path/to/aura-rsp-paper-artifact/experiments/experiment-07-cross-server-transplant
bash ./run_demo.sh
```

只输出中文或英文：

```bash
bash ./run_demo.sh --lang zh
bash ./run_demo.sh --lang en
```

机器接口：

```bash
bash ./run_demo.sh --machine-json
```

## 实验覆盖

AURA-RSP 使用当前生产代码中的真实 BBS+ 凭证、盲签操作票据、联合匿名证明、
一次性 Ed25519 签名和 `AuraServerState.authenticate()`。正向控制分别证明
SM-DP+-A 与 SM-DP+-B 可以正常认证并生成 `Bind_t`。攻击覆盖：

1. 原样把 A 的认证请求直接交给 B；
2. 修改 `sid`；
3. 修改 `serverOID`；
4. 修改 `PRaddr`；
5. 只替换目标服务器地址；
6. 修改协商能力 `cap`；
7. 修改事务随机量 `N_S`。

第2、3、4、6、7项采用“白盒强攻击夹具”：在 B 端克隆 A 的其他会话字段，
只改变被测字段，使请求能够越过“事务不存在”的最早拒绝点。攻击者仍然保留
A 的原证明和原一次性签名。这样能单独验证被测字段确实受到票据、`tau_auth`
或 `Pi_auth` 约束；它不代表真实攻击者能控制 B 的会话数据库。

Standard 对照使用 baseline 中真实测试 CI/TLS 证书，并按 osmo-smdpp 当前源码
执行事务号、eUICC签名和 serverChallenge 的受控检查。它还保存源码哈希和行号
证据。该部分明确标为 `source-backed controlled check`，不是两套 osmo-smdpp
网络进程的完整端到端运行。

## 结果文件

- `results/latest/summary.json`：完整汇总和机器断言
- `results/latest/scenarios.csv`：逐场景结果
- `results/latest/assertions.csv`：机器断言
- `results/latest/report-zh.md`、`report-en.md`：双语论文表格
- `results/latest/raw/aura-transcripts.jsonl`：AURA公开转录
- `results/latest/raw/standard-checks.jsonl`：Standard受控检查
- `results/latest/evidence/source-audit.json`：源码哈希、检查点与实现边界
- `results/latest/paper/`：中英文论文图、图题和CSV表

## 正确解释

本实验不把 Standard RSP 描述成有漏洞。正确实现的 Standard RSP 通过服务器
证书、服务器签名、事务号和挑战绑定拒绝跨服务器移植。实验要证明的是：
AURA-RSP 删除稳定 EID/设备证书暴露后，仍保留同类的服务器与事务绑定能力，
攻击请求不会生成有效 `Bind_t`，也不会进入 Profile 交付。

baseline 的 pySim 示例客户端虽然启用了测试 CI 的 TLS 校验，但其源码仍打印
若干应用层 `serverSignature1`、服务器证书和 transactionId 校验 TODO。本实验
不会把这些实现 TODO 上升为 Standard 协议漏洞；报告会把 TLS、服务端检查和
客户端实现边界分开说明。
