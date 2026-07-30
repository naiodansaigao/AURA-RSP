# 实验5：恶意SM-DP+诱导追踪与栽赃

本实验验证：持有合法服务器签名密钥的恶意SM-DP+，能否通过修改挑战上下文，
诱导诚实eUICC为同一票据生成两份不同有效响应，再提交给EUM恢复EID。

实验直接测试当前AURA客户端的`LocalTicketLog`读取逻辑。Standard RSP baseline、
实验1至实验4均未被改写。

## 运行

在WSL2 Ubuntu中执行：

```bash
cd /path/to/aura-rsp-paper-artifact/experiments/experiment-05-malicious-smdpp-framing
bash ./run_demo.sh
```

只显示中文、英文或机器JSON：

```bash
bash ./run_demo.sh --lang zh
bash ./run_demo.sh --lang en
bash ./run_demo.sh --machine-json
```

## 实验做了什么

恶意SM-DP+保持同一`(v, opid)`，分别修改：

```text
N_S, I_t, cap, serverOID, sid, pid_h, op, PRaddr
```

- `N_S/I_t/cap/serverOID`可由持有合法服务器密钥的SM-DP+重新签名；
- `sid/PRaddr`还会被客户端的服务器上下文一致性检查拒绝；
- `pid_h/op`位于MNO签名票据内，直接修改会使票据签名无效。

生产客户端现在于`create_auth_proof`之前查询`LocalTicketLog[(v, opid)]`：

1. 首次使用：保存`ctx_t`哈希和完整认证请求；
2. 完全相同上下文：返回逐字节相同的缓存请求；
3. 不同上下文：抛出`LocalTicketContextConflict`，不生成新证明；
4. 旧版只有哈希的记录：失败关闭，不冒险生成第二份响应。

## 预期结果（当前源码）

```text
status = PASS
distinct_valid_responses = 1
trace_result = insufficient_valid_evidence
false_trace = false
```

## 输出

```text
results/latest/
├── summary.json
├── summary.csv
├── summary.md
├── FIX-VERIFICATION.md
├── raw/
│   ├── current-base-auth-request.json
│   ├── current-cached-replay-request.json
│   ├── attack-materials.jsonl
│   ├── events.jsonl
│   └── events.csv
├── evidence/
│   ├── source-audit.json
│   ├── current-eum-trace.json
│   └── assertions.json
└── paper/
    ├── figure-1-framing-outcome-zh.svg
    ├── figure-1-framing-outcome-en.svg
    ├── figure-2-field-matrix-zh.svg
    ├── figure-2-field-matrix-en.svg
    ├── table-1-field-results-zh.csv
    ├── table-1-field-results-en.csv
    ├── captions-and-analysis-zh.txt
    └── captions-and-analysis-en.txt
```

## 结论边界

本实验支持的结论是：当前原型在这组诱导追踪路径上，能够做到精确重传幂等、
上下文冲突终止以及EUM证据不足时不追踪。

它不是对全部AURA-RSP实现或所有攻击的通用安全证明。研究原型仍使用JSON文件
保存本地日志；生产eUICC需要受保护存储、原子写入、崩溃恢复、过期归档和容量限制。
