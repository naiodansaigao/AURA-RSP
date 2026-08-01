# 实验5：恶意 SM-DP+ 诱导追踪与栽赃

本实验验证持有合法服务器签名密钥的恶意 SM-DP+，能否反复修改挑战上下文，诱导诚实 eUICC 为同一 `(v,opid)` 生成两份不同有效响应，再向 EUM 栽赃并恢复其 EID。

完整实现直接使用 `pysim-aura-integration/pySim/esim/aura/local_ticket_log.py`。两个消融版本只存在于本实验目录，不是 AURA-RSP 支持的协议模式：

- `Full AURA-RSP`：按 `(v,opid)` 缓存，并比较完整规范化上下文；
- `Without LocalTicketLog`：完全不缓存第一次响应；
- `Key-only cache`：按 `(v,opid)` 返回旧响应，但故意不比较上下文。

## 运行

```bash
cd experiments/experiment-05-malicious-smdpp-framing
bash ./run_demo.sh
```

仅输出机器 JSON：

```bash
bash ./run_demo.sh --machine-json
```

快速冒烟测试：

```bash
bash ./run_demo.sh --attacks-per-field 10 --machine-json
```

## 正式实验规模

- 八个字段：`N_S`、`I_t`、`cap`、`serverOID`、`sid`、`pid_h`、`op`、`PRaddr`；
- 每字段、每模式 1000 次固定种子随机篡改；
- 每个模式 8000 次，总计 24000 条逐攻击记录；
- 同一票据恶意挑战数：1、2、4、8、16、32、64、128；
- 每种安全结果类别另生成并验证真实 BBS+ 证明，使用生产追踪公式恢复 `k` 并查询 EID。

批量层测量 LocalTicketLog 状态机和上下文分类，不虚构执行 24000 次秒级 BBS+ 配对。真实密码学路径单独保存在 `evidence/crypto-calibration.json`。

## 结果解释

`N_S`、`I_t`、`cap` 和 `serverOID` 可由持有合法密钥的恶意服务器修改并重签。完整实现对它们触发 `LocalTicketContextConflict`，不会计算新 `c`。删除 LocalTicketLog 后，这四类字段会产生第二份真实有效证明，EUM 能恢复诚实设备 EID。

`sid`、`PRaddr` 先被设备的订单上下文检查拒绝，`pid_h`、`op` 先被 MNO 票据签名拒绝，因此删除 LocalTicketLog 也不会让这四类攻击成功。正式汇总误追踪率为：

| 实现 | 误追踪率 |
|---|---:|
| Full AURA-RSP | 0% |
| Without LocalTicketLog（消融） | 50% |
| Key-only cache（消融） | 0% |

Key-only cache 虽未产生第二份有效追踪证据，却会把旧响应错误返回给新上下文，随后被证明上下文验证拒绝。因此“缓存”和“比较上下文”分别解决重复生成与状态一致性问题，两者缺一不可。

## 论文材料

- `paper/figure-5a-challenge-scaling-en-600dpi.png`：挑战数量与不同有效响应数；
- `paper/figure-5b-ablation-outcomes-en-600dpi.png`：三种实现的攻击结果分布；
- 同名 `zh` 文件：中文版本；
- `paper/table-5-field-ablation-en.csv`：八字段消融结果表；
- `raw/bulk-trials.csv/jsonl`：24000 条原始记录；
- `raw/per-field-results.csv`：字段级聚合；
- `evidence/crypto-calibration.json`：真实 BBS+ 与追踪校准；
- `evidence/assertions.json`：机器可检查断言。

该实验支持“LocalTicketLog 阻止恶意服务器单方面制造追踪证据”的实现结论，不替代完整形式化证明。研究原型使用 JSON 状态；生产 eUICC 仍需受保护、原子且可恢复的本地存储。
