# 实验4：双花、精确重传与条件追踪

本目录是基于 `pysim-aura-integration` 的独立实验。它不再导入旧
`aura-rsp`，并直接复用集成版的：

- BBS+ 凭证、操作票据和联合证明；
- `gamma`、`c`、nullifier 与追踪密钥恢复公式；
- SM-DP+ 生产双花判定顺序；
- EUM `k -> EID` 查询语义。

## 运行

```bash
cd experiments/experiment-04-double-spend-tracing
bash ./run_demo.sh
```

小规模冒烟测试：

```bash
bash ./run_demo.sh --tickets 40 --max-db-size 1000 --machine-json
```

## 两层测量口径

实验明确分离两个阶段，避免混淆：

1. **真实密码学路径**：使用集成版 `create_auth_proof()` 和
   `verify_auth_proof()` 生成并验证同一票据的两份不同有效转录，随后真实恢复
   `k` 并查询 EID。
2. **UsedNullifier 数据库路径**：证明已经验证后，使用与生产服务相同的
   `classify_nullifier()` 判定函数，在 SQLite WAL、唯一主键和原子事务上测量
   新记录、精确重传和真正双花的分类延迟。

因此，图4(a)和图4(c)表示数据库分类阶段，不包含约秒级的BBS12-381配对；
图4(d)单独给出密码学验证和条件追踪各组成部分。

## 默认规模

- 每个混合场景：1000张票据；
- 双花比例：0%、1%、5%、10%、20%、50%；
- 精确重传次数：1、2、4、8、16；
- 真正双花转录数：2、4、8；
- 并发度：1、8、32；
- 票据到达窗口：0--5000 ms；
- UsedNullifier：10²、10³、10⁴、10⁵；
- 每种数据库规模、每类请求：100次真实测量。

`10^6` 被保留为可选扩展规模，但默认止于 `10^5`，以避免在论文复现环境中
生成过大的临时数据库。若需要，可把 `config.json` 的 `sizes` 增加到
`1000000` 后运行。

## 正确语义

- 新 nullifier：只执行一次业务并写入一条唯一记录；
- 完全相同认证报文：返回幂等缓存，不执行第二次业务，不追踪；
- 相同 nullifier 的不同有效转录：拒绝第二次业务，恢复 `k` 并查询 EID；
- 同一 `(nu, opid)` 的不同上下文：按集成版生产顺序返回上下文冲突，不作为
  可追踪双花证据。

## 输出

```text
results/latest/
├── summary.json
├── raw/
│   ├── mixed-events.csv/jsonl
│   ├── mixed-scenarios.csv
│   ├── scale-samples.csv
│   └── trace-breakdown-samples.csv
├── evidence/assertions.json
└── paper/
    ├── figure-4a-nullifier-scale-latency.png
    ├── figure-4b-request-outcomes.png
    ├── figure-4c-nullifier-latency-scatter.png
    ├── figure-4d-tracing-breakdown.png
    └── table-4-mixed-load.csv
```

四张PNG均使用英文、大字号、粗线条、紧凑裁边和600 DPI。

## 边界

- 这是研究原型的本地 SQLite 性能测试，不代表工业集群数据库吞吐。
- 入口到达窗口用于制造受控并发，不计入单条请求的分类延迟。
- Standard RSP从首次认证起即可获知稳定设备身份，因此没有AURA所定义的
  “正常匿名、双花后条件追踪”区分；本实验不把Standard的身份认证描述为漏洞。
