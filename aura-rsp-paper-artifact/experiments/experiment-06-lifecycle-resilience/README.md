# 实验6：生命周期重放、分叉与删除故障恢复

论文英文名称：

> Lifecycle Resilience under Replay, Concurrency, and Message Loss

本实验独立验证 AURA-RSP 匿名 Profile 生命周期的状态连续性。
实验直接调用 `pysim-aura-integration/pySim/esim/aura/lifecycle.py` 集成实现，
使用真实 HMAC、SQLite 事务和原子 CAS。

## 子测试

- 6A：旧状态收据重放，以及最新收据的幂等重试。
- 6B：篡改`st_old/st_new/ctr/last_hash/lph/rid/HMAC`。
- 6C：从同一前驱并发执行enable与delete。
- 6D：prepare-delete成功但`Rprep`响应丢失。
- 6E：`CommitReceipt`消息丢失，以及最终确认丢失。
- 6F：prepare-delete后票据到期，继续完成commit-delete。

## 运行

```bash
cd experiments/experiment-06-lifecycle-resilience
bash ./run_demo.sh
```

只显示中文、英文或机器JSON：

```bash
bash ./run_demo.sh --lang zh
bash ./run_demo.sh --lang en
bash ./run_demo.sh --machine-json
```

## 判定口径

状态记录为：

```text
(lph, state, ctr, last_hash)
```

状态收据由设备侧HMAC认证；服务器在SQLite`BEGIN IMMEDIATE`事务中重新读取当前行，
验证状态、计数器和前驱摘要，再用带前驱条件的`UPDATE ... WHERE`执行原子CAS。

删除采用两阶段提交：

```text
installed/disabled -> pending-delete -> tombstone
```

prepare成功后，服务器持久化完全相同的`Rprep`。commit-delete只依赖已经持久化的
pending-delete记录和有效`Rprep`，不重新要求原删除票据仍在有效期内。

## Standard对照边界

集成代码的 Standard 模式只执行下载、BPP处理和安装通知，没有可调用的enable、disable、
两阶段delete或生命周期状态链测试接口。因此Standard在本实验中报告`UNSUPPORTED`，
而不是被描述为“接受重放”或“存在标准协议漏洞”。

## 输出

```text
results/latest/
├── summary.json
├── summary.csv
├── summary.md
├── raw/
│   ├── events.jsonl
│   ├── events.csv
│   └── subtests.json
├── evidence/
│   ├── assertions.json
│   ├── standard-baseline-audit.json
│   └── database-snapshots.json
├── databases/
│   └── 6a.sqlite ... 6f.sqlite
└── paper/
    ├── figure-1-lifecycle-results-zh.svg
    ├── figure-1-lifecycle-results-en.svg
    ├── figure-2-delete-recovery-zh.svg
    ├── figure-2-delete-recovery-en.svg
    ├── table-1-subtests-zh.csv
    ├── table-1-subtests-en.csv
    ├── captions-and-analysis-zh.txt
    └── captions-and-analysis-en.txt
```

## 结论边界

实验验证的是当前研究原型中实现的状态链、收据认证、原子CAS和删除恢复语义。
SQLite的`BEGIN IMMEDIATE`相当于本实验部署中的写锁；生产系统若更换数据库，必须保留
等价的行锁、串行化事务或compare-and-swap语义，否则并发分叉安全结论不成立。
