# 实验2：MNO/Reseller 与 SM-DP+ 合谋及日志泄露

## 实验问题

当多个MNO/Reseller与共享SM-DP+交换日志，或者SM-DP+数据库整体泄露时，攻击者可以恢复多少“同一物理eUICC—不同MNO订单—不同Profile”的历史？

本目录是独立demo，不修改：

- `rsp-baseline/`
- `aura-rsp/`
- `experiment-01-shared-smdpp-linkability/`

## 重要口径

这是**受控协议可见日志实验**，默认生成每种协议1000条下载日志，但不声称实际执行了2000次完整网络下载。

当前AURA demo尚未实现论文中的完整生命周期状态机，因此 `downloaded/installed/enabled` 三类生命周期行仅用于验证“同一个Profile生命周期是否可在日志中关联”，字段中明确写有：

```text
semantic_scope=controlled_audit_log
```

不能把它描述为完整生命周期协议已经跑通。

## 默认规模

```text
250个模拟eUICC × 4个MNO = 1000条下载日志/协议
```

每个订单使用不同：

- 测试账号
- 订单号
- 授权标识
- Profile ID
- Profile摘要

因此攻击者不能通过重复账号关联设备。

## 一键运行

在WSL2 Ubuntu中：

```bash
cd /path/to/aura-rsp-paper-artifact/experiments/experiment-02-collusion-log-leakage
bash ./run_demo.sh
```

运行更小的20台设备版本：

```bash
bash ./run_demo.sh --devices 20
```

默认依次显示中文和英文终端结果。单独选择语言：

```bash
bash ./run_demo.sh --lang zh
bash ./run_demo.sh --lang en
```

机器JSON：

```bash
bash ./run_demo.sh --machine-json
```

不需要启动Standard SM-DP+、AURA SM-DP+或Privacy Relay。

## 2A：合谋分析

输入：

- MNO-A订单日志
- MNO-B订单日志
- 共享SM-DP+下载日志

第一步使用订单授权标识把MNO订单连接到当前下载事务。两种协议都应达到100%，因为AURA-RSP并不隐藏MNO卖了哪个Profile。

第二步尝试跨MNO、跨Profile恢复同一设备：

- Standard：用稳定EID、证书指纹和公钥指纹建立设备簇。
- AURA：只能按当前Profile的 `lph` 建立生命周期簇；不同Profile使用不同 `lph`。

## 2B：日志泄露

分析器获得SM-DP+数据库导出和审计日志：

- Standard预期形成250个设备簇，每簇4个Profile。
- AURA预期形成1000个Profile生命周期簇，每簇1个Profile。
- AURA同一 `lph` 下的生命周期事件仍可关联，这是方案有意保留的Profile级可见性。

## 结果目录

```text
results/latest/
├── raw/
│   ├── mno_reseller_logs.*
│   ├── smdpp_logs.*
│   ├── lifecycle_logs.*
│   └── ground_truth.*
├── exports/
│   ├── standard_rsp_smdpp_database_export.json
│   └── aura_rsp_smdpp_database_export.json
├── analysis/
│   ├── collusion_profile_recovery_by_device.*
│   └── leakage_profile_recovery_by_device.*
├── paper/
│   ├── figure-1-collusion-results-zh.svg
│   ├── figure-1-collusion-results-en.svg
│   ├── figure-2-log-leakage-radius-zh.svg
│   ├── figure-2-log-leakage-radius-en.svg
│   ├── figure-3-history-graph-standard_rsp-zh.svg
│   ├── figure-3-history-graph-standard_rsp-en.svg
│   ├── figure-3-history-graph-aura_rsp-zh.svg
│   ├── figure-3-history-graph-aura_rsp-en.svg
│   ├── table-1-collusion-leakage-zh.csv
│   ├── table-1-collusion-leakage-en.csv
│   ├── captions-and-analysis-zh.txt
│   └── captions-and-analysis-en.txt
├── summary.json
├── summary.csv
└── summary.md
```

## 指标解释

- `order_join_rate`：MNO订单能否对应到当前SM-DP+下载。
- `exact_device_history_recovery_rate`：能否完整恢复某台设备在作用域内的全部Profile，且不混入其他设备。
- `multi_mno_cluster_rate`：攻击者形成的簇中，有多少同时包含多个MNO。
- `cross_profile_pair_link_rate`：同设备不同Profile事务被归入同一簇的比例。
- `mean_profiles_per_cluster`：一份泄露日志平均暴露多少个互相关联的Profile。
- `within_profile_lifecycle_link_rate`：同一Profile生命周期事件是否可关联。

## 可以得出的结论

如果断言通过，可以表述为：

> AURA-RSP并不隐藏MNO自己的订单、Profile交付事实或同一Profile生命周期内的操作记录。它减少的是跨实体合谋和SM-DP+日志泄露的影响半径：Standard RSP的稳定设备身份材料允许恢复跨MNO设备级Profile历史，而AURA-RSP将可关联范围限制在一个订单和一个Profile生命周期。

不能把结果扩大解释为：

- 完整生命周期协议已经实现；
- PR与SM-DP+合谋仍然隐藏源地址；
- MNO不知道自己销售了哪个Profile；
- 已执行1000次真实网络下载；
- 终端、网络流量或业务系统不存在其他侧信道。
