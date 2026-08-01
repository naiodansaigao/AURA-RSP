# 实验2：MNO/Reseller与SM-DP+合谋及日志泄露

## 实验目标

本实验验证多个MNO/Reseller与共享SM-DP+交换日志，或SM-DP+数据库整体泄露时，攻击者能够恢复多少“物理eUICC—MNO订单—Profile”历史。

实验已迁移到`pysim-aura-integration`：Standard记录使用集成版测试eUICC身份材料；AURA记录直接复用集成版的BLS12-381 `nu/lph`、统一认证上下文、Binding上下文、安装收据和enable状态收据公式，不再由实验脚本自行模拟AURA密码学字段。

## 实验口径

这是批量协议可见日志分析，不是1000次吞吐量或HTTPS端到端下载测试。默认生成：

```text
250个模拟eUICC × 4个MNO = 每种协议1000条下载记录
```

每个订单使用独立的测试账号、订单号、授权标识、Profile ID和Profile摘要，避免账号复用成为额外关联信号。两种协议使用相同Profile大小和网络出口。

AURA的`downloaded`日志来自集成交付上下文；`installed`和`enabled`日志分别由集成版安装收据及认证状态收据公式生成。批量实验省略随机化BBS+证明主体和每条记录的HTTPS传输，这些路径由`pysim-aura-integration`回归测试单独覆盖。

## 2A：合谋分析

输入包括MNO-A、MNO-B订单日志和共享SM-DP+日志。分析器先通过订单授权标识连接订单与对应下载，再尝试跨MNO、跨Profile恢复同一设备历史：

- Standard RSP使用稳定EID、eUICC证书指纹和公钥指纹建立设备簇。
- AURA-RSP只能按当前Profile生命周期的`lph`建立簇；不同Profile使用不同`lph`。

订单连接率在两种协议中都应为100%，因为AURA-RSP不隐藏MNO自己的订单和交付事实。

## 2B：日志泄露

分析器获得共享SM-DP+下载日志及生命周期日志：

- Standard RSP预期形成250个设备簇，每簇4个Profile。
- AURA-RSP预期形成1000个Profile生命周期簇，每簇1个Profile。
- AURA同一`lph`下的生命周期事件仍然可关联，这是方案有意保留的Profile级可见性。

## 运行命令

在WSL2 Ubuntu中：

```bash
cd experiments/experiment-02-collusion-log-leakage
bash ./run_demo.sh
```

先运行20台设备的冒烟测试：

```bash
bash ./run_demo.sh --devices 20
```

机器可读输出：

```bash
bash ./run_demo.sh --machine-json
```

不需要手动启动SM-DP+或Privacy Relay。

## 输出

结果位于`results/latest/`：

- `raw/`：MNO、SM-DP+、生命周期和独立ground truth日志；
- `exports/`：两种协议的SM-DP+泄露数据库导出；
- `analysis/`：逐设备恢复结果；
- `paper/`：中英文表格、图和说明；
- `summary.json/csv/md`：机器可检查的完整结论。
- `publication-simple/experiment2-log-leakage-radius-en-600dpi.png`：4项每簇泄露影响半径。0/1型关联率保留在结果表中，不单独占用论文图。

`summary.json`中的`design.implementation_audit`记录实际复用的集成模块、源码SHA-256、能力模式和批量实验边界。

重新生成600 DPI论文图：

```bash
python plot_experiment2_simple.py
```

## 关键指标

- `order_join_rate`：MNO订单能否连接到对应SM-DP+下载。
- `exact_device_history_recovery_rate`：能否完整且无混淆地恢复设备在作用域内的全部Profile。
- `multi_mno_cluster_rate`：攻击者形成的簇中包含多个MNO的比例。
- `cross_profile_pair_link_rate`：同一设备的不同Profile事务被归入同一簇的比例。
- `mean_profiles_per_cluster`：一份泄露日志平均暴露多少个相互关联的Profile。
- `within_profile_lifecycle_link_rate`：同一Profile生命周期事件能否关联。

## 结论边界

AURA-RSP不隐藏MNO自己的订单、Profile交付事实或同一Profile生命周期内的操作记录。它降低的是跨实体合谋与SM-DP+日志泄露的影响半径：Standard RSP的稳定设备身份材料允许恢复跨MNO设备级Profile历史，而AURA-RSP把可关联范围限制在单个订单和单个Profile生命周期。

不得把本实验描述为执行了1000次完整网络下载，也不得扩展为对账号复用、端点失陷、PR与SM-DP+合谋或全局流量观察者的防护结论。
