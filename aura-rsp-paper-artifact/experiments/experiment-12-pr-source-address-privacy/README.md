# 实验12：PR源地址保护与PR–SM-DP+合谋

本实验是独立的网络元数据差分Demo，不修改Standard RSP、AURA-RSP认证、Profile
Binding、密钥协商或Profile交付代码。它比较同一批受控事务在三种观察模式下的关联
能力：

- 12A：设备直连SM-DP+，服务端看到每台设备稳定的源IP；
- 12B：所有设备通过共享Privacy Relay，服务端只看到统一PR出口IP；
- 12C：PR与SM-DP+交换入口/出口时间和流量大小日志，运行真实的一对一匹配算法。

## 一键运行

在WSL2 Ubuntu中执行：

```bash
cd /path/to/aura-rsp-paper-artifact/experiments/experiment-12-pr-source-address-privacy
bash ./run_demo.sh
```

默认生成100台模拟设备，每台4次事务，共400条事务。也可以运行小规模演示：

```bash
bash ./run_demo.sh --devices 20 --transactions 4
```

语言与机器接口：

```bash
bash ./run_demo.sh --lang zh
bash ./run_demo.sh --lang en
bash ./run_demo.sh --machine-json
```

## 攻击者可见信息

12A/12B的IP分析器只读取SM-DP+正常可见的`observed_source_ip`，真实设备标签只存在于
独立ground truth中。

12C的合谋分析器读取：

- PR入口日志：`ingress_id`、`device_ip`、`ingress_time_ms`、`flow_size_bytes`；
- SM-DP+出口日志：`session_id`、`session_time_ms`、`message_size_bytes`、
  `profile_request`。

两个日志没有共同事务号。匹配器按照时间残差和流量大小残差计算代价，再执行全局贪心
一对一匹配；设备标签和ground truth不参与匹配。

## 指标

- `ip_pairwise_roc_auc`：仅凭源IP区分两次事务是否来自同一设备；
- `ip_pairwise_balanced_accuracy`：同设备与不同设备两类召回率的平均值，避免负样本
  数量远大于正样本造成普通accuracy虚高；
- `exact_device_history_recovery`：攻击者聚类是否完整、精确恢复一台设备的全部事务；
- `mean_device_anonymity_set`：每个可见源IP背后平均包含多少台真实设备；
- `expected_ip_identification_rate`：只知道源IP时随机猜中真实设备的期望概率；
- `collusion_match_accuracy`：PR入口记录与SM-DP+出口会话一对一匹配正确率；
- `full_device_history_recovery`：合谋后四次事务全部匹配正确的设备比例。

## 结果文件

- `results/latest/summary.json`：完整结果与机器断言
- `results/latest/mode-metrics.csv`：三种模式主要指标
- `results/latest/assertions.csv`：机器断言
- `results/latest/raw/ground-truth.jsonl`：仅用于评估的真值
- `results/latest/raw/direct-smdpp.jsonl`：12A服务端日志
- `results/latest/raw/shared-pr-smdpp.jsonl`：12B服务端日志
- `results/latest/raw/pr-ingress.jsonl`：12C的PR入口日志
- `results/latest/raw/smdpp-egress.jsonl`：12C的SM-DP+出口日志
- `results/latest/analysis/`：IP簇、混淆矩阵和合谋匹配明细
- `results/latest/report-zh.md`、`report-en.md`：双语报告
- `results/latest/paper/`：中英文论文图、数据表和图题

## 仿真边界

本Demo使用固定种子的受控网络元数据轨迹，不代表100台物理eUICC或真实公网抓包。
它验证的是地址可见性和流量分析机制，不测量真实运营网络中的NAT变化、时钟漂移、
PR批处理、填充、混合网络或多PR级联。

12A让每台模拟设备在四次事务中保持同一源IP，用来构造“稳定IP可辅助关联”的受控
上界；真实移动网络中IP轮换、CGNAT或多人共享出口会改变该数值。12C的0—1匹配结果
也取决于配置中的并发度、时延抖动、流量大小噪声和攻击者时钟校准能力。

12C成功关联是论文威胁模型已声明的预期边界：共享PR提供源地址隔离，但不抵抗PR与
SM-DP+合谋，或同时观察入口和出口流量的全局观察者。该结果不应写成AURA协议漏洞。
