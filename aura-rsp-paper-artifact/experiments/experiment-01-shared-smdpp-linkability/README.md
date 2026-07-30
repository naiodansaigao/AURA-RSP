# 实验1：共享 SM-DP+ 跨 Profile 关联

## 实验问题

共享 SM-DP+ 能否仅凭正常可见的认证与下载记录，把不同 MNO、不同订单、不同 Profile 的事务归并到同一物理 eUICC？

本目录是一个独立最小 demo，不修改：

- `rsp-baseline/`
- `aura-rsp/`

## 实验口径

该 demo 是**受控协议可见转录实验**，不是 80 次 Standard 网络下载加 80 次 AURA 网络下载。它复用现有源码的字段语义，生成 SM-DP+ 在各协议中可见的最小记录，然后真实执行关联分析。

- Standard：每台模拟 eUICC 固定一个 EID、证书指纹和证书公钥指纹；这符合当前 osmo-smdpp 在 `authenticateClient` 中接收 eUICC 证书、保存证书并提取 EID 的行为。
- AURA：每个事务使用新的 `I_ac`、`nu`、`opid`、一次性 `vk_t` 和会话公钥；每个 Profile 使用不同 `pid_h` 与 `lph`。当前 AURA 源码把论文中的 nullifier `ν` 命名为字段 `v`，本实验报告统一写作 `nu`。
- 两组使用相同下载时间计划、Profile 大小、网络出口和共享 SM-DP+。
- 每个 Profile 有独立订单、测试账号、Profile ID 和 Profile 内容摘要。
- 每个逻辑 Profile 由同一基准 UPP 的末 32 字节替换为固定种子派生标记，因而内容不同但大小完全相同；这些派生 Profile 只用于计算不同 `pid_h`，不会写入或安装到 eUICC。

真实设备标签和内部逻辑下载编号保存在 `ground_truth.*` 中，只供评分使用。`standard_smdpp_view.*` 和 `aura_smdpp_view.*` 不含 `true_device_id` 或 `logical_download_id`，分类器不能读取答案。

## 默认规模

- 20 个模拟 eUICC
- 4 个 MNO
- 每台 eUICC 从每个 MNO 获取一个不同 Profile
- 每种协议 80 条事务

这是比 50 台/200 条更轻的 demo，但仍有足够的正负样本进行 5 折交叉验证。可使用 `--devices` 临时调整。

## 一键运行

在 WSL2 Ubuntu 中：

```bash
cd /path/to/aura-rsp-paper-artifact/experiments/experiment-01-shared-smdpp-linkability
chmod +x run_demo.sh
./run_demo.sh
```

运行更小的 8 台设备版本：

```bash
./run_demo.sh --devices 8
```

不需要启动 Standard SM-DP+、AURA SM-DP+ 或 Privacy Relay，因为本实验只检验关联所需的协议可见字段。

默认会依次显示中文版和英文版终端表格。只显示中文：

```bash
./run_demo.sh --lang zh
```

只显示英文：

```bash
./run_demo.sh --lang en
```

## 分析方法

### 1. 完全相同稳定标识直接分组

- Standard 使用 EID、eUICC 证书指纹和证书公钥指纹。
- AURA 检查 `nu/lph/opid/vk_t/proof_hash/Bind_t_hash/session_public_key` 是否重复。
- `sid`、共享出口、Profile 大小等所有人共同拥有的值不能作为设备标识，因此不用于直接设备分组。

### 2. 成对分类器

脚本从所有跨 MNO 事务对中构造：

- 正样本：属于同一真实设备；
- 负样本：属于不同真实设备；
- 正负样本数量相同；
- 特征：稳定字段相等性、临时字段相等性、字符串公共前缀、时间接近度、MNO、出口和大小等公开信息。

分类器是脚本内从零实现的逻辑回归，使用固定随机种子和 5 折分层交叉验证，不依赖 scikit-learn。ROC-AUC、accuracy、balanced accuracy、precision、recall 和 F1 都由真实预测计算。

### 3. 设备聚类

报告同时给出：

- 稳定标识直接分组；
- 分类器得分大于等于 0.5 后，通过连通分量形成的设备簇；
- B³ precision/recall/F1；
- Adjusted Rand Index；
- 完整设备簇恢复率；
- 同设备跨 Profile 关联率与错误关联率。

## 结果目录

每次运行会安全重置本实验自己的 `results/latest/`：

```text
results/latest/
├── raw/
│   ├── standard_smdpp_view.jsonl
│   ├── standard_smdpp_view.csv
│   ├── aura_smdpp_view.jsonl
│   ├── aura_smdpp_view.csv
│   ├── ground_truth.jsonl
│   └── ground_truth.csv
├── analysis/
│   ├── standard_rsp_pair_predictions.*
│   ├── aura_rsp_pair_predictions.*
│   └── cluster_assignments.csv
├── graphs/
│   ├── standard_rsp_relationship.dot
│   ├── standard_rsp_relationship.svg
│   ├── aura_rsp_relationship.dot
│   └── aura_rsp_relationship.svg
├── paper/
│   ├── figure-1-linkability-metrics-zh.svg
│   ├── figure-1-linkability-metrics-en.svg
│   ├── figure-2-roc-curve-zh.svg
│   ├── figure-2-roc-curve-en.svg
│   ├── table-1-linkability-results-zh.csv
│   ├── table-1-linkability-results-en.csv
│   ├── table-1-linkability-results-zh.md
│   ├── table-1-linkability-results-en.md
│   ├── captions-and-analysis-zh.txt
│   └── captions-and-analysis-en.txt
├── summary.json
├── summary.csv
└── summary.md
```

默认终端输出为便于阅读的对比表。若脚本或其他程序需要原来的一行 JSON 输出，可运行：

```bash
./run_demo.sh --machine-json
```

`paper/` 中自动生成中英文两套矢量 SVG，可直接插入新版 Microsoft Word；图中文字已针对论文版面整体放大。中英文 CSV 可直接由 Excel 打开，对应图题和论文分析文字分别保存在 `captions-and-analysis-zh.txt` 与 `captions-and-analysis-en.txt`。

## 600 DPI论文综合图

在实验结果已经生成后，可使用独立绘图脚本读取`results/latest`中的原始预测和汇总结果：

```bash
python3 plot_paper_results.py
```

脚本依赖`Pillow`和`NumPy`，会重新计算ROC-AUC、执行固定种子的5000次分层自助法置信
区间估计，并核对计算结果与`summary.json`一致。输出位于：

```text
results/latest/publication/
├── experiment1-cross-profile-linkability-zh-600dpi.png
├── experiment1-cross-profile-linkability-en-600dpi.png
├── experiment1-results-table-zh.csv
├── experiment1-results-table-zh.md
├── experiment1-results-table-en.csv
├── experiment1-results-table-en.md
├── experiment1-paper-caption-zh.txt
├── experiment1-paper-caption-en.txt
└── experiment1-figure-data.json
```

两张PNG均为4500×2820像素并写入600 DPI元数据。结果表额外报告
`max(AUC, 1−AUC)`，避免把低于0.5的AUC不严谨地解释成攻击者无法反转评分方向。

如果需要不带标题和题注的常规英文论文图，运行：

```bash
python3 plot_experiment1_simple.py
```

该脚本生成两张相互独立的4200×3000像素、600 DPI白底图片：

```text
results/latest/publication-simple/
├── experiment1-figure-a-roc-en-600dpi.png
├── experiment1-figure-b-bars-en-600dpi.png
├── experiment1-results-table-zh.csv
├── experiment1-results-table-zh.md
└── experiment1-data-audit.json
```

`experiment1-data-audit.json`保存三份输入结果文件的SHA-256，明确区分“真实执行的受控
软件仿真结果”与“真实硬件/完整网络下载测量”。

## 机器断言

`summary.json` 会检查：

- 两组事务数正确；
- 固定种子生成器可复现；
- 公开转录不含真实设备标签或内部逻辑下载编号；
- 订单、账号、Profile 和摘要均不同；
- 时间、大小和网络出口得到控制；
- Standard 稳定标识每台设备重复 4 次；
- AURA 逐事务字段全部唯一；
- Standard ROC-AUC 不低于 0.99；
- AURA ROC-AUC 位于 0.35–0.65；
- Standard 可完整恢复设备簇；
- AURA 无稳定标识直接跨 Profile 关联。

只有所有断言通过，程序才输出 `PASS` 并返回退出码 0。

## 可以得出的结论与边界

如果断言通过，可以表述为：

> 在控制订单、账号、时间、Profile 大小和网络出口后，Standard RSP 中 SM-DP+ 正常可见的稳定 eUICC 身份材料足以支持跨 MNO、跨 Profile 的硬件关联；AURA-RSP 当前公开转录在该受控实验中没有提供同类稳定设备标识，成对关联性能接近随机猜测。

不能把该结果扩大解释为：

- 对任意侧信道都达到匿名；
- 可抵抗 PR 与 SM-DP+ 合谋或入口/出口全局流量观察；
- 已完成真实硬件、真实证书和大量网络下载测试；
- AURA 的全部生命周期协议均已实现或验证。
