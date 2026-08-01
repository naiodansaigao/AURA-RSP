# 实验1：共享 SM-DP+ 跨 Profile 关联

状态：**PASS**

本结果来自受控协议可见转录实验，不代表执行了 80 次完整网络下载。分类器没有读取真实设备标签；真实标签只在评估阶段使用。

| 指标 | Standard RSP | AURA-RSP |
|---|---:|---:|
| 事务数 | 80 | 80 |
| Pairwise ROC-AUC | 1.000 | 0.424 |
| Pairwise accuracy | 1.000 | 0.467 |
| 直接分组 B³ F1 | 1.000 | 0.400 |
| 直接分组 ARI | 1.000 | 0.000 |
| 完整设备簇恢复率 | 1.000 | 0.000 |
| 跨 Profile 直接关联率 | 1.000 | 0.000 |
| 学习式聚类 B³ F1 | 1.000 | 0.095 |
| 学习式聚类 ARI | 1.000 | 0.000 |

## 解释

- Standard RSP 的共享 SM-DP+ 正常收到稳定 EID、eUICC 证书和证书公钥，因此无需篡改协议即可将不同 MNO、订单和 Profile 归并到同一硬件设备。
- AURA-RSP 的实验输入中，每个订单使用不同 `I_ac/pid_h/nu/lph/opid/vk_t`、证明摘要、`Bind_t` 摘要和会话公钥；分类器只能利用时间等受控公开特征。
- AURA 的期望是 ROC-AUC 接近 0.5，而不是固定等于 0.5。该数值是本次真实训练/交叉验证的输出。
- 这证明的是当前威胁模型下的协议字段不可链接性，不覆盖 PR 与 SM-DP+ 合谋、入口出口流量同时观测、终端秘密泄露或 MNO 主动植入额外标识。

## 论文可用产物

- `paper/figure-1-linkability-metrics-zh.svg` / `-en.svg`：中英文关键指标图。
- `paper/figure-2-roc-curve-zh.svg` / `-en.svg`：中英文 ROC 曲线。
- `paper/table-1-linkability-results-zh.csv` / `-en.csv`：中英文结果表。
- `paper/table-1-linkability-results-zh.md` / `-en.md`：中英文 Markdown 表。
- `paper/captions-and-analysis-zh.txt` / `-en.txt`：中英文图题、表题和边界说明。
