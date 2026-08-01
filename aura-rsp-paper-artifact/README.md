# AURA-RSP pySim/osmo-smdpp Research Artifact

本仓库是论文实验使用的可复现研究原型。它不是三套互不相关的模拟器，而是在同一份 Osmocom pySim/osmo-smdpp 代码中提供两种运行模式：

- **Standard RSP**：原始 ES9+ 流程、软件 eUICC/LPA、Bound Profile Package 下载与安装通知；
- **AURA-RSP**：在相同 SM-DP+、Profile、主机和 Python 环境中加入匿名凭证/操作票据、Privacy Relay、条件追踪、Profile Binding、会话密钥绑定与完整生命周期；
- **13 个独立实验**：全部以这份集成代码为后端，不依赖旧的独立 AURA-RSP 仿真目录。

## 目录结构

```text
.
├── pysim-aura-integration/   # Standard RSP + AURA-RSP 共用源码
├── experiments/              # 13 个相互独立的实验
├── reference-results/        # 已验证运行的摘要、断言与论文图（不含大体积原始日志）
├── scripts/                  # 安装、运行、验收和清单工具
├── docs/                     # 架构、实验索引、安全边界与复现说明
├── COPYING                   # pySim 衍生代码所适用的 GPL-2.0
└── MANIFEST.sha256           # 发布文件完整性清单
```

## WSL2 Ubuntu 快速复现

在 WSL2 中进入本目录：

```bash
cd /path/to/aura-rsp-pysim-artifact
```

首次安装依赖并生成**仅用于本地测试**的 Standard RSP 与 AURA-RSP 密钥材料：

```bash
bash ./scripts/setup_wsl.sh
```

运行 Standard RSP：

```bash
bash ./scripts/run_standard.sh
```

运行 AURA-RSP：

```bash
bash ./scripts/run_aura.sh
```

按论文采用的进程级计时边界对比 10 次：

```bash
bash ./scripts/run_benchmark.sh 10
```

运行单个实验（例：实验 5）：

```bash
bash ./scripts/run_experiment.sh 5
```

运行全部 13 个实验：

```bash
bash ./scripts/run_all_experiments.sh
```

执行发布包静态检查：

```bash
python3 ./scripts/verify_artifact.py
```

## 预期通过标记

- Standard RSP：`STANDARD_PYSIM_INTEGRATION_ALL_PASS`
- AURA-RSP：`AURA_PYSIM_INTEGRATION_ALL_PASS`
- 13 个实验：各实验 `results/latest/summary.json` 中的 `status` 为通过标记；实验 12C 和实验 13 的“攻击成功”是明确标注的威胁模型边界，而不是协议内安全失败。

## 结果与隐私材料

`reference-results/` 仅保存论文所需的摘要、机器断言和小型图片/表格。运行时生成的以下内容均由 `.gitignore` 排除：

- 测试私钥、匿名凭证、票据和追踪数据库；
- SQLite 数据库、服务 PID、网络日志和软件 eUICC 输出；
- 实验的大体积逐请求原始数据。

因此，克隆仓库后必须运行 `scripts/setup_wsl.sh` 本地生成测试材料。所有证书均为研究测试用途，不能用于真实运营网络。

## 研究边界

这是研究级纯软件原型，不宣称通过 GSMA SGP.22/SGP.23 认证，也不替代实体 eUICC、生产 EUM、SM-DS 或商业 GSMA PKI。详细威胁模型与实验含义见 [docs/SECURITY_SCOPE.md](docs/SECURITY_SCOPE.md) 和 [docs/EXPERIMENT_INDEX.md](docs/EXPERIMENT_INDEX.md)。

## 许可证与引用

集成代码源自 Osmocom pySim，基线提交见 `pysim-aura-integration/UPSTREAM.md`，相关代码依 GPL-2.0 发布，许可证全文见 `COPYING`。公开仓库前，请作者补全并确认实验代码的版权署名，并将 `CITATION.cff.example` 补全后改名为 `CITATION.cff`。
