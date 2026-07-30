# AURA-RSP Paper Artifact

本仓库是论文实验的可复现软件制品，包含：

1. 基于 **pySim/osmo-smdpp + 软件eUICC/LPA** 的Standard RSP baseline；
2. AURA-RSP研究原型，包括匿名凭证、匿名操作票据、Privacy Relay、Profile
   Binding、密钥协商、安全Profile下载和生命周期状态链；
3. 13个彼此独立的安全与隐私实验；
4. 固定依赖、上游源码版本、机器可读结果和复现脚本。

The repository is a reproducible research artifact containing the Standard RSP
baseline, the AURA-RSP prototype, thirteen independent experiments, pinned
dependencies, recorded evidence, and reproducibility scripts.

## 目录

```text
.
├── rsp-baseline/                   # Standard RSP baseline
├── aura-rsp/                       # AURA-RSP implementation
├── experiments/                    # Experiment 01–13
├── scripts/
│   ├── setup_wsl.sh
│   ├── run_all_experiments.sh
│   ├── run_benchmark.sh
│   └── verify_artifact.py
├── docs/
│   ├── EXPERIMENT_INDEX.md
│   ├── REPRODUCIBILITY.md
│   ├── SECURITY_SCOPE.md
│   └── DEPENDENCIES.md
├── THIRD_PARTY_NOTICES.md
└── MANIFEST.sha256
```

## 推荐环境

- Windows 10/11 + WSL2；
- Ubuntu 24.04；
- Python 3.12；
- 至少4 GB可用内存和5 GB可用磁盘；
- 网络连接仅在首次安装Python依赖时需要。

全部Profile、证书和身份均为测试材料，不得用于真实eSIM网络。

## 快速开始

```bash
git clone <YOUR_REPOSITORY_URL>
cd aura-rsp-paper-artifact

bash scripts/setup_wsl.sh

# Standard RSP
bash rsp-baseline/scripts/run_all.sh

# AURA-RSP
bash aura-rsp/scripts/run_all.sh

# 13个独立实验
bash scripts/run_all_experiments.sh

# Standard/AURA同机性能对比，10轮
bash scripts/run_benchmark.sh 10
```

运行单个实验：

```bash
bash experiments/experiment-04-double-spend-tracing/run_demo.sh
bash experiments/experiment-12-pr-source-address-privacy/run_demo.sh
bash experiments/experiment-13-out-of-scope-secret-compromise/run_demo.sh \
  --backend production
```

静态检查制品完整性：

```bash
python3 scripts/verify_artifact.py
sha256sum -c MANIFEST.sha256
```

## 结果解释

- `PASS`表示观察结果满足该实验定义的机器断言。
- `EXPECTED_BOUNDARY_FAILURE`表示攻击位于声明的隐私边界之外，例如PR与SM-DP+
  合谋后通过流量特征恢复连接。
- `EXPECTED OUT-OF-SCOPE COMPROMISE`表示根密钥、服务器私钥、诚实eUICC秘密或追踪
  数据库已经泄露；这用于标明保证前提，不表示协议威胁模型内攻击成功。
- Standard RSP已经防御的消息篡改和BPP移植只作为AURA匿名化后的安全回归测试，不
  被描述为Standard RSP漏洞。

## 仿真边界

- Standard流程使用软件eUICC/LPA，不执行实体eUICC的ES10 APDU写卡。
- AURA密码代码是研究参考实现，未经过独立密码工程审计。
- Python实现的配对、证明和ML-KEM性能不能代表安全芯片或优化C/Rust实现。
- 测试PKI、Profile和固定种子只用于可复现研究。
- 实验13必须在安装`py-ecc`的AURA环境中使用`--backend production`，才能作为
  BBS+生产路径结果；便携后端只验证密钥泄露的因果关系。

进一步说明见[复现文档](docs/REPRODUCIBILITY.md)和
[安全边界](docs/SECURITY_SCOPE.md)。

## 许可证

上游OpenEUICC、lpac、pySim/osmo-smdpp源码保留各自许可证。AURA-RSP和实验代码的
发布许可证需要由论文作者在公开仓库前确定，详见`LICENSE-NOTICE.md`与
`THIRD_PARTY_NOTICES.md`。

