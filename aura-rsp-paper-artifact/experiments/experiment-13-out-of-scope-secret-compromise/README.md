# 实验13：超出威胁模型的密钥或设备秘密泄露

本实验是独立的保证边界审计Demo，不修改Standard RSP或AURA-RSP生产源码。它分别
人为泄露六类秘密，并重新执行与该秘密直接相关的伪造、克隆、追踪或身份解析操作：

1. eUICC长期秘密`x`；
2. 票据隐藏见证`eta,d`；
3. EUM设备凭证签发密钥；
4. MNO操作票据签发密钥；
5. SM-DP+服务器认证/Profile Binding私钥；
6. EUM追踪数据库。

所有成功攻击都分类为：

```text
EXPECTED OUT-OF-SCOPE COMPROMISE
```

这表示根信任或诚实端点已经失陷，不表示协议内攻击突破了AURA-RSP。

## 一键运行

在WSL2 Ubuntu中执行：

```bash
cd experiments/experiment-13-out-of-scope-secret-compromise
bash ./run_demo.sh
```

AURA环境安装了`py-ecc`时，`auto`模式会直接使用当前AURA BBS+签发和验证代码：

```bash
bash ./run_demo.sh --backend production
```

没有`py-ecc`时，`auto`会使用便携边界夹具：EUM/MNO部分以Ed25519签名承诺模拟相同
的“签发私钥泄露”因果关系；SM-DP+仍使用与生产实现一致的P-256 ECDSA。便携后端
不冒充BBS+或零知识证明实现，结果中会明确记录该限制。

其他参数：

```bash
bash ./run_demo.sh --lang zh
bash ./run_demo.sh --lang en
bash ./run_demo.sh --machine-json
```

## 重要口径：`x`和`eta,d`不是签发密钥

仅知道`x`不能凭空生成EUM凭证或MNO票据签名；仅知道`eta,d`也不能绕过凭证中相同
`x`的联合证明。因此实验分别记录：

- 单独泄露隐藏见证是否足够；
- 攻击者同时复制设备内已有签名凭证、票据和其他持有者状态后是否能够克隆使用。

这样可以避免把“端点完整状态失陷”错误归因成“知道一个标量即可伪造BBS+签名”。

## 六类结果的安全含义

| 泄露 | 直接后果 | 不代表 |
|---|---|---|
| `x` | 与完整设备持有者状态组合后可克隆身份 | `x`可伪造EUM/MNO签名 |
| `eta,d` | 与匹配的`x/k`及签名材料组合后可复用票据 | 单独可生成合法票据 |
| EUM私钥 | 可为攻击者选择的隐藏见证签发设备凭证 | MNO票据也自动有效 |
| MNO私钥 | 可签发任意操作票据 | 设备凭证也自动有效 |
| SM-DP+私钥 | 可伪造服务器认证和`Bind_t` | MNO业务授权自动正确 |
| 追踪数据库 | 可读取`k -> EID`身份解析映射 | 可伪造匿名证明或签名 |

## 输出

- `results/latest/summary.json`：完整结果和机器断言
- `results/latest/scenarios.csv`：六类泄露的影响矩阵
- `results/latest/assertions.csv`：机器可检查断言
- `results/latest/raw/attack-attempts.jsonl`：对照和泄露后攻击记录
- `results/latest/evidence/source-audit.json`：AURA生产源码检查点
- `results/latest/evidence/key-fingerprints.json`：测试密钥公钥指纹
- `results/latest/evidence/trace-database-export.json`：测试追踪库泄露结果
- `results/latest/report-zh.md`、`report-en.md`：双语报告
- `results/latest/paper/`：中英文边界矩阵、信任根图、数据表和图题

## 威胁模型边界

本实验不能用于声称“AURA在密钥泄露后仍然安全”。它的用途是明确论文保证的前提：
EUM、MNO、SM-DP+私钥以及诚实eUICC内部秘密必须保持安全，EUM追踪数据库必须受到
访问控制和静态数据保护。密钥撤销、轮换、HSM、远程证明和入侵恢复属于部署层缓解
措施，不是本Demo验证的协议能力。
