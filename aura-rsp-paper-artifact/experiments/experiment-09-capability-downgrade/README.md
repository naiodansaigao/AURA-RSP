# 实验9：能力协商降级攻击

本实验是完全独立的AURA-RSP能力协商与Hybrid密钥协商Demo，不修改
`rsp-baseline/`、`aura-rsp/`或实验1—8。它复用当前AURA原型的P-256签名、
Ed25519一次性签名、ECDH/HKDF/AES-GCM、`Bind_t`和`ctx_K`结构，并在实验目录内
补充真实ML-KEM-768密钥封装与设备策略检查。

## 一键运行

在WSL2 Ubuntu中执行：

```bash
cd /path/to/aura-rsp-paper-artifact/experiments/experiment-09-capability-downgrade
bash ./run_demo.sh
```

第一次运行会在现有AURA虚拟环境中安装固定版本`kyber-py==1.2.0`。也可以提前执行：

```bash
bash ./install_deps.sh
```

语言和机器接口：

```bash
bash ./run_demo.sh --lang zh
bash ./run_demo.sh --lang en
bash ./run_demo.sh --machine-json
```

## 密钥协商模式

- Hybrid：P-256 ECDH与ML-KEM-768两个共享秘密共同进入HKDF。
- Classical：仅使用P-256 ECDH进入HKDF。
- 两种模式都把协商结果、能力提议摘要、`Bind_t`、双方P-256临时公钥以及适用的
  ML-KEM公钥/密文摘要放入`ctx_K`。
- Profile响应签名覆盖完整`ctx_K`、nonce、密文摘要和Profile摘要；AES-GCM的AAD也
  覆盖`ctx_K`。

`kyber-py`是遵循FIPS 203的纯Python教学/实验实现，不是常数时间生产密码库。本实验
只将它用于论文原型和攻击可复现实验，不能据此声称已经达到工业级PQC部署要求。

## 网络中间人子实验

1. 修改客户端能力提议，把Hybrid降为Classical；
2. 修改已签名服务器选择，把Hybrid标记为Classical；
3. 删除Hybrid密钥请求中的ML-KEM公钥；
4. 删除服务器返回的ML-KEM密文；
5. 替换服务器返回的ML-KEM密文；
6. 把Classical会话的P-256临时材料拼接到Hybrid响应；
7. 把Hybrid响应的模式标记成Classical。

所有攻击都保留攻击者不掌握客户端一次性私钥和服务器签名私钥这一威胁模型。

## 合法服务器策略子实验

客户端始终真实提议Hybrid和Classical两种能力，持合法签名密钥的SM-DP+主动选择
Classical：

- `allow_classical=true`：允许完成Classical Profile交付；
- `require_hybrid=true`：设备在生成`Bind_t`、建立会话密钥和接收Profile之前拒绝。

这一区分说明AURA防止的是协商篡改和跨模式拼接，而不是替设备制定安全策略。

## 结果文件

- `results/latest/summary.json`：完整结果和机器断言
- `results/latest/scenarios.csv`：逐场景结果
- `results/latest/assertions.csv`：机器断言
- `results/latest/raw/transcripts.jsonl`：公开协议转录与拒绝结果
- `results/latest/evidence/source-audit.json`：现有AURA源码绑定点与实验扩展边界
- `results/latest/report-zh.md`、`report-en.md`：双语论文报告
- `results/latest/paper/`：中英文论文图、CSV表和图题

## 论文结论口径

本实验支持的结论是：能力提议、协商模式、ML-KEM材料、`Bind_t`和会话临时密钥
经过统一转录绑定后，网络攻击者不能把Hybrid会话降级或拼接成Classical会话。
拥有合法服务器密钥的SM-DP+在设备允许Classical时可以合法选择Classical；设备若要
强制抗量子Hybrid模式，必须配置并执行`require_hybrid=true`策略。

