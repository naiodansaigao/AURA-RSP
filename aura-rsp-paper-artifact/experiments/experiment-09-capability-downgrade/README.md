# 实验9：能力协商降级攻击

本实验直接调用 `pysim-aura-integration/pySim/esim/aura/` 中的集成实现，不再依赖旧的独立 AURA 原型。集成代码实现 Classical（P-256 ECDH）和 Hybrid（P-256 ECDH + ML-KEM-768）两种模式；Hybrid 的两个共享秘密共同进入 HKDF，ML-KEM 公钥和密文摘要进入签名覆盖的 `ctx_K`。

默认性能基准仍使用 Classical，避免改变论文已有计时口径。只有本实验显式启用 Hybrid。`kyber-py==1.2.0` 用于可复现研究原型，不代表工业级常数时间 PQC 实现。

## 运行

```bash
cd experiments/experiment-09-capability-downgrade
bash ./run_demo.sh
```

机器可读输出：

```bash
bash ./run_demo.sh --machine-json
```

实验覆盖篡改能力提议、篡改已签名模式、删除或替换 ML-KEM 材料、跨模式拼接临时密钥及重标记响应。网络攻击 7/7 被拒绝。合法服务器选择 Classical 时，允许 Classical 的设备可接受；配置 `require_hybrid=true` 的设备以 `HYBRID_REQUIRED` 拒绝。

这证明 AURA-RSP 防止的是协商转录篡改和跨模式材料拼接；合法服务器在设备允许范围内选择 Classical 不属于网络降级攻击。结果位于 `results/latest/summary.json` 和 `results/latest/raw/scenarios.csv`。
