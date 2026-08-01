# 实验10：Profile 密文篡改、重放和明文替换

本实验直接调用集成版 `AuraService.get_profile()`、真实 P-256/HKDF/AES-GCM 密钥路径以及客户端共用的 `verify_profile_plaintext()`，不再使用旧的独立 Profile 交付模拟器。

## 运行

```bash
cd experiments/experiment-10-profile-ciphertext-integrity
bash ./run_demo.sh
```

机器可读输出：

```bash
bash ./run_demo.sh --machine-json
```

实验覆盖：10A 翻转密文字节或 AEAD Tag；10B 将 Session-A 密文移植到 Session-B；10C 由持有合法当前会话密钥的 SM-DP+ 加密错误 Profile。

10A 由 AES-GCM 完整性验证拒绝，10B 由 `ctx_K`、会话密钥和 AAD 绑定拒绝。10C 的 AEAD 本身可以通过，因此客户端解密后检查：

```text
H(Profile) == response.profileSha256 == ticket.pid_h
```

该检查由普通下载客户端和生命周期重装客户端共享。正式回归中 4/4 攻击均被拒绝，错误安装和安装收据均为 0。

如果 MNO 与 SM-DP+ 合谋，把错误 Profile 的摘要本身写入订单 `pid_h`，协议无法判断业务授权方恶意；这属于业务信任边界。结果位于 `results/latest/summary.json` 和 `results/latest/raw/scenarios.csv`。
