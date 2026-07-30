# 实验9：能力协商降级攻击结果

- 状态：**PASS**
- 网络中间人攻击：7/7拒绝
- 攻击路径Profile交付：0
- 机器断言：18/18

## 场景结果

| 场景 | 类型 | 结果 | 阶段/原因 | Profile交付 |
|---|---|---|---|---:|
| 篡改能力提议 | 网络中间人 | 拒绝 | `capability_transcript / CAPABILITY_TRANSCRIPT_MISMATCH` | 0 |
| 篡改已签名模式 | 网络中间人 | 拒绝 | `server_authentication / INVALID_SERVER_AUTH_SIGNATURE` | 0 |
| 删除ML-KEM公钥 | 网络中间人 | 拒绝 | `client_key_exchange_signature / INVALID_CLIENT_KEY_EXCHANGE_SIGNATURE` | 0 |
| 删除ML-KEM密文 | 网络中间人 | 拒绝 | `mlkem_server_material / MISSING_MLKEM_CIPHERTEXT` | 0 |
| 替换ML-KEM密文 | 网络中间人 | 拒绝 | `ctx_k_binding / MLKEM_CIPHERTEXT_HASH_MISMATCH` | 0 |
| 拼接Classic临时密钥 | 网络中间人 | 拒绝 | `server_key_exchange_signature / INVALID_SERVER_KEY_EXCHANGE_SIGNATURE` | 0 |
| Hybrid响应标成Classic | 网络中间人 | 拒绝 | `server_key_exchange_signature / INVALID_SERVER_KEY_EXCHANGE_SIGNATURE` | 0 |
| 合法服务器选Classic（允许） | 合法服务器策略 | 接受 | `CLASSICAL_ALLOWED_BY_DEVICE_POLICY` | 1 |
| 合法服务器选Classic（强制Hybrid） | 合法服务器策略 | 拒绝 | `device_policy / HYBRID_REQUIRED` | 0 |

## 结论与边界

所有网络篡改、材料删除、密文替换和跨模式拼接均未建立攻击会话密钥，也未交付Profile。
持合法签名密钥的服务器主动选择Classical时，允许Classical的设备正常接受；要求Hybrid的设备在Profile Binding和密钥协商前以`HYBRID_REQUIRED`拒绝。
ML-KEM部分使用`kyber-py 1.2.0`的真实ML-KEM-768实验实现，但该库不是常数时间生产库；当前AURA 9443生产原型仍只有Classical路径，本实验是独立能力层扩展。

## 机器断言

18/18 PASS
