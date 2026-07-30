# 实验13：超出威胁模型的密钥或设备秘密泄露

- 状态：**PASS**
- 统一分类：`EXPECTED OUT-OF-SCOPE COMPROMISE`
- 签发后端：`portable_signature_commitment_harness`
- 机器断言：20/20

| 泄露对象 | 单独足够 | 影响已观察 | 分类 |
|---|---:|---:|---|
| eUICC长期秘密x | 否 | 是 | `EXPECTED OUT-OF-SCOPE COMPROMISE` |
| 票据隐藏值eta,d | 否 | 是 | `EXPECTED OUT-OF-SCOPE COMPROMISE` |
| EUM签发私钥 | 是 | 是 | `EXPECTED OUT-OF-SCOPE COMPROMISE` |
| MNO票据签发私钥 | 是 | 是 | `EXPECTED OUT-OF-SCOPE COMPROMISE` |
| SM-DP+签名/Binding私钥 | 是 | 是 | `EXPECTED OUT-OF-SCOPE COMPROMISE` |
| EUM追踪数据库 | 是 | 是 | `EXPECTED OUT-OF-SCOPE COMPROMISE` |

## 关键解释

`x`和`eta,d`是隐藏见证，不是签发密钥；单独泄露不足以伪造EUM或MNO签名。与设备内
已有的匹配凭证、票据、`k`和其他持有者状态组合后，端点克隆才成功。

EUM/MNO/SM-DP+私钥泄露分别破坏凭证不可伪造性、票据不可伪造性以及服务器认证/
Profile Binding。追踪库泄露直接暴露测试`k -> EID`映射，但没有获得签发能力。

本次EUM/MNO签发使用便携Ed25519承诺夹具；它验证私钥泄露的因果关系，但不冒充BBS+或零知识证明。请在AURA WSL环境运行`--backend production`获得正式BBS+结果。

## 结论

这些结果用于明确方案保证的前提，不用于证明AURA在根信任或诚实端点失陷后仍然安全。
