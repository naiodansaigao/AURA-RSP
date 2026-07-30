# 实验10：Profile密文篡改、重放与明文替换

- 实验状态：**PASS**
- 安全属性：3/3
- 机器断言：17/17
- 10A与10B：全部拒绝且未安装、未生成收据
- 10C修复后客户端：错误Profile在安装和收据生成前被订单pid_h检查拒绝

## 场景结果

| 场景 | 签名 | AEAD | 订单pid_h | 安装 | 收据 | 结果 |
|---|---:|---:|---:|---:|---:|---|
| 正常会话A | PASS | PASS | PASS | 1 | 1 | 接受 |
| 正常会话B | PASS | PASS | PASS | 1 | 1 | 接受 |
| 10A 密文字节翻转 | FAIL | FAIL | N/C | 0 | 0 | 拒绝 / `INVALID_SERVER_KEY_EXCHANGE_SIGNATURE` |
| 10A 密文翻转+白盒重签 | PASS | FAIL | N/C | 0 | 0 | 拒绝 / `PROFILE_AEAD_AUTHENTICATION_FAILED` |
| 10A Tag翻转+白盒重签 | PASS | FAIL | N/C | 0 | 0 | 拒绝 / `PROFILE_AEAD_AUTHENTICATION_FAILED` |
| 10B A整包重放到B | FAIL | FAIL | N/C | 0 | 0 | 拒绝 / `CTX_K_MISMATCH` |
| 10B A密文放入B+白盒重签 | PASS | FAIL | N/C | 0 | 0 | 拒绝 / `PROFILE_AEAD_AUTHENTICATION_FAILED` |
| 10C 修复后客户端/错误Profile | PASS | PASS | FAIL | 0 | 0 | 拒绝 / `PROFILE_ORDER_DIGEST_MISMATCH` |
| 10C 移除pid_h检查/负向控制 | PASS | PASS | N/C | 1 | 1 | 接受 |
| MNO+SM-DP+共同错误授权 | PASS | PASS | PASS | 1 | 1 | 接受 |

## 10C修复验证

恶意SM-DP+仍使用当前合法会话密钥加密Profile-B，并以Profile-B自身摘要构造AAD和合法服务器签名。因此服务器签名、ctx_K、AEAD以及服务端自报摘要检查仍全部通过，证明攻击包在密码学上自洽。
修复后的客户端继续比较`H(Profile-B)`与订单`ticket.pid_h`中承诺的`H(Profile-A)`，返回`PROFILE_ORDER_DIGEST_MISMATCH`，没有写入错误Profile，也没有生成安装收据。
移除订单摘要检查的负向控制仍会接受、安装并生成收据，说明10C通过确实来自新增检查，而不是攻击夹具失效。

## 边界

若MNO与SM-DP+共同把Profile-B摘要写入订单，则订单承诺与交付明文一致，修复后的检查也会通过；这是业务授权信任边界，不是AEAD或Profile Binding可以判断的恶意业务决策。
