# 实验3：操作票据盗取与跨设备转移

状态：**PASS**

## AURA-RSP

| 检查项 | 结果 |
|---|---|
| Device-A正常认证 | 通过 |
| Device-A正常Bind_t | 已生成 |
| Device-B本地联合证明 | 被拒绝 |
| Device-B服务器认证 | 拒绝 |
| HTTP状态 | 401 |
| 统一拒绝原因 | `credential_ticket_secret_mismatch` |
| 服务器原始原因 | `BBS+ randomized signature pairing failed` |
| Bind_t生成 | False |
| Profile交付 | False |
| 公开EID | False |

## Standard RSP订单策略对照

| 策略 | Device-B认证 | Profile交付 | 稳定EID暴露 |
|---|---:|---:|---:|
| 预绑定EID | False | False | True |
| 未绑定Activation Code | True | True | True |

## 结论

AURA-RSP在不公开EID的情况下，依靠设备凭证与操作票据共享隐藏秘密`x`的联合证明拒绝跨设备转移。
Standard的结果取决于订单策略：预绑定EID可以拒绝，但需要稳定身份；未绑定激活码可能被另一合法设备抢先消费。

Standard部分是受控订单策略模型；AURA部分调用现有真实BBS+盲签、联合证明和服务器验证代码。
