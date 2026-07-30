# 实验11：非法Reinstall

- 实验状态：**PASS**
- 非法子测试拒绝：8/8
- 机器断言：23/23

## 场景结果

| 场景 | 前驱 | 结果 | 原因 | 状态变化 | Profile安装 |
|---|---|---|---|---:|---:|
| installed直接reinstall | installed | 拒绝 | `INVALID_REINSTALL_PREDECESSOR` | 0 | 0 |
| enabled直接reinstall | enabled | 拒绝 | `INVALID_REINSTALL_PREDECESSOR` | 0 | 0 |
| disabled直接reinstall | disabled | 拒绝 | `INVALID_REINSTALL_PREDECESSOR` | 0 | 0 |
| tombstone使用错误lph | tombstone | 拒绝 | `AUTHORIZATION_LPH_MISMATCH` | 0 | 0 |
| 使用新salt_p | tombstone | 拒绝 | `REINSTALL_SALT_MISMATCH` | 0 | 0 |
| 使用旧票据 | tombstone | 拒绝 | `TICKET_EXPIRED` | 0 | 0 |
| 重放旧ReinstallReceipt | enabled | 拒绝 | `STALE_RECEIPT_REPLAY` | 0 | 0 |
| 修改ctr或last_hash | tombstone | 拒绝 | `COUNTER_MISMATCH;LAST_HASH_MISMATCH` | 0 | 0 |
| 合法tombstone→installed | tombstone | 接受 | `ACCEPTED` | 1 | 1 |

## 结论

八类非法Reinstall子测试全部拒绝，错误业务执行为0。计数器与`last_hash`子测试内部包含两次独立篡改，两次均未改变状态。
合法控制从`tombstone`延续同一`lph/salt_p`，使用新票据、新会话和新`Bind_t`；Profile通过AES-GCM解密和摘要检查后生成HMAC收据，服务器以连续计数器和正确前驱摘要原子更新到`installed`。

## 边界

Standard baseline没有可调用的Reinstall状态链接口，因此结果为`UNSUPPORTED`，本实验不据此宣称Standard存在Reinstall漏洞。
