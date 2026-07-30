# 实验4：票据双花、重放识别与条件追踪

状态：**PASS**

| 场景 | 第二次业务执行 | 追踪 | 身份结果 | business_execution_count |
|---|---:|---:|---|---:|
| 4A 正常单次使用 | 否 | 否 | SM-DP+不知道EID | 1 |
| 4B 完全相同报文重传 | 否 | 否 | SM-DP+不知道EID | 1 |
| 4C 两个不同有效转录 | 否 | 是 | 恢复正确EID | 1 |

## 核心结果

- `trace_success = true`
- `recovered_eid == malicious_device_eid = true`
- `false_trace_count = 0`
- `business_execution_count = 1`
- `k`公式恢复与设备追踪标量一致：True

## 解释边界

AURA部分真实调用当前BBS+凭证/票据、匿名证明、nullifier数据库、条件追踪、
P-256 ECDHE、HKDF、AES-GCM和安装通知代码。EUM查询由隔离的本地追踪数据库模拟。
Standard对照只说明服务器从首次标准认证即能看到稳定EID/证书，这是预期身份认证行为，
不是Standard RSP消息完整性漏洞。
