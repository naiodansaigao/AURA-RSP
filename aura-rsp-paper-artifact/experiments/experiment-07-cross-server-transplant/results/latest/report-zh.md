# 实验7：跨服务器移植

| 协议 | 场景 | 结果 | 拒绝原因 | Bind_t/BPP |
|---|---|---|---|---|
| AURA-RSP | direct_replay_to_server_b | 拒绝 | UNKNOWN_TRANSACTION | 未生成/未到达 |
| AURA-RSP | modify_sid | 拒绝 | INVALID_OR_EXPIRED_TICKET | 未生成/未到达 |
| AURA-RSP | modify_server_oid | 拒绝 | INVALID_TAU_AUTH | 未生成/未到达 |
| AURA-RSP | modify_praddr | 拒绝 | INVALID_OR_EXPIRED_TICKET | 未生成/未到达 |
| AURA-RSP | replace_target_address_only | 拒绝 | SERVER_AUTH_SIGNATURE_MISMATCH | 未生成/未到达 |
| AURA-RSP | modify_cap | 拒绝 | INVALID_TAU_AUTH | 未生成/未到达 |
| AURA-RSP | modify_transaction_nonce | 拒绝 | INVALID_TAU_AUTH | 未生成/未到达 |
| Standard RSP | direct_replay_to_server_b | 拒绝 | TRANSACTION_ID_UNKNOWN | 未生成/未到达 |
| Standard RSP | replace_outer_transaction_id | 拒绝 | SERVER_CHALLENGE_MISMATCH | 未生成/未到达 |
| Standard RSP | modify_signed_server_address | 拒绝 | EUICC_SIGNATURE_INVALID | 未生成/未到达 |
| Standard RSP | replace_target_address_only | 拒绝 | TLS_HOSTNAME_MISMATCH | 未生成/未到达 |

机器断言：13/13通过。

结论：AURA-RSP在不公开稳定设备身份的前提下，仍通过服务器本地会话、统一上下文、票据、一次性签名和匿名证明拒绝跨服务器移植。Standard对照也拒绝移植，因此本结果是安全能力回归，而不是Standard漏洞。
