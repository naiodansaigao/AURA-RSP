# 实验8：跨Profile与跨操作移植

| 协议 | 场景 | 结果 | 拒绝位置 | 原因 |
|---|---|---|---|---|
| AURA-RSP | profile_pid_h_plain_mutation | 拒绝 | one_time_context_signature | INVALID_TAU_AUTH |
| AURA-RSP | profile_pid_h_resigned_envelope | 拒绝 | anonymous_proof | INVALID_PI_AUTH |
| AURA-RSP | profile_a_bind_t_to_profile_b_session | 拒绝 | profile_binding | BIND_T_MISMATCH |
| AURA-RSP | operation_download_to_delete | 拒绝 | ticket_public_fields | INVALID_OR_EXPIRED_TICKET |
| AURA-RSP | operation_download_to_reinstall | 拒绝 | ticket_public_fields | INVALID_OR_EXPIRED_TICKET |
| AURA-RSP | operation_download_to_enable | 拒绝 | ticket_public_fields | INVALID_OR_EXPIRED_TICKET |
| Standard RSP | modify_profile_hash_keep_binding_signature | 拒绝 | bpp_signature | BPP_BINDING_SIGNATURE_INVALID |
| Standard RSP | profile_a_binding_to_profile_b_transaction | 拒绝 | transaction_binding | SIGNED_TRANSACTION_MISMATCH |
| Standard RSP | replace_outer_and_signed_transaction | 拒绝 | bpp_signature | BPP_BINDING_SIGNATURE_INVALID |

机器断言：14/14通过。

结论：AURA-RSP匿名认证同时绑定Profile、操作、认证转录和密钥会话，不是可以跨订单复用的通用设备通行证。Standard对照同样拒绝Profile移植，因此本实验是安全能力回归，不是Standard漏洞。
