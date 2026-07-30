# 实验6：生命周期重放、分叉与删除故障恢复

总体状态：**PASS**

| 子测试 | 场景 | 结果 | 最终状态 |
|---|---|---:|---|
| 6A | `old_receipt_replay_and_latest_idempotency` | PASS | `disabled` |
| 6B | `receipt_field_tampering` | PASS | `installed` |
| 6C | `concurrent_enable_delete_fork` | PASS | `pending-delete` |
| 6D | `lost_rprep_response` | PASS | `pending-delete` |
| 6E | `lost_commit_receipt_or_final_ack` | PASS | `tombstone` |
| 6F | `commit_after_delete_ticket_expiry` | PASS | `tombstone` |

## 核心结果

- 旧状态收据：`rejected`
- 最新收据重复：`idempotent`
- 篡改拒绝：7/7
- 并发后继数量：1
- Rprep是否完全相同：True
- Commit/确认丢失后收敛：True
- 票据过期后完成commit-delete：True

## Standard baseline

状态：**UNSUPPORTED**

当前baseline没有生命周期状态链和两阶段删除测试接口。因此不声称Standard接受重放，
也不把`UNSUPPORTED`描述为标准协议漏洞。
