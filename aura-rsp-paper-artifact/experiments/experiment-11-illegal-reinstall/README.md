# 实验11：非法Reinstall

本实验位于独立目录，直接调用`aura_rsp.lifecycle`生产生命周期核心，不修改Standard
RSP baseline或实验1—10。实验验证AURA-RSP只允许同一Profile生命周期从
`tombstone -> installed`执行Reinstall。

## 一键运行

在WSL2 Ubuntu中执行：

```bash
cd /path/to/aura-rsp-paper-artifact/experiments/experiment-11-illegal-reinstall
bash ./run_demo.sh
```

语言和机器接口：

```bash
bash ./run_demo.sh --lang zh
bash ./run_demo.sh --lang en
bash ./run_demo.sh --machine-json
```

## 八类非法场景

1. 从`installed`直接Reinstall；
2. 从`enabled`直接Reinstall；
3. 从`disabled`直接Reinstall；
4. 在`tombstone`状态使用错误`lph`；
5. 使用新的`salt_p`冒充原生命周期；
6. 使用已经过期的旧票据；
7. 当前状态链已经推进后重放旧`ReinstallReceipt`；
8. 分别篡改`ctr`和`last_hash`，要求两次均拒绝。

## 合法正向控制

合法Reinstall必须同时满足：

- 当前服务器状态为`tombstone`；
- 使用服务器保存的原`lph`与原`salt_p`；
- 使用新`rid`票据、新会话和新`Bind_t`；
- `ctr = current_ctr + 1`；
- `last_hash`等于当前链头；
- Profile通过真实AES-256-GCM解密且摘要与票据一致；
- 安装后生成的`ReinstallReceipt`具有正确HMAC。

服务端在SQLite`BEGIN IMMEDIATE`事务中重新读取当前状态并使用带前驱条件的CAS更新，
成功后仍更新原来的`lifecycle_profiles`行，不创建第二条Profile生命周期。

## 旧收据口径

本实验中的“旧ReinstallReceipt”是状态链后来已经继续推进、该收据不再是最新链头时
进行的历史重放。它应返回`STALE_RECEIPT_REPLAY`。这不等于网络层对当前最新响应的
普通重试。

## 结果文件

- `results/latest/summary.json`：完整结果与机器断言
- `results/latest/scenarios.csv`：九个子测试结果
- `results/latest/assertions.csv`：机器断言
- `results/latest/raw/attempts.jsonl`：每次独立攻击尝试
- `results/latest/raw/events.jsonl`：生产生命周期核心事件
- `results/latest/evidence/database-snapshots.json`：状态与数据库证据
- `results/latest/evidence/source-audit.json`：生产源码检查点
- `results/latest/report-zh.md`、`report-en.md`：双语报告
- `results/latest/paper/`：中英文结果矩阵、状态链图、CSV表和图题

## Standard边界

当前Standard baseline只覆盖Profile下载、BPP和安装通知，没有可调用的Reinstall状态
链、`lph/salt_p`连续性或ReinstallReceipt接口，因此本实验将Standard标记为
`UNSUPPORTED`，不把它描述为Standard协议漏洞。
