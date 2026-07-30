# 实验3：操作票据盗取与跨设备转移

## 实验问题

Device-A拥有隐藏秘密`x_A`和合法匿名设备凭证`Cred_A`。MNO为它签发隐藏同一
`x_A`的操作票据`Tok_A`。攻击者复制`Tok_A`、订单公开信息和等价激活材料到另一台
合法Device-B，但Device-B只能使用包含`x_B`的`Cred_B`。

本实验验证：

```text
x_credential = x_ticket
```

这一联合证明要求是否会在`x_A != x_B`时拒绝转移，同时不公开EID。

## 独立性

本目录不会修改：

- `rsp-baseline/`
- `aura-rsp/`
- 实验1和实验2

AURA部分直接导入现有`aura_rsp`密码模块和`AuraServerState`，使用独立运行目录、
独立SQLite、独立权威密钥和独立服务器密钥。

## 一键运行

在WSL2 Ubuntu中：

```bash
cd /path/to/aura-rsp-paper-artifact/experiments/experiment-03-ticket-transfer
bash ./run_demo.sh
```

只显示中文或英文：

```bash
bash ./run_demo.sh --lang zh
bash ./run_demo.sh --lang en
```

机器JSON：

```bash
bash ./run_demo.sh --machine-json
```

## AURA测试步骤

1. 同一EUM为Device-A和Device-B分别盲签合法匿名凭证。
2. MNO只为Device-A的`x_A`盲签两张票据：一张用于正常持有者对照，一张作为被盗票据。
3. Device-A使用对照票据完成真实联合证明，服务器应返回200并生成`Bind_t`。
4. 攻击脚本复制Device-A的被盗票据、隐藏票据状态`eta/d`、公开订单信息和等价激活材料给Device-B。
5. Device-B正常证明器以`Cred_B/x_B`使用`Tok_A`，应在本地BBS+签名一致性检查中失败。
6. 为验证服务器端防线，独立恶意客户端夹具仅跳过证明器本地pairing快速失败，仍用真实
   `create_auth_proof`生成无效联合证明；恢复原始密码函数后提交未修改的
   `AuraServerState.authenticate`。
7. 服务器必须返回401；会话保持`initiated`，`bind_t`为空，`used_nullifiers`和
   `notifications`没有攻击事务，后续Profile请求被拒绝。

实验结果中的统一语义原因：

```text
credential_ticket_secret_mismatch
```

同时保留服务器原始原因：

```text
BBS+ randomized signature pairing failed
```

统一原因不是伪造服务器错误码，而是由以下证据联合归类：

- `Cred_B`对`x_B`有效；
- `Tok_A`对`x_A`有效；
- `Tok_A`对`x_B`无效；
- `x_A != x_B`；
- 服务器真实联合证明验证返回401。

## Standard RSP对照

Standard部分明确分成两种订单策略：

- **预绑定EID：** Device-B被拒绝，但服务器必须读取稳定EID并比较。
- **未绑定Activation Code：** Device-B持有正确激活码时可以抢先消费订单，随后Device-A被拒绝。

这是受控订单策略模型，不声称所有Standard RSP部署都允许转移，也不把未绑定订单策略描述为
标准协议必然漏洞。

## 输出

```text
results/latest/
├── raw/
│   ├── events.jsonl
│   ├── events.csv
│   ├── copied-ticket-public.json
│   └── aura-server.jsonl
├── evidence/
│   ├── database-state.json
│   └── assertions.json
├── paper/
│   ├── figure-1-transfer-outcomes-zh.svg
│   ├── figure-1-transfer-outcomes-en.svg
│   ├── figure-2-aura-transfer-flow-zh.svg
│   ├── figure-2-aura-transfer-flow-en.svg
│   ├── table-1-ticket-transfer-zh.csv
│   ├── table-1-ticket-transfer-en.csv
│   ├── captions-and-analysis-zh.txt
│   └── captions-and-analysis-en.txt
├── summary.json
├── summary.csv
└── summary.md
```

## 结论边界

若全部断言通过，可以说明：

> AURA-RSP在不向SM-DP+公开EID的情况下，通过设备匿名凭证与操作票据共享隐藏秘密`x`
> 的联合证明，实现了确定的密码学不可转移性。

本实验不证明AURA-RSP所有安全性质，也不覆盖设备内部秘密泄露、EUM/MNO签发密钥泄露、
恶意签发机构或纯阻断型DoS。
