# 实验8：跨Profile与跨操作移植

本实验位于独立目录，不修改Standard RSP baseline、AURA-RSP协议源码或实验1—7。
它先完成`Profile-A + download`正向认证和Profile交付，再复制公开认证、`Bind_t`
和密钥请求材料，尝试将其移植到Profile-B或其他操作。

## 一键运行

在WSL2 Ubuntu中执行：

```bash
cd experiments/experiment-08-profile-operation-transplant
bash ./run_demo.sh
```

只输出中文或英文：

```bash
bash ./run_demo.sh --lang zh
bash ./run_demo.sh --lang en
```

机器接口：

```bash
bash ./run_demo.sh --machine-json
```

## AURA-RSP测试

正向控制分别使用两份真实测试Profile：

- Profile-A：`pid_h = SHA-256(Profile-A)`，`op = download`
- Profile-B：`pid_h = SHA-256(Profile-B)`，`op = download`

两者都通过真实BBS+凭证、盲签操作票据、`Pi_auth`、一次性Ed25519签名、
`AuraServerState.authenticate()`、`Bind_t`、ECDHE/HKDF/AEAD和解密摘要检查。

攻击覆盖：

1. 只把Profile-A票据中的`pid_h`改成Profile-B，保留旧`tau_auth`和旧证明；
2. 修改`pid_h`后用白盒夹具重新签名外层`tau_auth`，但保留Profile-A的旧`Pi_auth`；
3. 把Profile-A的`Bind_t/ctx_bind`移植到已认证的Profile-B会话；
4. 把`op=download`改成`delete`；
5. 把`op=download`改成`reinstall`；
6. 把`op=download`改成`enable`。

第2项故意把攻击者能力加强到持有本次会话的一次性签名私钥，用来隔离验证
`Pi_auth`本身的Profile绑定；这不表示网络攻击者通常拥有该密钥。

## Standard RSP对照

Standard部分根据当前osmo-smdpp源码执行事务/Profile/BPP签名的受控对照，并保存
源码哈希与行号证据。它验证：

- 修改Profile摘要但保留原BPP绑定签名会导致签名失败；
- 把Profile-A绑定材料放到Profile-B事务会导致事务或Profile不匹配；
- 替换外层事务号不能把A的签名事务移植到B。

该部分明确标记为`source-backed controlled check`，不是两套osmo-smdpp网络进程
的完整端到端运行。Standard正确实现时也应拒绝，因此不能把结果写成Standard漏洞。

## 能力边界

当前AURA下载服务器只提供`op=download`的认证与Profile交付HTTP路径。
`delete/reinstall/enable`已存在独立生命周期核心实验，但尚未接入同一下载HTTP端点。
因此本实验能够真实证明“download票据不能被改造成其他操作授权”，不能声称三种
生命周期操作已经在9443网络端点完整执行。

## 结果文件

- `results/latest/summary.json`：完整结果和机器断言
- `results/latest/scenarios.csv`：逐场景结果
- `results/latest/assertions.csv`：机器断言
- `results/latest/report-zh.md`、`report-en.md`：双语论文表格
- `results/latest/raw/aura-transcripts.jsonl`：AURA公开转录与响应
- `results/latest/raw/standard-checks.jsonl`：Standard受控检查
- `results/latest/evidence/source-audit.json`：源码哈希、行号与实现边界
- `results/latest/paper/`：中英文论文图、图题和CSV表

## 论文结论口径

实验支持的结论是：AURA-RSP匿名认证不是可复用的“合法设备通行证”，而是同时
绑定Profile、操作、事务和一次性会话材料的最小授权。攻击者不能把Profile-A的
download认证结果用于Profile-B，也不能把download改造成delete、reinstall或enable。
