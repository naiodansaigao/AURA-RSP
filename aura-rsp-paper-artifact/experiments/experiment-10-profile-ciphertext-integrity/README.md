# 实验10：Profile密文篡改、重放与明文替换

本实验位于完全独立的目录，不修改`rsp-baseline/`或实验1—9。根据实验首次暴露的
实现缺口，正式AURA客户端已在解密后补上论文规定的订单`pid_h`检查；本实验读取该
源码检查状态，并使用与当前AURA原型一致的P-256 ECDH、HKDF-SHA256、
AES-256-GCM、Profile响应签名、`ctx_K`和安装收据HMAC语义检查三个层次的问题：

1. 网络攻击者修改密文或AEAD标签；
2. 把Session-A的密文重放到Session-B；
3. 持合法服务器密钥的恶意SM-DP+使用当前合法`K_enc`加密错误Profile。

## 一键运行

在WSL2 Ubuntu中执行：

```bash
cd /path/to/aura-rsp-paper-artifact/experiments/experiment-10-profile-ciphertext-integrity
bash ./run_demo.sh
```

语言和机器接口：

```bash
bash ./run_demo.sh --lang zh
bash ./run_demo.sh --lang en
bash ./run_demo.sh --machine-json
```

若希望在CI中要求三项安全属性全部通过：

```bash
bash ./run_demo.sh --strict-security
```

修复后的当前结果为`PASS`。如果以后正式客户端再次缺少订单摘要检查，
`--strict-security`会让命令以非零状态退出，并在结果中重新标记
`IMPLEMENTATION_GAP_DETECTED`。

## 10A：密文和Tag篡改

- 普通网络攻击路径：修改密文但不掌握服务器签名私钥，首先触发Profile响应签名失败。
- 白盒深度检查：测试夹具使用服务器私钥重新签署被修改的响应，只用于绕过外层签名并
  单独验证AEAD；密文字节翻转和最后16字节Tag翻转均触发AES-GCM认证失败。

白盒重签不属于普通网络攻击者能力，它只是验证“即使前一层被隔离，AEAD自身仍正确”。

## 10B：跨会话重放

- 整包把Session-A响应交给Session-B时，设备首先发现`ctx_K`事务、`Bind_t`或临时
  公钥不匹配。
- 白盒夹具把A的nonce和密文放入B的响应结构并重新签名后，B仍使用独立会话密钥和
  B的`ctx_K`作为AAD，因此AES-GCM认证失败。

## 10C：合法服务器加密错误Profile

恶意SM-DP+使用Session-C的正确`K_enc`，以错误Profile自身的摘要构造正确AAD，
生成有效AES-GCM密文并使用合法服务器密钥签名。当前客户端会依次通过：

- 服务器Profile响应签名；
- `ctx_K`检查；
- AES-GCM认证；
- `H(P) == response.profileSha256`。

正式客户端现已继续检查：

```text
H(P) == ticket.pid_h
```

如果两者不同，客户端在写入Profile文件和生成安装收据之前拒绝，实验记录为
`PROFILE_ORDER_DIGEST_MISMATCH`。因此修复后的10C结果为：

```text
authentication/session binding = passed
AEAD = passed
order pid_h check = failed
profile installed = false
receipt generated = false
```

实验还保留一个明确标注的“移除订单摘要检查”负向控制。该控制会重新接受、安装错误
Profile并生成收据，用于证明10C通过确实来自新增检查，而不是攻击夹具失效。负向控制
不是修复后生产客户端的行为。

## 业务信任边界

如果MNO与SM-DP+共同把错误Profile的摘要写入订单`pid_h`，那么设备看到的订单承诺
与收到的Profile完全一致，协议无法判断业务签发方是否恶意。这属于MNO业务授权信任
问题，不属于密文完整性或Profile Binding可以解决的攻击。

## 结果文件

- `results/latest/summary.json`：完整结果、实现缺口和机器断言
- `results/latest/scenarios.csv`：逐场景检查结果
- `results/latest/assertions.csv`：机器断言和负向控制验证
- `results/latest/raw/transcripts.jsonl`：受控公开转录与设备处理结果
- `results/latest/evidence/source-audit.json`：源码行号、摘要及缺口证据
- `results/latest/report-zh.md`、`report-en.md`：双语论文报告
- `results/latest/paper/`：中英文结果矩阵、检查链图、CSV和图题
