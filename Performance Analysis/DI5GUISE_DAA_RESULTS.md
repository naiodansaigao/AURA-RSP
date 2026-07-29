# Di5Guise 真实 DAA 性能结果

## 实现与参数

- DAA 实现：Intel EPID SDK 8.0.0，Intel EPID 协议 2.0
- 仓库：https://github.com/Intel-EPID-SDK/epid-sdk
- 固定 commit：`389426ff4ba2286d2e133bec29d178427d434d8c`
- 成员实现：SDK `member_split` 静态库
- 直接 API：`EpidSign`、`EpidVerify`
- 曲线：256-bit Barreto–Naehrig pairing-friendly curve，embedding degree 12
- 目标安全级别：128 bit
- 哈希：SHA-256（由官方测试 group ID 指定）
- basename：`NULL, 0` 随机模式（匿名、不可链接）
- GroupRL、PrivRL、SigRL：官方 0 条目测试列表；VerifierRL 在 random-base 模式下不适用
- 消息：固定 32 字节，十六进制 `000102...1f`
- EPID 签名长度：392 字节
- 计时器：Windows `QueryPerformanceCounter`，频率 10,000,000 Hz
- 预热：每项 1000 次
- 正式测量：每项 10000 次
- 正确性：初始自检通过；正式生成的 10000 个签名全部验证通过；正式验证 10000/10000 次有效

## DAA 平均时间

| 符号 | 直接调用 | Raw ns | Raw μs | Raw ms | Baseline-corrected ns | Baseline-corrected μs | Baseline-corrected ms |
|---|---|---:|---:|---:|---:|---:|---:|
| 离线预签名 | `EpidAddPreSigs(1)` | 12,097,504.380 | 12,097.504380 | 12.097504380 | 12,097,492.060 | 12,097.492060 | 12.097492060 |
| `T_DG` | `EpidSign` | 26,048.900 | 26.048900 | 0.026048900 | 26,036.560 | 26.036560 | 0.026036560 |
| `T_DV` | `EpidVerify` | 13,602,908.110 | 13,602.908110 | 13.602908110 | 13,602,907.880 | 13,602.907880 | 13.602907880 |

离线预签名时间仅作完整成本披露，不加入用户指定的在线 Di5Guise 公式。
若运行时没有可用预签名，则一次 quote 生成的“离线预计算 + 在线签名”
合计为 `12.123528620 ms`；把该成本也计入方案端到端总量时为
`26.259109050 ms`。这两个值仅用于披露，不替换下述在线公式结果。

## Di5Guise 完整计算

公式：

```text
2T_DH + T_PE + T_PD + T_S + T_V + T_DG + T_DV + 2T_AE + 2T_AD
```

采用 baseline-corrected 平均值：

```text
2T_DH = 2 × 0.023852810 ms = 0.047705620 ms
T_PE  = 0.084980890 ms
T_PD  = 0.062151140 ms
T_S   = 0.025462440 ms
T_V   = 0.071730740 ms
T_DG  = 0.026036560 ms
T_DV  = 13.602907880 ms
2T_AE = 2 × 0.059511780 ms = 0.119023560 ms
2T_AD = 2 × 0.060809080 ms = 0.121618160 ms
```

```text
Di5Guise
= 0.047705620
  + 0.084980890
  + 0.062151140
  + 0.025462440
  + 0.071730740
  + 0.026036560
  + 13.602907880
  + 0.119023560
  + 0.121618160
= 14.161616990 ms
```

Raw 总时间为 `14.161842760 ms`。两个口径在 `schemes` 输出中的状态均为 `OK`。

## 计时边界

密钥/CA/撤销列表加载与认证、成员和验证者上下文创建、成员与验证者 pairing
预计算、Windows CSPRNG 配置、固定消息和签名缓冲区分配都在计时前完成。
对每个样本，程序先调用一次 `EpidAddPreSigs(member, 1)`，确认池为 1；
完成该离线调用后才启动 `T_DG` 计时，`EpidSign` 返回后确认池为 0。
`T_DV` 只测一次对已生成且自检有效 quote 的 `EpidVerify`。没有把进程启动、
普通数字签名或模拟循环计为 DAA。
