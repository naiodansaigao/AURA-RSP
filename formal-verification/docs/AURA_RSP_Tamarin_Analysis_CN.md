# AURA-RSP Tamarin 形式化验证：完整模型与 Lemma 分析

本文档对 AURA-RSP 的六个 Tamarin 模型进行逐文件、逐规则和逐 lemma 分析，可直接作为 GitHub 仓库中的验证说明文档。分析以仓库中的 `.spthy` 源代码为准，不仅说明每个 lemma 的自然语言含义，还说明其依赖的事件、能够排除的攻击、建模边界以及验证结果应如何解释。

## 1. 验证范围与总体结论

六个模型共包含 **41 个 lemmas**：

- **7 个可执行性（exists-trace）lemmas**：证明每条主要协议分支确实存在诚实完成轨迹，避免安全性质真空成立；
- **34 个全轨迹（all-traces）安全 lemmas**：验证认证、授权、上下文绑定、秘密性、重放处理、条件追踪、密钥协商与安全下载。

所有 41 个 lemmas 均已由 Tamarin 成功验证。推荐的逻辑阅读顺序为：

1. `aura_rsp_server_auth_scheme.spthy`：服务器认证；
2. `aura_rsp_anon_ticket_auth_scheme(1).spthy`：凭证、票据与匿名客户端认证；
3. `aura_rsp_profile_binding_scheme.spthy`：Profile Binding；
4. `aura_rsp_trace_scheme.spthy`：同一票据异常复用时的条件追踪；
5. `aura_rsp_hybrid_scheme.spthy`：classic/hybrid 密钥协商；
6. `aura_rsp_download_scheme.spthy`：加密 Profile 下载与安装确认。

条件追踪是匿名认证后的异常分支，而不是正常下载流程的必经阶段。

## 2. 建模假设与边界

- BBS+ 盲签、随机化签名持有证明和联合 NIZK 被建模为理想不可伪造证明对象；Tamarin 验证协议组合关系，而不是重新证明 BBS+ 的计算不可伪造性、盲性或零知识性。
- `nullifier(eta)`、`profile_handle(pidh,salt_p,x)` 和 `trace_response(d,k,gamma)` 是协议代数关系的符号化构造。
- 条件追踪中的有限域提取公式由理想提取规则表示，只有两份不同且有效的响应同时存在时才能触发。
- ML-KEM 通过理想 encapsulation/decapsulation 等式建模；其底层计算安全作为前提。
- 凭证和票据过期通过抽象有效性事实表示，而非显式时钟。
- PR 网络转发和流量关联不在模型中；`PRaddr` 仍作为订单、签名和事务上下文字段被绑定。
- 当前模型不覆盖 enable、disable、delete、commit-delete、tombstone 和 reinstall。
- secrecy lemma 不等同于观察等价意义下的跨事务不可链接性。

## 3. 代码中的主要符号映射

| 协议对象 | Tamarin 表示 | 含义 |
|---|---|---|
| $k=H_{tr}(EID\|r_{tr})$ | `h(<'trace-index',eid,rtr>)` | EUM 追踪索引 |
| $\nu=g_\nu^\eta$ | `nullifier(eta)` | 同票据稳定的重花检测值 |
| $lph=H_{lph}(pid_h\|salt_p)^x$ | `profile_handle(pidh,salt_p,x)` | Profile 生命周期局部句柄 |
| $c=d+\gamma k$ | `trace_response(d,k,Gamma)` | 条件追踪响应 |
| $\gamma=H(ctx_t)$ | `h(<'gamma',Ctx>)` | 事务挑战 |
| $\tau_{auth}$ | `sign(h(<'auth',Ctx,Gamma,Resp>),skT)` | 一次性会话签名 |
| $Bind_t$ | `sign(CtxB,skSp)` | SM-DP+ 的 Profile-Binding 签名 |
| $K,K_{enc},K_{mac}$ | `kdf`, `kenc`, `kmac` | 主密钥与用途分离子密钥 |
| AEAD Profile 密文 | `aead(profile,Kenc,CtxK)` | 绑定 $ctx_K$ 的加密 Profile |
| 安装收据标签 | `mac(Data,Kmac)` | 安装状态真实性 |

## 4. 如何解释 Tamarin 结果

- `verified` 表示在当前符号模型、规则和建模假设下，Tamarin 未找到违反 lemma 的轨迹。
- `exists-trace verified` 表示至少存在一条满足目标事件的协议轨迹。
- `all-traces verified` 表示所有可达轨迹均满足给定一阶逻辑性质。
- 证明结果只覆盖 lemma 明确量化的事件和参数；不能把一个 secrecy lemma 扩大解释为完整匿名性或不可链接性证明。

## 5. 服务器认证与能力转录绑定

- **文件：** `aura_rsp_server_auth_scheme.spthy`
- **Theory：** `AURA_RSP_Server_Auth_Scheme_V6`
- **Lemma 数量：** 4

该模型对应协议中的服务器认证阶段，直接建模
$\sigma_S^{auth}=\mathrm{Sig}_{SK_{Sa}}(I_t\|N_S\|N_U\|sid\|serverOID\|PRaddr\|cap)$。
设备只有在验证签名后才产生 `DeviceAcceptedServer`。

**建模边界：** 该模型固定实例化 hybrid 能力转录；classic/hybrid 两种模式的一致性由独立密钥协商模型验证。PR 的转发过程未建模，但 $PRaddr$ 仍是订单和服务器签名中的绑定字段。

### 规则流程

| Rule | 作用 |
|---|---|
| `Setup_Server` | 生成 SM-DP+ 服务器认证密钥，并公开验证公钥。 |
| `Create_Download_Order` | 创建下载订单，绑定 $I_{ac}$、$sid$、$pid_h$、$exp$ 与 $PRaddr$。 |
| `Device_Send_Server_Authentication_Request` | 设备生成 $N_U$ 并发送订单、路由和能力集合。 |
| `Server_Send_Authentication_Response` | SM-DP+ 生成 $I_t$、$N_S$，并签名完整服务器认证上下文。 |
| `Device_Accept_Authenticated_Server` | 设备验证服务器签名后产生接受事件。 |

### Lemma 逐项分析

#### 1. `exists_server_authentication`

- **类型：** 可执行性
- **原始定义：**

```tamarin
lemma exists_server_authentication:
exists-trace
  "Ex eid Iac sid It #i.
     ServerAuthenticationComplete(eid,Iac,sid,It) @ #i"
```

- **形式化含义：** 证明至少存在一条轨迹，使设备完成服务器认证。
- **验证的安全效果：** 它排除服务器认证分支不可达所造成的真空证明，并确认订单创建、请求、响应、签名验证和接受事件可以按顺序发生。
- **解释边界：** 该 lemma 不表达攻击抵抗性；其作用是为后续全称性质提供可执行性基础。
- **验证结果：** `verified`

#### 2. `server_authentication_agreement`

- **类型：** 认证一致性
- **原始定义：**

```tamarin
lemma server_authentication_agreement:
"All eid Iac sid It NS NU serverOID PRaddr Cap #i.
     DeviceAcceptedServer(eid,Iac,sid,It,NS,NU,
                          serverOID,PRaddr,Cap) @ #i
     ==> (Ex #j.
            ServerAuthSent(Iac,sid,It,NS,NU,
                           serverOID,PRaddr,Cap) @ #j
          & #j < #i)"
```

- **形式化含义：** 设备接受某一服务器认证上下文时，SM-DP+ 必须此前发送过完全相同的上下文。
- **验证的安全效果：** 绑定 $I_{ac}$、$sid$、$I_t$、$N_S$、$N_U$、$serverOID$、$PRaddr$ 和 $Cap$，排除服务器冒充、随机数替换、事务搬用和签名响应跨会话重放。
- **解释边界：** 这是非注入式 agreement：它证明接受事件存在匹配发送事件，但不要求不同接受事件一定对应不同发送事件。
- **验证结果：** `verified`

#### 3. `server_authentication_order_binding`

- **类型：** 订单绑定
- **原始定义：**

```tamarin
lemma server_authentication_order_binding:
"All eid Iac sid It NS NU serverOID PRaddr Cap #i.
     DeviceAcceptedServer(eid,Iac,sid,It,NS,NU,
                          serverOID,PRaddr,Cap) @ #i
     ==> (Ex pidh exp #j.
            OrderCreated(Iac,sid,pidh,'download',exp,PRaddr) @ #j
          & #j < #i)"
```

- **形式化含义：** 设备接受服务器认证时，必须存在更早创建的同一下载订单。
- **验证的安全效果：** 确保认证结果不能脱离 $I_{ac}$、$sid$、$pid_h$、$exp$ 和 $PRaddr$ 所描述的订单上下文使用。
- **解释边界：** 它证明字段与订单事件的对应关系，不模拟现实业务数据库或物理时间。
- **验证结果：** `verified`

#### 4. `capability_transcript_binding`

- **类型：** 能力绑定
- **原始定义：**

```tamarin
lemma capability_transcript_binding:
"All eid Iac sid It NS NU serverOID PRaddr Cap #i.
     DeviceAcceptedServer(eid,Iac,sid,It,NS,NU,
                          serverOID,PRaddr,Cap) @ #i
     ==> Cap = capability('caps-hybrid','hybrid')"
```

- **形式化含义：** 设备接受的能力转录必须等于模型中选定的 hybrid 能力转录。
- **验证的安全效果：** 阻止攻击者把服务器签名响应中的能力结果替换成其他值。
- **解释边界：** 该文件固定 hybrid 实例；classic/hybrid 双模式与防交叉接受由 hybrid 模型覆盖。
- **验证结果：** `verified`

## 6. 匿名凭证、一次性票据与匿名客户端认证

- **文件：** `aura_rsp_anon_ticket_auth_scheme(1).spthy`
- **Theory：** `AURA_RSP_Anon_Ticket_Auth_Scheme_V6`
- **Lemma 数量：** 14

该模型覆盖离线凭证签发、一次性操作票据、服务器会话输入以及匿名客户端认证。
核心关系被保留为 `nullifier(eta)`、`profile_handle(pidh,salt_p,x)` 和
`trace_response(d,k,Gamma)`，并通过 `ValidAnonProof` 表达两份 BBS+ 签名、共享隐藏
$x$ 以及 $\nu$、$lph$、$c$ 的联合证明。

**建模边界：** BBS+ 盲签发和联合随机化零知识证明由发行状态与私有事实 `ValidAnonProof` 理想化表示。票据和凭证的有效期由抽象有效性事实表示，而不是显式物理时钟。

### 规则流程

| Rule | 作用 |
|---|---|
| `Create_Order_Context` | 建立票据公开订单字段。 |
| `Offline_Register_And_Issue_Credential` | EUM 注册设备并建立包含同一 $x$、$k$ 和 $cred_{exp}$ 的凭证状态。 |
| `Issue_One_Time_Operation_Ticket` | MNO/Reseller 针对当前订单签发包含隐藏 $x$、$\eta$、$d$ 的一次性票据。 |
| `Establish_Authenticated_Server_Session` | 抽象前一服务器认证阶段，建立 $I_t$、$N_S$、$N_U$ 和 $cap$。 |
| `Device_Generate_Anonymous_Authentication` | 设备构造 $\nu$、$lph$、$ctx_t$、$\gamma$、$c$、$\tau_{auth}$ 与理想化 $\Pi_{auth}$。 |
| `Server_Accept_Fresh_Anonymous_Authentication` | 服务器验证证明、临时签名和有效性事实，并消耗未使用的 nullifier。 |
| `Server_Process_Exact_Replay` | 对已经接受的完全相同认证消息执行幂等重传处理。 |

### Lemma 逐项分析

#### 1. `exists_anonymous_authentication`

- **类型：** 可执行性
- **原始定义：**

```tamarin
lemma exists_anonymous_authentication:
exists-trace
  "Ex eid x k Iac sid pidh op exp PRaddr Ctx Nf Lph opid VkT #i.
     SmdpAcceptedAnonymousAuth(eid,x,k,Iac,sid,pidh,op,exp,
                               PRaddr,Ctx,Nf,Lph,opid,VkT) @ #i"
```

- **形式化含义：** 证明匿名凭证、票据、服务器会话、联合证明、临时签名和新鲜 nullifier 可以形成一次成功认证。
- **验证的安全效果：** 确认匿名认证分支可达，避免所有后续安全性质因为服务器永远无法接受而真空成立。
- **解释边界：** 不单独证明任何安全保证。
- **验证结果：** `verified`

#### 2. `anonymous_authentication_soundness`

- **类型：** 匿名认证可靠性
- **原始定义：**

```tamarin
lemma anonymous_authentication_soundness:
"All eid x k Iac sid pidh op exp PRaddr Ctx Nf Lph opid VkT #i.
     SmdpAcceptedAnonymousAuth(eid,x,k,Iac,sid,pidh,op,exp,
                               PRaddr,Ctx,Nf,Lph,opid,VkT) @ #i
     ==> (Ex cred_exp #c.
            CredentialIssued(eid,x,k,cred_exp) @ #c & #c < #i)
       & (Ex eta d #t.
            TicketIssued(eid,x,Iac,sid,pidh,op,exp,
                         PRaddr,eta,d) @ #t
          & #t < #i)"
```

- **形式化含义：** SM-DP+ 接受匿名认证，必然对应更早的 EUM 凭证签发和 MNO/Reseller 票据签发。
- **验证的安全效果：** 排除没有合法凭证、没有当前订单票据或凭空伪造 `ValidAnonProof` 的认证。
- **解释边界：** 它依赖 BBS+ 和联合 NIZK 的理想不可伪造抽象；不重新证明底层 BBS+ 安全。
- **验证结果：** `verified`

#### 3. `ticket_non_transferability`

- **类型：** 票据不可转移
- **原始定义：**

```tamarin
lemma ticket_non_transferability:
"All eid x k Iac sid pidh op exp PRaddr Ctx Nf Lph opid VkT #i.
     SmdpAcceptedAnonymousAuth(eid,x,k,Iac,sid,pidh,op,exp,
                               PRaddr,Ctx,Nf,Lph,opid,VkT) @ #i
     ==> (Ex cred_exp eta d #c #t.
            CredentialIssued(eid,x,k,cred_exp) @ #c
          & TicketIssued(eid,x,Iac,sid,pidh,op,exp,
                         PRaddr,eta,d) @ #t
          & #c < #i & #t < #i)"
```

- **形式化含义：** 匹配的凭证与票据签发事件必须共享同一个隐藏秘密 $x$。
- **验证的安全效果：** 阻止攻击者组合设备 A 的凭证与设备 B 的票据，或者把窃取的票据交给另一个合法设备使用。
- **解释边界：** 该保证基于 eUICC 长期秘密 $x$ 不泄露以及联合证明正确执行。
- **验证结果：** `verified`

#### 4. `minimal_authorization_context_binding`

- **类型：** 最小授权上下文绑定
- **原始定义：**

```tamarin
lemma minimal_authorization_context_binding:
"All eid x k Iac sid pidh op exp PRaddr Ctx Nf Lph opid VkT #i.
     SmdpAcceptedAnonymousAuth(eid,x,k,Iac,sid,pidh,op,exp,
                               PRaddr,Ctx,Nf,Lph,opid,VkT) @ #i
     ==> (Ex eta d #t.
            TicketIssued(eid,x,Iac,sid,pidh,op,exp,
                         PRaddr,eta,d) @ #t
          & #t < #i)"
```

- **形式化含义：** 被接受的认证必须对应针对完全相同订单字段签发的票据。
- **验证的安全效果：** 绑定 $I_{ac}$、$sid$、$pid_h$、$op$、$exp$ 和 $PRaddr$，排除跨订单、跨服务器、跨 Profile、跨操作和跨路由使用票据。
- **解释边界：** `exp` 在本模型中是被签名并检查的字段，时间流逝通过抽象有效性事实处理。
- **验证结果：** `verified`

#### 5. `authentication_signature_is_verified`

- **类型：** 临时会话签名验证
- **原始定义：**

```tamarin
lemma authentication_signature_is_verified:
"All eid x k Iac sid pidh op exp PRaddr Ctx Nf Lph opid VkT #i.
     SmdpAcceptedAnonymousAuth(eid,x,k,Iac,sid,pidh,op,exp,
                               PRaddr,Ctx,Nf,Lph,opid,VkT) @ #i
     ==> (Ex Gamma Resp.
            AuthenticationSignatureVerified(VkT,Ctx,Gamma,Resp) @ #i)"
```

- **形式化含义：** 每个匿名认证接受事件都伴随对 $\tau_{auth}$ 的成功验证。
- **验证的安全效果：** 保证 $vk_t$、$ctx_t$、$\gamma$ 和 $c$ 之间的临时签名绑定，排除攻击者替换响应或使用不匹配的临时公钥。
- **解释边界：** 验证事件与接受事件位于同一个规则时刻，说明验证是接受的必要条件。
- **验证结果：** `verified`

#### 6. `accepted_authentication_uses_valid_credential_and_ticket`

- **类型：** 有效性检查
- **原始定义：**

```tamarin
lemma accepted_authentication_uses_valid_credential_and_ticket:
"All eid x k Iac sid pidh op exp PRaddr Ctx Nf Lph opid VkT #i.
     SmdpAcceptedAnonymousAuth(eid,x,k,Iac,sid,pidh,op,exp,
                               PRaddr,Ctx,Nf,Lph,opid,VkT) @ #i
     ==> (Ex cred_exp #c.
            CredentialValidityEstablished(eid,cred_exp) @ #c
          & #c < #i)
       & (Ex #t. TicketValidityEstablished(Iac,exp) @ #t
          & #t < #i)"
```

- **形式化含义：** 接受认证之前必须建立凭证有效和票据有效的事实。
- **验证的安全效果：** 排除模型中的过期或被撤销凭证/票据直接进入接受规则。
- **解释边界：** 这是抽象有效性证明，不是对实时时钟、撤销列表传播延迟或时钟同步的分析。
- **验证结果：** `verified`

#### 7. `profile_handle_bound_to_credential_secret`

- **类型：** Profile 句柄绑定
- **原始定义：**

```tamarin
lemma profile_handle_bound_to_credential_secret:
"All eid x k Iac sid pidh op exp PRaddr Ctx Nf Lph opid VkT #i.
     SmdpAcceptedAnonymousAuth(eid,x,k,Iac,sid,pidh,op,exp,
                               PRaddr,Ctx,Nf,Lph,opid,VkT) @ #i
     ==> (Ex #j.
            DeviceAuthGenerated(eid,x,k,Iac,sid,pidh,op,exp,
                                PRaddr,Nf,Lph,opid,VkT,Ctx) @ #j
          & #j < #i)"
```

- **形式化含义：** 被接受的 $lph$ 必须来自更早的设备认证生成事件，并与同一个 $x$、$pid_h$ 和事务上下文相连。
- **验证的安全效果：** 阻止其他设备冒用目标 Profile 生命周期句柄，也阻止把一个 Profile 的句柄替换到另一个认证中。
- **解释边界：** 具体离散对数关系由 `profile_handle(pidh,salt_p,x)` 的理想构造表达。
- **验证结果：** `verified`

#### 8. `nullifier_single_business_acceptance`

- **类型：** 一次性业务执行
- **原始定义：**

```tamarin
lemma nullifier_single_business_acceptance:
"All Nf Ctx1 Ctx2 #i #j.
     BusinessAccepted(Nf,Ctx1) @ #i
   & BusinessAccepted(Nf,Ctx2) @ #j
     ==> #i = #j"
```

- **形式化含义：** 同一个 nullifier 对应的两个 `BusinessAccepted` 事件必须是同一事件。
- **验证的安全效果：** 确保同一票据最多触发一次实际业务接受，即使攻击者并发重放或重新排列消息。
- **解释边界：** 它不阻止服务器记录相同消息的幂等重传；幂等行为由独立规则处理。
- **验证结果：** `verified`

#### 9. `exact_replay_is_idempotent`

- **类型：** 精确重传幂等性
- **原始定义：**

```tamarin
lemma exact_replay_is_idempotent:
"All Nf Ctx #i.
     ExactReplayProcessed(Nf,Ctx) @ #i
     ==> not (Ex Ctx2 #j.
                BusinessAccepted(Nf,Ctx2) @ #j & #i < #j)"
```

- **形式化含义：** 服务器处理完全相同的认证消息后，不会在其后再次对同一 nullifier 产生新的业务接受。
- **验证的安全效果：** 区分网络重传与新业务执行，避免丢包重试导致重复下载或重复状态改变。
- **解释边界：** 该性质针对完全相同的 `Mauth`；内容不同的同一票据使用由追踪模型分析。
- **验证结果：** `verified`

#### 10. `eid_secrecy`

- **类型：** EID 秘密性
- **原始定义：**

```tamarin
lemma eid_secrecy:
"All eid #i.
     SecretEID(eid) @ #i ==> not (Ex #j. K(eid) @ #j)"
```

- **形式化含义：** 攻击者不能推导 EID。
- **验证的安全效果：** 验证在线消息和模型状态不会把真实设备身份泄露给网络攻击者。
- **解释边界：** 不等同于观察等价意义下的不可链接性，也不分析外部元数据。
- **验证结果：** `verified`

#### 11. `x_secrecy`

- **类型：** 长期秘密 $x$ 的秘密性
- **原始定义：**

```tamarin
lemma x_secrecy:
"All x #i.
     SecretX(x) @ #i ==> not (Ex #j. K(x) @ #j)"
```

- **形式化含义：** 攻击者不能推导 eUICC 长期匿名秘密 $x$。
- **验证的安全效果：** 保护凭证与票据不可转移绑定以及 $lph$ 的生成秘密。
- **解释边界：** 不包含 eUICC 硬件被攻陷后的密钥提取情形。
- **验证结果：** `verified`

#### 12. `eta_secrecy`

- **类型：** 票据随机量 $\eta$ 的秘密性
- **原始定义：**

```tamarin
lemma eta_secrecy:
"All eta #i.
     SecretEta(eta) @ #i ==> not (Ex #j. K(eta) @ #j)"
```

- **形式化含义：** 攻击者不能从公开 nullifier 推导 $\eta$。
- **验证的安全效果：** 保持不同票据的 nullifier 随机性，并避免公开指数秘密。
- **解释边界：** 依赖 `nullifier/1` 的单向理想抽象。
- **验证结果：** `verified`

#### 13. `d_secrecy`

- **类型：** 追踪偏移 $d$ 的秘密性
- **原始定义：**

```tamarin
lemma d_secrecy:
"All d #i.
     SecretD(d) @ #i ==> not (Ex #j. K(d) @ #j)"
```

- **形式化含义：** 攻击者不能获得固定于票据的追踪偏移 $d$。
- **验证的安全效果：** 保证单份 $c=d+\gamma k$ 不会直接暴露追踪索引 $k$。
- **解释边界：** 该 lemma 单独证明 $d$ 不泄露；单份响应不可追踪还由 trace 模型的结构性质支持。
- **验证结果：** `verified`

#### 14. `temporary_signing_key_secrecy`

- **类型：** 一次性私钥秘密性
- **原始定义：**

```tamarin
lemma temporary_signing_key_secrecy:
"All skT #i.
     SecretTemporarySigningKey(skT) @ #i
     ==> not (Ex #j. K(skT) @ #j)"
```

- **形式化含义：** 攻击者不能获得 $sk_t$。
- **验证的安全效果：** 阻止伪造 $\tau_{auth}$ 和后续设备侧密钥协商签名。
- **解释边界：** 不考虑 eUICC 临时密钥存储被直接攻陷。
- **验证结果：** `verified`

## 7. 事务绑定的 Profile Binding

- **文件：** `aura_rsp_profile_binding_scheme.spthy`
- **Theory：** `AURA_RSP_Profile_Binding_Scheme_V6`
- **Lemma 数量：** 4

该模型严格建模
$th_{auth}=H(\text{"auth-transcript"}\|ctx_t\|H(M_U^{auth}))$、
$ctx_{bind}=H(\text{"bind"}\|ctx_t\|th_{auth})$ 和
$Bind_t=\mathrm{Sig}_{SK_{Sp}}(ctx_{bind})$。

**建模边界：** 匿名认证模块与本模块采用组合式验证：本文件不重复执行凭证和票据流程，而把已经接受的匿名认证上下文作为入口状态。

### 规则流程

| Rule | 作用 |
|---|---|
| `Setup_Profile_Binding_Key` | 生成 SM-DP+ 的 Profile-Binding 签名密钥。 |
| `Establish_Accepted_Anonymous_Context` | 将已经接受的完整 $ctx_t$ 和 $M_U^{auth}$ 作为模块输入。 |
| `Server_Create_Profile_Binding` | 计算 $th_{auth}$、$ctx_{bind}$ 并生成 $Bind_t$。 |
| `Device_Accept_Profile_Binding` | 设备验证 $Bind_t$ 后接受绑定结果。 |

### Lemma 逐项分析

#### 1. `exists_profile_binding`

- **类型：** 可执行性
- **原始定义：**

```tamarin
lemma exists_profile_binding:
exists-trace
  "Ex eid sid Ctx Bind #i.
     BoundProtocolComplete(eid,sid,Ctx,Bind) @ #i"
```

- **形式化含义：** 证明匿名认证被接受后，服务器可以生成 $Bind_t$，设备可以完成验证。
- **验证的安全效果：** 确认 Profile Binding 模块不是不可达分支。
- **解释边界：** 不单独表达绑定安全。
- **验证结果：** `verified`

#### 2. `profile_binding_agreement`

- **类型：** Profile Binding 一致性
- **原始定义：**

```tamarin
lemma profile_binding_agreement:
"All eid sid serverOID Order Ctx CtxB Bind #i.
     DeviceAcceptedBinding(eid,sid,serverOID,Order,Ctx,CtxB,Bind) @ #i
     ==> (Ex #j.
            ServerCreatedBinding(sid,serverOID,Order,Ctx,CtxB,Bind) @ #j
          & #j < #i)"
```

- **形式化含义：** 设备接受的每个绑定都必须对应服务器更早创建的相同 `Order`、$Ctx$、$CtxB$ 和 `Bind`。
- **验证的安全效果：** 排除攻击者伪造 $Bind_t$、替换绑定摘要或把服务器未生成的绑定注入设备。
- **解释边界：** 依赖数字签名和哈希的理想安全。
- **验证结果：** `verified`

#### 3. `binding_uses_accepted_anonymous_context`

- **类型：** 绑定依赖匿名认证
- **原始定义：**

```tamarin
lemma binding_uses_accepted_anonymous_context:
"All eid sid serverOID Order Ctx CtxB Bind #i.
     DeviceAcceptedBinding(eid,sid,serverOID,Order,Ctx,CtxB,Bind) @ #i
     ==> (Ex Iac pidh lph nu VkT Cap #j.
            AnonymousAuthenticationAccepted(eid,sid,Iac,pidh,Ctx,
                                            lph,nu,VkT,Cap) @ #j
          & #j < #i)"
```

- **形式化含义：** 设备接受 $Bind_t$ 之前，必须存在同一设备、服务器、订单与 $ctx_t$ 的匿名认证接受事件。
- **验证的安全效果：** 保证服务器不能绕过匿名凭证/票据验证直接为任意上下文生成可接受的 Profile Binding。
- **解释边界：** 由于采用模块化模型，匿名认证事件在本文件中作为入口抽象产生。
- **验证结果：** `verified`

#### 4. `binding_cannot_cross_contexts`

- **类型：** 跨上下文抗转移
- **原始定义：**

```tamarin
lemma binding_cannot_cross_contexts:
"All eid1 eid2 sid serverOID Order1 Order2 Ctx1 Ctx2
       CtxB1 CtxB2 Bind #i #j.
     DeviceAcceptedBinding(eid1,sid,serverOID,Order1,Ctx1,CtxB1,Bind) @ #i
   & DeviceAcceptedBinding(eid2,sid,serverOID,Order2,Ctx2,CtxB2,Bind) @ #j
     ==> Ctx1 = Ctx2 & Order1 = Order2"
```

- **形式化含义：** 如果同一个 `Bind` 被两个设备接受，则两次接受的 $Ctx$ 和 `Order` 必须相同。
- **验证的安全效果：** 排除跨订单、跨 Profile 或跨认证转录复用同一个绑定结果。
- **解释边界：** 它允许同一绑定消息的合法重传，但不允许其语义上下文改变。
- **验证结果：** `verified`

## 8. 条件追踪与抗栽赃

- **文件：** `aura_rsp_trace_scheme.spthy`
- **Theory：** `AURA_RSP_Trace_Scheme_V6`
- **Lemma 数量：** 6

该模型分析同一票据被重复使用时的条件追踪。首次响应被缓存；完全相同的消息被视为重传；
只有第二份有效响应具有不同挑战时，服务器才能产生 `TraceEvidence` 并请求 EUM 解析身份。

**建模边界：** 有限域恢复公式 $k=(c-c')(\gamma-\gamma')^{-1}$ 被表示为理想提取规则；该规则只有在同一 $\nu$ 下存在两份不同且有效的响应时才能启用。

### 规则流程

| Rule | 作用 |
|---|---|
| `Register_Device` | 建立凭证记录以及 $k\mapsto EID$ 的追踪表。 |
| `Issue_Ticket` | 生成固定于同一票据的 $\eta$、$d$ 和 $\nu$。 |
| `Device_First_Valid_Response` | 为票据首次生成完整有效响应并缓存。 |
| `Device_Return_Cached_Response` | 相同操作实例只返回缓存消息。 |
| `Device_Reuse_Ticket_For_New_Operation` | 模拟同一票据在新的 $opid$ 和事务上下文中被再次使用。 |
| `Server_Accept_First_Response` | 服务器接受首次有效响应并记录使用过的 nullifier。 |
| `Server_Process_Exact_Replay` | 相同消息被识别为精确重传。 |
| `Server_Detect_Double_Spend` | 仅在第二份响应有效且挑战不同的情况下产生追踪证据。 |
| `EUM_Resolve` | EUM 根据恢复的 $k$ 查询追踪表并解析 EID。 |

### Lemma 逐项分析

#### 1. `exists_conditional_trace`

- **类型：** 可执行性
- **原始定义：**

```tamarin
lemma exists_conditional_trace:
exists-trace
  "Ex eid Nu k #i. ConditionalTraceComplete(eid,Nu,k) @ #i"
```

- **形式化含义：** 证明同一票据在两个不同操作实例中产生不同有效响应后，服务器能够生成追踪证据并由 EUM 解析身份。
- **验证的安全效果：** 确认条件追踪路径确实可达，而不是只有不可追踪性质成立。
- **解释边界：** 该轨迹模拟恶意或违规重用票据，不代表正常诚实执行必然触发追踪。
- **验证结果：** `verified`

#### 2. `tracing_requires_two_distinct_valid_responses`

- **类型：** 双响应追踪条件
- **原始定义：**

```tamarin
lemma tracing_requires_two_distinct_valid_responses:
"All eid Nu k M1 M2 #i.
     IdentityResolved(eid,Nu,k,M1,M2) @ #i
     ==> (Ex opid1 opid2 Ctx1 Ctx2 G1 G2 C1 C2 #j #m.
            ServerAcceptedValidResponse(Nu,opid1,Ctx1,G1,C1,k,M1) @ #j
          & ServerAcceptedValidResponse(Nu,opid2,Ctx2,G2,C2,k,M2) @ #m
          & #j < #i & #m < #i
          & not (G1 = G2))"
```

- **形式化含义：** 任何身份解析必须有两份服务器接受的有效响应，且两份响应的挑战不同。
- **验证的安全效果：** 保证单个服务器转录不足以追踪设备，并要求追踪证据来自同一 nullifier 的真实双重使用。
- **解释边界：** 有限域代数恢复采用理想提取规则；该 lemma 验证启用提取的协议条件。
- **验证结果：** `verified`

#### 3. `trace_resolves_issued_device`

- **类型：** 追踪解析正确性
- **原始定义：**

```tamarin
lemma trace_resolves_issued_device:
"All eid Nu k M1 M2 #i.
     IdentityResolved(eid,Nu,k,M1,M2) @ #i
     ==> (Ex x cred_exp #j.
            CredentialIssued(eid,x,k,cred_exp) @ #j & #j < #i)"
```

- **形式化含义：** 被解析的 EID 必须对应 EUM 更早签发凭证时登记的同一个追踪索引 $k$。
- **验证的安全效果：** 防止追踪结果指向未注册设备或把设备 A 的证据解析成设备 B。
- **解释边界：** 假设 EUM 的 `TraceMap` 完整且未被攻陷。
- **验证结果：** `verified`

#### 4. `same_opid_is_non_frameable`

- **类型：** 同一操作标识抗栽赃
- **原始定义：**

```tamarin
lemma same_opid_is_non_frameable:
"All eid Nu opid Ctx1 Ctx2 G1 G2 C1 C2 k M1 M2 #i #j.
     DeviceValidResponse(eid,Nu,opid,Ctx1,G1,C1,k,M1) @ #i
   & DeviceValidResponse(eid,Nu,opid,Ctx2,G2,C2,k,M2) @ #j
     ==> Ctx1 = Ctx2 & M1 = M2"
```

- **形式化含义：** 诚实设备若对同一 $\nu$ 和同一 `opid` 产生两个有效响应，则两者的上下文和完整消息必须相同。
- **验证的安全效果：** 阻止恶意服务器在相同操作实例下改变随机数、挑战或能力上下文，诱导设备生成两份可提取响应。
- **解释边界：** 新操作实例允许使用不同 `opid`；违规票据重用的追踪仍然可发生。
- **验证结果：** `verified`

#### 5. `exact_replay_does_not_create_trace`

- **类型：** 重传不触发追踪
- **原始定义：**

```tamarin
lemma exact_replay_does_not_create_trace:
"All Nu opid Ctx Msg #i.
     ExactReplayProcessed(Nu,opid,Ctx,Msg) @ #i
     ==> not (Ex eid k #j.
                IdentityResolved(eid,Nu,k,Msg,Msg) @ #j)"
```

- **形式化含义：** 被标记为精确重传的同一消息不会以 `(Msg,Msg)` 的形式产生身份解析。
- **验证的安全效果：** 防止网络重复、超时重试或攻击者复制同一消息被误判为双花。
- **解释边界：** 该性质不保护两份不同且有效的重花响应；后者是设计上允许追踪的条件。
- **验证结果：** `verified`

#### 6. `no_trace_from_single_accepted_response`

- **类型：** 单响应不可追踪
- **原始定义：**

```tamarin
lemma no_trace_from_single_accepted_response:
"All eid Nu k M1 M2 #i.
     IdentityResolved(eid,Nu,k,M1,M2) @ #i
     ==> not (M1 = M2)"
```

- **形式化含义：** 每次身份解析使用的两份消息必须不同。
- **验证的安全效果：** 确保复制一份响应不能满足追踪条件。
- **解释边界：** 与双挑战 lemma 共同说明追踪需要两份真正不同的有效转录。
- **验证结果：** `verified`

## 9. Classic/Hybrid 认证密钥协商

- **文件：** `aura_rsp_hybrid_scheme.spthy`
- **Theory：** `AURA_RSP_Hybrid_Scheme_V6`
- **Lemma 数量：** 7

该模型同时包含 classic ECDHE 与 ECDHE+ML-KEM hybrid 两条分支。
能力转录先写入 $ctx_t$ 并由 $Bind_t$ 绑定；设备和服务器的密钥协商签名严格覆盖论文中规定的
ECDHE/KEM 材料。

**建模边界：** ML-KEM 通过 `kem_enc/kem_dec` 和理想解封等式建模；底层计算安全不在 Tamarin 中重新证明。模式选择被写入 $ctx_t$ 并由 $Bind_t$ 绑定。

### 规则流程

| Rule | 作用 |
|---|---|
| `Setup` | 生成服务器 Profile-Binding/密钥协商签名密钥。 |
| `Create_Unselected_Bound_Context` | 建立尚未选择 classic 或 hybrid 的绑定上下文。 |
| `Select_Classic_Bound_Context` | 将 classic 能力转录写入 $ctx_t$ 并签名生成 $Bind_t$。 |
| `Select_Hybrid_Bound_Context` | 将 hybrid 能力转录写入 $ctx_t$ 并签名生成 $Bind_t$。 |
| `Device_Send_Classic_KA` | 设备发送 ECDHE 公钥及由 $sk_t$ 认证的 classic 请求。 |
| `Server_Accept_Classic_KA` | 服务器验证请求、生成 $Q_S$ 并派生 classic 会话密钥。 |
| `Device_Accept_Classic_KA` | 设备验证服务器签名并派生相同 classic 密钥。 |
| `Device_Send_Hybrid_KA` | 设备同时发送 ECDHE 公钥和 ML-KEM 公钥。 |
| `Server_Accept_Hybrid_KA` | 服务器执行 ECDHE、KEM encapsulation 并派生 hybrid 密钥。 |
| `Device_Accept_Hybrid_KA` | 设备解封 KEM 密文并派生相同 hybrid 密钥。 |

### Lemma 逐项分析

#### 1. `exists_classic_key_agreement`

- **类型：** 可执行性
- **原始定义：**

```tamarin
lemma exists_classic_key_agreement:
exists-trace
  "Ex eid sid Iac CtxK K #i.
     ClassicComplete(eid,sid,Iac,CtxK,K) @ #i"
```

- **形式化含义：** 证明 classic ECDHE 路径可以完成并产生 `ClassicComplete`。
- **验证的安全效果：** 确认模式选择、双方签名验证和密钥派生链条可执行。
- **解释边界：** 不单独表达密钥安全。
- **验证结果：** `verified`

#### 2. `exists_hybrid_key_agreement`

- **类型：** 可执行性
- **原始定义：**

```tamarin
lemma exists_hybrid_key_agreement:
exists-trace
  "Ex eid sid Iac CtxK K #i.
     HybridComplete(eid,sid,Iac,CtxK,K) @ #i"
```

- **形式化含义：** 证明 ECDHE+ML-KEM hybrid 路径可以完成并产生 `HybridComplete`。
- **验证的安全效果：** 确认 KEM 公钥、密文、解封和混合 KDF 的诚实轨迹可执行。
- **解释边界：** 不重新证明 ML-KEM 的计算安全。
- **验证结果：** `verified`

#### 3. `key_agreement_mode_and_transcript_agreement`

- **类型：** 模式与转录一致性
- **原始定义：**

```tamarin
lemma key_agreement_mode_and_transcript_agreement:
"All eid sid Iac mode Cap CtxK K QU QS PkPQ CtPQ #i.
     DeviceDerived(eid,sid,Iac,mode,Cap,CtxK,K,QU,QS,PkPQ,CtPQ) @ #i
     ==> (Ex #j.
            ServerDerived(sid,Iac,mode,Cap,CtxK,K,QU,QS,PkPQ,CtPQ) @ #j
          & #j < #i)"
```

- **形式化含义：** 设备派生密钥时，服务器必须更早针对相同模式、能力转录、$ctx_K$、密钥以及全部 KA 材料派生相同结果。
- **验证的安全效果：** 排除公钥替换、KEM 密文替换、跨会话响应重放、未知密钥共享和模式材料混合。
- **解释边界：** 这是设备到服务器方向的 agreement；服务器接受设备请求由签名验证规则保证。
- **验证结果：** `verified`

#### 4. `hybrid_acceptance_requires_hybrid_capability_transcript`

- **类型：** Hybrid 能力一致性
- **原始定义：**

```tamarin
lemma hybrid_acceptance_requires_hybrid_capability_transcript:
"All eid sid Iac Cap CtxK K QU QS PkPQ CtPQ #i.
     DeviceDerived(eid,sid,Iac,'hybrid',Cap,CtxK,K,QU,QS,PkPQ,CtPQ) @ #i
     ==> Cap = cap_transcript('caps-hybrid','hybrid')"
```

- **形式化含义：** 设备接受 hybrid 密钥时，绑定的能力转录必须明确选择 hybrid。
- **验证的安全效果：** 阻止在 classic 能力上下文下偷偷注入 PQ 材料或把 hybrid 结果从其他上下文搬入。
- **解释边界：** 能力协商策略本身被抽象为 `cap_transcript`，不分析 UI 或外部策略错误。
- **验证结果：** `verified`

#### 5. `classic_acceptance_requires_classic_capability_transcript`

- **类型：** Classic 能力一致性
- **原始定义：**

```tamarin
lemma classic_acceptance_requires_classic_capability_transcript:
"All eid sid Iac Cap CtxK K QU QS #i.
     DeviceDerived(eid,sid,Iac,'classic',Cap,CtxK,K,QU,QS,
                   'none','none') @ #i
     ==> Cap = cap_transcript('caps-classic','classic')"
```

- **形式化含义：** 设备接受 classic 密钥时，能力转录必须明确选择 classic，PQ 参数必须为 `none`。
- **验证的安全效果：** 阻止 hybrid 上下文被静默当作 classic 使用，并避免遗留 PQ 材料。
- **解释边界：** 不判断策略是否应该优先 hybrid，只验证已选择模式的一致性。
- **验证结果：** `verified`

#### 6. `no_cross_mode_key_acceptance`

- **类型：** 跨模式接受禁止
- **原始定义：**

```tamarin
lemma no_cross_mode_key_acceptance:
"All eid sid Iac Cap1 Cap2 CtxK1 CtxK2 K1 K2
       QU1 QU2 QS1 QS2 P1 P2 C1 C2 #i #j.
     DeviceDerived(eid,sid,Iac,'classic',Cap1,CtxK1,K1,
                   QU1,QS1,P1,C1) @ #i
   & DeviceDerived(eid,sid,Iac,'hybrid',Cap2,CtxK2,K2,
                   QU2,QS2,P2,C2) @ #j
     ==> F"
```

- **形式化含义：** 同一设备、服务器和订单不能同时产生 classic 与 hybrid 的设备密钥接受事件。
- **验证的安全效果：** 排除攻击者把两个模式的签名、密钥材料或上下文拼接成双重接受。
- **解释边界：** 该性质也受模型中一次性模式选择状态的结构约束支持。
- **验证结果：** `verified`

#### 7. `key_secrecy`

- **类型：** 密钥秘密性
- **原始定义：**

```tamarin
lemma key_secrecy:
"All key #i.
     SecretKAKey(key) @ #i
     ==> not (Ex #j. K(key) @ #j)"
```

- **形式化含义：** 攻击者不能推导模型标记的 $K$、$K_{enc}$ 或 $K_{mac}$。
- **验证的安全效果：** 保护 classic 与 hybrid 会话密钥及用途分离子密钥。
- **解释边界：** 不分析端点被攻陷、随机数生成器失效或底层 DH/KEM 计算攻击。
- **验证结果：** `verified`

## 10. 加密 Profile 下载与安装确认

- **文件：** `aura_rsp_download_scheme.spthy`
- **Theory：** `AURA_RSP_Download_Scheme_V6`
- **Lemma 数量：** 6

该模型从已经接受的 $ctx_t$ 和 $Bind_t$ 开始，验证 classic ECDHE、用途分离密钥、
AEAD Profile 密文、设备安装以及 `InstallReceipt` 的真实性。

**建模边界：** 本模型验证初次 download 的 classic ECDHE 路径；hybrid 协商本身由独立 hybrid 模型验证。enable、disable、delete、commit-delete 和 reinstall 不在本文件中。

### 规则流程

| Rule | 作用 |
|---|---|
| `Setup` | 建立服务器签名密钥。 |
| `Establish_Bound_Download_Context` | 抽象前序认证和 Profile Binding，建立下载上下文及 Profile 明文。 |
| `Device_Send_KA` | 设备发送由 $sk_t$ 签名的 ECDHE 公钥。 |
| `Server_Accept_KA` | 服务器验证设备签名，派生 $K$、$K_{enc}$ 和 $K_{mac}$。 |
| `Device_Accept_KA` | 设备验证服务器签名并派生相同密钥。 |
| `Server_Send_Profile` | 使用 $K_{enc}$ 和 $ctx_K$ 对 Profile 进行 AEAD 加密。 |
| `Device_Install_Profile` | 设备正确解密后生成绑定 $Bind_t$ 和密文哈希的安装收据。 |
| `Server_Accept_InstallReceipt` | 服务器验证 MAC 并建立 installed 状态记录。 |

### Lemma 逐项分析

#### 1. `exists_complete_download`

- **类型：** 可执行性
- **原始定义：**

```tamarin
lemma exists_complete_download:
exists-trace
  "Ex sid Iac pidh Lph Rid #i.
     DownloadComplete(sid,Iac,pidh,Lph,Rid) @ #i"
```

- **形式化含义：** 证明绑定上下文、ECDHE、加密下载、解密安装、收据验证和服务器状态建立可完整执行。
- **验证的安全效果：** 排除下载安全性质因安装流程不可达而真空成立。
- **解释边界：** 仅覆盖初次 download 到 installed 状态。
- **验证结果：** `verified`

#### 2. `key_agreement_device_to_server`

- **类型：** 下载阶段密钥一致性
- **原始定义：**

```tamarin
lemma key_agreement_device_to_server:
"All eid sid Iac CtxK K QU QS #i.
     DeviceKeyDerived(eid,sid,Iac,CtxK,K,QU,QS) @ #i
     ==> (Ex #j.
            ServerKeyDerived(sid,Iac,CtxK,K,QU,QS) @ #j
          & #j < #i)"
```

- **形式化含义：** 设备派生某一密钥时，服务器必须此前针对相同 $I_{ac}$、$ctx_K$、$Q_U$ 和 $Q_S$ 派生同一个 $K$。
- **验证的安全效果：** 排除设备接受攻击者构造的服务器公钥、跨会话密钥响应或不同转录下的密钥。
- **解释边界：** 本文件验证 classic 下载路径；hybrid 的模式和材料一致性由独立模型覆盖。
- **验证结果：** `verified`

#### 3. `installation_receipt_authenticity`

- **类型：** 安装收据真实性
- **原始定义：**

```tamarin
lemma installation_receipt_authenticity:
"All sid Iac pidh Lph BindHash Rid #i.
     InstallReceiptAccepted(sid,Iac,pidh,Lph,BindHash,Rid) @ #i
     ==> (Ex eid profile CtxK #j.
            ProfileInstalled(eid,sid,Iac,pidh,profile,Lph,BindHash,CtxK) @ #j
          & #j < #i)"
```

- **形式化含义：** 服务器接受安装收据之前，必须有设备更早成功解密并安装相同 Profile、$lph$、`BindHash` 和 $ctx_K$。
- **验证的安全效果：** 阻止攻击者在未安装 Profile 的情况下伪造安装完成状态。
- **解释边界：** 依赖 $K_{mac}$ 不泄露以及安装规则仅在 AEAD 解密成功后触发。
- **验证结果：** `verified`

#### 4. `installation_receipt_is_bound_to_profile_binding`

- **类型：** 收据与 Binding 的绑定
- **原始定义：**

```tamarin
lemma installation_receipt_is_bound_to_profile_binding:
"All sid Iac pidh Lph BindHash Rid #i.
     InstallReceiptAccepted(sid,Iac,pidh,Lph,BindHash,Rid) @ #i
     ==> (Ex eid profile CtxK #j.
            ProfileInstalled(eid,sid,Iac,pidh,profile,Lph,BindHash,CtxK) @ #j
          & #j < #i)"
```

- **形式化含义：** 服务器接受的收据必须对应具有相同 `BindHash` 的设备安装事件。
- **验证的安全效果：** 意图保证收据不能从其他 Profile Binding 或其他事务搬用。
- **解释边界：** 当前代码中的量化公式与 `installation_receipt_authenticity` 完全相同，因此两者在形式上证明同一对应性质；后续可把该 lemma 加强为显式关联 `BoundDownloadContext` 事件。
- **验证结果：** `verified`

#### 5. `profile_confidentiality`

- **类型：** Profile 机密性
- **原始定义：**

```tamarin
lemma profile_confidentiality:
"All profile #i.
     SecretProfile(profile) @ #i
     ==> not (Ex #j. K(profile) @ #j)"
```

- **形式化含义：** 攻击者不能推导 Profile 明文。
- **验证的安全效果：** 保证公开信道只暴露由 $K_{enc}$ 和 $ctx_K$ 保护的 AEAD 密文。
- **解释边界：** 不分析长度、流量模式或端点安装后的本地泄露。
- **验证结果：** `verified`

#### 6. `session_key_secrecy`

- **类型：** 下载会话密钥秘密性
- **原始定义：**

```tamarin
lemma session_key_secrecy:
"All key #i.
     SecretSessionKey(key) @ #i
     ==> not (Ex #j. K(key) @ #j)"
```

- **形式化含义：** 攻击者不能推导 $K$、$K_{enc}$ 或 $K_{mac}$。
- **验证的安全效果：** 保护 Profile 解密密钥和安装收据 MAC 密钥。
- **解释边界：** 依赖 ECDHE、KDF、签名和 AEAD/MAC 的理想安全以及端点未被攻陷。
- **验证结果：** `verified`

## 11. 六个模型之间的组合关系

这些 `.spthy` 文件是彼此独立的 Tamarin theories，不会在运行时直接导入对方的状态事实。它们通过一致的协议字段和模块入口进行组合式验证：

1. 服务器认证模型证明设备只接受匹配订单和能力转录的 SM-DP+ 响应；
2. 匿名认证模型把该服务器会话作为已建立状态，并验证凭证、票据、共享 $x$、$\tau_{auth}$、nullifier 和一次性业务执行；
3. Profile Binding 模型把已接受的匿名认证转录作为入口，并验证 $Bind_t$ 与该转录不可分离；
4. hybrid 模型把已接受的 $ctx_t$ 和 $Bind_t$ 作为绑定上下文，验证模式与密钥材料一致；
5. download 模型从绑定上下文开始，验证 classic 下载路径、Profile 机密性和安装收据；
6. trace 模型独立分析同票据异常复用、精确重传和 EUM 身份解析。

因此，论文中应表述为“六个模块化模型共同验证 AURA-RSP 核心流程的安全性质”，而不是声称存在一个把所有阶段合并在同一 theory 中的单体端到端模型。

## 12. Lemma 覆盖矩阵

| 安全目标 | 主要 lemmas |
|---|---|
| 服务器认证 | `server_authentication_agreement`, `server_authentication_order_binding`, `capability_transcript_binding` |
| 匿名合法性 | `anonymous_authentication_soundness`, `accepted_authentication_uses_valid_credential_and_ticket` |
| 票据不可转移 | `ticket_non_transferability` |
| 最小授权 | `minimal_authorization_context_binding` |
| 会话签名真实性 | `authentication_signature_is_verified` |
| Nullifier 一次性使用 | `nullifier_single_business_acceptance`, `exact_replay_is_idempotent` |
| 秘密值保护 | `eid_secrecy`, `x_secrecy`, `eta_secrecy`, `d_secrecy`, `temporary_signing_key_secrecy` |
| Profile Binding | `profile_binding_agreement`, `binding_uses_accepted_anonymous_context`, `binding_cannot_cross_contexts` |
| 条件追踪 | `tracing_requires_two_distinct_valid_responses`, `trace_resolves_issued_device` |
| 抗栽赃与重传区分 | `same_opid_is_non_frameable`, `exact_replay_does_not_create_trace`, `no_trace_from_single_accepted_response` |
| 模式和 KA 转录一致性 | `key_agreement_mode_and_transcript_agreement`, `hybrid_acceptance_requires_hybrid_capability_transcript`, `classic_acceptance_requires_classic_capability_transcript`, `no_cross_mode_key_acceptance` |
| 会话密钥秘密性 | `key_secrecy`, `session_key_secrecy` |
| Profile 机密性 | `profile_confidentiality` |
| 安装收据真实性 | `installation_receipt_authenticity`, `installation_receipt_is_bound_to_profile_binding` |

## 13. 复现命令

建议使用单线程运行，以降低虚拟机内存压力：

```bash
tamarin-prover "aura_rsp_server_auth_scheme.spthy" --prove +RTS -N1 -RTS
tamarin-prover "aura_rsp_anon_ticket_auth_scheme(1).spthy" --prove +RTS -N1 -RTS
tamarin-prover "aura_rsp_profile_binding_scheme.spthy" --prove +RTS -N1 -RTS
tamarin-prover "aura_rsp_trace_scheme.spthy" --prove +RTS -N1 -RTS
tamarin-prover "aura_rsp_hybrid_scheme.spthy" --prove +RTS -N1 -RTS
tamarin-prover "aura_rsp_download_scheme.spthy" --prove +RTS -N1 -RTS
```

也可以先运行各模型的可执行性 lemma，再运行全部安全 lemma。若结果中出现任何 wellformedness warning，则不能把对应 `verified` 结果作为最终证明结论，应先修正变量绑定、大小写或 action-fact 问题。

## 14. 已知可改进点

1. `installation_receipt_authenticity` 与 `installation_receipt_is_bound_to_profile_binding` 当前具有相同的量化公式，因此形式上证明的是同一个 correspondence。可在后续版本中让第二个 lemma 显式要求更早的 `BoundDownloadContext` 或 `ServerCreatedBinding` 事件。
2. 若论文需要严格的跨事务不可链接性结论，应增加 observational equivalence/diff-equivalence 模型，而不能只引用 secrecy lemmas。
3. 若要覆盖完整论文方案，还需单独增加 Profile 生命周期状态机模型。
4. 若要验证真实 PR 路径，应建模经认证的 PR 转发事实；当前只验证 `PRaddr` 字段绑定。

## 15. 总结

当前六个模型在理想密码原语假设下验证了 AURA-RSP 的服务器认证、匿名合法性、票据不可转移、最小授权、临时会话签名、nullifier 一次性业务执行、精确重传幂等性、秘密值保护、强 Profile Binding、条件追踪、抗栽赃、classic/hybrid 模式一致性、会话密钥秘密性、Profile 机密性以及安装收据真实性。全部 7 个可执行性 lemmas 和 34 个安全 lemmas 均得到 `verified`。
