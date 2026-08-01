# Paper-ready implementation description

## English

Standard RSP and AURA-RSP were evaluated within the same
pySim/osmo-smdpp-based research testbed, sharing the Klein/Twisted HTTPS and TLS
stack, Profile repository, software-eUICC installation function, notification
boundary, and measurement runner. The Standard mode retained the pySim ES9+
authentication and Bound Profile Package path. The AURA mode added four
namespaced download endpoints to the same `osmo-smdpp.py` server and replaced
device-identifying authentication with a BBS+-based joint proof over a device
credential and an operation ticket. After authentication, the implementation
bound the authorization transcript to `Bind_t`, established an ephemeral P-256
session key, and delivered the same Profile bytes using HKDF-derived AES-GCM
keys and a context-bound InstallReceipt. Offline credential and ticket issuance
and server startup were excluded from online latency. Each device verified the
server transcript, `Bind_t`, key-agreement signature, AEAD integrity, and the
post-decryption condition `H(Profile)=pid_h` before installation. This is a
research implementation of the Profile Download process with test
certificates; it is not claimed to be a fully GSMA SGP.22-compliant production
system.

## 中文

Standard RSP与AURA-RSP在同一套基于pySim/osmo-smdpp的研究型测试床中进行
评估，两种模式共享Klein/Twisted HTTPS与TLS框架、Profile仓库、软件eUICC
安装函数、安装通知终点和统一测量程序。Standard模式保留pySim原有ES9+认证
与Bound Profile Package处理路径；AURA模式在同一`osmo-smdpp.py`服务中增加
四个独立命名空间的下载端点，并以基于BBS+的设备凭证—操作票据联合证明替换
会暴露稳定设备身份的认证。匿名认证成功后，实现使用`Bind_t`绑定授权转录，
通过临时P-256密钥建立会话密钥，并使用HKDF派生的AES-GCM密钥和上下文绑定的
InstallReceipt交付与Standard模式字节完全相同的Profile。在线时延不包含离线
设备凭证/操作票据签发和服务启动；设备仅在服务器转录、`Bind_t`、密钥协商
签名、AEAD完整性以及解密后`H(Profile)=pid_h`全部通过后执行安装。本实现是
使用测试证书的Profile Download研究原型，不宣称达到完整GSMA SGP.22生产
合规性。
