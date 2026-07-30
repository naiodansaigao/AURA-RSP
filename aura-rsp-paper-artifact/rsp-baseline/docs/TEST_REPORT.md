# Baseline 测试报告

测试日期：2026-07-29  
平台：Windows + WSL2 Ubuntu 24.04.1 LTS  
范围：标准 Consumer RSP 研究用最小闭环，不包含 AURA-RSP 或匿名认证修改。

## 已通过

1. `osmo-smdpp` 在本机 HTTPS 443 端口启动。
2. 测试 CI → DP TLS/DP Auth/DP PB，以及 EUM → eUICC 证书链生成并校验。
3. 测试 profile `TS48V2-SAIP2-1-NOBERTLV-UNIQUE` 可按 matching ID 领取。
4. 软件化 eUICC 客户端依次完成：
   - `initiateAuthentication`
   - `authenticateClient`
   - `getBoundProfilePackage`
5. Bound Profile Package 成功解密为 UPP、ISD-P 和 Store Metadata。
6. 软件化客户端发送带 eUICC 测试证书签名的安装结果通知，服务端返回 HTTP 204。
7. lpac 在 WSL 中编译成功，PC/SC 与 curl 插件动态链接正确。
8. OpenEUICC 的 privileged 和 unprivileged debug APK 均编译成功。

## 最后一次记录

- SM-DP+：`https://testsmdpplus1.example.com`
- activation code：`LPA:1$testsmdpplus1.example.com$TS48V2-SAIP2-1-NOBERTLV-UNIQUE`
- 模拟 EID：`89049032123451234512345678901235`
- profile ICCID：`8949449999999990007f`
- 最终一键复现事务 ID：`19856F7434A6447FADAE114B0FE385C6`
- 成功标记：`SOFTWARE_RSP_BASELINE_PASS`
- 通知标记：`INSTALL_NOTIFICATION_PASS`

## 产物 SHA-256

- privileged APK：`667890CC951F18127BF4BB1511DD62A28E38390E3123C684910AC228CB99FB06`
- unprivileged APK：`B0E9673A7D881AED074231F180F7799116D30ABCCE3764408210E5259A1FB1F4`
- UPP DER：`38C7D4B90141E1886D045603BBFD938B64449247F097BAA328F8356C0BCD2422`

## 未覆盖边界

没有连接带匹配测试 PKI 的实体 eUICC、USB/PCSC 读卡器或 Android 设备，因此没有声称完成真实 ES10 APDU 写卡。当前通过的是服务端、证书链、ES9+、BPP 绑定/下载/解密和安装结果通知组成的可重复软件闭环。接入匹配测试卡后，现有 lpac/OpenEUICC 产物可用于补做硬件侧验证。
