# LocalTicketLog修复验证

生产实现现在于`create_auth_proof`之前查询`(v, opid)`：

1. 首次使用保存规范化`ctx_t`哈希和完整认证请求；
2. 上下文完全相同时返回逐字节相同的缓存请求；
3. 上下文不同时抛出`LocalTicketContextConflict`，不调用证明生成器；
4. 旧版仅保存哈希的记录采取失败关闭，避免不安全地生成第二份响应。

实验5直接调用`pySim.esim.aura.local_ticket_log`生产模块。完整实现下八种字段修改均未生成
第二份不同有效响应，EUM因只有一份不同有效证据而返回
`insufficient_valid_evidence`，诚实设备未被错误追踪。

工程边界：当前JSON文件持久化适用于研究原型；生产eUICC仍需受保护存储、原子写入、
崩溃恢复、过期归档和容量限制。
