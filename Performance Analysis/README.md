# AURA-RSP 原生 Windows 基准测试

本版本直接运行在 Windows 10/11，不使用 WSL2、Linux 虚拟机或 Docker。

## 1. 安装 Python

安装 **64 位 Python 3.12.x**。安装时建议勾选：

- Add python.exe to PATH
- Install launcher for all users

安装后打开 PowerShell 或 CMD，检查：

```powershell
py -3.12 --version
py -3.12 -c "import struct; print(struct.calcsize('P') * 8)"
```

第二条应输出 `64`。

## 2. 把文件放在同一文件夹

建议新建：

```text
D:\AURA-RSP-Benchmark
```

文件夹内至少包含：

```text
crypto_operation_benchmark_windows.py
requirements_windows.txt
setup_windows.bat
run_benchmark_windows.bat
```

## 3. 安装 Python 依赖

双击：

```text
setup_windows.bat
```

该脚本会：

1. 检查 Python 3.12 x64；
2. 创建 `.venv` 虚拟环境；
3. 安装 Windows 预编译密码库；
4. 测试所有导入。

无需 PowerShell 激活虚拟环境，也无需修改 ExecutionPolicy。

## 4. 安装并编译真实 Intel EPID 2.0

依次运行：

```text
setup_epid_windows.bat
build_epid_windows.bat
```

第一个脚本会安装 MSYS2 UCRT64 工具链，下载 Intel 官方开源仓库，固定到
commit `389426ff4ba2286d2e133bec29d178427d434d8c`，并应用仅涉及 Windows
构建兼容性的补丁。第二个脚本会把 SDK 编译为本地静态库，并链接原生
`aura_epid_benchmark.exe`。完整构建日志保存在 `logs\epid_build.log`。

采用 SDK 自带的 `example\split_data` 官方测试材料：group A 公钥、member0
私钥、CA 证书以及官方签名的空 GroupRL、PrivRL、SigRL。基准程序直接调用
`EpidSign` 和 `EpidVerify`，不启动 `signmsg.exe`/`verifysig.exe` 计时。

## 5. 设置 Profile 大小

用记事本打开 `run_benchmark_windows.bat`，找到：

```bat
set PROFILE_BYTES=65536
```

将 `65536` 改成实验所用加密 Profile 包的真实字节数。

## 6. 运行

双击：

```text
run_benchmark_windows.bat
```

真实 DAA 签名与验证分别预热 1000 次、正式执行 10000 次。计时前已完成
密钥和撤销列表认证、上下文创建、pairing 预计算和缓冲区分配；`T_DG`
只包含一次 `EpidSign`，`T_DV` 只包含一次对已生成有效 quote 的
`EpidVerify`。其余密码操作使用相同的预热和正式次数。

输出：

```text
aura_rsp_windows_operations.csv
aura_rsp_windows_schemes.csv
aura_rsp_windows.json
epid_daa_results.json
logs\epid_build.log
logs\epid_benchmark.log
logs\python_benchmark.log
```

本仓库提交时使用的正式结果快照位于 `results\`。重新运行测试时，脚本会在
仓库根目录生成最新结果，可在核验后复制到 `results\` 作为新的发布快照。

- `operations.csv`：每个 T_* 原语的平均时间；
- `schemes.csv`：按比较表公式计算的方案总时间；
- `json`：CPU、Windows、Python、库版本、原始结果和计算公式。

## 7. Di5Guise 真实 DAA 统计口径

Di5Guise 使用设计层面的真实 DAA 模型，DAA 具体实例为 Intel EPID 2.0：

```text
2T_DH + T_PE + T_PD + T_S + T_V + T_DG + T_DV + 2T_AE + 2T_AD
```

EPID 参数为 256 位 Barreto–Naehrig pairing-friendly 曲线、嵌入度 12、
128-bit 目标安全级别。官方测试 GID 指定 SHA-256；basename 使用
`NULL, 0` 随机模式，签名匿名且不可链接。GroupRL、PrivRL、SigRL 使用
官方零条目列表；VerifierRL 在 random-base 模式下不适用。消息固定为
32 字节。

每次在线 `EpidSign` 恰好消费一个由 `EpidAddPreSigs` 提前生成的单次
预签名。对每个测量样本，程序先在 `T_DG` 计时窗口外调用
`EpidAddPreSigs(member, 1)` 并确认池大小为 1，再计时一次 `EpidSign`
并确认池恢复为 0。预签名生成成本使用匹配的单次计时括号单独记录在原生
JSON 和日志中，不计入 Di5Guise 在线公式。
`T_DG`/`T_DV` 不使用 Ed25519、ECDSA、BBS+ 或模拟循环替代。

## 8. 稳定测试建议

- 笔记本接通电源；
- Windows 电源模式设置为“最佳性能”；
- 关闭浏览器、杀毒扫描和大型后台程序；
- 使用同一台电脑、同一组依赖测试所有原语；
- 正式实验建议完整运行 3 次，并保留三个 JSON 文件；
- 论文中报告 CPU 型号、Windows 版本、Python 版本、库版本、Profile 大小和迭代次数。
