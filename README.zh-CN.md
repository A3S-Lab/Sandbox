# A3S Sandbox

<p align="center">
  <strong>语言 / Language:</strong>
  <a href="README.md">English</a> ·
  <a href="README.zh-CN.md">中文</a>
</p>

<p align="center">
  <img src="./assets/readme/boundary.svg" width="100%" alt="a3s-sandbox 将不受信任的命令经策略边界与原生 macOS、Linux 或 Windows 后端处理后，再返回有界输出">
</p>

<p align="center">
  <a href="https://github.com/A3S-Lab/Sandbox/actions/workflows/ci.yml"><img src="https://github.com/A3S-Lab/Sandbox/actions/workflows/ci.yml/badge.svg" alt="CI status"></a>
  <a href="https://github.com/A3S-Lab/Sandbox/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-d6a85f.svg" alt="MIT license"></a>
  <a href="https://github.com/A3S-Lab/Sandbox/releases"><img src="https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-7fb6a4.svg" alt="macOS, Linux, and Windows"></a>
</p>

`a3s-sandbox` 是面向 A3S Bash 及其他 A3S 产品的 Rust 原生、失败闭合（fail-closed）命令边界。它将不受信任的命令变成有界进程树，并由宿主操作系统强制执行显式的工作区、凭证、环境、网络与生命周期限制。

执行路径中没有 Node.js 运行时、npm 包或 SRT 进程。该库刻意独立于 A3S Code，以便可被 CLI、Agent 或未来的 SDK 嵌入。

## 快速开始

从 crates.io 添加已发布的 crate。crate 版本不可变；采用更新版本时请有意更新版本号：

```toml
[dependencies]
a3s-sandbox = "0.1.1"
```

通过原生边界运行命令：

```rust,no_run
use a3s_sandbox::NativeSandbox;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let workspace = std::env::current_dir()?;
    let sandbox = NativeSandbox::new(workspace)?;

    // Fail before running a tool when the host cannot provide the boundary.
    sandbox.probe().await?;

    let output = sandbox.exec_command("echo inside sandbox").await?;
    println!("{}", output.stdout);
    Ok(())
}
```

`CommandOutput` 包含分开的 `stdout` 与 `stderr`、退出码，以及 `timed_out` 标志。捕获输出上限为 100 KiB；可选的 `OutputObserver` 可接收实时增量与最终核算。

## 当前强制执行的内容

默认的 A3S Bash 配置故意严格：

- 拒绝网络访问与宿主 Unix 域套接字；
- 写入仅限于规范工作区与私有临时目录；
- 保护凭证、密钥文件、`.git`、`.a3s`、Agent 元数据，以及 shell/工具引导文件；
- 拒绝符号链接与硬链接逃逸路径；
- 清理子进程环境、重定向临时状态，并移除 shell 注入变量；
- 截止时间终止完整后代树，输出捕获保持有界；
- 缺少启动器、命名空间不可用或能力探测失败时返回错误，而不是在宿主上执行。

这些保证适用于进程树，而不仅是第一个 shell。威胁模型、平台注意事项与精确受保护路径见 [安全模型](SECURITY.md)。

## 原生边界

| 宿主 | 边界 | 宿主要求 |
| --- | --- | --- |
| macOS | Seatbelt 配置文件加上进程组生命周期 | 系统 `/usr/bin/sandbox-exec` |
| Linux | Bubblewrap 用户/挂载/PID/IPC/UTS 命名空间加上 seccomp | `/usr/bin/bwrap` 与非特权用户命名空间 |
| Windows | AppContainer 内的 PowerShell 7、受限工作区 ACL、临时驱动器，以及 kill-on-close Job Object | 系统 Program Files 下的 PowerShell 7 |
| 其他目标 | 显式的不支持平台错误 | 无宿主回退 |

后端在编译时选择，而策略构造与命令输出保持平台中立。Windows 执行会串行化，因为临时 ACL 与设备映射变更是共享进程状态；清理会恢复精确的先前 ACL 状态。

## 执行模型

```text
CommandRequest
    │
    ├── canonical workspace + private scratch directory
    ├── sanitized environment + protected path set
    └── native backend
          ├── macOS  → Seatbelt
          ├── Linux  → Bubblewrap + seccomp
          └── Windows → AppContainer + Job Object
                    │
                    └── bounded CommandOutput + observer events
```

策略层是唯一真相来源。平台模块强制执行其决策；宿主功能缺失时不会静默放宽。

## 范围与路线图

Gate 0——完整的 A3S Bash 基线——已在 macOS、Linux 与 Windows 上交付并测试。下一阶段将加入可选的、经中介的 HTTP/HTTPS 与 SOCKS5 网络、Unix 套接字策略、TLS 处理、动态策略快照、结构化违规监控、嵌套沙箱协商，以及发布迁移工具。

能力矩阵、分阶段交付计划、验收门、跨架构测试矩阵与安全发布风险见 [ROADMAP.md](ROADMAP.md)。

目标是达到 SRT 级安全结果与控制，同时提供 A3S 拥有的 Rust API——而不是逐行克隆 SRT 的内部 TypeScript 实现。

## 开发

安装平台前置条件，然后运行与 CI 相同的门禁：

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

CI 矩阵覆盖 `ubuntu-latest`、`macos-14` 与 `windows-latest`。安全敏感变更应包含负面测试，证明被拒绝的操作无法通过后代、继承句柄、环境变量、符号链接、硬链接、套接字或替代网络路径到达宿主。

## 许可证

MIT
