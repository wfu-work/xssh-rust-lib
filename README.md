# xssh-rust-lib

`xssh-rust-lib` 是一个纯 Rust SSH 库，一个 package 内按源码目录划分为三个模块：

```text
xssh-rust-lib
└── src
    ├── core       SSH 连接、认证、主机密钥、通用 channel
    ├── terminal   PTY、交互式 shell、输入输出、窗口调整
    └── sftp       SFTP subsystem、远程文件与目录操作
```

三个模块共享同一个版本、Cargo 配置和错误类型。GPUI、CLI、Tauri 或其他前端只依赖一个 crate 即可。

## 模块职责

### `core`

- SSH TCP 连接、握手超时和 keepalive；
- 密码与私钥认证；
- 服务器主机密钥指纹校验；
- 连接生命周期；
- 通用 SSH session channel 和异步字节流。

### `terminal`

- PTY 分配；
- 登录 shell 启动；
- 输入写入和输出事件读取；
- 窗口大小调整；
- EOF、退出状态、退出信号和关闭事件。

该模块只负责 SSH PTY 协议，不负责 VT100/ANSI 解析和界面绘制。

### `sftp`

- SFTP subsystem 初始化和关闭；
- `read`、`write`、`exists`；
- 流式 `open`、`create` 和显式 `OpenFlags`；
- 创建、读取和删除目录；
- 元数据查询、重命名和路径规范化。

## Feature

默认启用 `terminal` 和 `sftp`：

```toml
[dependencies]
xssh-rust-lib = "0.2"
```

如果只需要 SSH core，可以关闭默认功能：

```toml
[dependencies]
xssh-rust-lib = { version = "0.2", default-features = false }
```

也可以按需启用：

```toml
xssh-rust-lib = { version = "0.2", default-features = false, features = ["terminal"] }
```

## 使用示例

```rust,no_run
use xssh_rust_lib::{AuthMethod, KnownHostKeyVerifier, SshConfig, SshSession};
use xssh_rust_lib::terminal::{TerminalOptions, TerminalSession};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = SshConfig::new("server.example.com", "alice")?;

    // 生产环境应从受保护的 known-hosts 存储加载指纹。
    let verifier = KnownHostKeyVerifier::new();
    let session = SshSession::connect(
        config,
        verifier,
        AuthMethod::password(std::env::var("XSSH_PASSWORD")?),
    )
    .await?;

    let mut terminal = TerminalSession::open(&session, TerminalOptions::default()).await?;
    terminal.write(b"echo ready\n").await?;
    while let Some(event) = terminal.next_event().await {
        println!("{event:?}");
        if matches!(event, xssh_rust_lib::terminal::TerminalEvent::Close) {
            break;
        }
    }

    session.disconnect().await?;
    Ok(())
}
```

SFTP 使用同一个 core 会话：

```rust,no_run
use xssh_rust_lib::sftp::SftpClient;

# async fn run(session: &xssh_rust_lib::SshSession) -> Result<(), Box<dyn std::error::Error>> {
let sftp = SftpClient::connect(session).await?;
sftp.write("/tmp/hello.txt", b"hello").await?;
let bytes = sftp.read("/tmp/hello.txt").await?;
assert_eq!(bytes, b"hello");
sftp.close().await?;
# Ok(())
# }
```

## 安全边界

- core 默认拒绝未知或变更的服务器主机密钥；
- 密码和私钥 passphrase 使用 `zeroize` 包装，不应写入日志或持久化配置；
- known-hosts 持久化由上层应用负责，应使用系统密钥链或经过审计的加密存储；
- terminal 和 sftp 不绕过 core 的认证和主机密钥策略。

## 当前未包含

GPUI UI、VT100 渲染、SQLite、Keychain、Windows Credential Manager、SSH agent、端口转发和代理链不属于当前基础库。

## 开发检查

```bash
CARGO_HOME=/tmp/xssh-rust-lib-cargo \
CARGO_TARGET_DIR=/tmp/xssh-rust-lib-target \
cargo fmt -- --check

CARGO_HOME=/tmp/xssh-rust-lib-cargo \
CARGO_TARGET_DIR=/tmp/xssh-rust-lib-target \
cargo test --all-features

CARGO_HOME=/tmp/xssh-rust-lib-cargo \
CARGO_TARGET_DIR=/tmp/xssh-rust-lib-target \
cargo clippy --all-targets --all-features -- -D warnings
```

核心库使用 MIT 许可证。
