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

- SSH TCP 连接、握手超时、认证超时、操作超时和 keepalive；
- 密码与私钥认证；
- 服务器主机密钥指纹校验；
- 连接生命周期；
- 通用 SSH session channel 和异步字节流；
- 可复用的 `CancellationToken`、`OperationContext` 和结构化 `SshError`。

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
xssh-rust-lib = "0.3"
```

如果只需要 SSH core，可以关闭默认功能：

```toml
[dependencies]
xssh-rust-lib = { version = "0.3", default-features = false }
```

也可以按需启用：

```toml
xssh-rust-lib = { version = "0.3", default-features = false, features = ["terminal"] }
```

## 超时、截止时间与取消

`SshConfig` 默认分别为连接/握手 15 秒、认证 15 秒、普通操作 30 秒。旧的异步方法会自动使用这些默认值：

```rust,no_run
let mut config = SshConfig::new("server.example.com", "alice")?;
config.connect_timeout = std::time::Duration::from_secs(10);
config.authentication_timeout = std::time::Duration::from_secs(15);
config.operation_timeout = std::time::Duration::from_secs(30);
```

需要由 GPUI 任务或上层工作流取消单个连接/终端/SFTP 操作时，传入独立的 `OperationContext`。截止时间和取消信号同时生效，先触发的条件会返回 `ErrorKind::Timeout` 或 `ErrorKind::Cancelled`：

```rust,no_run
use std::time::Duration;
use xssh_rust_lib::{CancellationToken, OperationContext};

let cancellation = CancellationToken::new();
let context = OperationContext::with_timeout(Duration::from_secs(20))
    .with_cancellation(cancellation.clone());

let session = xssh_rust_lib::SshSession::connect_with_context(
    config,
    verifier,
    auth,
    context.clone(),
).await?;

// 取消当前工作流时调用；不会自动关闭整个 SSH session。
cancellation.cancel();
```

`SshSession::open_session_channel_with_context`、`TerminalSession::open_with_context`、
`SftpClient::connect_with_context` 以及各模块的 `*_with_context` 方法可用于覆盖单次操作的 context。
等待终端/channel 事件时，推荐使用返回 `Result` 的 `next_event_with_context`，这样可以区分正常关闭、超时和取消；
`SshChannelStream` 也提供 `read_with_context`、`write_with_context` 和 `flush_with_context`。

`SshError` 会保留错误源（如果底层库提供）、错误阶段、operation、host/port、远程 path 和 `is_retryable()` 标记；这些字段不包含密码或私钥内容，适合交给 GPUI 的状态层和日志层。

## 主机密钥、known_hosts 与 TOFU

`KnownHostKeyVerifier` 是严格的内存校验器，可以直接解析 OpenSSH
`known_hosts` 文本或文件：

```rust,no_run
use xssh_rust_lib::{AuthMethod, KnownHostKeyVerifier, SshConfig, SshSession};

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let verifier = KnownHostKeyVerifier::from_path("/home/alice/.ssh/known_hosts")?;
let config = SshConfig::new("server.example.com", "alice")?;
let session = SshSession::connect(
    config,
    verifier,
    AuthMethod::password(std::env::var("XSSH_PASSWORD")?),
)
.await?;
session.disconnect().await?;
# Ok(())
# }
```

解析和匹配支持普通主机、`[host]:port`、`*`/`?` 通配符、`!` 排除模式以及
OpenSSH `|1|salt|hmac` hashed host。`@revoked` 条目会返回
`HostKeyDecision::Revoked`；`@cert-authority` 会被保留为结构化 marker，但当前
库只验证直接提供的服务器公钥，不执行 SSH host certificate 的 CA 验证。

`KnownHostKeyVerifier::check` 返回 `HostKeyObservation`，其中包含 presented
fingerprint、匹配的 known_hosts 行号、期望指纹和 `Trusted`、`Unknown`、`Changed`
或 `Revoked` 决策，适合直接交给 GPUI 的信任确认状态层。`SshSession` 会拒绝
`Unknown`、`Changed` 和 `Revoked`；调用 `SshError::host_key_observation()` 可以直接
读取同一份结构化信息，无需解析错误字符串。

需要明确采用 trust-on-first-use 时，可以使用 `TofuHostKeyVerifier`：首次出现的
公钥会在内存中记录并接受，后续 changed/revoked key 仍会拒绝。连接成功后由上层
负责安全持久化快照，核心库不会直接写用户配置文件：

```rust,no_run
use xssh_rust_lib::{
    AuthMethod, KnownHostKeyVerifier, SshConfig, SshSession, TofuHostKeyVerifier,
};

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let verifier = TofuHostKeyVerifier::new(KnownHostKeyVerifier::new());
let retained_verifier = verifier.clone();
let session = SshSession::connect(
    SshConfig::new("server.example.com", "alice")?,
    verifier,
    AuthMethod::password(std::env::var("XSSH_PASSWORD")?),
)
.await?;

let snapshot = retained_verifier.snapshot()?;
let known_hosts_text = snapshot.known_hosts().to_openssh();
// 由应用使用原子替换和 Keychain/权限控制保存 known_hosts_text。
let _ = known_hosts_text;
session.disconnect().await?;
# Ok(())
# }
```

## 使用示例

```rust,no_run
use xssh_rust_lib::{AuthMethod, KnownHostKeyVerifier, SshConfig, SshSession};
use xssh_rust_lib::terminal::{TerminalOptions, TerminalSession};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = SshConfig::new("server.example.com", "alice")?;

    // 生产环境应从受保护的 known_hosts 存储加载条目。
    let verifier = KnownHostKeyVerifier::from_path("/home/alice/.ssh/known_hosts")?;
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

- `KnownHostKeyVerifier` 默认拒绝未知、变更或 revoked 的服务器主机密钥；需要自动首次信任时显式使用 `TofuHostKeyVerifier`；
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
