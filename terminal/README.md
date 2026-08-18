# xssh-rust-terminal

`xssh-rust-terminal` 在已认证的 `xssh-rust-core::SshSession` 上创建交互式 SSH 终端。

```rust,no_run
use xssh_rust_terminal::{TerminalOptions, TerminalSession};

# async fn run(session: &xssh_rust_core::SshSession) -> Result<(), Box<dyn std::error::Error>> {
let mut terminal = TerminalSession::open(session, TerminalOptions::default()).await?;
terminal.write(b"uname -a\n").await?;
while let Some(event) = terminal.next_event().await {
    println!("{event:?}");
    if matches!(event, xssh_rust_terminal::TerminalEvent::Close) {
        break;
    }
}
# Ok(())
# }
```

该包只负责 SSH PTY 协议和字节事件，不负责 VT100/ANSI 解析或界面绘制。GPUI、SwiftUI、CLI 等上层可以将 `TerminalEvent::Data` 接入自己的终端模拟器。
