//! Host-supervised network mediators for Gate 4+.

mod connect;
mod relay;
mod socks;

#[cfg(test)]
pub(crate) use connect::parse_connect_target;
pub use connect::{ConnectMediator, ConnectMediatorHandle};
pub use relay::{
    default_guest_relay_addr, posix_shell_single_quote, resolve_relay_executable,
    stage_relay_into_scratch, wrap_command_with_guest_relay, wrap_command_with_guest_relays,
    TcpUnixRelay, TcpUnixRelayHandle, GUEST_HTTP_CONNECT_RELAY_PORT,
    GUEST_SOCKS_CONNECT_RELAY_PORT,
};
pub use socks::{Socks5Mediator, Socks5MediatorHandle};
