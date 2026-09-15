//! Guest TCP→Unix CONNECT relay binary for Linux netns mediation bridges.
//!
//! Run inside the guest (or on the host for local tests):
//!   a3s-sandbox-relay --unix /path/to/mediator.sock [--listen 127.0.0.1:24731]

use a3s_sandbox::{default_guest_relay_addr, TcpUnixRelay};
use anyhow::{bail, Context, Result};
use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("a3s-sandbox-relay: {error:#}");
            ExitCode::from(1)
        }
    }
}

async fn run() -> Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args
        .iter()
        .any(|a| a == "help" || a == "-h" || a == "--help")
    {
        print_usage();
        return Ok(());
    }

    let mut unix = None;
    let mut listen = default_guest_relay_addr();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--unix" => {
                i += 1;
                let path = args.get(i).context("--unix requires a path")?;
                unix = Some(PathBuf::from(path));
            }
            "--listen" => {
                i += 1;
                let addr = args.get(i).context("--listen requires host:port")?;
                listen = addr
                    .parse::<SocketAddr>()
                    .with_context(|| format!("invalid --listen address {addr:?}"))?;
            }
            other => bail!("unexpected argument {other:?}"),
        }
        i += 1;
    }

    let unix = unix.context("missing --unix PATH")?;
    TcpUnixRelay::run_forever(listen, unix).await
}

fn print_usage() {
    eprintln!(
        "Usage:\n  \
         a3s-sandbox-relay --unix PATH [--listen 127.0.0.1:24731]\n"
    );
}
