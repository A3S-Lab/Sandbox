//! `a3s-sandbox` CLI — probe, digest, capabilities, reproduction exec, and relay.

use a3s_sandbox::{default_guest_relay_addr, CapabilityReport, NativeSandbox, TcpUnixRelay};
use anyhow::{bail, Context, Result};
use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(code) => code,
        Err(error) => {
            eprintln!("a3s-sandbox: {error:#}");
            ExitCode::from(1)
        }
    }
}

async fn run() -> Result<ExitCode> {
    let mut args = env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        print_usage();
        bail!("missing command");
    }
    let command = args.remove(0);
    match command.as_str() {
        "help" | "-h" | "--help" => {
            print_usage();
            Ok(ExitCode::SUCCESS)
        }
        "probe" => {
            let workspace = parse_workspace(&args)?;
            let sandbox = NativeSandbox::new(&workspace)?;
            sandbox.probe().await?;
            let report = sandbox.capability_report();
            println!("ok backend={}", report.backend);
            print_unavailable(&report);
            Ok(ExitCode::SUCCESS)
        }
        "digest" => {
            let workspace = parse_workspace(&args)?;
            let sandbox = NativeSandbox::new(&workspace)?;
            println!("{}", sandbox.policy_digest());
            Ok(ExitCode::SUCCESS)
        }
        "capabilities" => {
            let workspace = parse_workspace(&args)?;
            let sandbox = NativeSandbox::new(&workspace)?;
            let report = sandbox.capability_report();
            print_capabilities_json(&report)?;
            Ok(ExitCode::SUCCESS)
        }
        "matrix" => {
            print!("{}", a3s_sandbox::capability_matrix_markdown());
            Ok(ExitCode::SUCCESS)
        }
        "exec" => {
            let (workspace, command) = parse_exec(&args)?;
            let sandbox = NativeSandbox::new(&workspace)?;
            let output = sandbox.exec_command(command).await?;
            print!("{}", output.stdout);
            eprint!("{}", output.stderr);
            if output.timed_out {
                bail!("command timed out");
            }
            Ok(ExitCode::from(output.exit_code.clamp(0, 255) as u8))
        }
        "relay" => {
            let (unix, listen) = parse_relay(&args)?;
            TcpUnixRelay::run_forever(listen, unix).await?;
            Ok(ExitCode::SUCCESS)
        }
        other => {
            print_usage();
            bail!("unknown command {other:?}");
        }
    }
}

fn print_usage() {
    eprintln!(
        "Usage:\n  \
         a3s-sandbox probe [--workspace PATH]\n  matrix\n  \
         a3s-sandbox digest [--workspace PATH]\n  \
         a3s-sandbox capabilities [--workspace PATH]\n  \
         a3s-sandbox exec [--workspace PATH] -- <command>\n  \
         a3s-sandbox relay --unix PATH [--listen 127.0.0.1:24731]\n"
    );
}

fn parse_relay(args: &[String]) -> Result<(PathBuf, SocketAddr)> {
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
    let unix = unix.context("relay requires --unix PATH")?;
    Ok((unix, listen))
}

fn parse_workspace(args: &[String]) -> Result<PathBuf> {
    let mut workspace = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--workspace" | "-w" => {
                i += 1;
                let path = args.get(i).context("--workspace requires a path")?;
                workspace = Some(PathBuf::from(path));
            }
            other => bail!("unexpected argument {other:?}"),
        }
        i += 1;
    }
    Ok(workspace.unwrap_or_else(|| env::current_dir().expect("cwd")))
}

fn parse_exec(args: &[String]) -> Result<(PathBuf, String)> {
    let mut workspace = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--workspace" | "-w" => {
                i += 1;
                let path = args.get(i).context("--workspace requires a path")?;
                workspace = Some(PathBuf::from(path));
            }
            "--" => {
                i += 1;
                break;
            }
            other => bail!("unexpected argument {other:?}; use -- before the command"),
        }
        i += 1;
    }
    if i >= args.len() {
        bail!("exec requires a command after --");
    }
    let command = args[i..].join(" ");
    let workspace = workspace.unwrap_or_else(|| env::current_dir().expect("cwd"));
    Ok((workspace, command))
}

fn print_unavailable(report: &CapabilityReport) {
    if report.unavailable.is_empty() {
        println!("unavailable=");
    } else {
        println!("unavailable={}", report.unavailable.join(","));
    }
}

fn print_capabilities_json(report: &CapabilityReport) -> Result<()> {
    let caps = &report.capabilities;
    let payload = serde_json::json!({
        "backend": report.backend,
        "policy_digest": report.policy_digest,
        "unavailable": report.unavailable,
        "capabilities": {
            "filesystem_path_policy": caps.filesystem_path_policy,
            "filesystem_readonly_mounts": caps.filesystem_readonly_mounts,
            "filesystem_ephemeral_writes": caps.filesystem_ephemeral_writes,
            "network_deny_all": caps.network_deny_all,
            "mediated_http": caps.mediated_http,
            "mediated_socks": caps.mediated_socks,
            "unix_socket_allowlist": caps.unix_socket_allowlist,
            "resource_timeout": caps.resource_timeout,
            "resource_output_limit": caps.resource_output_limit,
            "resource_memory_limit": caps.resource_memory_limit,
            "resource_process_limit": caps.resource_process_limit,
            "resource_cpu_limit": caps.resource_cpu_limit,
        }
    });
    println!("{payload}");
    Ok(())
}
