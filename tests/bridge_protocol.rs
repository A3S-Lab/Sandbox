//! Integration test for the `a3s-sandbox-bridge` machine protocol: spawns the
//! built binary, performs the initialize handshake, probes, executes a command,
//! and verifies the fail-closed path for method errors.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};

struct Bridge {
    child: Child,
    stdin: std::process::ChildStdin,
    stdout: BufReader<std::process::ChildStdout>,
}

impl Bridge {
    fn spawn(workspace: &std::path::Path) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_a3s-sandbox-bridge"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn a3s-sandbox-bridge");
        let stdin = child.stdin.take().expect("bridge stdin");
        let stdout = child.stdout.take().expect("bridge stdout");
        let mut bridge = Self {
            child,
            stdin,
            stdout: BufReader::new(stdout),
        };
        bridge.request(
            1,
            serde_json::json!({"method": "initialize", "params": {"workspace": workspace}}),
        );
        let response = bridge.read_response();
        assert_eq!(response["id"], 1);
        assert_eq!(response["ok"], true, "initialize failed: {response}");
        bridge
    }

    fn request(&mut self, id: u64, payload: serde_json::Value) {
        let mut line = serde_json::json!({"id": id});
        let object = line.as_object_mut().unwrap();
        for (key, value) in payload.as_object().unwrap() {
            object.insert(key.clone(), value.clone());
        }
        writeln!(self.stdin, "{line}").expect("write request");
    }

    /// Reads lines until one carries a response (skipping events).
    fn read_response(&mut self) -> serde_json::Value {
        let mut line = String::new();
        loop {
            line.clear();
            let bytes = self
                .stdout
                .read_line(&mut line)
                .expect("read bridge response");
            assert!(bytes > 0, "bridge closed stdout before responding");
            let value: serde_json::Value = serde_json::from_str(&line).expect("valid JSON line");
            if value.get("event").is_none() {
                return value;
            }
        }
    }
}

#[test]
fn handshake_probe_exec_and_shutdown() {
    let workspace = tempfile::tempdir().expect("temp workspace");
    let mut bridge = Bridge::spawn(workspace.path());

    bridge.request(2, serde_json::json!({"method": "probe"}));
    let response = bridge.read_response();
    assert_eq!(response["id"], 2);
    if response["ok"] != true {
        // A host without an enforceable boundary fails closed here; that is a
        // valid outcome, and exec assertions below would not hold.
        eprintln!("probe failed on this host: {response}");
        return;
    }

    bridge.request(
        3,
        serde_json::json!({"method": "exec", "params": {"command": "echo bridge-ok"}}),
    );
    let response = loop {
        let value = bridge.read_response();
        if value.get("id") == Some(&serde_json::json!(3)) && value.get("ok").is_some() {
            break value;
        }
        // else: an output event for id 3 — keep reading
    };
    assert_eq!(response["ok"], true, "exec failed: {response}");
    assert!(
        response["result"]["stdout"].as_str().unwrap().contains("bridge-ok"),
        "stdout: {response}"
    );
    assert_eq!(response["result"]["exit_code"], 0);

    bridge.request(4, serde_json::json!({"method": "shutdown"}));
    let response = bridge.read_response();
    assert_eq!(response["ok"], true);

    let status = bridge.child.wait().expect("wait bridge");
    assert!(status.success(), "bridge exit status: {status}");
}

#[test]
fn unknown_method_fails_without_killing_the_bridge() {
    let workspace = tempfile::tempdir().expect("temp workspace");
    let mut bridge = Bridge::spawn(workspace.path());

    bridge.request(2, serde_json::json!({"method": "definitely_not_a_method"}));
    let response = bridge.read_response();
    assert_eq!(response["ok"], false);
    assert_eq!(response["error"]["code"], "unknown_method");

    bridge.request(3, serde_json::json!({"method": "ping"}));
    let response = bridge.read_response();
    assert_eq!(response["ok"], true, "bridge must survive unknown methods");

    bridge.request(4, serde_json::json!({"method": "shutdown"}));
    bridge.read_response();
    let status = bridge.child.wait().expect("wait bridge");
    assert!(status.success());
}
