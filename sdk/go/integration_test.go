package sandbox

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// integrationBridge returns the path to a built a3s-sandbox-bridge, or skips
// the test. Set A3S_SANDBOX_BRIDGE to run these against a real build:
//
//	cargo build --bin a3s-sandbox-bridge
//	A3S_SANDBOX_BRIDGE=../../target/debug/a3s-sandbox-bridge go test -run Integration -v
func integrationBridge(t *testing.T) string {
	t.Helper()
	path := os.Getenv("A3S_SANDBOX_BRIDGE")
	if path == "" {
		t.Skip("A3S_SANDBOX_BRIDGE is not set; build a3s-sandbox-bridge to run integration tests")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("A3S_SANDBOX_BRIDGE points at %q: %v", path, err)
	}
	return path
}

func newIntegrationClient(t *testing.T) *Client {
	t.Helper()
	bridge := integrationBridge(t)
	c, err := New(context.Background(),
		WithBridgePath(bridge),
		WithWorkspace(t.TempDir()),
	)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestIntegrationProbeAndCapabilities(t *testing.T) {
	c := newIntegrationClient(t)
	if err := c.Probe(context.Background()); err != nil {
		t.Fatalf("probe: %v", err)
	}
	report := c.Report()
	if report.Backend == "" {
		t.Fatal("backend is empty")
	}
	if !report.Capabilities.NetworkDenyAll {
		t.Fatal("network_deny_all capability must be enforced")
	}
	if report.PolicyDigest == "" {
		t.Fatal("policy digest is empty")
	}
}

func TestIntegrationExecEcho(t *testing.T) {
	c := newIntegrationClient(t)
	out, err := c.Exec(context.Background(), "echo inside-sandbox-check")
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if !strings.Contains(out.Stdout, "inside-sandbox-check") {
		t.Fatalf("stdout = %q, want the check marker", out.Stdout)
	}
	if out.ExitCode != 0 || out.TimedOut {
		t.Fatalf("output = %+v", out)
	}
}

func TestIntegrationExitCodePropagates(t *testing.T) {
	c := newIntegrationClient(t)
	out, err := c.Exec(context.Background(), "sh -c 'exit 3'")
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if out.ExitCode != 3 {
		t.Fatalf("exit code = %d, want 3", out.ExitCode)
	}
}

func TestIntegrationTimeoutKillsTree(t *testing.T) {
	c := newIntegrationClient(t)
	ctx := context.Background()
	start := time.Now()
	out, err := c.Exec(ctx, "sleep 5", WithTimeout(300*time.Millisecond))
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	elapsed := time.Since(start)
	if !out.TimedOut {
		t.Fatalf("TimedOut = false, want true")
	}
	if elapsed >= 2*time.Second {
		t.Fatalf("elapsed %v: the tree was not killed at the deadline", elapsed)
	}
}

func TestIntegrationStreamDeltas(t *testing.T) {
	c := newIntegrationClient(t)
	var builder strings.Builder
	out, err := c.ExecStream(context.Background(), func(delta string) {
		builder.WriteString(delta)
	}, "printf stream-me")
	if err != nil {
		t.Fatalf("exec stream: %v", err)
	}
	if !strings.Contains(out.Stdout, "stream-me") {
		t.Fatalf("stdout = %q", out.Stdout)
	}
	if builder.Len() == 0 {
		t.Skip("backend delivered no live deltas; final capture only")
	}
	if !strings.Contains(builder.String(), "stream") {
		t.Fatalf("deltas = %q, want the output content", builder.String())
	}
}
