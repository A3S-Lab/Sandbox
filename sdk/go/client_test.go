package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func newFakeClient(t *testing.T, scenario string) *Client {
	t.Helper()
	c, err := newFakeClientE(t, scenario)
	if err != nil {
		t.Fatalf("new fake client: %v", err)
	}
	return c
}

func newFakeClientE(t *testing.T, scenario string) (*Client, error) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcess")
	cmd.Env = append(os.Environ(),
		"GO_SANDBOX_FAKE_BRIDGE=1",
		"GO_SANDBOX_FAKE_SCENARIO="+scenario,
	)
	return newWithCommand(context.Background(), cmd, t.TempDir(), 5*time.Second, os.Stderr)
}

func newFakeClientFail(t *testing.T, scenario string) (*Client, error) {
	t.Helper()
	return newFakeClientE(t, scenario)
}

func TestHandshake(t *testing.T) {
	c := newFakeClient(t, "")
	defer c.Close()
	if got := c.Report().Backend; got != "fake" {
		t.Fatalf("backend = %q, want %q", got, "fake")
	}
	if err := c.Probe(context.Background()); err != nil {
		t.Fatalf("probe: %v", err)
	}
}

func TestInitializeFailure(t *testing.T) {
	_, err := newFakeClientFail(t, "init_fail")
	if err == nil {
		t.Fatal("expected initialize failure")
	}
	var bridgeErr *BridgeError
	if !errors.As(err, &bridgeErr) || bridgeErr.Code != "initialize_failed" {
		t.Fatalf("error = %v, want initialize_failed BridgeError", err)
	}
}

func TestProbeFailure(t *testing.T) {
	c := newFakeClient(t, "probe_fail")
	defer c.Close()
	err := c.Probe(context.Background())
	var bridgeErr *BridgeError
	if !errors.As(err, &bridgeErr) || bridgeErr.Code != "probe_failed" {
		t.Fatalf("probe error = %v, want probe_failed BridgeError", err)
	}
}

func TestExecOutput(t *testing.T) {
	c := newFakeClient(t, "")
	defer c.Close()
	out, err := c.Exec(context.Background(), "echo hi")
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if out.Stdout != "hello" || out.ExitCode != 0 || out.TimedOut {
		t.Fatalf("output = %+v", out)
	}
}

func TestExecBridgeError(t *testing.T) {
	c := newFakeClient(t, "exec_fail")
	defer c.Close()
	_, err := c.Exec(context.Background(), "anything")
	var bridgeErr *BridgeError
	if !errors.As(err, &bridgeErr) || bridgeErr.Code != "exec_failed" {
		t.Fatalf("error = %v, want exec_failed BridgeError", err)
	}
}

func TestExecStream(t *testing.T) {
	c := newFakeClient(t, "")
	defer c.Close()
	var got strings.Builder
	out, err := c.ExecStream(context.Background(), func(delta string) {
		got.WriteString(delta)
	}, "streaming command")
	if err != nil {
		t.Fatalf("exec stream: %v", err)
	}
	if got.String() != "hello" {
		t.Fatalf("deltas = %q, want %q", got.String(), "hello")
	}
	if out.Stdout != "hello" {
		t.Fatalf("stdout = %q", out.Stdout)
	}
}

// WithTimeout must translate into the bridge-side timeout_ms, which is what
// actually kills the process tree.
func TestExecTimeoutFromContext(t *testing.T) {
	c := newFakeClient(t, "echo_params")
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	out, err := c.Exec(ctx, "sleep a bit")
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	var params struct {
		TimeoutMS int64 `json:"timeout_ms"`
	}
	if err := json.Unmarshal([]byte(out.Stdout), &params); err != nil {
		t.Fatalf("decode echoed params %q: %v", out.Stdout, err)
	}
	if params.TimeoutMS <= 0 || params.TimeoutMS > 1500 {
		t.Fatalf("timeout_ms = %d, want (0, 1500]", params.TimeoutMS)
	}
}

func TestExecContextCancel(t *testing.T) {
	c := newFakeClient(t, "hang")
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(150 * time.Millisecond)
		cancel()
	}()
	_, err := c.Exec(ctx, "long running")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func TestCloseFailsSubsequentCalls(t *testing.T) {
	c := newFakeClient(t, "")
	if err := c.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	_, err := c.Exec(context.Background(), "echo hi")
	if err == nil {
		t.Fatal("exec after close should fail")
	}
}

func TestJunkLineFailsClosed(t *testing.T) {
	_, err := newFakeClientFail(t, "junk")
	if err == nil {
		t.Fatal("expected handshake failure on junk protocol line")
	}
}

func jsonUnmarshal(data string, v any) error { return json.Unmarshal([]byte(data), v) }
