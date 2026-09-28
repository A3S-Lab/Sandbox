package sandbox

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- Options and New validation -------------------------------------------

func TestNewRejectsEmptyWorkspace(t *testing.T) {
	_, err := New(context.Background())
	if err == nil || !strings.Contains(err.Error(), "workspace is required") {
		t.Fatalf("err = %v, want workspace-required", err)
	}
}

func TestNewRejectsRelativeWorkspace(t *testing.T) {
	_, err := New(context.Background(), WithWorkspace("relative/path"))
	if err == nil || !strings.Contains(err.Error(), "absolute path") {
		t.Fatalf("err = %v, want absolute-path error", err)
	}
}

func TestNewMissingBridgeFailsClosed(t *testing.T) {
	_, err := New(context.Background(),
		WithBridgePath(filepath.Join(t.TempDir(), "no-such-bridge")),
		WithWorkspace(t.TempDir()),
	)
	if err == nil || !strings.Contains(err.Error(), "start bridge") {
		t.Fatalf("err = %v, want start-bridge failure", err)
	}
}

// --- Client state: Done / Err ----------------------------------------------

func TestErrNilWhileRunning(t *testing.T) {
	c := newFakeClient(t, "")
	defer c.Close()
	if err := c.Err(); err != nil {
		t.Fatalf("Err while running = %v, want nil", err)
	}
	select {
	case <-c.Done():
		t.Fatal("Done closed while running")
	default:
	}
}

func TestErrAndDoneAfterUnexpectedExit(t *testing.T) {
	c := newFakeClient(t, "")
	// Kill the bridge directly: the SDK must notice and surface it.
	if err := c.cmd.Process.Kill(); err != nil {
		t.Fatalf("kill: %v", err)
	}
	waitFor(t, func() bool {
		select {
		case <-c.Done():
			return true
		default:
			return false
		}
	})
	if err := c.Err(); err == nil || !errors.Is(err, ErrBridgeExited) {
		t.Fatalf("Err = %v, want ErrBridgeExited", err)
	}
	if _, err := c.Exec(context.Background(), "x"); !errors.Is(err, ErrBridgeExited) {
		t.Fatalf("exec after exit = %v, want ErrBridgeExited", err)
	}
}

// --- Protocol robustness -----------------------------------------------------

func TestExecEmptyCommandRejected(t *testing.T) {
	c := newFakeClient(t, "")
	defer c.Close()
	if _, err := c.Exec(context.Background(), ""); err == nil {
		t.Fatal("empty command must be rejected")
	}
}

func TestExecNegativeTimeoutFallsBackToDefault(t *testing.T) {
	c := newFakeClient(t, "echo_params")
	defer c.Close()
	out, err := c.Exec(context.Background(), "x", WithTimeout(-time.Second))
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	var params struct {
		TimeoutMS int64 `json:"timeout_ms"`
	}
	if err := jsonUnmarshal(out.Stdout, &params); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if params.TimeoutMS != int64(defaultTimeout.Milliseconds()) {
		t.Fatalf("timeout_ms = %d, want default %d", params.TimeoutMS, defaultTimeout.Milliseconds())
	}
}

func TestExecUnserializableParamsFail(t *testing.T) {
	c := newFakeClient(t, "")
	defer c.Close()
	// A func value cannot be JSON-encoded: exercises the encode-error path.
	_, err := c.callWithSink(context.Background(), "exec", map[string]any{
		"command": "x",
		"env":     map[string]any{"bad": func() {}},
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "encode") {
		t.Fatalf("err = %v, want encode failure", err)
	}
}

func TestUnknownIDResponseIgnored(t *testing.T) {
	c := newFakeClient(t, "unknown_id")
	defer c.Close()
	out, err := c.Exec(context.Background(), "x")
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if out.Stdout != "right-call" {
		t.Fatalf("stdout = %q, want the correlated response", out.Stdout)
	}
}

func TestMalformedEventFailsClosed(t *testing.T) {
	c := newFakeClient(t, "bad_event")
	_, err := c.Exec(context.Background(), "x")
	if err == nil {
		t.Fatal("expected protocol-violation error")
	}
	// fail() kills the bridge; the client must report the exit.
	waitFor(t, func() bool { return c.Err() != nil })
	if !errors.Is(c.Err(), ErrBridgeExited) {
		t.Fatalf("Err = %v, want ErrBridgeExited", c.Err())
	}
}

func TestOversizedLineFailsClosed(t *testing.T) {
	c := newFakeClient(t, "bigline")
	_, err := c.Exec(context.Background(), "x")
	if err == nil {
		t.Fatal("expected failure on oversized protocol line")
	}
	waitFor(t, func() bool { return c.Err() != nil })
}

// --- Close semantics ---------------------------------------------------------

func TestCloseWithInflightExec(t *testing.T) {
	c := newFakeClient(t, "hang")
	errCh := make(chan error, 1)
	go func() {
		_, err := c.Exec(context.Background(), "hangs forever")
		errCh <- err
	}()
	time.Sleep(150 * time.Millisecond) // let the request land
	if err := c.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("inflight exec must fail after close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("inflight exec did not return after close")
	}
}

func TestCloseKillAfterGrace(t *testing.T) {
	c := newFakeClient(t, "unkillable")
	c.grace = 150 * time.Millisecond
	start := time.Now()
	if err := c.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if elapsed := time.Since(start); elapsed < 100*time.Millisecond {
		t.Fatalf("close returned after %v; kill grace was not applied", elapsed)
	}
}

// --- Liveness and fresh capabilities ----------------------------------------

func TestPing(t *testing.T) {
	c := newFakeClient(t, "")
	defer c.Close()
	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("ping: %v", err)
	}
}

func TestCapabilitiesFresh(t *testing.T) {
	c := newFakeClient(t, "")
	defer c.Close()
	report, err := c.Capabilities(context.Background())
	if err != nil {
		t.Fatalf("capabilities: %v", err)
	}
	if report.Backend != "fake" || report.SessionID != "sess-1" {
		t.Fatalf("report = %+v", report)
	}
}

func TestPingAndCapabilitiesAfterClose(t *testing.T) {
	c := newFakeClient(t, "")
	c.Close()
	ctx := context.Background()
	if err := c.Ping(ctx); err == nil {
		t.Fatal("ping after close must fail")
	}
	if _, err := c.Capabilities(ctx); err == nil {
		t.Fatal("capabilities after close must fail")
	}
}

// --- Concurrency -------------------------------------------------------------

func TestConcurrentExecs(t *testing.T) {
	c := newFakeClient(t, "echo_params")
	defer c.Close()
	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			out, err := c.Exec(context.Background(), "echo")
			if err != nil {
				errs[i] = err
				return
			}
			var params struct {
				Command string `json:"command"`
			}
			_ = jsonUnmarshal(out.Stdout, &params)
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent exec %d: %v", i, err)
		}
	}
}

// commandOf is a formatting helper; cover both branches directly.
func TestCommandOf(t *testing.T) {
	if got := commandOf(map[string]any{"command": "ls"}); got != "ls" {
		t.Fatalf("commandOf = %q", got)
	}
	if got := commandOf(map[string]any{}); got != "" {
		t.Fatalf("commandOf = %q, want empty", got)
	}
}

// --- helpers -----------------------------------------------------------------

func newFakeClientWithStderr(t *testing.T, scenario string, stderr *bytes.Buffer) *Client {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcess")
	cmd.Env = append(os.Environ(),
		"GO_SANDBOX_FAKE_BRIDGE=1",
		"GO_SANDBOX_FAKE_SCENARIO="+scenario,
	)
	c, err := newWithCommand(context.Background(), cmd, t.TempDir(), 5*time.Second, stderr)
	if err != nil {
		t.Fatalf("new fake client: %v", err)
	}
	return c
}

func fakeCommand(t *testing.T, scenario string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcess")
	cmd.Env = append(os.Environ(),
		"GO_SANDBOX_FAKE_BRIDGE=1",
		"GO_SANDBOX_FAKE_SCENARIO="+scenario,
	)
	return cmd
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met within 2s")
}
