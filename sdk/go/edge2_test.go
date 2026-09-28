package sandbox

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// New with WithBridgeEnv: exercises the bridge-env option and New's default
// stderr branch in one hermetic test.
func TestNewWithBridgeEnvAndDefaultStderr(t *testing.T) {
	c, err := New(context.Background(),
		WithBridgePath(bridgeCommandPath(t, "")),
		WithWorkspace(t.TempDir()),
		WithBridgeEnv([]string{
			"GO_SANDBOX_FAKE_BRIDGE=1",
			"GO_SANDBOX_FAKE_SCENARIO=",
		}),
	)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer c.Close()
	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("ping: %v", err)
	}
}

// bridgeCommandPath builds a test-binary command that acts as the fake bridge.
func bridgeCommandPath(t *testing.T, scenario string) string {
	t.Helper()
	cmd := fakeCommand(t, scenario)
	// Reuse the fake through New's own exec path: the fake is this test
	// binary activated by env, so point BridgePath at os.Args[0] and set the
	// activation env via WithBridgeEnv.
	t.Setenv("GO_SANDBOX_FAKE_BRIDGE", "1")
	t.Setenv("GO_SANDBOX_FAKE_SCENARIO", scenario)
	_ = cmd
	return os.Args[0]
}

// StdinPipe/StdoutPipe failures are reachable when the caller pre-sets the
// corresponding field on the exec.Cmd; the SDK must report them, not panic.
func TestNewSurfacesStdinPipeError(t *testing.T) {
	cmd := fakeCommand(t, "")
	cmd.Stdin = os.Stdin // pre-set: StdinPipe must fail
	_, err := newWithCommand(context.Background(), cmd, t.TempDir(), time.Second, os.Stderr)
	if err == nil || !strings.Contains(err.Error(), "stdin pipe") {
		t.Fatalf("err = %v, want stdin pipe failure", err)
	}
}

func TestNewSurfacesStdoutPipeError(t *testing.T) {
	cmd := fakeCommand(t, "")
	cmd.Stdout = os.Stdout // pre-set: StdoutPipe must fail
	_, err := newWithCommand(context.Background(), cmd, t.TempDir(), time.Second, os.Stderr)
	if err == nil || !strings.Contains(err.Error(), "stdout pipe") {
		t.Fatalf("err = %v, want stdout pipe failure", err)
	}
}

// Kill the bridge, wait for the exit to be observed, then Exec: the write
// fails and the SDK must surface the exit (fail closed), not the pipe error.
func TestWriteErrorAfterBridgeExitSurfacesExit(t *testing.T) {
	c := newFakeClient(t, "")
	_ = c.cmd.Process.Kill()
	<-c.Done()
	_, err := c.Exec(context.Background(), "x")
	if !errors.Is(err, ErrBridgeExited) {
		t.Fatalf("err = %v, want ErrBridgeExited", err)
	}
}

// Closing stdin manually forces a deterministic write error while the bridge
// is still running: the default (pipe) error branch must be reported.
func TestWriteErrorWhileBridgeRunning(t *testing.T) {
	c := newFakeClient(t, "")
	defer c.Close()
	if err := c.stdin.Close(); err != nil {
		t.Fatalf("close stdin: %v", err)
	}
	_, err := c.Exec(context.Background(), "x")
	if err == nil || !strings.Contains(err.Error(), "write request") {
		t.Fatalf("err = %v, want write failure", err)
	}
}

// A graceful Close racing a call: the call observes waitDone with a nil exit
// error and must report ErrBridgeExited.
func TestCallRacingGracefulClose(t *testing.T) {
	c := newFakeClient(t, "hang")
	go func() {
		time.Sleep(100 * time.Millisecond)
		_ = c.Close()
	}()
	_, err := c.Exec(context.Background(), "hangs")
	if err == nil {
		t.Fatal("call must fail once the client is closed")
	}
	if !errors.Is(err, ErrBridgeExited) && !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want ErrBridgeExited", err)
	}
}

// Empty lines from the bridge are skipped, and the response after them still
// correlates correctly.
func TestEmptyProtocolLinesSkipped(t *testing.T) {
	c := newFakeClient(t, "empty_lines")
	defer c.Close()
	out, err := c.Exec(context.Background(), "echo")
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if out.Stdout != "after-empty" {
		t.Fatalf("stdout = %q", out.Stdout)
	}
}

// A summary field with the wrong JSON type is a protocol violation.
func TestMalformedSummaryFailsClosed(t *testing.T) {
	c := newFakeClient(t, "bad_summary")
	_, err := c.Exec(context.Background(), "x")
	if err == nil {
		t.Fatal("expected protocol-violation error")
	}
	waitFor(t, func() bool { return c.Err() != nil })
}

// An error object with the wrong member types is a protocol violation too —
// the base frame parses, so this exercises the response-decode failure branch.
func TestMalformedErrorShapeFailsClosed(t *testing.T) {
	c := newFakeClient(t, "bad_error_shape")
	_, err := c.Exec(context.Background(), "x")
	if err == nil {
		t.Fatal("expected protocol-violation error")
	}
	waitFor(t, func() bool { return c.Err() != nil })
}
