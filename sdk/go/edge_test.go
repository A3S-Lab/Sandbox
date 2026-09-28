package sandbox

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// Options round-trip (the option functions are trivial but part of the API).
func TestStderrAndHandshakeTimeoutOptions(t *testing.T) {
	o := &Options{}
	opts := []Option{
		WithStderr(os.Stderr),
		WithHandshakeTimeout(3 * time.Second),
		WithBridgePath("/some/bridge"),
		WithWorkspace("/some/ws"),
	}
	for _, opt := range opts {
		opt(o)
	}
	if o.Stderr != os.Stderr || o.HandshakeTimeout != 3*time.Second || o.BridgePath != "/some/bridge" || o.Workspace != "/some/ws" {
		t.Fatalf("options = %+v", o)
	}
}

// Behavioral coverage for WithHandshakeTimeout: a bridge that answers the
// handshake too slowly must fail New.
func TestWithHandshakeTimeoutTimesOut(t *testing.T) {
	cmd := fakeCommand(t, "slow_init")
	_, err := newWithCommand(context.Background(), cmd, t.TempDir(), 50*time.Millisecond, os.Stderr)
	if err == nil {
		t.Fatal("expected handshake timeout")
	}
}

// syncBuffer is a race-safe io.Writer for capturing the bridge's stderr,
// which os/exec copies from its own goroutine.
type syncBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (w *syncBuffer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

func (w *syncBuffer) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

// Behavioral coverage for WithStderr: bridge stderr reaches the writer.
func TestWithStderrCapturesBridgeDiagnostics(t *testing.T) {
	var buf syncBuffer
	// The fake bridge needs its activation env; route it via the test helper
	// so New's option path is exercised with a working fake.
	cmd := fakeCommand(t, "stderr_noise")
	c, err := newWithCommand(context.Background(), cmd, t.TempDir(), 5*time.Second, &buf)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer c.Close()
	_ = c.Probe(context.Background())
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(buf.String(), "bridge-diagnostic-line") {
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(buf.String(), "bridge-diagnostic-line") {
		t.Fatalf("bridge stderr not captured: %q", buf.String())
	}
}

func TestBridgeErrorMessage(t *testing.T) {
	c := newFakeClient(t, "probe_fail")
	defer c.Close()
	err := c.Probe(context.Background())
	var bridgeErr *BridgeError
	if !errors.As(err, &bridgeErr) {
		t.Fatalf("want BridgeError, got %v", err)
	}
	if msg := bridgeErr.Error(); !strings.Contains(msg, bridgeErr.Message) || !strings.Contains(msg, bridgeErr.Code) {
		t.Fatalf("Error() = %q, want code+message", msg)
	}
}

func TestInitializeBadResultFailsDecode(t *testing.T) {
	_, err := newFakeClientE(t, "init_bad_result")
	if err == nil || !strings.Contains(err.Error(), "decode initialize result") {
		t.Fatalf("err = %v, want initialize decode failure", err)
	}
}

func TestCapabilitiesBadResultFailsDecode(t *testing.T) {
	c := newFakeClient(t, "cap_bad_result")
	defer c.Close()
	if _, err := c.Capabilities(context.Background()); err == nil || !strings.Contains(err.Error(), "decode capabilities result") {
		t.Fatalf("err = %v, want capabilities decode failure", err)
	}
}

func TestBadResponseFailsClosed(t *testing.T) {
	c := newFakeClient(t, "bad_response")
	_, err := c.Exec(context.Background(), "x")
	if err == nil {
		t.Fatal("expected protocol-violation error on malformed response")
	}
	waitFor(t, func() bool { return c.Err() != nil })
}

func TestExecStreamNilSinkRejected(t *testing.T) {
	c := newFakeClient(t, "")
	defer c.Close()
	if _, err := c.ExecStream(context.Background(), nil, "echo"); err == nil {
		t.Fatal("nil sink must be rejected")
	}
}

func TestUnknownMethodSurfacesBridgeError(t *testing.T) {
	c := newFakeClient(t, "")
	defer c.Close()
	_, err := c.call(context.Background(), "definitely_not_a_method", nil)
	var bridgeErr *BridgeError
	if !errors.As(err, &bridgeErr) || bridgeErr.Code != "unknown_method" {
		t.Fatalf("err = %v, want unknown_method", err)
	}
}
