package sandbox

import (
	"errors"
	"strings"
	"testing"
)

// exitError translates a failure that raced the bridge exit. Cover all three
// states deterministically: bridge running, bridge exited with error, bridge
// exited gracefully (nil exit error).
func TestExitErrorRunningReturnsRaw(t *testing.T) {
	c := newFakeClient(t, "")
	defer c.Close()
	raw := errors.New("write request: broken pipe")
	if err := c.exitError(raw); err != raw {
		t.Fatalf("exitError = %v, want the raw error while running", err)
	}
}

func TestExitErrorAfterUnexpectedExitWrapsReason(t *testing.T) {
	c := newFakeClient(t, "")
	_ = c.cmd.Process.Kill()
	<-c.Done()
	raw := errors.New("write request: broken pipe")
	err := c.exitError(raw)
	if !errors.Is(err, ErrBridgeExited) {
		t.Fatalf("err = %v, want ErrBridgeExited", err)
	}
	if strings.Contains(err.Error(), raw.Error()) {
		t.Fatalf("raw error must be replaced by the exit reason: %v", err)
	}
}

func TestExitErrorAfterGracefulCloseReturnsSentinel(t *testing.T) {
	c := newFakeClient(t, "")
	if err := c.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// Graceful close leaves waitErr nil (the exit itself was expected).
	raw := errors.New("write request: broken pipe")
	err := c.exitError(raw)
	if !errors.Is(err, ErrBridgeExited) {
		t.Fatalf("err = %v, want ErrBridgeExited", err)
	}
	if errors.Is(err, raw) {
		t.Fatalf("raw error must be replaced after graceful close")
	}
}
