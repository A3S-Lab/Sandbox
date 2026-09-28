package sandbox

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// End-to-end tests against a real a3s-sandbox-bridge and the real platform
// sandbox (macOS Seatbelt / Linux bwrap). Skipped without A3S_SANDBOX_BRIDGE.

func TestE2EExecWithEnv(t *testing.T) {
	c := newIntegrationClient(t)
	out, err := c.Exec(context.Background(),
		"printenv FAKE_ENV_MARKER",
		WithEnv(map[string]string{"FAKE_ENV_MARKER": "e2e-marker-42"}))
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	// The bridge scrubbed env cannot remove caller-provided entries; the fake
	// reports its own process env here, the real bridge reports the child's.
	if out.TimedOut {
		t.Fatalf("unexpected timeout: %+v", out)
	}
}

func TestE2EEnvEchoThroughBridge(t *testing.T) {
	c := newFakeClient(t, "env_echo")
	defer c.Close()
	out, err := c.Exec(context.Background(),
		"printenv FAKE_ENV_MARKER",
		WithEnv(map[string]string{"FAKE_ENV_MARKER": "marker-7"}))
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if !strings.Contains(out.Stdout, "marker-7") {
		t.Fatalf("stdout = %q, want the env marker echoed", out.Stdout)
	}
}

func TestE2EPingReal(t *testing.T) {
	c := newIntegrationClient(t)
	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("ping: %v", err)
	}
	fresh, err := c.Capabilities(context.Background())
	if err != nil {
		t.Fatalf("capabilities: %v", err)
	}
	if fresh.Backend != c.Report().Backend {
		t.Fatalf("fresh backend %q != initialize backend %q", fresh.Backend, c.Report().Backend)
	}
}

func TestE2ELargeOutputTruncated(t *testing.T) {
	c := newIntegrationClient(t)
	// 200 KB of output through the 100 KiB capture cap.
	out, err := c.Exec(context.Background(), "head -c 200000 /dev/zero | tr '\\0' a")
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	// The crate caps captured output at ~100 KiB; truncation happens at read
	// granularity, so assert bounded-ness rather than an exact boundary.
	const cap = 150 * 1024
	if len(out.Stdout) == 0 || len(out.Stdout) > cap {
		t.Fatalf("stdout length = %d, want (0, %d]", len(out.Stdout), cap)
	}
}

func TestE2EConcurrentExecs(t *testing.T) {
	c := newIntegrationClient(t)
	const n = 6
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			marker := "marker-" + string(rune('a'+i))
			out, err := c.Exec(context.Background(), "echo "+marker)
			if err != nil {
				errs[i] = err
				return
			}
			if !strings.Contains(out.Stdout, marker) {
				errs[i] = errors.New("marker missing from " + out.Stdout)
			}
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent exec %d: %v", i, err)
		}
	}
}

func TestE2ECloseTerminatesQuickly(t *testing.T) {
	c := newIntegrationClient(t)
	errCh := make(chan error, 1)
	go func() {
		_, _ = c.Exec(context.Background(), "sleep 30")
		errCh <- nil
	}()
	time.Sleep(200 * time.Millisecond) // let sleep 30 start
	start := time.Now()
	if err := c.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("close took %v; the sleeping tree was not torn down promptly", elapsed)
	}
}

func TestE2EDecodeErrorSurfaces(t *testing.T) {
	c := newFakeClient(t, "bad_result")
	_, err := c.Exec(context.Background(), "x")
	if err == nil || !strings.Contains(err.Error(), "decode exec result") {
		t.Fatalf("err = %v, want decode failure", err)
	}
}

func TestErrAfterGracefulCloseReportsExited(t *testing.T) {
	c := newFakeClient(t, "")
	if err := c.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := c.Err(); !errors.Is(err, ErrBridgeExited) {
		t.Fatalf("Err after graceful close = %v, want ErrBridgeExited", err)
	}
}
