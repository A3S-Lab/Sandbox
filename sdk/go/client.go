// Package sandbox is the Go SDK for a3s-sandbox, the fail-closed native
// command sandbox. It drives the a3s-sandbox-bridge process over a
// newline-delimited JSON protocol: the bridge owns the Rust enforcement and
// every sandboxed process tree, so when the bridge exits — gracefully or not —
// nothing outlives it.
//
// Fail-closed by construction: if the bridge cannot start, the handshake
// fails, or a call's context is cancelled, Exec returns an error and never
// falls back to unsandboxed execution.
package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

// DefaultBridgeName is looked up on PATH when Options.BridgePath is empty.
const DefaultBridgeName = "a3s-sandbox-bridge"

const (
	defaultTimeout   = 2 * time.Minute
	handshakeTimeout = 30 * time.Second
	closeGrace       = 5 * time.Second
)

// CommandOutput is the final accounting for a command executed inside the
// sandbox boundary.
type CommandOutput struct {
	Stdout   string
	Stderr   string
	ExitCode int
	TimedOut bool
}

// Capabilities reports what the compiled backend can actually enforce.
// Policy features that exceed these capabilities are rejected before launch
// by the bridge; silent degradation is forbidden.
type Capabilities struct {
	FilesystemPathPolicy     bool `json:"filesystem_path_policy"`
	FilesystemReadonlyMounts bool `json:"filesystem_readonly_mounts"`
	FilesystemEphemeralWr    bool `json:"filesystem_ephemeral_writes"`
	NetworkDenyAll           bool `json:"network_deny_all"`
	MediatedHTTP             bool `json:"mediated_http"`
	MediatedSocks            bool `json:"mediated_socks"`
	UnixSocketAllowlist      bool `json:"unix_socket_allowlist"`
	ResourceTimeout          bool `json:"resource_timeout"`
	ResourceOutputLimit      bool `json:"resource_output_limit"`
	ResourceMemoryLimit      bool `json:"resource_memory_limit"`
	ResourceProcessLimit     bool `json:"resource_process_limit"`
	ResourceCPULimit         bool `json:"resource_cpu_limit"`
}

// CapabilityReport describes the initialized sandbox boundary.
type CapabilityReport struct {
	Backend      string       `json:"backend"`
	SessionID    string       `json:"session_id"`
	PolicyDigest string       `json:"policy_digest"`
	Unavailable  []string     `json:"unavailable"`
	Capabilities Capabilities `json:"capabilities"`
}

// Options configures New.
type Options struct {
	// BridgePath locates the a3s-sandbox-bridge executable. Empty means
	// DefaultBridgeName is looked up on PATH.
	BridgePath string
	// Workspace is the sandbox's canonical workspace directory. It must be an
	// absolute path; the bridge rejects anything else.
	Workspace string
	// Stderr receives the bridge process's stderr (diagnostics only — the
	// protocol runs on stdout). Default: io.Discard.
	Stderr io.Writer
	// BridgeEnv adds environment variables for the bridge process itself
	// (for example A3S_SANDBOX_RELAY). The sandboxed command's env is set
	// per-exec via WithEnv, not here.
	BridgeEnv []string
	// HandshakeTimeout bounds the initialize round-trip in New.
	// Default: 30s.
	HandshakeTimeout time.Duration
}

type Option func(*Options)

// WithBridgePath overrides the bridge executable path.
func WithBridgePath(path string) Option { return func(o *Options) { o.BridgePath = path } }

// WithWorkspace sets the sandbox workspace (required, absolute path).
func WithWorkspace(dir string) Option { return func(o *Options) { o.Workspace = dir } }

// WithStderr redirects bridge stderr. Default: io.Discard.
func WithStderr(w io.Writer) Option { return func(o *Options) { o.Stderr = w } }

// WithHandshakeTimeout bounds the initialize round-trip in New.
func WithHandshakeTimeout(d time.Duration) Option {
	return func(o *Options) { o.HandshakeTimeout = d }
}

// WithBridgeEnv adds environment variables for the bridge process itself.
func WithBridgeEnv(env []string) Option { return func(o *Options) { o.BridgeEnv = env } }

// ErrBridgeExited is returned by calls after the bridge process has exited.
// Any running commands were terminated with it (process-group guards).
var ErrBridgeExited = errors.New("a3s-sandbox-bridge exited")

// BridgeError is a structured error returned by the bridge.
type BridgeError struct {
	Code    string
	Message string
}

func (e *BridgeError) Error() string { return fmt.Sprintf("a3s sandbox %s: %s", e.Code, e.Message) }

type pendingCall struct {
	ch chan response
}

// Client is a handle to one bridge process and its sandbox. It is safe for
// concurrent use; commands may run concurrently inside the sandbox boundary.
type Client struct {
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	stderrW io.Writer

	writeMu  sync.Mutex
	mu       sync.Mutex
	inflight map[int64]*pendingCall
	sinks    map[int64]func(outputEvent)
	nextID   int64
	closed   bool
	grace    time.Duration // Close kill grace; default closeGrace
	waitErr  error         // set once, before waitDone closes

	waitDone chan struct{}

	report CapabilityReport
}

// New spawns the bridge process and performs the initialize handshake.
// The caller should Close the client when finished; closing terminates the
// bridge and every process tree it spawned.
func New(ctx context.Context, opts ...Option) (*Client, error) {
	o := &Options{
		BridgePath:       DefaultBridgeName,
		Stderr:           io.Discard,
		HandshakeTimeout: handshakeTimeout,
	}
	for _, apply := range opts {
		apply(o)
	}
	if o.Workspace == "" {
		return nil, errors.New("sandbox: workspace is required (WithWorkspace)")
	}
	if !filepath.IsAbs(o.Workspace) {
		return nil, fmt.Errorf("sandbox: workspace must be an absolute path, got %q", o.Workspace)
	}
	if o.Stderr == nil {
		o.Stderr = io.Discard
	}
	cmd := exec.Command(o.BridgePath)
	if len(o.BridgeEnv) > 0 {
		cmd.Env = append(os.Environ(), o.BridgeEnv...)
	}
	cmd.Stderr = o.Stderr
	return newWithCommand(ctx, cmd, o.Workspace, o.HandshakeTimeout, o.Stderr)
}

// newWithCommand starts a prepared bridge command and runs the handshake.
func newWithCommand(ctx context.Context, cmd *exec.Cmd, workspace string, handshakeTimeout time.Duration, stderr io.Writer) (*Client, error) {
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("sandbox: stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("sandbox: stdout pipe: %w", err)
	}
	if stderr == nil {
		stderr = io.Discard
	}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("sandbox: start bridge %q: %w", cmd.Path, err)
	}

	c := &Client{
		cmd:      cmd,
		stdin:    stdin,
		stderrW:  stderr,
		inflight: make(map[int64]*pendingCall),
		sinks:    make(map[int64]func(outputEvent)),
		grace:    closeGrace,
		waitDone: make(chan struct{}),
	}
	go func() {
		waitErr := cmd.Wait()
		c.mu.Lock()
		if c.waitErr == nil {
			if waitErr != nil {
				c.waitErr = fmt.Errorf("%w: %v", ErrBridgeExited, waitErr)
			} else if !c.closed {
				c.waitErr = ErrBridgeExited
			}
		}
		c.mu.Unlock()
		close(c.waitDone)
	}()
	go c.readLoop(stdout)

	report, err := handshake(ctx, c, workspace, handshakeTimeout)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	c.report = report
	return c, nil
}

func handshake(ctx context.Context, c *Client, workspace string, timeout time.Duration) (CapabilityReport, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	raw, err := c.call(ctx, "initialize", map[string]string{"workspace": workspace})
	if err != nil {
		return CapabilityReport{}, err
	}
	var report CapabilityReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return CapabilityReport{}, fmt.Errorf("sandbox: decode initialize result: %w", err)
	}
	return report, nil
}

// Report returns the capability report captured at initialize time.
func (c *Client) Report() CapabilityReport { return c.report }

// Probe verifies the platform boundary is enforceable on this host. A
// fail-closed operation: an error means the sandbox cannot run here.
func (c *Client) Probe(ctx context.Context) error {
	_, err := c.call(ctx, "probe", nil)
	return err
}

// Ping checks bridge liveness with a protocol round-trip.
func (c *Client) Ping(ctx context.Context) error {
	_, err := c.call(ctx, "ping", nil)
	return err
}

// Capabilities fetches a fresh capability report from the bridge. The report
// captured at initialize time is available via Report without a round-trip.
func (c *Client) Capabilities(ctx context.Context) (*CapabilityReport, error) {
	raw, err := c.call(ctx, "capabilities", nil)
	if err != nil {
		return nil, err
	}
	var report CapabilityReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, fmt.Errorf("sandbox: decode capabilities result: %w", err)
	}
	return &report, nil
}

// Exec runs command inside the sandbox boundary and returns its output.
//
// Cancellation: if ctx has a deadline it becomes the in-sandbox timeout
// (enforced by the bridge, which kills the whole process tree). If ctx is
// cancelled before completion, Exec returns immediately with ctx.Err(); the
// command itself keeps running until its timeout elapses and its result is
// discarded. To terminate everything right now, Close the client.
func (c *Client) Exec(ctx context.Context, command string, opts ...ExecOption) (*CommandOutput, error) {
	return c.exec(ctx, command, opts...)
}

// ExecStream is Exec with live output deltas delivered to onDelta as the
// backend observes them. Deltas are interleaved in observation order; the
// protocol does not split them by stream.
func (c *Client) ExecStream(ctx context.Context, onDelta func(delta string), command string, opts ...ExecOption) (*CommandOutput, error) {
	if onDelta == nil {
		return nil, errors.New("sandbox: onDelta must not be nil")
	}
	return c.exec(ctx, command, append(opts, WithOutputSink(onDelta))...)
}

// Close terminates the bridge: stdin EOF triggers a graceful shutdown, and
// after closeGrace the process is killed. Every sandboxed process tree dies
// with the bridge. Close is idempotent.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		<-c.waitDone
		return c.waitErr
	}
	c.closed = true
	c.mu.Unlock()

	_ = c.stdin.Close() // EOF: the bridge drops the sandbox and kills the trees
	timer := time.NewTimer(c.grace)
	defer timer.Stop()
	select {
	case <-c.waitDone:
	case <-timer.C:
		if c.cmd.Process != nil {
			_ = c.cmd.Process.Kill()
		}
		<-c.waitDone
	}
	c.mu.Lock()
	err := c.waitErr
	c.mu.Unlock()
	if errors.Is(err, ErrBridgeExited) {
		return nil // graceful close: the exit itself is expected
	}
	return err
}

// Done is closed when the bridge process exits for any reason.
func (c *Client) Done() <-chan struct{} { return c.waitDone }

// Err reports how the bridge process exited, or nil while it is running.
func (c *Client) Err() error {
	select {
	case <-c.waitDone:
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.waitErr == nil {
			return ErrBridgeExited
		}
		return c.waitErr
	default:
		return nil
	}
}
