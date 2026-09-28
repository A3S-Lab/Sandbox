package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

type execConfig struct {
	timeout time.Duration
	env     map[string]string
	onDelta func(outputEvent)
}

// ExecOption customizes a single Exec/ExecStream call.
type ExecOption func(*execConfig)

// WithOutputSink delivers live output deltas to fn as the backend observes
// them. Deltas are interleaved in observation order.
func WithOutputSink(fn func(delta string)) ExecOption {
	return func(cfg *execConfig) {
		if fn != nil {
			cfg.onDelta = func(ev outputEvent) { fn(ev.Delta) }
		}
	}
}

// WithTimeout bounds the command inside the sandbox: the bridge kills the
// whole process tree when the deadline passes and reports TimedOut. If unset,
// a ctx deadline is used; if neither is set, the bridge default (120s) applies.
func WithTimeout(d time.Duration) ExecOption { return func(cfg *execConfig) { cfg.timeout = d } }

// WithEnv adds environment variables for the command, layered over the
// bridge's scrubbed baseline.
func WithEnv(env map[string]string) ExecOption { return func(cfg *execConfig) { cfg.env = env } }

func (c *Client) exec(ctx context.Context, command string, opts ...ExecOption) (*CommandOutput, error) {
	cfg := execConfig{}
	for _, apply := range opts {
		apply(&cfg)
	}
	if command == "" {
		return nil, errors.New("sandbox: command must not be empty")
	}

	timeout := cfg.timeout
	if timeout <= 0 {
		// No explicit timeout (or a nonsensical negative): fall back to the
		// context deadline, then to the bridge default.
		if deadline, ok := ctx.Deadline(); ok {
			timeout = time.Until(deadline)
		}
		if timeout <= 0 {
			timeout = defaultTimeout
		}
	}

	params := map[string]any{
		"command":    command,
		"timeout_ms": timeout.Milliseconds(),
	}
	if cfg.env != nil {
		params["env"] = cfg.env
	}

	raw, err := c.callWithSink(ctx, "exec", params, cfg.onDelta)
	if err != nil {
		return nil, err
	}
	var result execResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("sandbox: decode exec result: %w", err)
	}
	return &CommandOutput{
		Stdout:   result.Stdout,
		Stderr:   result.Stderr,
		ExitCode: result.ExitCode,
		TimedOut: result.TimedOut,
	}, nil
}
