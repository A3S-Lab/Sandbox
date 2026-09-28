package sandbox

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
)

// call performs a request/response round-trip. Events that arrive for the
// same id while waiting are dropped unless a sink is registered.
func (c *Client) call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	return c.callWithSink(ctx, method, params, nil)
}

func (c *Client) callWithSink(ctx context.Context, method string, params any, sink func(outputEvent)) (json.RawMessage, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		// A closed client implies the bridge exited (see Close); surface the
		// precise exit error when one was recorded.
		if c.waitErr != nil {
			return nil, fmt.Errorf("sandbox: %w", c.waitErr)
		}
		return nil, ErrBridgeExited
	}
	c.nextID++
	id := c.nextID
	call := &pendingCall{ch: make(chan response, 1)}
	c.inflight[id] = call
	if sink != nil {
		c.sinks[id] = sink
	}
	c.mu.Unlock()

	rawParams, err := json.Marshal(params)
	if err != nil {
		c.mu.Lock()
		delete(c.inflight, id)
		delete(c.sinks, id)
		c.mu.Unlock()
		return nil, fmt.Errorf("sandbox: encode params: %w", err)
	}
	// The request envelope cannot fail to marshal: params is already valid
	// JSON (checked above) and RawMessage.MarshalJSON copies it verbatim.
	line, _ := json.Marshal(request{ID: id, Method: method, Params: rawParams})

	c.writeMu.Lock()
	if _, err := c.stdin.Write(append(line, '\n')); err != nil {
		c.writeMu.Unlock()
		c.mu.Lock()
		delete(c.inflight, id)
		delete(c.sinks, id)
		c.mu.Unlock()
		// A write failure after the bridge exited is a symptom — surface the
		// exit (fail closed) rather than the raw pipe error.
		return nil, c.exitError(fmt.Errorf("sandbox: write request: %w", err))
	}
	c.writeMu.Unlock()

	defer func() {
		c.mu.Lock()
		delete(c.inflight, id)
		delete(c.sinks, id)
		c.mu.Unlock()
	}()

	select {
	case resp := <-call.ch:
		if resp.OK {
			return resp.Result, nil
		}
		return nil, &BridgeError{Code: resp.Error.Code, Message: resp.Error.Message}
	case <-ctx.Done():
		return nil, fmt.Errorf("sandbox: %s %q: %w", method, commandOf(params), ctx.Err())
	case <-c.waitDone:
		return nil, c.exitError(ErrBridgeExited)
	}
}

// exitError translates a failure that raced the bridge process exiting: if
// the bridge is gone, its exit reason wins over the raw error (fail closed).
func (c *Client) exitError(raw error) error {
	select {
	case <-c.waitDone:
		c.mu.Lock()
		waitErr := c.waitErr
		c.mu.Unlock()
		if waitErr != nil {
			return fmt.Errorf("sandbox: %w", waitErr)
		}
		return ErrBridgeExited
	default:
		return raw
	}
}

// commandOf best-effort extracts params.command for error messages.
func commandOf(params any) string {
	if m, ok := params.(map[string]any); ok {
		if command, ok := m["command"].(string); ok {
			return command
		}
	}
	return ""
}

// readLoop parses the bridge's stdout: events route to per-call sinks,
// responses to their pending calls. Anything unparseable is a protocol
// violation — the bridge is supposed to exit non-zero on that; we mark the
// client broken and stop reading.
func (c *Client) readLoop(stdout io.Reader) {
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var base struct {
			ID    int64  `json:"id"`
			OK    *bool  `json:"ok"`
			Event string `json:"event"`
		}
		if err := json.Unmarshal(line, &base); err != nil {
			c.fail(fmt.Errorf("bridge sent a malformed protocol line: %w", err))
			return
		}
		if base.Event != "" {
			var ev outputEvent
			if err := json.Unmarshal(line, &ev); err != nil {
				c.fail(fmt.Errorf("bridge sent a malformed event: %w", err))
				return
			}
			c.mu.Lock()
			sink := c.sinks[ev.ID]
			c.mu.Unlock()
			if sink != nil {
				sink(ev)
			}
			continue
		}
		var resp response
		if err := json.Unmarshal(line, &resp); err != nil {
			c.fail(fmt.Errorf("bridge sent a malformed response: %w", err))
			return
		}
		c.mu.Lock()
		call := c.inflight[resp.ID]
		c.mu.Unlock()
		if call != nil {
			call.ch <- resp
		}
	}
	if err := scanner.Err(); err != nil {
		// A read failure or an oversized line is a protocol violation:
		// fail closed and take the bridge down with us.
		c.fail(fmt.Errorf("bridge stdout read failed: %w", err))
		return
	}
	// Scanner ended (EOF). The Wait goroutine records the exit; calls still
	// pending fail through waitDone.
}

// fail handles a protocol violation from the bridge: fail every pending call,
// then kill the bridge process. The Wait goroutine closes waitDone when the
// process is gone, and the exit error was already recorded by fail.
func (c *Client) fail(err error) {
	c.mu.Lock()
	if c.waitErr == nil {
		c.waitErr = fmt.Errorf("%w: %v", ErrBridgeExited, err)
	}
	for id, call := range c.inflight {
		call.ch <- response{Error: &bridgeError{Code: "protocol_violation", Message: err.Error()}}
		delete(c.inflight, id)
	}
	for id := range c.sinks {
		delete(c.sinks, id)
	}
	process := c.cmd.Process
	c.mu.Unlock()
	if process != nil {
		// Fail closed: a bridge that emits garbage must not outlive the
		// violation. Its own guards terminate the sandboxed trees.
		_ = process.Kill()
	}
}
