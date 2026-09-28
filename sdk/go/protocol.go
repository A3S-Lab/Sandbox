package sandbox

import "encoding/json"

// Wire protocol v1 for a3s-sandbox-bridge: newline-delimited JSON over the
// bridge process's stdin/stdout. One object per line.
//
//	request  {"id": 1, "method": "...", "params": {...}}
//	response {"id": 1, "ok": true, "result": {...}}
//	response {"id": 1, "ok": false, "error": {"code": "...", "message": "..."}}
//	event    {"event": "output", "id": 2, "delta": "..."}
//	event    {"event": "output_complete", "id": 2, "summary": {...}}

type request struct {
	ID     int64           `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

type bridgeError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type response struct {
	ID     int64           `json:"id"`
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *bridgeError    `json:"error,omitempty"`
}

type outputEvent struct {
	Event   string         `json:"event"`
	ID      int64          `json:"id"`
	Delta   string         `json:"delta,omitempty"`
	Summary *outputSummary `json:"summary,omitempty"`
}

type outputSummary struct {
	TotalBytes    int  `json:"total_bytes"`
	CapturedBytes int  `json:"captured_bytes"`
	Truncated     bool `json:"truncated"`
	TimedOut      bool `json:"timed_out"`
}

type execResult struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exit_code"`
	TimedOut bool   `json:"timed_out"`
}
