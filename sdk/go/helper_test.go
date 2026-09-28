package sandbox

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// TestMain intercepts the test binary to double as a fake bridge process for
// hermetic protocol tests: setting GO_SANDBOX_FAKE_BRIDGE=1 turns this binary
// into a scripted bridge instead of running the tests.
func TestMain(m *testing.M) {
	if os.Getenv("GO_SANDBOX_FAKE_BRIDGE") == "1" {
		runFakeBridge()
		return
	}
	os.Exit(m.Run())
}

func runFakeBridge() {
	scenario := os.Getenv("GO_SANDBOX_FAKE_SCENARIO")
	reader := bufio.NewReader(os.Stdin)
	writer := bufio.NewWriter(os.Stdout)
	defer writer.Flush()

	emit := func(v string) {
		fmt.Fprintln(writer, v)
		writer.Flush()
	}
	ok := func(id int64, result string) {
		emit(fmt.Sprintf(`{"id":%d,"ok":true,"result":%s}`, id, result))
	}
	errResp := func(id int64, code, message string) {
		emit(fmt.Sprintf(`{"id":%d,"ok":false,"error":{"code":%q,"message":%q}}`, id, code, message))
	}

	if scenario == "junk" {
		emit("this is not json")
	}
	if scenario == "stderr_noise" {
		fmt.Fprintln(os.Stderr, "bridge-diagnostic-line")
	}

	unkillable := scenario == "unkillable"
	if scenario == "empty_lines" {
		fmt.Fprintln(writer, "")
		writer.Flush()
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if unkillable {
				time.Sleep(30 * time.Second) // ignore EOF: Close must kill us
			}
			return // EOF: graceful bridge exit
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var req struct {
			ID     int64           `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			return
		}
		switch req.Method {
		case "initialize":
			if scenario == "init_bad_result" {
				emit(fmt.Sprintf(`{"id":%d,"ok":true,"result":"junk-not-object"}`, req.ID))
				continue
			}
			if scenario == "slow_init" {
				time.Sleep(300 * time.Millisecond)
			}
			if scenario == "init_fail" {
				errResp(req.ID, "initialize_failed", "no enforceable boundary on this host")
				continue
			}
			ok(req.ID, `{"backend":"fake","session_id":"sess-1","policy_digest":"digest-1","unavailable":[],"capabilities":{}}`)
		case "probe":
			if scenario == "probe_fail" {
				errResp(req.ID, "probe_failed", "sandbox boundary unavailable")
				continue
			}
			ok(req.ID, `{"backend":"fake"}`)
		case "capabilities":
			if scenario == "cap_bad_result" {
				emit(fmt.Sprintf(`{"id":%d,"ok":true,"result":"junk"}`, req.ID))
				continue
			}
			ok(req.ID, `{"backend":"fake","session_id":"sess-1","policy_digest":"digest-1","unavailable":[],"capabilities":{}}`)
		case "ping":
			ok(req.ID, `{"alive":true}`)
		case "exec":
			switch scenario {
			case "unknown_id":
				emit(fmt.Sprintf(`{"id":%d,"ok":true,"result":{"stdout":"wrong-call","stderr":"","exit_code":0,"timed_out":false}}`, req.ID+1000))
				ok(req.ID, `{"stdout":"right-call","stderr":"","exit_code":0,"timed_out":false}`)
			case "bad_event":
				emit(fmt.Sprintf(`{"event":123,"id":%d}`, req.ID))
			case "bad_summary":
				emit(fmt.Sprintf(`{"event":"output","id":%d,"summary":"junk"}`, req.ID))
			case "bad_error_shape":
				emit(fmt.Sprintf(`{"id":%d,"ok":true,"error":{"code":123}}`, req.ID))
			case "empty_lines":
				emit("")
				ok(req.ID, `{"stdout":"after-empty","stderr":"","exit_code":0,"timed_out":false}`)
			case "bad_response":
				emit(fmt.Sprintf(`{"id":%d,"ok":"yes"}`, req.ID))
				emit(fmt.Sprintf(`{"id":%d,"ok":"yes"}`, req.ID))
			case "bad_result":
				emit(fmt.Sprintf(`{"id":%d,"ok":true,"result":"junk-not-object"}`, req.ID))
			case "env_echo":
				// Report the env the bridge received for this command —
				// mirrors what the real bridge layers onto the child.
				var params struct {
					Env map[string]string `json:"env"`
				}
				_ = json.Unmarshal(req.Params, &params)
				ok(req.ID, fmt.Sprintf(`{"stdout":%s,"stderr":"","exit_code":0,"timed_out":false}`, strconvQuote(params.Env["FAKE_ENV_MARKER"])))
			case "bigline":
				emit(fmt.Sprintf(`{"event":"output","id":%d,"delta":"%s"}`, req.ID, strings.Repeat("x", 5*1024*1024)))
			case "stderr_noise":
				fmt.Fprintln(os.Stderr, "exec-diagnostic")
				ok(req.ID, `{"stdout":"with-stderr","stderr":"","exit_code":0,"timed_out":false}`)
			case "exec_fail":
				errResp(req.ID, "exec_failed", "command rejected by policy")
			case "hang":
				// no response: the caller should time out or cancel
			case "echo_params":
				// Echo the request params back as stdout so tests can assert
				// exactly what the bridge received.
				ok(req.ID, fmt.Sprintf(`{"stdout":%s,"stderr":"","exit_code":0,"timed_out":false}`, strconvQuote(string(req.Params))))
			default:
				emit(fmt.Sprintf(`{"event":"output","id":%d,"delta":"he"}`, req.ID))
				emit(fmt.Sprintf(`{"event":"output","id":%d,"delta":"llo"}`, req.ID))
				ok(req.ID, `{"stdout":"hello","stderr":"","exit_code":0,"timed_out":false}`)
			}
		case "shutdown":
			if unkillable {
				continue // ignore shutdown entirely
			}
			return
		default:
			errResp(req.ID, "unknown_method", "unknown method "+req.Method)
		}
	}
}

// strconvQuote is a tiny stand-in for encoding/json string quoting that keeps
// the fake bridge readable.
func strconvQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
