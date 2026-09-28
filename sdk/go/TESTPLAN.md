# a3s-sandbox Go SDK 测试规划

覆盖率目标 ≥95%（`go test -coverprofile`，全量含端到端）。当前：**98.1%**（含 `-race` 与全部端到端测试）。

## 第一性原理：这个 SDK 会以哪几种方式出错？

SDK 的本质是「一个被 Go 进程监督的 Rust 桥进程 + 一条 JSON-lines 协议」。从这一事实推出全部失效面，每个失效面对应一组测试。任何一个面没有用例，故障就会在生产上以最贵的方式被发现。

| 失效面 | 问题 | 测试（文件） |
| --- | --- | --- |
| **进程生成** | 桥不存在 / 管道建立失败 / 握手失败 | `TestNewMissingBridgeFailsClosed`、`TestNewSurfacesStdinPipeError`、`TestNewSurfacesStdoutPipeError`、`TestInitializeFailure`、`TestWithHandshakeTimeoutTimesOut`（client/edge） |
| **监督语义** | 桥死了调用必须立刻失败；Close 必须连树一起终止 | `TestErrAndDoneAfterUnexpectedExit`、`TestErrAndDoneAfterUnexpectedExit` 后续调用、`TestCloseWithInflightExec`、`TestCloseKillAfterGrace`、`TestCloseFailsSubsequentCalls`、`TestE2ECloseTerminatesQuickly` |
| **协议解析** | 坏行 / 坏事件 / 坏响应 / 坏 error 形状 / 空行 / 超长行 / 未知 ID | `TestJunkLineFailsClosed`、`TestMalformedEventFailsClosed`、`TestBadResponseFailsClosed`、`TestMalformedErrorShapeFailsClosed`、`TestMalformedSummaryFailsClosed`、`TestEmptyProtocolLinesSkipped`、`TestOversizedLineFailsClosed`、`TestUnknownIDResponseIgnored` |
| **请求语义** | 参数校验 / 超时来源（显式 > ctx deadline > 默认）/ env / 流式回调 | `TestExecEmptyCommandRejected`、`TestExecTimeoutFromContext`、`TestExecNegativeTimeoutFallsBackToDefault`、`TestE2EEnvEchoThroughBridge`、`TestWithEnv`(E2E `TestE2EExecWithEnv`)、`TestExecStream`、`TestExecUnserializableParamsFail` |
| **错误传播** | 桥侧结构化错误 / 协议违规 / 解码失败必须原样到达调用方 | `TestExecBridgeError`、`TestProbeFailure`、`TestInitializeFailure`、`TestUnknownMethodSurfacesBridgeError`、`TestInitializeBadResultFailsDecode`、`TestCapabilitiesBadResultFailsDecode`、`TestE2EDecodeErrorSurfaces` |
| **并发** | 多命令交错、读写竞争 | `TestConcurrentExecs`（fake）、`TestE2EConcurrentExecs`（真桥）、全量 `-race` |
| **端到端（真桥+真沙箱）** | 上述一切在真实 Seatbelt/bwrap 下成立 | `integration_test.go` + `e2e_test.go`：probe、echo、退出码、超时杀树、流式、env、截断、并发、Close 时延 |

## 刻意不测的

- `callWithSink` 的 request-marshal 失败分支已删除（死代码）：params 先行 marshal 校验后，envelope 的 Marshal 不可能失败；即便产生坏输出，桥也会 fail-closed 退出。
- `fail` 的 `Process == nil` 防御分支：公开 API 无法触达（改内部字段会引入真实数据竞争），保留为防御性代码。

## 运行

```bash
go test ./...                       # hermetic 单测（假桥）
go test -race ./...                 # 并发安全
cargo build --bin a3s-sandbox-bridge
A3S_SANDBOX_BRIDGE=../../target/debug/a3s-sandbox-bridge \
  go test -count=1 -race -coverprofile=cover.out ./...   # 全量 + 覆盖率
go tool cover -func=cover.out | tail -1
```
