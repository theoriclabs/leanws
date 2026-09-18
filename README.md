# LeanWs

A Lean-native WebSocket library (RFC 6455) for Lean 4. Framing, the opening
handshake, fragment reassembly, a session with backpressure and timeouts, a
TCP server and a `ws://` client, all in Lean over `Std.Http.Transport` — no C
code and no OpenSSL. Handshake requests reuse `Std.Http`'s validated request
and response heads, methods, headers and URIs.

```toml
[[require]]
name = "leanws"
git = "https://github.com/theoriclabs/leanws"
rev = "v0.1.0"
```

```lean
import LeanWs

open LeanWs Std.Async

def main : IO Unit := Async.block do
  let addr : Std.Net.SocketAddress := .v4 { addr := .ofParts 127 0 0 1, port := 9001 }
  let server ← Server.serve addr {}
    (fun req _remote => pure (Handshake.server req { subprotocols := ["chat.v1"] }))
    (fun session _accept => do
      repeat
        match ← session.recv with
        | none => break
        | some msg =>
            match ← session.send msg with
            | .ok () => pure ()
            | .error .queueFull => session.close .tryAgainLater "slow consumer"; break
            | .error .closed => break)
  IO.println s!"listening on ws://{server.localAddr}"
  server.waitShutdown
```

`Server.serve` accepts connections, runs the handshake under a byte and time
budget, and hands each connection to `onSession` as a `Session` in its own
task. The session's reader answers pings, reassembles fragments, validates
UTF-8, enforces size limits and the idle timeout, and fails the connection
with the RFC 6455 close codes; its writer serializes frames and bounds the
outbound queue so a slow peer surfaces as `SendError.queueFull` rather than
unbounded memory.

## Modules and public API

| Module | Contents |
| --- | --- |
| `LeanWs.Frame` | `Opcode`, `Frame`, `Frame.encode`, `Frame.parse` (incremental; `.ok none` = need more bytes), `Frame.parseHeader`, `Frame.applyMask`, `FrameError` |
| `LeanWs.Close` | `CloseCode` with the registered constants, `CloseInfo`, `Frame.close`, `Frame.parseClosePayload` |
| `LeanWs.Message` | `Message` (`.text`/`.binary`), `Limits`, `Message.toFrames`, `Assembler` (fragment reassembly), `AssembleError` |
| `LeanWs.Sha1`, `LeanWs.Base64` | Pure-Lean SHA-1 and base64 for the handshake key; protocol utilities, not security primitives |
| `LeanWs.Handshake` | `acceptKey`, `Handshake.server`, `Handshake.client`, `Handshake.verify`, `ServerOptions`, `Accept`, `Reject`, `ClientReject`, wire parsers `parseRequest`/`parseResponse` built on `Std.Http`'s H1 parsers, `encodeRequest`/`encodeResponse` |
| `LeanWs.Session` | `Session.start`, `send`, `recv`, `recvSelector`, `ping`, `close`, `abort`, `waitClosed`, `closed?`, `isOpen`, `Role`, `SessionOptions`, `SendError`, `Closed` |
| `LeanWs.Tcp` | `Tcp`, a `Transport` over `Std.Async.TCP.Socket.Client` suited to thousands of sessions |
| `LeanWs.Server` | `Server.serve`, `Server.upgrade`, `Server.drain`, `Server.shutdown`, `Server.waitShutdown`, `Server.activeSessions`, `ServerConfig`, `RemoteAddr` |
| `LeanWs.Client` | `Client.connect`, `Client.connectDetailed`, `ClientOptions`, `ConnectError`, `Connection` |

`import LeanWs` re-exports everything.

### Framing

```lean
def Frame.encode : Frame → ByteArray
def Frame.parse  : ByteArray → Except FrameError (Option (Frame × ByteArray))
```

`Frame` carries `fin`, the three `rsv` bits, the `opcode`, an optional
masking key and the unmasked `payload`. `encode` always uses the minimal
length encoding and masks when `mask` is set; `parse` accepts all three
length encodings, returns the unconsumed suffix, and reports reserved
opcodes, fragmented or oversized control frames and invalid 64-bit lengths
as `FrameError`. Reserved bits are preserved for the session to judge. For
every `Frame.wellFormed` frame, `parse (encode f) = .ok (some (f, .empty))`;
this is checked by property tests (random frames over every opcode, masking
choice and length encoding, and every byte boundary of the incremental
parser), not proven.

### Handshake

```lean
def Handshake.acceptKey (clientKey : String) : String
def Handshake.server (req : Std.Http.Request.Head) (opts : ServerOptions := {}) : Except Reject Accept
def Handshake.client (uri : Std.Http.URI) (subprotocols : List String := []) (key : String)
    (extraHeaders : Std.Http.Headers := .empty) : Std.Http.Request.Head × String
def Handshake.verify (res : Std.Http.Response.Head) (expectedAccept : String)
    (subprotocols : List String := []) : Except ClientReject (Option String)
```

`Handshake.server` checks the method, HTTP version, `Upgrade`, `Connection`,
`Sec-WebSocket-Version: 13` and a well-formed `Sec-WebSocket-Key`, applies the
caller's `checkOrigin : Option String → Bool` predicate, and selects the first
of `opts.subprotocols` the client also offered. `Accept.toResponse` is the
`101` response; `Reject.toResponse` is `426 Upgrade Required` (with `Upgrade`
and `Sec-WebSocket-Version: 13`) for requests that are not upgrades or use
another version, `400` for malformed upgrade requests, `403` for a rejected
origin and `405` for non-GET methods. Extensions (including
permessage-deflate) are never negotiated. `Accept.request` keeps the request
head so a session handler can route on its path, query or headers.

### Session

```lean
def Session.start [Transport α] (t : α) (role : Role) (limits : Limits := {})
    (opts : SessionOptions := {}) (initial : ByteArray := .empty) : Async Session
def Session.send  : Session → Message → Async (Except SendError Unit)
def Session.recv  : Session → Async (Option Message)          -- none once closed and drained
def Session.close : Session → (code : CloseCode := .normal) → (reason : String := "") → Async Unit
def Session.ping  : Session → (payload : ByteArray := .empty) → Async Unit
def Session.waitClosed : Session → Async Closed
```

A session runs over any `Std.Http.Transport` — `LeanWs.Tcp` for sockets, or
`Std.Http.Internal.Mock` in tests. `Session.start` spawns the reader and
writer tasks and returns at once; `initial` carries bytes that arrived
together with the handshake. Every operation may be called from any task.

`recv` yields complete messages in order and `none` after the session has
closed and its buffered messages are consumed. `recvSelector` exposes the
same source for `Selectable.one`.

`Closed` records the close frame we `sent` and the one we `received`;
`Closed.code` is the peer's code, or `1006` if the connection ended without
one, and `Closed.clean` is `true` when both frames were exchanged.

## Limits and behaviour

```lean
structure Limits where
  maxFrame : Nat := 1 <<< 20      -- 1 MiB per frame
  maxMessage : Nat := 4 <<< 20    -- 4 MiB per reassembled message
  maxFragments : Nat := 1024      -- frames per message; 0 removes the bound

structure SessionOptions where
  sendQueue : Nat := 256          -- messages accepted but not yet written
  sendTimeoutMs : Nat := 1000     -- how long `send` waits for room; 0 = never
  recvQueue : Nat := 64           -- messages buffered for `recv`
  idleTimeoutMs : Nat := 60000    -- ping at idle/2, close at idle; 0 disables
  closeTimeoutMs : Nat := 2000    -- wait for the peer's close frame
  recvChunkBytes : Nat := 65536
  writeBatchBytes : Nat := 256 * 1024
```

**Backpressure.** `send` queues a message and returns once the writer owns
it. At most `sendQueue` messages may be accepted but not yet written to the
transport; beyond that `send` waits up to `sendTimeoutMs` for room and then
returns `.queueFull`. With `sendTimeoutMs := 0` it never waits, which fan-out
code that must not stall on one peer should prefer. The caller decides what
to do next — drop the message, or close the peer (`1013 Try Again Later` is
customary). Messages larger than `limits.maxFrame` are fragmented on the
wire. On the receive side, `recvQueue` bounds buffered messages; when it is
full the reader stops reading and TCP flow control pushes back on the peer.
The writer coalesces queued messages into one transport write up to
`writeBatchBytes`.

**Fairness.** One reader task and one writer task per session; writes are
serialized per session; there is no global lock. Control frames (pong
replies, pings) are written ahead of queued data; the close frame is written
in order after messages queued before `close` was called.

**Timeouts.** The server bounds the handshake with `handshakeTimeoutMs` and
`handshakeMaxBytes` (`400` past the byte budget, a dropped connection past
the time budget). A session sends a ping after `idleTimeoutMs / 2` without
traffic and closes with `1001` when the full timeout elapses without any
frame from the peer. `close` sends our close frame, then waits up to
`closeTimeoutMs` for the peer's before tearing the transport down; the same
bound applies to flushing the writer during teardown.

**Close codes.** The reader fails the connection with `1002` for reserved
bits, a masking violation (clients must mask, servers must not), a reserved
opcode, a fragmented or oversized control frame, a continuation without a
message in progress, a new message while one is fragmented, too many
fragments, or a malformed close payload; `1007` for invalid UTF-8 in a text
message or close reason; `1009` for a frame above `maxFrame` (detected from
the header, before the payload arrives) or a message above `maxMessage`;
`1011` is reserved for the application. A peer's close frame is echoed with
its status code and the connection then closes; an empty close payload is
echoed empty and reported as `1005`. Received codes outside
`1000–1003`, `1007–1014` and `3000–4999` are protocol errors. After a failure
the server does not wait for the peer's close frame.

**Fragmentation.** Text is validated after reassembly, not per fragment.
Control frames interleaved with a fragmented message are handled in place.

**Known limitation.** `Std.Async.TCP` offers `shutdown` but no `close`; a
socket is released when its last reference is dropped. `Tcp`'s `close` shuts
down the write side, so a peer that never reads while we have data in flight
keeps its socket until the pending write completes or the peer disappears.

## Server

```lean
structure ServerConfig where
  maxSockets : Nat := 4096          -- 0 = unlimited; the accept loop waits at the limit
  handshakeTimeoutMs : Nat := 5000
  handshakeMaxBytes : Nat := 8192
  idleTimeoutMs : Nat := 60000
  limits : Limits := {}
  sendQueue : Nat := 256
  sendTimeoutMs : Nat := 1000
  recvQueue : Nat := 64
  closeTimeoutMs : Nat := 2000
  backlog : UInt32 := 1024

def Server.serve (addr : Std.Net.SocketAddress) (config : ServerConfig := {})
    (onUpgrade : Std.Http.Request.Head → RemoteAddr → Async (Except Handshake.Reject Handshake.Accept))
    (onSession : Session → Handshake.Accept → Async Unit) : Async Server
```

`onUpgrade` decides each request; the usual body is `Handshake.server req
opts`, possibly after authenticating the request head (`RemoteAddr` is the
peer's socket address). `onSession` runs in its own task per connection and
owns the session until it returns; the server then closes the session with
`1000` if it is still open and waits for it to finish before releasing the
socket. Non-WebSocket requests receive `426` or `400` and the connection is
closed.

`Server.localAddr` reflects the port the OS chose when `serve` got port `0`.
`Server.drain` stops accepting, closes every session with `1001` (the code
and reason are parameters), waits for the closing handshakes (each bounded by
`closeTimeoutMs`) and for all connection tasks to finish; handshakes still in
progress are dropped. `Server.shutdown` does the same without a closing
handshake. `Server.waitShutdown` blocks until either has completed.

`Server.upgrade` completes an upgrade on any `Transport` whose request head
has already been read and accepted: it writes the `101` for an `Accept` and
starts a server-role session. Use it from a custom listener, together with
`Handshake.parseRequest` and `Handshake.server`.

## Client

```lean
def Client.connect (uri : Std.Http.URI) (opts : ClientOptions := {}) : Async (Except ConnectError Session)
def Client.connectDetailed (uri : Std.Http.URI) (opts : ClientOptions := {}) : Async (Except ConnectError Connection)
```

Only `ws://` is supported; TLS termination is the job of the ingress in front
of the server (`wss://` via libcurl is tracked in leanhttp). Host names are
resolved with `Std.Async.DNS`. `ClientOptions` carries the offered
`subprotocols`, extra request `headers` (for example `Origin` or
`Authorization`), connect and handshake timeouts, `limits` and
`SessionOptions`. `connectDetailed` also returns the negotiated subprotocol
and the server's `101` response head.

## Tests

```bash
lake test
```

runs `tests/run.sh`, which raises the descriptor limit, builds and runs the
`leanws_tests` executable (also available as `lake exe leanws_tests [suite …]`
with the suites `frame`, `crypto`, `handshake`, `message`, `session`,
`loopback`). The suite covers frame codec property tests (random frames over
all opcodes, masked and unmasked, all three length encodings, the incremental
parser split at every byte boundary), SHA-1 and base64 RFC vectors, the RFC
6455 §1.3 handshake vector (`dGhlIHNhbXBsZSBub25jZQ==` →
`s3pPLMBiTxaQ9kYGzzhZRbK+xOo=`), sessions over `Std.Http.Internal.Mock`
(fragmentation, ping/pong, close codes, oversize rejection, backpressure,
idle timeout), and loopback integration of `Server` and `Client` with 1,000
concurrent sockets exchanging 10,000 messages followed by a drain that closes
the remaining sockets with `1001`. The loopback size can be scaled with
`LEANWS_LOOPBACK_SOCKETS` and `LEANWS_LOOPBACK_MESSAGES`. The whole suite runs
in well under a minute.

## Autobahn testsuite

`lake exe leanws_echo [port] [ipv4-host]` starts an echo server (default
`127.0.0.1:9001`) with limits raised for the testsuite's large-message
cases and no idle timeout. To run the
[Autobahn](https://github.com/crossbario/autobahn-testsuite) fuzzing client
against it:

```bash
lake exe leanws_echo 9001 0.0.0.0 &

mkdir -p /tmp/autobahn/config /tmp/autobahn/reports
cat > /tmp/autobahn/config/fuzzingclient.json <<'EOF'
{
  "outdir": "./reports/servers",
  "servers": [{ "agent": "leanws", "url": "ws://host.docker.internal:9001" }],
  "cases": ["*"],
  "exclude-cases": ["12.*", "13.*"],
  "exclude-agent-cases": {}
}
EOF

docker run --rm -v /tmp/autobahn/config:/config -v /tmp/autobahn/reports:/reports \
  crossbario/autobahn-testsuite wstest -m fuzzingclient -s /config/fuzzingclient.json
open /tmp/autobahn/reports/servers/index.html
```

On Linux use `--network host` and `ws://127.0.0.1:9001` instead of
`host.docker.internal`. Cases 12.* and 13.* exercise the permessage-deflate
extension, which leanws does not implement, and are excluded; the remaining
cases (1–10, framing, pings, reserved bits, opcodes, fragmentation, UTF-8,
close handling, limits and performance) are the conformance target. The
report for this release has not been recorded because the Docker daemon was
unavailable on the release machine; the `session` test suite covers the
same protocol rules with hand-built frames.

## Upstream note

`Std.Http.Server` in Lean 4.33 has no upgrade hook: once a handler responds,
the connection stays an HTTP/1.1 connection, so a WebSocket endpoint cannot
share the HTTP port. A small `onUpgrade` hook in `Std.Http.Server.Connection`
— handing the socket, the parsed request head and any buffered bytes to the
application on `101 Switching Protocols` — would let `Server.upgrade` take
over from there. Until then, consumers run the WebSocket listener on a
separate (loopback) port and let their ingress route `Upgrade: websocket`
requests to it.

## Runtime and development

Requires Lean `v4.33.0`. No native dependencies beyond the Lean runtime
(libuv is part of it). Changes are recorded in [CHANGELOG.md](CHANGELOG.md);
published versions are available in
[GitHub Releases](https://github.com/theoriclabs/leanws/releases). See
[RELEASING.md](RELEASING.md) for the versioning and release process.
