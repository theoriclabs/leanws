# LeanWs

A Lean-native WebSocket library (RFC 6455) for Lean 4.33. Framing, handshake,
message reassembly and sessions are pure Lean over `Std.Http.Transport`. There
is no C FFI and no OpenSSL dependency: SHA-1 and base64 for the opening
handshake are implemented in Lean against the RFC test vectors (they are not
security primitives here).

```toml
[[require]]
name = "leanws"
git = "https://github.com/theoriclabs/leanws"
rev = "v0.1.0"
```

```lean
import LeanWs

open LeanWs

def main : IO Unit := do
  -- See LeanWs.Server / LeanWs.Client and the echo binary for loopback usage.
  IO.println s!"accept key demo: {Handshake.acceptKey "dGhlIHNhbXBsZSBub25jZQ=="}"
```

## Modules

| Module | Role |
| --- | --- |
| `LeanWs.Frame` | Pure RFC 6455 framing: encode and incremental parse |
| `LeanWs.Message` | Fragment reassembly, UTF-8 text validation, size limits |
| `LeanWs.Handshake` | Server accept / client request; `acceptKey`; Origin as a caller predicate |
| `LeanWs.Session` | Read/write loop over any `[Transport α]`; ping/pong; backpressure; close handshake |
| `LeanWs.Server` | Accept loop; handshake under `handshakeMaxBytes`; drain with close 1001 |
| `LeanWs.Client` | `ws://` connect (TLS is the ingress's job) |
| `LeanWs.Sha1` / `LeanWs.Base64` | Handshake helpers with RFC vectors |

Permessage-deflate is out of scope. Payloads here are expected to be small JSON.

## Behaviour

- **Backpressure.** `Session.send` fails with `.queueFull` when the outbound
  queue is saturated; callers decide whether to drop or close (LeanApp channels
  close slow consumers with 1013).
- **Timeouts.** Handshake, idle (ping every `idle/2`, close on a missed pong),
  and close handshake (2 s).
- **Fairness.** One dedicated task per session for reads; writes are
  serialized per session.
- **Drain.** `Server` stop accepting, close sessions with 1001, then shut down.

Until `Std.Http.Server` gains an `onUpgrade` hook, run the WebSocket listener
on its own loopback port next to the HTTP server (see LeanApp LA-14 / LA-15).

## Limits (defaults)

`maxFrame` 1 MiB, `maxMessage` 4 MiB, `maxFragments` 1024, `maxSockets` 4096,
`handshakeTimeoutMs` 5000, `handshakeMaxBytes` 8192, `idleTimeoutMs` 60000.

## Tests

```bash
lake build
lake test                 # or: lake exe leanws_tests
lake exe leanws_echo       # echo server for manual / Autobahn checks
```

Suites: `frame`, `crypto`, `handshake`, `message`, `session`, `loopback`.
Pass a suite name to run only that suite.

### Autobahn

Docker is optional. Against a running echo server:

```bash
lake exe leanws_echo -- --port 9001
docker run --rm --net=host crossbario/autobahn-testsuite \
  wstest -m fuzzingclient -w ws://127.0.0.1:9001
```

Expect the core cases (1–10) to pass. Compression cases (12–13) are excluded
because permessage-deflate is not implemented.

## License

MIT. See [LICENSE](LICENSE).
