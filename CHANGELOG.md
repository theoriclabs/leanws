# Changelog

User-visible changes are recorded here. Versions use semantic versioning and
are published as `vX.Y.Z` Git tags and GitHub releases.

## [Unreleased]

## [0.1.0] - 2026-09-18

Initial release: a Lean-native WebSocket library (RFC 6455) over
`Std.Http.Transport`, with no C code and no OpenSSL.

### Added

- `LeanWs.Frame`: pure framing with an incremental parser, all three length
  encodings, masking, and `FrameError` for reserved opcodes, fragmented or
  oversized control frames and invalid lengths.
- `LeanWs.Close`: registered close codes, `CloseInfo`, close-payload
  encoding and validation.
- `LeanWs.Message`: text and binary messages, `Limits` (1 MiB frames, 4 MiB
  messages, 1024 fragments), fragment reassembly with UTF-8 validation, and
  outbound fragmentation.
- `LeanWs.Sha1` and `LeanWs.Base64` with RFC test vectors, used for the
  `Sec-WebSocket-Accept` key.
- `LeanWs.Handshake`: server-side validation and subprotocol negotiation
  with a caller-supplied origin predicate, client request construction and
  response verification, `426`/`400`/`403`/`405` rejection responses, and
  wire parsers built on `Std.Http`'s H1 request-line and header parsers.
- `LeanWs.Session`: reader and writer tasks per connection over any
  `Transport`; bounded outbound queue with `SendError.queueFull` after
  `sendTimeoutMs`; bounded inbound queue; ping/pong; idle timeout with pings
  at half the interval; close handshake with a 2 s timeout; protocol failures
  reported with close codes `1002`, `1007` and `1009`.
- `LeanWs.Tcp`: a socket `Transport` whose receive selector never blocks a
  worker thread, for thousands of concurrent sessions.
- `LeanWs.Server`: accept loop with `maxSockets`, handshake time and byte
  budgets, one task per session, `drain` (closes with `1001`) and `shutdown`,
  plus `Server.upgrade` for custom listeners.
- `LeanWs.Client`: `ws://` connect with DNS resolution, connect and handshake
  timeouts, subprotocol negotiation and extra headers.
- `leanws_echo`, an echo server for manual checks and the Autobahn testsuite.
- Test suite: frame codec property tests, SHA-1/base64/handshake vectors,
  session tests over `Std.Http.Internal.Mock`, and loopback integration with
  1,000 concurrent sockets and 10,000 messages followed by a drain.

### Not included

- Extensions, including permessage-deflate (Autobahn cases 12–13).
- `wss://`; TLS is left to an ingress.
- A recorded Autobahn report; see the README for how to run it.

[Unreleased]: https://github.com/theoriclabs/leanws/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/theoriclabs/leanws/releases/tag/v0.1.0
