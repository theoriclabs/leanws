# Changelog

User-visible changes are recorded here. Versions use semantic versioning and
are published as `vX.Y.Z` Git tags and GitHub releases.

## [Unreleased]

## [0.1.0] - 2026-09-18

### Added

- Initial release: RFC 6455 framing, handshake, message reassembly, sessions
  over `Std.Http.Transport`, TCP server and `ws://` client.
- SHA-1 and base64 helpers with the RFC 6455 §1.3 handshake vector.
- `leanws_echo` binary and `lake test` suites (frame, crypto, handshake,
  message, session, loopback).
- Documented Autobahn procedure; compression cases 12–13 excluded.
