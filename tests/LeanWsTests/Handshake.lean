import LeanWs
import LeanWsTests.Harness

namespace LeanWsTests.Handshake

open LeanWs Std.Async Std.Http

private def rfcRequest : String :=
  "GET /chat HTTP/1.1\r\nHost: server.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" ++
  "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nOrigin: http://example.com\r\n" ++
  "Sec-WebSocket-Protocol: chat, superchat\r\nSec-WebSocket-Version: 13\r\n\r\n"

private def parseHead (raw : String) : Async (Request.Head × Nat) := do
  match LeanWs.Handshake.parseRequest raw.toUTF8 with
  | .ok (some r) => pure r
  | .ok none => throw (failure "request head incomplete")
  | .error e => throw (failure s!"request head: {e}")

private def accepted (head : Request.Head) (opts : LeanWs.Handshake.ServerOptions := {}) :
    Async LeanWs.Handshake.Accept := do
  match LeanWs.Handshake.server head opts with
  | .ok a => pure a
  | .error e => throw (failure s!"unexpected reject {e}")

private def rejected (head : Request.Head) (opts : LeanWs.Handshake.ServerOptions := {}) :
    Async LeanWs.Handshake.Reject := do
  match LeanWs.Handshake.server head opts with
  | .ok _ => throw (failure "unexpected accept")
  | .error e => pure e

/-- Replace every value of `name` (headers are a multimap; `insert` appends). -/
private def withHeader (head : Request.Head) (name value : String) : Request.Head :=
  let erased := head.headers.erase (Header.Name.ofString! name)
  { head with headers := (erased.insert? name value).getD erased }

private def withoutHeader (head : Request.Head) (name : String) : Request.Head :=
  { head with headers := head.headers.erase (Header.Name.ofString! name) }

/-- The RFC 6455 §1.3 exchange. -/
def serverAccept : Async Unit := do
  let (head, used) ← parseHead (rfcRequest ++ "trailing")
  checkEq used rfcRequest.utf8ByteSize "bytes consumed stop at the blank line"
  checkEq (toString head.uri) "/chat" "request target"
  let accept ← accepted head { subprotocols := ["superchat", "chat"] }
  checkEq accept.key "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" "accept key"
  checkEq accept.subprotocol (some "superchat") "server preference wins"
  checkEq accept.origin (some "http://example.com") "origin captured"
  let response := accept.toResponse
  checkEq response.status.toCode 101 "101"
  checkEq ((response.headers.get? LeanWs.Handshake.Header.secWebSocketAccept).map (·.value))
    (some "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") "accept header"
  check (LeanWs.Handshake.Header.hasToken response.headers Header.Name.connection "upgrade") "Connection: Upgrade"
  check (LeanWs.Handshake.Header.hasToken response.headers LeanWs.Handshake.Header.upgrade "websocket") "Upgrade: websocket"
  -- the serialized response parses back and verifies on the client side
  match LeanWs.Handshake.parseResponse (LeanWs.Handshake.encodeResponse response) with
  | .ok (some (parsedResponse, _)) =>
      checkEq (LeanWs.Handshake.verify parsedResponse "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" ["chat", "superchat"])
        (.ok (some "superchat")) "client verifies the response"
  | _ => throw (failure "response head does not parse")
  -- no server subprotocols → none negotiated, still accepted
  let plain ← accepted head
  checkEq plain.subprotocol none "no subprotocol without server support"
  checkEq (plain.toResponse.headers.contains LeanWs.Handshake.Header.secWebSocketProtocol) false "no protocol header"

def serverReject : Async Unit := do
  let (head, _) ← parseHead rfcRequest
  checkEq (← rejected { head with method := .post }) .methodNotGet "POST"
  checkEq (← rejected { head with version := .v10 }) .versionNotHttp11 "HTTP/1.0"
  checkEq (← rejected (withoutHeader head "upgrade")) .notAnUpgrade "missing Upgrade"
  checkEq (← rejected (withHeader head "Connection" "keep-alive")) .notAnUpgrade "Connection without upgrade"
  checkEq (← rejected (withHeader head "Sec-WebSocket-Version" "8")) (.unsupportedVersion (some "8")) "version 8"
  checkEq (← rejected (withoutHeader head "sec-websocket-version")) (.unsupportedVersion none) "missing version"
  checkEq (← rejected (withoutHeader head "sec-websocket-key")) .missingKey "missing key"
  checkEq (← rejected (withHeader head "Sec-WebSocket-Key" "not-base64!")) .malformedKey "bad key"
  checkEq (← rejected (withHeader head "Sec-WebSocket-Key" "Zm9v")) .malformedKey "short key"
  checkEq (← rejected head { checkOrigin := (· == some "https://allowed.example") })
    (.originRejected (some "http://example.com")) "origin policy"
  let _ ← accepted head { checkOrigin := (· == some "http://example.com") }
  -- mixed-case tokens and lists are accepted
  let _ ← accepted (withHeader (withHeader head "Upgrade" "WebSocket") "Connection" "keep-alive, Upgrade")
  -- rejection responses
  let (res426, _) := LeanWs.Handshake.Reject.notAnUpgrade.toResponse
  checkEq res426.status.toCode 426 "426 for non-upgrade"
  checkEq ((res426.headers.get? LeanWs.Handshake.Header.secWebSocketVersion).map (·.value)) (some "13") "advertises version 13"
  checkEq (LeanWs.Handshake.Reject.malformedKey.toResponse.1.status.toCode) 400 "400 for bad key"
  checkEq ((LeanWs.Handshake.Reject.originRejected none).toResponse.1.status.toCode) 403 "403 for origin"
  checkEq (LeanWs.Handshake.Reject.unauthorized.toResponse.1.status.toCode) 401 "401 for unauthorized"
  checkEq ((LeanWs.Handshake.Reject.unsupportedVersion (some "8")).toResponse.1.status.toCode) 426 "426 for version"

def clientRequest : Async Unit := do
  let uri := URI.parse! "ws://example.com:8080/socket?room=1"
  let (req, expected) := LeanWs.Handshake.client uri ["a", "b"] "dGhlIHNhbXBsZSBub25jZQ=="
  checkEq expected "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" "expected accept"
  checkEq (toString req.uri) "/socket?room=1" "origin-form target"
  checkEq ((req.headers.get? Header.Name.host).map (·.value)) (some "example.com:8080") "Host with port"
  checkEq ((req.headers.get? LeanWs.Handshake.Header.secWebSocketProtocol).map (·.value)) (some "a, b") "offered protocols"
  -- the request parses back and is accepted by the server side
  match LeanWs.Handshake.parseRequest (LeanWs.Handshake.encodeRequest req) with
  | .ok (some (head, _)) =>
      let a ← accepted head { subprotocols := ["b"] }
      checkEq a.key expected "server computes the same accept"
      checkEq a.subprotocol (some "b") "negotiated b"
  | _ => throw (failure "client request does not parse")
  -- default port and empty path
  let (bare, _) := LeanWs.Handshake.client (URI.parse! "ws://example.com") [] "dGhlIHNhbXBsZSBub25jZQ=="
  checkEq (toString bare.uri) "/" "empty path becomes /"
  checkEq ((bare.headers.get? Header.Name.host).map (·.value)) (some "example.com") "Host without port"
  -- verification failures
  let okHeaders := Headers.empty.insert! "Upgrade" "websocket" |>.insert! "Connection" "Upgrade"
    |>.insert! "Sec-WebSocket-Accept" "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
  let ok : Response.Head := { status := .switchingProtocols, headers := okHeaders }
  checkEq (LeanWs.Handshake.verify ok expected) (.ok none) "verify ok"
  checkEq (LeanWs.Handshake.verify { ok with status := .ok } expected) (.error (.status 200)) "200 rejected"
  checkEq (LeanWs.Handshake.verify { ok with headers := ok.headers.erase LeanWs.Handshake.Header.upgrade } expected)
    (.error .notAnUpgrade) "missing Upgrade"
  checkEq (LeanWs.Handshake.verify ok "wrong") (.error .acceptMismatch) "accept mismatch"
  checkEq (LeanWs.Handshake.verify { ok with headers := ok.headers.insert! "Sec-WebSocket-Protocol" "zzz" } expected ["a"])
    (.error (.unexpectedSubprotocol "zzz")) "unoffered subprotocol"

def wireParsing : Async Unit := do
  match LeanWs.Handshake.parseRequest "GET / HTTP/1.1\r\nHost: x\r\n".toUTF8 with
  | .ok none => pure ()
  | _ => throw (failure "incomplete head should need more bytes")
  check (LeanWs.Handshake.parseRequest "GARBAGE\r\n\r\n".toUTF8 |>.toOption |>.isNone) "garbage fails"
  check (LeanWs.Handshake.parseRequest "GET / HTTP/2.0\r\n\r\n".toUTF8 |>.toOption |>.isNone) "HTTP/2.0 fails"
  checkEq (LeanWs.Handshake.headEnd? "ab\r\n\r\ncd".toUTF8) (some 6) "head end"
  checkEq (LeanWs.Handshake.headEnd? "ab\r\n\rcd".toUTF8) none "no head end"

def run (runner : Runner) : IO Unit := do
  suite "Handshake"
  test runner "server accept (RFC 6455 §1.3)" serverAccept
  test runner "server rejections and responses" serverReject
  test runner "client request and response verification" clientRequest
  test runner "wire parsing" wireParsing

end LeanWsTests.Handshake
