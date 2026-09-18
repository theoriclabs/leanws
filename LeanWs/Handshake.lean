import Std.Http
import LeanWs.Sha1
import LeanWs.Base64

namespace LeanWs

open Std.Http

/-!
The opening handshake (RFC 6455 §4) as pure functions over `Std.Http` request
and response heads, plus the byte-level head parsers `Server` and `Client`
use before a connection becomes a `Session`.
-/

namespace Handshake

/-- The fixed GUID appended to the client key (RFC 6455 §1.3). -/
def guid : String := "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

/-- `Sec-WebSocket-Accept` for a client's `Sec-WebSocket-Key`:
    `base64(sha1(key ++ guid))`. -/
def acceptKey (clientKey : String) : String :=
  Base64.encode (Sha1.hash (clientKey ++ guid).toUTF8)

/-- A fresh 16-byte nonce, base64-encoded, for `Sec-WebSocket-Key`. -/
def randomKey : IO String := do
  return Base64.encode (← IO.getRandomBytes 16)

namespace Header

def upgrade : Std.Http.Header.Name := .mk "upgrade"
def secWebSocketKey : Std.Http.Header.Name := .mk "sec-websocket-key"
def secWebSocketAccept : Std.Http.Header.Name := .mk "sec-websocket-accept"
def secWebSocketVersion : Std.Http.Header.Name := .mk "sec-websocket-version"
def secWebSocketProtocol : Std.Http.Header.Name := .mk "sec-websocket-protocol"
def origin : Std.Http.Header.Name := .mk "origin"

/-- Comma-separated tokens across every header line with this name, trimmed. -/
def tokens (headers : Headers) (name : Std.Http.Header.Name) : List String :=
  (headers.getAll? name).getD #[] |>.toList.flatMap fun value =>
    (value.value.splitOn ",").filterMap fun s =>
      let t := s.trimAscii.toString
      if t.isEmpty then none else some t

/-- Whether some token of the header equals `token`, ignoring case. -/
def hasToken (headers : Headers) (name : Std.Http.Header.Name) (token : String) : Bool :=
  (tokens headers name).any (·.toLower == token.toLower)

end Header

/-- Server-side handshake policy. -/
structure ServerOptions where
  /-- Subprotocols the server speaks, in order of preference. The first one
      the client also offers is selected; with an empty list none is. -/
  subprotocols : List String := []
  /-- Origin policy over the `Origin` header (`none` when absent). The default
      accepts everything; browsers always send it, so servers exposed to
      browsers should check it. -/
  checkOrigin : Option String → Bool := fun _ => true

/-- Why a request is not accepted as a WebSocket upgrade. -/
inductive Reject where
  | methodNotGet
  | versionNotHttp11
  /-- No `Upgrade: websocket` or no `Connection: upgrade`. -/
  | notAnUpgrade
  | unsupportedVersion (got : Option String)
  | missingKey
  /-- The key is not base64 for exactly 16 bytes. -/
  | malformedKey
  | originRejected (origin : Option String)
  deriving Repr, BEq

instance : ToString Reject where
  toString
    | .methodNotGet => "method is not GET"
    | .versionNotHttp11 => "HTTP version is not 1.1"
    | .notAnUpgrade => "not a websocket upgrade request"
    | .unsupportedVersion got => s!"unsupported Sec-WebSocket-Version {got.getD "(missing)"}"
    | .missingKey => "missing Sec-WebSocket-Key"
    | .malformedKey => "malformed Sec-WebSocket-Key"
    | .originRejected origin => s!"origin rejected: {origin.getD "(missing)"}"

/-- A completed server-side handshake decision. -/
structure Accept where
  /-- The `Sec-WebSocket-Accept` value. -/
  key : String
  /-- The negotiated subprotocol, if any. -/
  subprotocol : Option String := none
  /-- The client's `Origin`, if any. -/
  origin : Option String := none
  /-- The upgrade request, for routing on path, query or headers. -/
  request : Request.Head
  deriving Inhabited

private def headerValue (s : String) : Std.Http.Header.Value :=
  (Std.Http.Header.Value.ofString? s).getD ⟨"", by decide⟩

/-- The HTTP status a rejection is answered with. -/
def Reject.status : Reject → Status
  | .notAnUpgrade | .unsupportedVersion _ => .upgradeRequired
  | .methodNotGet => .methodNotAllowed
  | .originRejected _ => .forbidden
  | .versionNotHttp11 | .missingKey | .malformedKey => .badRequest

/-- The response for a rejected request: `426` with `Upgrade` and
    `Sec-WebSocket-Version` for non-upgrade requests, `400`, `403` or `405`
    otherwise, always with `Connection: close` and a short text body. -/
def Reject.toResponse (r : Reject) : Response.Head × ByteArray :=
  let body := (toString r).toUTF8
  let headers := Headers.empty
    |>.insert Std.Http.Header.Name.connection ⟨"close", by decide⟩
    |>.insert Std.Http.Header.Name.contentType ⟨"text/plain; charset=utf-8", by decide⟩
    |>.insert Std.Http.Header.Name.contentLength (headerValue (toString body.size))
  let headers := match r with
    | .notAnUpgrade | .unsupportedVersion _ =>
        headers.insert Header.upgrade ⟨"websocket", by decide⟩
          |>.insert Header.secWebSocketVersion ⟨"13", by decide⟩
    | _ => headers
  ({ status := r.status, version := .v11, headers }, body)

/-- The `101 Switching Protocols` response for an accepted request. -/
def Accept.toResponse (a : Accept) : Response.Head :=
  let headers := Headers.empty
    |>.insert Header.upgrade ⟨"websocket", by decide⟩
    |>.insert Std.Http.Header.Name.connection ⟨"Upgrade", by decide⟩
    |>.insert Header.secWebSocketAccept (headerValue a.key)
  let headers := match a.subprotocol with
    | some p => headers.insert Header.secWebSocketProtocol (headerValue p)
    | none => headers
  { status := .switchingProtocols, version := .v11, headers }

/-- Validate a client's upgrade request (RFC 6455 §4.2.1) and negotiate one
    subprotocol. Extensions are ignored, so none is ever negotiated. -/
def server (req : Request.Head) (opts : ServerOptions := {}) : Except Reject Accept := do
  unless req.method == .get do throw .methodNotGet
  unless req.version == .v11 do throw .versionNotHttp11
  let headers := req.headers
  unless Header.hasToken headers Header.upgrade "websocket" &&
      Header.hasToken headers Std.Http.Header.Name.connection "upgrade" do
    throw .notAnUpgrade
  unless Header.hasToken headers Header.secWebSocketVersion "13" do
    throw (.unsupportedVersion ((headers.get? Header.secWebSocketVersion).map (·.value)))
  let some key := headers.get? Header.secWebSocketKey | throw .missingKey
  match Base64.decode key.value with
  | some nonce => unless nonce.size == 16 do throw .malformedKey
  | none => throw .malformedKey
  let origin := (headers.get? Header.origin).map (·.value)
  unless opts.checkOrigin origin do throw (.originRejected origin)
  let offered := Header.tokens headers Header.secWebSocketProtocol
  let subprotocol := opts.subprotocols.find? (offered.contains ·)
  return { key := acceptKey key.value, subprotocol, origin, request := req }

/-- Build a client upgrade request for `uri` (RFC 6455 §4.1) with the given
    base64 `key`, returning it with the `Sec-WebSocket-Accept` value the
    server must answer. `extraHeaders` (for example `Origin` or
    `Authorization`) are added verbatim. Only `ws://` is meaningful here;
    the scheme itself is not checked. -/
def client (uri : URI) (subprotocols : List String := []) (key : String)
    (extraHeaders : Headers := .empty) : Request.Head × String :=
  let host := match uri.authority with
    | some auth =>
        match auth.port with
        | .value p => s!"{auth.host}:{p}"
        | _ => toString auth.host
    | none => ""
  let path : URI.Path := if uri.path.segments.isEmpty then { segments := #[], absolute := true } else uri.path
  let target : RequestTarget := .originForm path (if uri.query.isEmpty then none else some uri.query)
  let headers := extraHeaders
    |>.insert Std.Http.Header.Name.host (headerValue host)
    |>.insert Header.upgrade ⟨"websocket", by decide⟩
    |>.insert Std.Http.Header.Name.connection ⟨"Upgrade", by decide⟩
    |>.insert Header.secWebSocketKey (headerValue key)
    |>.insert Header.secWebSocketVersion ⟨"13", by decide⟩
  let headers := if subprotocols.isEmpty then headers
    else headers.insert Header.secWebSocketProtocol (headerValue (", ".intercalate subprotocols))
  ({ method := .get, version := .v11, uri := target, headers }, acceptKey key)

/-- Why a server response does not complete the handshake. -/
inductive ClientReject where
  | status (code : UInt16)
  | notAnUpgrade
  | acceptMismatch
  /-- The server selected a subprotocol the client did not offer. -/
  | unexpectedSubprotocol (name : String)
  deriving Repr, BEq

instance : ToString ClientReject where
  toString
    | .status code => s!"server answered {code}"
    | .notAnUpgrade => "response is not a websocket upgrade"
    | .acceptMismatch => "Sec-WebSocket-Accept does not match"
    | .unexpectedSubprotocol name => s!"server selected unoffered subprotocol {name}"

/-- Validate the server's response (RFC 6455 §4.1 step 4). Returns the
    negotiated subprotocol. -/
def verify (res : Response.Head) (expectedAccept : String) (subprotocols : List String := []) :
    Except ClientReject (Option String) := do
  unless res.status == .switchingProtocols do throw (.status res.status.toCode)
  let headers := res.headers
  unless Header.hasToken headers Header.upgrade "websocket" &&
      Header.hasToken headers Std.Http.Header.Name.connection "upgrade" do
    throw .notAnUpgrade
  unless (headers.get? Header.secWebSocketAccept).map (·.value) == some expectedAccept do
    throw .acceptMismatch
  match Header.tokens headers Header.secWebSocketProtocol with
  | [] => return none
  | [p] => if subprotocols.contains p then return some p else throw (.unexpectedSubprotocol p)
  | p :: _ => throw (.unexpectedSubprotocol p)

/-! ### Wire format -/

private def encode [Std.Http.Internal.Encode .v11 α] (a : α) : ByteArray :=
  (Std.Http.Internal.Encode.encode (v := .v11) Std.Http.Internal.ChunkedBuffer.empty a).toByteArray

/-- Serialize a request head as HTTP/1.1 bytes. -/
def encodeRequest (head : Request.Head) : ByteArray := encode head

/-- Serialize a response head as HTTP/1.1 bytes. -/
def encodeResponse (head : Response.Head) : ByteArray := encode head

/-- Index just past the first `CRLF CRLF`, if present. -/
def headEnd? (bytes : ByteArray) : Option Nat := Id.run do
  let n := bytes.size
  let mut i := 0
  while i + 3 < n do
    if bytes.get! i == 13 && bytes.get! (i + 1) == 10 && bytes.get! (i + 2) == 13 && bytes.get! (i + 3) == 10 then
      return some (i + 4)
    i := i + 1
  return none

open Std.Internal.Parsec in
open Std.Internal.Parsec.ByteArray in
/-- Header lines after the start line, into `Headers`. -/
private def parseHeaders (limits : Protocol.H1.Config) : Parser Headers := do
  let mut headers := Headers.empty
  repeat
    match ← Protocol.H1.parseSingleHeader limits with
    | none => break
    | some (name, value) =>
        match headers.insert? name value with
        | some updated => headers := updated
        | none => fail s!"invalid header {name}"
  return headers

/-- Incrementally parse an upgrade request from a byte buffer with the
    `Std.Http` H1 parsers. `.ok none` means the head is incomplete; on success
    the second component is the number of bytes consumed, so any bytes after
    the head can be handed to the session as its first frames. -/
def parseRequest (bytes : ByteArray) (limits : Protocol.H1.Config := {}) :
    Except String (Option (Request.Head × Nat)) := do
  let some stop := headEnd? bytes | return none
  let parser : Std.Internal.Parsec.ByteArray.Parser Request.Head := do
    let head ← Protocol.H1.parseRequestLine limits
    let headers ← parseHeaders limits
    return { head with headers }
  match parser.run (bytes.extract 0 stop) with
  | .ok head => return some (head, stop)
  | .error e => throw e

/-- Incrementally parse a handshake response; see `parseRequest`. -/
def parseResponse (bytes : ByteArray) (limits : Protocol.H1.Config := {}) :
    Except String (Option (Response.Head × Nat)) := do
  let some stop := headEnd? bytes | return none
  let parser : Std.Internal.Parsec.ByteArray.Parser Response.Head := do
    let head ← Protocol.H1.parseStatusLine limits
    let headers ← parseHeaders limits
    return { head with headers }
  match parser.run (bytes.extract 0 stop) with
  | .ok head => return some (head, stop)
  | .error e => throw e

end Handshake

end LeanWs
