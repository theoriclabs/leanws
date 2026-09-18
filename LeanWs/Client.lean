import Std.Async
import Std.Async.TCP
import Std.Async.DNS
import LeanWs.Handshake
import LeanWs.Session
import LeanWs.Tcp

namespace LeanWs

open Std Std.Async Std.Async.TCP Std.Http

/-!
A `ws://` client: resolve, connect, handshake, and wrap the socket in a
`Session`. TLS is left to an ingress in front of the server; `wss://` is not
supported here.
-/

/-- Client configuration. Times are milliseconds. -/
structure ClientOptions where
  /-- Subprotocols to offer, in order of preference. -/
  subprotocols : List String := []
  /-- Extra request headers, for example `Origin` or `Authorization`. -/
  headers : Headers := .empty
  connectTimeoutMs : Nat := 10000
  handshakeTimeoutMs : Nat := 5000
  limits : Limits := {}
  session : SessionOptions := {}
  deriving Inhabited

/-- Why `Client.connect` failed. -/
inductive ConnectError where
  | unsupportedScheme (scheme : String)
  | missingHost
  | resolve (host : String) (message : String)
  | connect (message : String)
  /-- Connecting or the handshake exceeded its timeout. -/
  | timeout
  /-- The server's response was not a valid HTTP response head. -/
  | malformedResponse (message : String)
  | rejected (reason : Handshake.ClientReject)
  | io (message : String)
  deriving Repr

instance : ToString ConnectError where
  toString
    | .unsupportedScheme scheme => s!"unsupported scheme {scheme} (only ws is supported)"
    | .missingHost => "URI has no host"
    | .resolve host message => s!"cannot resolve {host}: {message}"
    | .connect message => s!"cannot connect: {message}"
    | .timeout => "timed out"
    | .malformedResponse message => s!"malformed handshake response: {message}"
    | .rejected reason => s!"handshake rejected: {reason}"
    | .io message => s!"I/O error: {message}"

/-- A connected client with the negotiated details. -/
structure Connection where
  session : Session
  subprotocol : Option String
  /-- The server's `101` response. -/
  response : Response.Head

namespace Client

private def now : BaseIO Nat := IO.monoMsNow

private def socketAddress (uri : URI) : Async (Except ConnectError Std.Net.SocketAddress) := do
  let some auth := uri.authority | return .error .missingHost
  let port : UInt16 := match auth.port with
    | .value p => p
    | _ => 80
  match auth.host with
  | .ipv4 addr => return .ok (.v4 { addr, port })
  | .ipv6 addr => return .ok (.v6 { addr, port })
  | .name name =>
      let addrs : Array Std.Net.IPAddr ← try DNS.getAddrInfo name (toString port)
        catch e => return .error (.resolve name (toString e))
      match addrs[0]? with
      | some (Std.Net.IPAddr.v4 addr) => return .ok (.v4 { addr, port })
      | some (Std.Net.IPAddr.v6 addr) => return .ok (.v6 { addr, port })
      | none => return .error (.resolve name "no addresses")

private inductive ReadEvent where
  | bytes (chunk : Option ByteArray)
  | timeout

/-- Read the handshake response within the deadline. -/
private def readResponse (t : Tcp) (deadline : Nat) (maxBytes : Nat) :
    Async (Except ConnectError (Response.Head × ByteArray)) := do
  let mut buf : ByteArray := .empty
  repeat
    match Handshake.parseResponse buf with
    | .error e => return .error (.malformedResponse e)
    | .ok (some (head, used)) => return .ok (head, buf.extract used buf.size)
    | .ok none =>
        if buf.size ≥ maxBytes then return .error (.malformedResponse "response head too large")
        let n ← now
        let remaining := if deadline > n then deadline - n else 0
        let event ← Selectable.one #[
          .case (Transport.recvSelector t (maxBytes - buf.size).toUInt64) (fun chunk => pure (ReadEvent.bytes chunk)),
          .case (← Selector.sleep (Time.Millisecond.Offset.ofNat remaining)) (fun _ => pure ReadEvent.timeout)]
        match event with
        | .bytes (some chunk) => buf := if buf.isEmpty then chunk else buf ++ chunk
        | .bytes none => return .error (.io "connection closed during handshake")
        | .timeout => return .error .timeout
  return .error .timeout

/-- Connect to a `ws://` URI and complete the handshake, returning the
    session together with the negotiated subprotocol and response head. -/
def connectDetailed (uri : URI) (opts : ClientOptions := {}) : Async (Except ConnectError Connection) := do
  unless uri.scheme.val == "ws" do return .error (.unsupportedScheme uri.scheme.val)
  let addr ← match ← socketAddress uri with
    | .ok addr => pure addr
    | .error e => return .error e
  let socket ← Socket.Client.mk
  let connected ← try
      Async.race (do socket.connect addr; pure (Except.ok ()))
        (do sleep (Time.Millisecond.Offset.ofNat opts.connectTimeoutMs); pure (Except.error ConnectError.timeout))
    catch e => pure (.error (.connect (toString e)))
  if let .error e := connected then return .error e
  try socket.noDelay catch _ => pure ()
  let t ← Tcp.new socket
  let key ← Handshake.randomKey
  let (request, expected) := Handshake.client uri opts.subprotocols key opts.headers
  try
    Transport.sendAll t #[Handshake.encodeRequest request]
  catch e =>
    Transport.close t
    return .error (.io (toString e))
  let deadline := (← now) + opts.handshakeTimeoutMs
  match ← readResponse t deadline 65536 with
  | .error e => Transport.close t; return .error e
  | .ok (response, leftover) =>
      match Handshake.verify response expected opts.subprotocols with
      | .error reject => Transport.close t; return .error (.rejected reject)
      | .ok subprotocol =>
          let session ← Session.start t .client opts.limits opts.session leftover
          return .ok { session, subprotocol, response }

/-- Connect to a `ws://` URI and complete the handshake. -/
def connect (uri : URI) (opts : ClientOptions := {}) : Async (Except ConnectError Session) := do
  return (← connectDetailed uri opts).map (·.session)

end Client

end LeanWs
