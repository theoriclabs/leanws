import Std.Async
import Std.Async.TCP
import Std.Sync
import Std.Data.HashMap
import LeanWs.Handshake
import LeanWs.Session
import LeanWs.Tcp

namespace LeanWs

open Std Std.Async Std.Async.TCP Std.Http

/-!
A WebSocket listener: accepts TCP connections, runs the opening handshake
under a byte and time budget, then hands each connection to `onSession` as
a `Session` in its own task. Modelled on `Std.Http.Server.serve`.
-/

/-- The peer's socket address, passed to `onUpgrade`. -/
abbrev RemoteAddr := Std.Net.SocketAddress

/-- Listener configuration. Times are milliseconds. -/
structure ServerConfig where
  /-- Connections (in handshake or as sessions) accepted at once; the accept
      loop waits when the limit is reached. `0` means unlimited. -/
  maxSockets : Nat := 4096
  /-- Budget for the whole upgrade request to arrive. -/
  handshakeTimeoutMs : Nat := 5000
  /-- Largest upgrade request accepted; larger ones are answered `400`. -/
  handshakeMaxBytes : Nat := 8192
  /-- See `SessionOptions.idleTimeoutMs`. -/
  idleTimeoutMs : Nat := 60000
  limits : Limits := {}
  /-- See `SessionOptions.sendQueue`. -/
  sendQueue : Nat := 64
  /-- See `SessionOptions.recvQueue`. -/
  recvQueue : Nat := 64
  /-- See `SessionOptions.closeTimeoutMs`. -/
  closeTimeoutMs : Nat := 2000
  backlog : UInt32 := 1024
  deriving Repr, Inhabited

/-- `SessionOptions` derived from a server configuration. -/
def ServerConfig.sessionOptions (c : ServerConfig) : SessionOptions :=
  { sendQueue := c.sendQueue, recvQueue := c.recvQueue, idleTimeoutMs := c.idleTimeoutMs,
    closeTimeoutMs := c.closeTimeoutMs }

/-- A running listener. Obtain one from `Server.serve`. -/
structure Server where private mk ::
  /-- The bound address; reflects the port the OS chose when `serve` got port `0`. -/
  localAddr : Std.Net.SocketAddress
  config : ServerConfig
  private stop : CancellationToken
  private sessions : IO.Ref (Std.HashMap Nat Session)
  private nextId : IO.Ref Nat
  /-- The accept loop plus every connection still in flight. -/
  private active : IO.Ref Nat
  private finished : IO.Promise Unit

namespace Server

private def now : BaseIO Nat := IO.monoMsNow

private def enter (s : Server) : BaseIO Unit :=
  s.active.modify (· + 1)

/-- Leave a tracked task; the last one out after `stop` resolves `finished`. -/
private def leave (s : Server) : BaseIO Unit := do
  let remaining ← s.active.modifyGet fun n => (n - 1, n - 1)
  if remaining == 0 && (← s.stop.isCancelled) then
    s.finished.resolve ()

private def register (s : Server) (session : Session) : BaseIO Nat := do
  let id ← s.nextId.modifyGet fun n => (n, n + 1)
  s.sessions.modify (·.insert id session)
  return id

private def unregister (s : Server) (id : Nat) : BaseIO Unit :=
  s.sessions.modify (·.erase id)

private inductive HandshakeEvent where
  | bytes (chunk : Option ByteArray)
  | timeout
  | stop

/-- Answer a request that will not become a session, then shut down the
    write side and drain what the client is still sending (bounded by
    `lingerMs`) so the close does not turn into a reset before the client has
    read the response. -/
private def respond (t : Tcp) (head : Response.Head) (body : ByteArray := .empty) (lingerMs : Nat := 500) :
    Async Unit := do
  try
    Transport.sendAll t #[Handshake.encodeResponse head, body]
    Transport.close t
    let deadline := (← now) + lingerMs
    repeat
      let n ← now
      if n ≥ deadline then break
      let more ← Selectable.one #[
        .case (Transport.recvSelector t 4096) (fun chunk => pure chunk.isSome),
        .case (← Selector.sleep (Time.Millisecond.Offset.ofNat (deadline - n))) (fun _ => pure false)]
      unless more do break
  catch _ => pure ()

private def badRequest (message : String) : Response.Head × ByteArray :=
  let body := message.toUTF8
  let headers := Headers.empty
    |>.insert Header.Name.connection ⟨"close", by decide⟩
    |>.insert Header.Name.contentType ⟨"text/plain; charset=utf-8", by decide⟩
    |>.insert Header.Name.contentLength ((Header.Value.ofString? (toString body.size)).getD ⟨"0", by decide⟩)
  ({ status := .badRequest, version := .v11, headers }, body)

/-- Read and parse the upgrade request within `handshakeTimeoutMs` and
    `handshakeMaxBytes`. Returns the head and any bytes that followed it, or
    `none` after answering the client or giving up. -/
private def readHandshake (s : Server) (t : Tcp) : Async (Option (Request.Head × ByteArray)) := do
  let deadline := (← now) + s.config.handshakeTimeoutMs
  let mut buf : ByteArray := .empty
  repeat
    match Handshake.parseRequest buf with
    | .error e =>
        let (head, body) := badRequest s!"malformed request: {e}"
        respond t head body
        return none
    | .ok (some (head, used)) =>
        return some (head, buf.extract used buf.size)
    | .ok none =>
        if buf.size ≥ s.config.handshakeMaxBytes then
          let (head, body) := badRequest "request head too large"
          respond t head body
          return none
        let n ← now
        let remaining := if deadline > n then deadline - n else 0
        let event ← Selectable.one #[
          .case (Transport.recvSelector t (s.config.handshakeMaxBytes - buf.size).toUInt64)
            (fun chunk => pure (HandshakeEvent.bytes chunk)),
          .case (← Selector.sleep (Time.Millisecond.Offset.ofNat remaining)) (fun _ => pure HandshakeEvent.timeout),
          .case s.stop.selector (fun _ => pure HandshakeEvent.stop)]
        match event with
        | .bytes (some chunk) => buf := if buf.isEmpty then chunk else buf ++ chunk
        | .bytes none => Transport.close t; return none
        | .timeout | .stop => Transport.close t; return none
  return none

/-- Handshake one accepted socket, then run `onSession` for the resulting
    session and close it with `1000` when the handler returns. -/
private def handleConnection (s : Server) (socket : Socket.Client)
    (onUpgrade : Request.Head → RemoteAddr → Async (Except Handshake.Reject Handshake.Accept))
    (onSession : Session → Handshake.Accept → Async Unit) : Async Unit := do
  let t ← Tcp.new socket
  let remote ← try socket.getPeerName catch _ => pure s.localAddr
  let some (head, leftover) ← readHandshake s t | return
  match ← (try onUpgrade head remote catch e => pure (.error (.originRejected (some (toString e))))) with
  | .error reject =>
      let (res, body) := reject.toResponse
      respond t res body
  | .ok accept =>
      try
        Transport.sendAll t #[Handshake.encodeResponse accept.toResponse]
      catch _ =>
        Transport.close t
        return
      let session ← Session.start t .server s.config.limits s.config.sessionOptions leftover
      let id ← register s session
      try
        try onSession session accept catch _ => pure ()
        if ← session.isOpen then session.close .normal
        discard session.waitClosed
      finally
        unregister s id

/-- Accept until `stop` is cancelled. -/
private partial def acceptLoop (s : Server) (listener : Socket.Server) (permits : Option Semaphore)
    (onUpgrade : Request.Head → RemoteAddr → Async (Except Handshake.Reject Handshake.Accept))
    (onSession : Session → Handshake.Accept → Async Unit) : Async Unit := do
  repeat
    let mut acquired := false
    if let some sem := permits then
      -- Wait for a permit unless shutdown arrives first.
      let permit ← sem.acquire
      acquired ← Async.race (do discard (await permit); pure true)
        (do discard (await (← s.stop.wait)); pure false)
      unless acquired do break
    let accepted ← Selectable.one #[
      .case listener.acceptSelector (fun c => pure (some c)),
      .case s.stop.selector (fun _ => pure none)]
    match accepted with
    | none =>
        if acquired then if let some sem := permits then sem.release
        break
    | some client =>
        enter s
        background do
          try handleConnection s client onUpgrade onSession catch _ => pure ()
          if acquired then if let some sem := permits then sem.release
          leave s

/-- Bind `addr` and start accepting. `onUpgrade` decides each request (usually
    `Handshake.server req opts`, possibly after authentication); `onSession`
    runs in its own task per connection and owns the session until it
    returns. Sessions run with `config.limits` and `config.sessionOptions`. -/
def serve (addr : Std.Net.SocketAddress) (config : ServerConfig := {})
    (onUpgrade : Request.Head → RemoteAddr → Async (Except Handshake.Reject Handshake.Accept))
    (onSession : Session → Handshake.Accept → Async Unit) : Async Server := do
  let listener ← Socket.Server.mk
  listener.bind addr
  listener.listen config.backlog
  listener.noDelay
  let localAddr ← listener.getSockName
  let permits ← if config.maxSockets == 0 then pure none else some <$> Semaphore.new config.maxSockets
  let server : Server := {
    localAddr, config
    stop := ← CancellationToken.new
    sessions := ← IO.mkRef {}
    nextId := ← IO.mkRef 0
    active := ← IO.mkRef 0
    finished := ← IO.Promise.new }
  enter server
  background do
    try acceptLoop server listener permits onUpgrade onSession catch _ => pure ()
    leave server
  return server

/-- Sessions past the handshake that have not finished. -/
def activeSessions (s : Server) : BaseIO Nat := do
  return (← s.sessions.get).size

/-- Wait until accepting has stopped and every connection has finished. -/
def waitShutdown (s : Server) : Async Unit := do
  discard (await s.finished.result?)

/-- Stop accepting, tear down every session without a closing handshake and
    wait for all connection tasks to finish. -/
def shutdown (s : Server) : Async Unit := do
  s.stop.cancel
  let sessions := (← s.sessions.get).toArray.map (·.2)
  discard (Async.concurrentlyAll (sessions.map (·.abort)))
  s.waitShutdown

/-- Stop accepting, close every session with `code` (default `1001`) and wait
    for the closing handshakes (bounded by `closeTimeoutMs` each) and for all
    connection tasks to finish. Handshakes still in progress are dropped. -/
def drain (s : Server) (code : CloseCode := .goingAway) (reason : String := "server shutting down") :
    Async Unit := do
  s.stop.cancel
  let sessions := (← s.sessions.get).toArray.map (·.2)
  discard (Async.concurrentlyAll (sessions.map (·.close code reason)))
  s.waitShutdown

end Server

end LeanWs
