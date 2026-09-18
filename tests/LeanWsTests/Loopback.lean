import LeanWs
import LeanWsTests.Harness

namespace LeanWsTests.Loopback

open LeanWs Std Std.Async Std.Async.TCP Std.Http

/-!
`Server` and `Client` over real loopback sockets.
-/

private def loopback (port : UInt16 := 0) : Std.Net.SocketAddress :=
  .v4 { addr := .ofParts 127 0 0 1, port }

private def wsUri (server : LeanWs.Server) (path : String := "/") : URI :=
  URI.parse! s!"ws://127.0.0.1:{server.localAddr.port}{path}"

private def echo (session : LeanWs.Session) (_ : Handshake.Accept) : Async Unit := do
  repeat
    match ← session.recv with
    | none => break
    | some msg =>
        match ← session.send msg with
        | .ok () => pure ()
        | .error _ => break

private def acceptAll (req : Request.Head) (_ : RemoteAddr) : Async (Except Handshake.Reject Handshake.Accept) :=
  pure (Handshake.server req { subprotocols := ["echo.v1"] })

private def connected (uri : URI) (opts : ClientOptions := {}) : Async LeanWs.Session := do
  match ← Client.connect uri opts with
  | .ok s => pure s
  | .error e => throw (failure s!"connect {uri}: {e}")

/-- Connect with a few retries; the kernel may drop SYNs when a thousand
    arrive at once and the listen queue overflows. -/
private def connectRetry (uri : URI) (opts : ClientOptions) (attempts : Nat := 5) : Async LeanWs.Session := do
  let mut lastError := ""
  for i in [0:attempts] do
    match ← Client.connect uri opts with
    | .ok s => return s
    | .error e =>
        lastError := toString e
        sleep (Time.Millisecond.Offset.ofNat (50 * (i + 1)))
  throw (failure s!"connect failed after {attempts} attempts: {lastError}")

def basics : Async Unit := do
  let server ← LeanWs.Server.serve (loopback) { idleTimeoutMs := 0 } acceptAll echo
  check (server.localAddr.port != 0) "ephemeral port assigned"
  match ← Client.connectDetailed (wsUri server "/room/1?x=y") { subprotocols := ["nope", "echo.v1"] } with
  | .error e => throw (failure s!"connect: {e}")
  | .ok conn =>
      checkEq conn.subprotocol (some "echo.v1") "subprotocol negotiated"
      checkEq conn.response.status.toCode 101 "101"
      let s := conn.session
      checkEq (← s.send (.text "ping")) (.ok ()) "send"
      checkEq (← s.recv) (some (.text "ping")) "echo text"
      let payload := ByteArray.mk (Array.range 3000 |>.map (·.toUInt8))
      checkEq (← s.send (.binary payload)) (.ok ()) "send binary"
      checkEq (← s.recv) (some (.binary payload)) "echo binary"
      -- larger than maxFrame: fragmented on the wire both ways
      let big := ByteArray.mk (Array.replicate (3 * 1024 * 1024) 0x5A)
      checkEq (← s.send (.binary big)) (.ok ()) "send 3 MiB"
      checkEq ((← s.recv).map (·.size)) (some big.size) "echo 3 MiB"
      checkEq (← server.activeSessions) 1 "one active session"
      s.close .normal "done"
      let closed ← s.waitClosed
      checkEq closed.received (some { code := .normal }) "server echoed 1000"
      check closed.clean "clean close"
      let mut waited := 0
      while (← server.activeSessions) > 0 && waited < 100 do
        sleep 10
        waited := waited + 1
      checkEq (← server.activeSessions) 0 "session unregistered"
  -- the server closes with 1000 when the handler returns
  let server2 ← LeanWs.Server.serve (loopback) { idleTimeoutMs := 0 } acceptAll
    (fun s _ => do discard (s.send (.text "bye")))
  let s ← connected (wsUri server2)
  checkEq (← s.recv) (some (.text "bye")) "handler message"
  checkEq (← s.recv) none "then closed"
  checkEq (← s.waitClosed).code .normal "1000 from handler return"
  server.shutdown
  server2.shutdown

def rejections : Async Unit := do
  let server ← LeanWs.Server.serve (loopback) { handshakeTimeoutMs := 300 }
    (fun req _ => pure (Handshake.server req { checkOrigin := (· == some "https://ok.example") })) echo
  -- origin policy → 403 seen by the client as a rejected status
  match ← Client.connect (wsUri server) { headers := Headers.empty.insert! "Origin" "https://evil.example" } with
  | .error (.rejected (.status 403)) => pure ()
  | other => throw (failure s!"expected 403, got {repr (other.map fun _ => ())}")
  let s ← connected (wsUri server) { headers := Headers.empty.insert! "Origin" "https://ok.example" }
  s.close
  -- raw HTTP request → 426 and close
  let raw ← Socket.Client.mk
  raw.connect server.localAddr
  raw.send "GET / HTTP/1.1\r\nHost: x\r\n\r\n".toUTF8
  let mut response : ByteArray := .empty
  repeat
    match ← raw.recv? 4096 with
    | some chunk => response := response ++ chunk
    | none => break
  let text := (String.fromUTF8? response).getD ""
  check (text.startsWith "HTTP/1.1 426") s!"426 for plain HTTP: {text.take 40}"
  -- garbage → 400
  let raw2 ← Socket.Client.mk
  raw2.connect server.localAddr
  raw2.send "NOT HTTP AT ALL\r\n\r\n".toUTF8
  let mut response2 : ByteArray := .empty
  repeat
    match ← raw2.recv? 4096 with
    | some chunk => response2 := response2 ++ chunk
    | none => break
  check (((String.fromUTF8? response2).getD "").startsWith "HTTP/1.1 400") "400 for garbage"
  -- silent connection → dropped after handshakeTimeoutMs
  let raw3 ← Socket.Client.mk
  raw3.connect server.localAddr
  let t0 ← IO.monoMsNow
  checkEq (← raw3.recv? 16) none "silent handshake dropped"
  let elapsed := (← IO.monoMsNow) - t0
  check (elapsed ≥ 200 && elapsed < 2000) s!"dropped after {elapsed} ms"
  -- oversized request head → 400
  let raw4 ← Socket.Client.mk
  raw4.connect server.localAddr
  raw4.send ("GET / HTTP/1.1\r\nX-Pad: " ++ String.ofList (List.replicate 9000 'a')).toUTF8
  let mut response4 : ByteArray := .empty
  repeat
    match ← raw4.recv? 4096 with
    | some chunk => response4 := response4 ++ chunk
    | none => break
  check (((String.fromUTF8? response4).getD "").startsWith "HTTP/1.1 400") "400 for oversized head"
  -- client-side errors
  match ← Client.connect (URI.parse! "wss://127.0.0.1:1/") with
  | .error (.unsupportedScheme "wss") => pure ()
  | _ => throw (failure "wss should be unsupported")
  match ← Client.connect (wsUri server) { subprotocols := ["x"], headers := Headers.empty.insert! "Origin" "https://ok.example" } with
  | .ok s => s.close  -- server offers none; the client accepts a plain connection
  | .error e => throw (failure s!"plain connect: {e}")
  server.shutdown

def maxSockets : Async Unit := do
  let server ← LeanWs.Server.serve (loopback) { maxSockets := 1, idleTimeoutMs := 0 } acceptAll echo
  let first ← connected (wsUri server)
  let second ← async (Client.connect (wsUri server) { handshakeTimeoutMs := 3000 })
  sleep 200
  checkEq (← server.activeSessions) 1 "second connection waits for a permit"
  first.close
  match ← await second with
  | .ok s => checkEq (← s.send (.text "x")) (.ok ()) "second connected after the first closed"; s.close
  | .error e => throw (failure s!"second connect: {e}")
  server.shutdown

def drain : Async Unit := do
  let server ← LeanWs.Server.serve (loopback) { idleTimeoutMs := 0 } acceptAll echo
  let sessions ← (List.range 20).mapM fun _ => connected (wsUri server)
  for s in sessions do checkEq (← s.send (.text "hello")) (.ok ()) "send before drain"
  for s in sessions do checkEq (← s.recv) (some (.text "hello")) "echo before drain"
  checkEq (← server.activeSessions) 20 "20 sessions"
  let t0 ← IO.monoMsNow
  server.drain
  let elapsed := (← IO.monoMsNow) - t0
  for s in sessions do
    checkEq (← s.recv) none "recv none after drain"
    let closed ← s.waitClosed
    checkEq closed.received (some { code := .goingAway, reason := "server shutting down" }) "1001 from drain"
    check closed.clean "drain handshake completed"
  checkEq (← server.activeSessions) 0 "no sessions after drain"
  check (elapsed < 1500) s!"drain took {elapsed} ms"
  match ← Client.connect (wsUri server) { connectTimeoutMs := 500 } with
  | .ok s => s.abort; throw (failure "listener still accepting after drain")
  | .error _ => pure ()

private def sizeOrDefault (name : String) (default : Nat) : IO Nat := do
  return ((← IO.getEnv name) >>= String.toNat?).getD default

/-- One client: connect, exchange `perSocket` messages, then either close
    cleanly or stay open for the drain phase. Returns the message count and
    the time spent connecting. -/
private def clientRun (uri : URI) (id perSocket : Nat) (keepOpen : Bool) (kept : IO.Ref (Array LeanWs.Session)) :
    Async (Nat × Nat) := do
  let t0 ← IO.monoMsNow
  let s ← connectRetry uri { session := { idleTimeoutMs := 0 } }
  let connectMs := (← IO.monoMsNow) - t0
  let mut count := 0
  for i in [0:perSocket] do
    let msg : LeanWs.Message := if i % 2 == 0 then .text s!"c{id}-m{i}"
      else .binary (ByteArray.mk #[id.toUInt8, i.toUInt8, (id / 256).toUInt8])
    match ← s.send msg with
    | .ok () => pure ()
    | .error e => throw (failure s!"client {id}: send {e}")
    match ← s.recv with
    | some back =>
        unless back == msg do throw (failure s!"client {id}: echo mismatch")
        count := count + 1
    | none => throw (failure s!"client {id}: closed early: {repr (← s.closed?)}")
  if keepOpen then
    kept.modify (·.push s)
  else
    s.close .normal
    let closed ← s.waitClosed
    unless closed.clean do throw (failure s!"client {id}: unclean close {repr closed}")
  return count

/-- 1,000 concurrent sockets, 10 messages each, then drain the rest with 1001. -/
def stress : Async Unit := do
  let sockets ← sizeOrDefault "LEANWS_LOOPBACK_SOCKETS" 1000
  let perSocket ← sizeOrDefault "LEANWS_LOOPBACK_MESSAGES" 10
  let server ← LeanWs.Server.serve (loopback) { idleTimeoutMs := 0, backlog := 4096 } acceptAll echo
  let uri := wsUri server "/stress"
  let kept ← IO.mkRef (#[] : Array LeanWs.Session)
  let t0 ← IO.monoMsNow
  let counts ← Async.concurrentlyAll ((Array.range sockets).map fun id =>
    clientRun uri id perSocket (id % 20 == 0) kept)
  let elapsed := (← IO.monoMsNow) - t0
  let total := counts.foldl (· + ·) 0
  checkEq total (sockets * perSocket) "every message echoed"
  let keptSessions ← kept.get
  checkEq keptSessions.size ((sockets + 19) / 20) "sessions kept open for drain"
  let rate := if elapsed == 0 then 0 else total * 1000 / elapsed
  IO.println s!"    {sockets} sockets × {perSocket} messages = {total} round trips in {elapsed} ms ({rate} msg/s)"
  let t1 ← IO.monoMsNow
  server.drain
  let drainMs := (← IO.monoMsNow) - t1
  for s in keptSessions do
    checkEq (← s.recv) none "kept session drained"
    checkEq (← s.waitClosed).code .goingAway "1001 on drain"
  checkEq (← server.activeSessions) 0 "all sessions gone"
  IO.println s!"    drained {keptSessions.size} open sessions with 1001 in {drainMs} ms"

def run (runner : Runner) : IO Unit := do
  suite "Loopback (Server + Client)"
  test runner "connect, echo, close, handler return" basics
  test runner "rejections: 403, 426, 400, handshake timeout, wss" rejections
  test runner "maxSockets gates the accept loop" maxSockets
  test runner "drain closes sessions with 1001" drain
  test runner "1,000 concurrent sockets × 10 messages, then drain" stress (timeoutMs := 110000)

end LeanWsTests.Loopback
