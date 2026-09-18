import LeanWs
import LeanWsTests.Harness

namespace LeanWsTests.Session

open LeanWs Std Std.Async Std.Http Std.Http.Internal

/-!
Sessions driven from the peer side over `Std.Http.Internal.Mock`: the test
plays a raw WebSocket client against a server-role session and inspects the
frames it sends back.
-/

private def quick : SessionOptions := { idleTimeoutMs := 0, closeTimeoutMs := 300 }

/-- A raw peer: reads frames out of the mock client's byte stream. -/
private structure Peer where
  client : Mock.Client
  buf : IO.Ref ByteArray

private def Peer.new (client : Mock.Client) : BaseIO Peer := do
  return { client, buf := ← IO.mkRef .empty }

private def Peer.send (p : Peer) (f : LeanWs.Frame) : Async Unit :=
  p.client.send f.encode

private partial def Peer.frame (p : Peer) : Async LeanWs.Frame := do
  let buf ← p.buf.get
  match LeanWs.Frame.parse buf with
  | .ok (some (f, rest)) => p.buf.set rest; return f
  | .error e => throw (failure s!"peer received a malformed frame: {e}")
  | .ok none =>
      match ← p.client.recv? with
      | some chunk => p.buf.set (buf ++ chunk); p.frame
      | none => throw (failure "peer hit EOF while expecting a frame")

private def Peer.expectClose (p : Peer) (code : CloseCode) (what : String) : Async CloseInfo := do
  let f ← p.frame
  checkEq f.opcode .close s!"{what}: expected a close frame, got {f.opcode}"
  match LeanWs.Frame.parseClosePayload f.payload with
  | .ok (some info) => checkEq info.code code s!"{what}: close code"; return info
  | .ok none => throw (failure s!"{what}: close frame without status")
  | .error e => throw (failure s!"{what}: bad close payload {repr e}")

/-- The mock `recv?` resolves `none` once the session has closed its side. -/
private def Peer.expectEof (p : Peer) (what : String) : Async Unit := do
  if !(← p.buf.get).isEmpty then throw (failure s!"{what}: unexpected bytes before EOF")
  match ← p.client.recv? with
  | none => pure ()
  | some chunk => throw (failure s!"{what}: expected EOF, got {chunk.size} bytes")

private def start (limits : Limits := {}) (opts : SessionOptions := quick) (initial : ByteArray := .empty) :
    Async (Peer × LeanWs.Session) := do
  let (client, server) ← Mock.new
  let session ← LeanWs.Session.start server .server limits opts initial
  return (← Peer.new client, session)

private def recvSome (s : LeanWs.Session) (what : String) : Async LeanWs.Message := do
  match ← s.recv with
  | some m => pure m
  | none => throw (failure s!"{what}: recv returned none")

def echoAndFragments : Async Unit := do
  let (peer, session) ← start
  peer.send (LeanWs.Frame.text "hello" (some 0xA1B2C3D4))
  checkEq (← recvSome session "text") (.text "hello") "text arrives unmasked"
  peer.send (LeanWs.Frame.binary (ByteArray.mk #[0, 255, 7]) (some 1))
  checkEq (← recvSome session "binary") (.binary (ByteArray.mk #[0, 255, 7])) "binary arrives"
  checkEq (← session.send (.text "wörld")) (.ok ()) "send ok"
  let f ← peer.frame
  checkEq (f.opcode, f.fin, f.mask.isSome) (.text, true, false) "server frames are final and unmasked"
  checkEq (String.fromUTF8? f.payload) (some "wörld") "payload"
  -- three fragments with a ping in the middle
  peer.send { fin := false, opcode := .text, mask := some 5, payload := "frag".toUTF8 }
  peer.send (LeanWs.Frame.ping "p".toUTF8 (some 9))
  peer.send { fin := false, opcode := .continuation, mask := some 6, payload := "men".toUTF8 }
  peer.send { opcode := .continuation, mask := some 7, payload := "ted".toUTF8 }
  let pong ← peer.frame
  checkEq (pong.opcode, String.fromUTF8? pong.payload) (.pong, some "p") "pong interleaved"
  checkEq (← recvSome session "fragmented") (.text "fragmented") "fragments reassembled"
  -- a large outbound message is fragmented at maxFrame
  let (peer2, session2) ← start { maxFrame := 100 }
  let payload := ByteArray.mk (Array.range 250 |>.map (·.toUInt8))
  checkEq (← session2.send (.binary payload)) (.ok ()) "large send"
  let a ← peer2.frame
  let b ← peer2.frame
  let c ← peer2.frame
  checkEq ((a.opcode, a.fin), (b.opcode, b.fin), (c.opcode, c.fin))
    ((.binary, false), (.continuation, false), (.continuation, true)) "outbound fragments"
  checkEq (a.payload ++ b.payload ++ c.payload) payload "fragments carry the payload"
  -- bytes handed over from the handshake are parsed first
  let (peer3, session3) ← start (initial := (LeanWs.Frame.text "early" (some 3)).encode)
  checkEq (← recvSome session3 "initial") (.text "early") "initial bytes"
  let _ := peer3
  session.abort
  session2.abort
  session3.abort

def pingPong : Async Unit := do
  let (peer, session) ← start
  session.ping "hi".toUTF8
  let f ← peer.frame
  checkEq (f.opcode, String.fromUTF8? f.payload) (.ping, some "hi") "session ping reaches peer"
  peer.send (LeanWs.Frame.pong "hi".toUTF8 (some 2))
  peer.send (LeanWs.Frame.ping (ByteArray.mk (Array.replicate 125 1)) (some 2))
  let pong ← peer.frame
  checkEq (pong.opcode, pong.payload.size) (.pong, 125) "125-byte ping answered"
  -- unsolicited pongs are ignored, the session keeps working
  peer.send (LeanWs.Frame.pong "x".toUTF8 (some 2))
  peer.send (LeanWs.Frame.text "after" (some 2))
  checkEq (← recvSome session "after pong") (.text "after") "still open"
  session.abort

def peerClose : Async Unit := do
  let (peer, session) ← start
  peer.send (LeanWs.Frame.close .normal "bye" (some 8))
  let echo ← peer.expectClose .normal "echoed close"
  checkEq echo.reason "" "echo carries the status only"
  peer.expectEof "after close handshake"
  let closed ← session.waitClosed
  checkEq closed.received (some { code := .normal, reason := "bye" }) "peer close recorded"
  checkEq closed.sent (some { code := .normal }) "our close recorded"
  check closed.clean "clean"
  checkEq closed.code .normal "code"
  checkEq (← session.recv) none "recv none after close"
  checkEq (← session.send (.text "late")) (.error .closed) "send after close"
  -- empty close payload is echoed empty and reported as 1005
  let (peer, session) ← start
  peer.send { opcode := .close, mask := some 8 }
  let f ← peer.frame
  checkEq (f.opcode, f.payload.size) (.close, 0) "empty close echoed empty"
  checkEq (← session.waitClosed).code .noStatus "1005 reported"
  -- pending messages remain readable after the peer closed
  let (peer, session) ← start
  peer.send (LeanWs.Frame.text "one" (some 1))
  peer.send (LeanWs.Frame.text "two" (some 1))
  peer.send (LeanWs.Frame.close .normal "" (some 1))
  discard (session.waitClosed)
  checkEq (← session.recv) (some (.text "one")) "buffered one"
  checkEq (← session.recv) (some (.text "two")) "buffered two"
  checkEq (← session.recv) none "then none"

def localClose : Async Unit := do
  -- peer answers: handshake completes
  let (peer, session) ← start
  let closer ← async (session.close .goingAway "drain")
  let f ← peer.expectClose .goingAway "our close"
  checkEq f.reason "drain" "reason sent"
  checkEq (← session.send (.text "x")) (.error .closed) "send rejected while closing"
  peer.send (LeanWs.Frame.close .goingAway "ok" (some 3))
  await closer
  let closed ← session.waitClosed
  checkEq closed.received (some { code := .goingAway, reason := "ok" }) "peer answer recorded"
  check closed.clean "clean"
  peer.expectEof "after local close"
  -- peer never answers: close returns after closeTimeoutMs
  let (peer, session) ← start (opts := { quick with closeTimeoutMs := 200 })
  let t0 ← IO.monoMsNow
  session.close .normal
  let elapsed := (← IO.monoMsNow) - t0
  check (elapsed ≥ 150 && elapsed < 1500) s!"close timed out in {elapsed} ms"
  let closed ← session.waitClosed
  checkEq closed.received none "no peer close"
  checkEq closed.code .abnormal "1006 when the peer never answered"
  discard (peer.expectClose .normal "timed-out close")
  -- data frames from the peer after we sent close are dropped
  let (peer, session) ← start
  background (session.close .normal)
  discard (peer.expectClose .normal "close first")
  peer.send (LeanWs.Frame.text "ignored" (some 4))
  peer.send (LeanWs.Frame.close .normal "" (some 4))
  discard session.waitClosed
  checkEq (← session.recv) none "data after close dropped"

private def expectFailure (setup : Peer → Async Unit) (code : CloseCode) (what : String)
    (limits : Limits := {}) : Async Unit := do
  let (peer, session) ← start limits
  setup peer
  discard (peer.expectClose code what)
  peer.expectEof s!"{what}: EOF after failure"
  let closed ← session.waitClosed
  checkEq (closed.sent.map (·.code)) (some code) s!"{what}: sent code"
  checkEq closed.received none s!"{what}: nothing received"
  checkEq (← session.recv) none s!"{what}: recv none"

def protocolErrors : Async Unit := do
  expectFailure (·.send { opcode := .text, rsv1 := true, mask := some 1, payload := "x".toUTF8 }) .protocolError "rsv1"
  expectFailure (·.send { opcode := .binary, rsv2 := true, mask := some 1 }) .protocolError "rsv2"
  expectFailure (·.send { opcode := .ping, rsv3 := true, mask := some 1 }) .protocolError "rsv3"
  expectFailure (·.send (LeanWs.Frame.text "unmasked")) .protocolError "unmasked client frame"
  expectFailure (·.client.send (ByteArray.mk #[0x83, 0x80, 1, 2, 3, 4])) .protocolError "reserved opcode"
  expectFailure (·.client.send (ByteArray.mk #[0x09, 0x80, 1, 2, 3, 4])) .protocolError "fragmented ping"
  expectFailure (·.client.send (ByteArray.mk #[0x88, 0xFE, 0x00, 0x7E, 1, 2, 3, 4])) .protocolError "126-byte close"
  expectFailure (·.send { opcode := .continuation, mask := some 1, payload := "x".toUTF8 }) .protocolError "lone continuation"
  expectFailure (fun p => do
      p.send { fin := false, opcode := .text, mask := some 1, payload := "a".toUTF8 }
      p.send (LeanWs.Frame.text "b" (some 1))) .protocolError "interleaved message"
  expectFailure (·.send { opcode := .close, mask := some 1, payload := ByteArray.mk #[0x03] }) .protocolError "1-byte close"
  expectFailure (·.send { opcode := .close, mask := some 1, payload := ByteArray.mk #[0x03, 0xED] }) .protocolError "close 1005"
  expectFailure (·.send { opcode := .close, mask := some 1, payload := ByteArray.mk #[0x03, 0xE8, 0xFF] }) .invalidPayload "close reason UTF-8"
  expectFailure (·.send { opcode := .text, mask := some 1, payload := ByteArray.mk #[0xCE] }) .invalidPayload "truncated UTF-8"
  expectFailure (fun p => do
      p.send { fin := false, opcode := .text, mask := some 1, payload := ByteArray.mk #[0xCE, 0xBA, 0xE1] }
      p.send { opcode := .continuation, mask := some 1, payload := ByteArray.mk #[0xBD, 0xB9, 0xF4, 0x90] })
    .invalidPayload "invalid UTF-8 across fragments"

def oversize : Async Unit := do
  let limits : Limits := { maxFrame := 100, maxMessage := 150, maxFragments := 4 }
  -- the header alone triggers 1009 before the payload arrives
  let (peer, session) ← start limits
  peer.client.send ((LeanWs.Frame.binary (ByteArray.mk (Array.replicate 101 0)) (some 1)).encode.extract 0 10)
  discard (peer.expectClose .messageTooBig "oversize frame header")
  checkEq (← session.waitClosed).sent (some { code := .messageTooBig, reason := "frame too large" }) "1009 sent early"
  expectFailure (fun p => do
      p.send { fin := false, opcode := .binary, mask := some 1, payload := ByteArray.mk (Array.replicate 100 0) }
      p.send { opcode := .continuation, mask := some 1, payload := ByteArray.mk (Array.replicate 51 0) })
    .messageTooBig "message over maxMessage" limits
  expectFailure (fun p => do
      p.send { fin := false, opcode := .binary, mask := some 1, payload := ByteArray.mk #[0] }
      for _ in [0:4] do
        p.send { fin := false, opcode := .continuation, mask := some 1, payload := ByteArray.mk #[0] })
    .protocolError "too many fragments" limits
  -- exactly at the limits is fine
  let (peer, session) ← start limits
  peer.send (LeanWs.Frame.binary (ByteArray.mk (Array.replicate 100 9)) (some 1))
  checkEq ((← recvSome session "at limit").size) 100 "frame at maxFrame accepted"
  session.abort

/-- A transport whose writes block until released, to fill the outbound queue. -/
private structure Stuck where
  gate : IO.Promise Unit
  sent : IO.Ref Nat
  inbound : CloseableChannel ByteArray

private instance : Transport Stuck where
  recv t _ := do await (← t.inbound.recv)
  sendAll t data := do
    discard (await t.gate.result?)
    t.sent.modify (· + data.size)
  recvSelector t _ := t.inbound.recvSelector
  close t := discard t.inbound.close.toBaseIO

def backpressure : Async Unit := do
  let t : Stuck := { gate := ← IO.Promise.new, sent := ← IO.mkRef 0, inbound := ← CloseableChannel.new }
  let session ← LeanWs.Session.start t .server {} { quick with sendQueue := 4, sendTimeoutMs := 100 }
  -- sendQueue bounds messages accepted but not yet written, including the one
  -- the writer is blocked on
  let mut ok := 0
  let mut full := 0
  let t0 ← IO.monoMsNow
  for i in [0:8] do
    match ← session.send (.text s!"m{i}") with
    | .ok () => ok := ok + 1
    | .error .queueFull => full := full + 1
    | .error .closed => throw (failure "closed")
  let elapsed := (← IO.monoMsNow) - t0
  checkEq (ok, full) (4, 4) "queue bounded at sendQueue"
  check (elapsed ≥ 350 && elapsed < 2000) s!"each queueFull waited sendTimeoutMs ({elapsed} ms)"
  -- releasing the peer drains everything that was accepted
  t.gate.resolve ()
  let mut waited := 0
  while (← t.sent.get) < 4 && waited < 100 do
    sleep 10
    waited := waited + 1
  checkEq (← t.sent.get) 4 "accepted messages were written"
  checkEq (← session.send (.text "again")) (.ok ()) "queue has room again"
  -- non-blocking mode reports queueFull immediately
  let t2 : Stuck := { gate := ← IO.Promise.new, sent := ← IO.mkRef 0, inbound := ← CloseableChannel.new }
  let session2 ← LeanWs.Session.start t2 .server {} { quick with sendQueue := 2, sendTimeoutMs := 0 }
  let t1 ← IO.monoMsNow
  let results ← (List.range 5).mapM fun i => session2.send (.text s!"n{i}")
  checkEq (results.filter (· == .error .queueFull)).length 3 "three rejected"
  check ((← IO.monoMsNow) - t1 < 200) "non-blocking send does not wait"
  t2.gate.resolve ()
  session.abort
  session2.abort

def idleTimeout : Async Unit := do
  let (peer, session) ← start (opts := { idleTimeoutMs := 300, closeTimeoutMs := 100 })
  let t0 ← IO.monoMsNow
  let ping ← peer.frame
  let pingAt := (← IO.monoMsNow) - t0
  checkEq ping.opcode .ping "ping after idle/2"
  check (pingAt ≥ 100 && pingAt < 300) s!"ping at {pingAt} ms"
  -- answering the ping keeps the session alive
  peer.send (LeanWs.Frame.pong .empty (some 1))
  let ping2 ← peer.frame
  let ping2At := (← IO.monoMsNow) - t0
  checkEq ping2.opcode .ping "second ping"
  check (ping2At ≥ 250 && ping2At < 600) s!"second ping at {ping2At} ms"
  -- ignoring it closes with 1001
  let info ← peer.expectClose .goingAway "idle close"
  checkEq info.reason "idle timeout" "reason"
  let closedAt := (← IO.monoMsNow) - t0
  check (closedAt ≥ 400 && closedAt < 1200) s!"closed at {closedAt} ms"
  checkEq (← session.waitClosed).code .abnormal "peer never answered"
  checkEq (← session.isOpen) false "not open"

/-- Read one frame from the server end of a mock pair. -/
private partial def serverFrame (server : Mock.Server) (buf : ByteArray := .empty) : Async LeanWs.Frame := do
  match LeanWs.Frame.parse buf with
  | .ok (some (f, _)) => return f
  | .error e => throw (failure s!"server received a malformed frame: {e}")
  | .ok none =>
      match ← server.recv? with
      | some chunk => serverFrame server (buf ++ chunk)
      | none => throw (failure "server hit EOF while expecting a frame")

def clientRole : Async Unit := do
  let (client, server) ← Mock.new
  let session ← LeanWs.Session.start client .client {} quick
  checkEq (← session.send (.text "hi")) (.ok ()) "client send"
  let f ← serverFrame server
  check f.mask.isSome "client frames are masked"
  checkEq (String.fromUTF8? f.payload) (some "hi") "payload unmasked on parse"
  -- an unmasked server frame is accepted, a masked one is a protocol error
  server.send (LeanWs.Frame.text "ok").encode
  checkEq (← session.recv) (some (.text "ok")) "unmasked server frame accepted"
  server.send (LeanWs.Frame.text "bad" (some 1)).encode
  let closed ← session.waitClosed
  checkEq (closed.sent.map (·.code)) (some .protocolError) "masked server frame → 1002"

def run (runner : Runner) : IO Unit := do
  suite "Session (mock transport)"
  test runner "echo, fragmentation, initial bytes" echoAndFragments
  test runner "ping/pong" pingPong
  test runner "close initiated by the peer" peerClose
  test runner "close initiated locally (with and without answer)" localClose
  test runner "protocol errors → 1002/1007" protocolErrors
  test runner "oversize frames and messages → 1009" oversize
  test runner "backpressure → queueFull" backpressure
  test runner "idle timeout → ping, then 1001" idleTimeout
  test runner "client role masking" clientRole

end LeanWsTests.Session
