import Std.Http.Transport
import Std.Async
import Std.Sync.Channel
import LeanWs.Frame
import LeanWs.Close
import LeanWs.Message

namespace LeanWs

open Std Std.Async Std.Http

/-!
A `Session` runs the post-handshake protocol over any `Std.Http.Transport`:
one reader task per connection and one writer task that serializes every
frame. The reader answers pings, reassembles fragments, enforces limits and
timeouts, and fails the connection with the RFC 6455 close codes; the writer
takes control frames ahead of a bounded queue of data messages so that a slow
peer surfaces as `SendError.queueFull` rather than unbounded memory.
-/

/-- Which side of the connection this session is. Clients mask every frame
    they send and reject masked frames; servers do the opposite. -/
inductive Role where
  | client
  | server
  deriving Repr, BEq, DecidableEq, Inhabited

/-- Per-session tuning. Times are milliseconds; `0` disables a timeout. -/
structure SessionOptions where
  /-- Messages that may wait for the writer before `send` reports `.queueFull`. -/
  sendQueue : Nat := 256
  /-- How long `send` waits for room in the queue before `.queueFull`. `0`
      makes `send` non-blocking, which fan-out code that must never stall on
      one peer should prefer. -/
  sendTimeoutMs : Nat := 1000
  /-- Messages buffered for `recv`; when full the reader pauses, which lets
      TCP flow control push back on the peer. -/
  recvQueue : Nat := 64
  /-- Bytes the writer coalesces into one transport write when several
      messages are queued. -/
  writeBatchBytes : Nat := 256 * 1024
  /-- Ping after half of this without traffic; close with `1001` once it
      elapses with no pong or other frame. -/
  idleTimeoutMs : Nat := 60000
  /-- How long to wait for the peer's close frame after sending ours, and for
      the writer to flush during teardown. -/
  closeTimeoutMs : Nat := 2000
  /-- Bytes requested per transport read. -/
  recvChunkBytes : Nat := 65536
  deriving Repr, Inhabited

/-- Why `Session.send` did not queue a message. -/
inductive SendError where
  /-- The session is closing or closed. -/
  | closed
  /-- `sendQueue` messages were still waiting after `sendTimeoutMs`; the peer
      is not draining. -/
  | queueFull
  deriving Repr, BEq, DecidableEq

instance : ToString SendError where
  toString
    | .closed => "session closed"
    | .queueFull => "outbound queue full"

/-- How a session ended. `received` is the peer's close frame (its code is
    `1005` when the frame had no payload); `sent` is ours. -/
structure Closed where
  sent : Option CloseInfo := none
  received : Option CloseInfo := none
  deriving Repr, BEq, Inhabited

namespace Closed

/-- Both close frames were exchanged. -/
def clean (c : Closed) : Bool := c.sent.isSome && c.received.isSome

/-- The peer's close code, or `1006` when the connection dropped without one. -/
def code (c : Closed) : CloseCode := (c.received.map (·.code)).getD .abnormal

end Closed

private inductive Phase where
  | open
  /-- Our close frame is queued; `deadline` (monotonic ms) bounds the wait for the peer's. -/
  | closing (deadline : Nat)
  | closed
  deriving Inhabited

private structure State where
  phase : Phase := .open
  sent : Option CloseInfo := none
  received : Option CloseInfo := none
  /-- Monotonic milliseconds of the last frame from the peer. -/
  lastActivity : Nat
  pingOutstanding : Bool := false
  deriving Inhabited

private inductive Command where
  | close (info : CloseInfo)
  | abort

/-- An item in the ordered data queue. -/
private inductive Outbound where
  /-- One message; holds a send permit until written. -/
  | message (fs : Array Frame)
  /-- Our close frame; the writer stops after sending it, so messages queued
      earlier still go out first and nothing follows it. -/
  | close (f : Frame)

/-- One WebSocket connection after the handshake. Create with `Session.start`;
    all operations are safe to call from any task. -/
structure Session where private mk ::
  role : Role
  limits : Limits
  opts : SessionOptions
  private inbound : CloseableChannel Message
  /-- Messages and the final close frame in send order; `permits` bounds the
      messages to `sendQueue`. -/
  private data : CloseableChannel Outbound
  private permits : Semaphore
  /-- Pings and pongs; sent ahead of queued data. -/
  private control : CloseableChannel (Array Frame)
  private commands : CloseableChannel Command
  private state : IO.Ref State
  private writerDone : IO.Promise Unit
  private closedPromise : IO.Promise Closed

namespace Session

private def now : BaseIO Nat := IO.monoMsNow

/-- A fresh masking key for client frames; servers never mask. -/
private def mask (s : Session) : IO (Option UInt32) := do
  match s.role with
  | .server => return none
  | .client =>
      let bytes ← IO.getRandomBytes 4
      return some (((bytes.get! 0).toUInt32 <<< 24) ||| ((bytes.get! 1).toUInt32 <<< 16) |||
        ((bytes.get! 2).toUInt32 <<< 8) ||| (bytes.get! 3).toUInt32)

private def enqueueControl (s : Session) (fs : Array Frame) : BaseIO Unit :=
  discard (s.control.trySend fs)

/-- Queue our close frame once; later calls return `false`. Also closes the
    inbound queue so a reader blocked on a full queue can proceed. -/
private def sendClose (s : Session) (info : CloseInfo) : IO Bool := do
  let n ← now
  let first ← s.state.modifyGet fun st =>
    if st.sent.isSome then (false, st)
    else (true, { st with sent := some info, phase := .closing (n + s.opts.closeTimeoutMs) })
  if first then
    let key ← mask s
    let frame : Frame :=
      if info.code == .noStatus then { opcode := .close, mask := key }
      else Frame.close info.code info.reason key
    discard (s.data.trySend (.close frame))
    discard s.inbound.close.toBaseIO
  return first

/-- Tear down: close every queue, give the writer `closeTimeoutMs` to flush,
    close the transport and resolve `closed`. Idempotent. -/
private def finish [Transport α] (s : Session) (t : α) : Async Unit := do
  let already ← s.state.modifyGet fun st =>
    match st.phase with
    | .closed => (true, st)
    | _ => (false, { st with phase := .closed })
  if already then return
  discard s.data.close.toBaseIO
  discard s.control.close.toBaseIO
  discard s.commands.close.toBaseIO
  discard s.inbound.close.toBaseIO
  Async.race (do discard (await s.writerDone.result?)) (sleep (Time.Millisecond.Offset.ofNat s.opts.closeTimeoutMs))
  try Transport.close t catch _ => pure ()
  let st ← s.state.get
  s.closedPromise.resolve { sent := st.sent, received := st.received }

/-- Fail the connection: send `code` and tear down without waiting for the peer. -/
private def fail [Transport α] (s : Session) (t : α) (code : CloseCode) (reason : String) : Async Unit := do
  discard (sendClose s { code, reason })
  finish s t

private inductive WriteEvent where
  | control (fs : Option (Array Frame))
  | data (o : Option Outbound)

/-- Send whatever control frames are already queued. -/
private partial def flushControl [Transport α] (s : Session) (t : α) : Async Unit := do
  match ← s.control.tryRecv with
  | none => pure ()
  | some fs => Transport.sendAll t (fs.map Frame.encode); flushControl s t

/-- Send `first` plus any data already waiting, up to `writeBatchBytes`, in
    one transport write. Returns `true` once the close frame has been sent. -/
private def writeBatch [Transport α] (s : Session) (t : α) (first : Outbound) : Async Bool := do
  let mut chunks : Array ByteArray := #[]
  let mut bytes := 0
  let mut messages := 0
  let mut closed := false
  let mut next := some first
  repeat
    match next with
    | none => break
    | some (.close f) =>
        chunks := chunks.push f.encode
        closed := true
        break
    | some (.message fs) =>
        let encoded := fs.map Frame.encode
        bytes := bytes + encoded.foldl (· + ·.size) 0
        chunks := chunks ++ encoded
        messages := messages + 1
        next ← if bytes < s.opts.writeBatchBytes then s.data.tryRecv else pure none
  try
    Transport.sendAll t chunks
  finally
    for _ in [0:messages] do s.permits.release
  return closed

/-- Send everything still queued after the queues were closed: control
    frames, then data up to and including the close frame. -/
private partial def drainAll [Transport α] (s : Session) (t : α) : Async Unit := do
  flushControl s t
  match ← s.data.tryRecv with
  | none => pure ()
  | some item =>
      unless ← writeBatch s t item do drainAll s t

/-- The writer: control frames first, then data in order, until the close
    frame is sent or every queue is closed. A transport error aborts the session. -/
private partial def writeLoop [Transport α] (s : Session) (t : α) : Async Unit := do
  try
    repeat
      let event ← match ← s.control.tryRecv with
        | some fs => pure (WriteEvent.control (some fs))
        | none => Selectable.one #[
            .case s.control.recvSelector (fun fs => pure (WriteEvent.control fs)),
            .case s.data.recvSelector (fun o => pure (WriteEvent.data o))]
      match event with
      | .control none | .data none => drainAll s t; break
      | .control (some fs) => Transport.sendAll t (fs.map Frame.encode)
      | .data (some item) => if ← writeBatch s t item then break
  catch _ =>
    discard (s.commands.trySend .abort)
  s.writerDone.resolve ()

private inductive ReadEvent where
  | bytes (chunk : Option ByteArray)
  | command (cmd : Option Command)
  | timer

/-- When the reader next needs to wake without traffic, in monotonic ms. -/
private def nextDeadline (s : Session) : BaseIO (Option Nat) := do
  let st ← s.state.get
  match st.phase with
  | .closing deadline => return some deadline
  | .closed => return none
  | .open =>
      if s.opts.idleTimeoutMs == 0 then return none
      if st.pingOutstanding then return some (st.lastActivity + s.opts.idleTimeoutMs)
      return some (st.lastActivity + s.opts.idleTimeoutMs / 2)

/-- Handle one complete frame. Returns the assembler and whether to keep reading. -/
private def handleFrame [Transport α] (s : Session) (t : α) (asm : Assembler) (f : Frame) :
    Async (Assembler × Bool) := do
  let st ← s.state.get
  match f.opcode with
  | .ping =>
      if st.sent.isNone then
        enqueueControl s #[Frame.pong f.payload (← mask s)]
      return (asm, true)
  | .pong => return (asm, true)
  | .close =>
      match Frame.parseClosePayload f.payload with
      | .error .invalidReason => fail s t .invalidPayload "invalid close reason"; return (asm, false)
      | .error _ => fail s t .protocolError "invalid close frame"; return (asm, false)
      | .ok info? =>
          let info := info?.getD { code := .noStatus }
          s.state.modify fun st => { st with received := some info }
          if st.sent.isNone then
            -- Echo the peer's status (RFC 6455 §5.5.1); an empty payload is echoed empty.
            discard (sendClose s { code := info.code })
          finish s t
          return (asm, false)
  | _ =>
      if st.sent.isSome then return (asm, true) -- closing: data frames are dropped
      match asm.push s.limits f with
      | .error (.tooLarge _) => fail s t .messageTooBig "message too large"; return (asm, false)
      | .error .invalidUtf8 => fail s t .invalidPayload "invalid UTF-8 in text message"; return (asm, false)
      | .error e => fail s t .protocolError (toString e); return (asm, false)
      | .ok (asm, none) => return (asm, true)
      | .ok (asm, some msg) =>
          discard (await (← s.inbound.send msg))
          return (asm, true)

/-- Decode and handle every complete frame in `buf`. Returns the unconsumed
    suffix, the assembler and whether to keep reading. -/
private def processBuffer [Transport α] (s : Session) (t : α) (buf : ByteArray) (asm : Assembler) :
    Async (ByteArray × Assembler × Bool) := do
  let mut offset := 0
  let mut asm := asm
  repeat
    match Frame.parseHeader buf offset with
    | .error e =>
        fail s t .protocolError (toString e)
        return (.empty, asm, false)
    | .ok none => break
    | .ok (some h) =>
        if h.rsv1 || h.rsv2 || h.rsv3 then
          fail s t .protocolError "reserved bits set without a negotiated extension"
          return (.empty, asm, false)
        if (s.role == .server) != h.mask.isSome then
          fail s t .protocolError (if h.mask.isSome then "masked frame from server" else "unmasked frame from client")
          return (.empty, asm, false)
        if h.payloadLength > s.limits.maxFrame then
          fail s t .messageTooBig "frame too large"
          return (.empty, asm, false)
        match Frame.parseAt buf offset with
        | .ok (some (frame, stop)) =>
            offset := stop
            let (asm', continue?) ← handleFrame s t asm frame
            asm := asm'
            unless continue? do return (.empty, asm, false)
        | .ok none => break
        | .error e =>
            fail s t .protocolError (toString e)
            return (.empty, asm, false)
  let rest := if offset == 0 then buf else buf.extract offset buf.size
  return (rest, asm, true)

/-- The reader: multiplexes transport bytes, API commands and the idle/close
    timers until the session finishes. -/
private partial def readLoop [Transport α] (s : Session) (t : α) (initial : ByteArray) : Async Unit := do
  try
    let mut buf := initial
    let mut asm : Assembler := {}
    let mut running := true
    if !buf.isEmpty then
      let (rest, asm', continue?) ← processBuffer s t buf asm
      buf := rest
      asm := asm'
      running := continue?
    while running do
      let mut selectables : Array (Selectable ReadEvent) := #[
        .case (Transport.recvSelector t s.opts.recvChunkBytes.toUInt64) (fun chunk => pure (ReadEvent.bytes chunk)),
        .case s.commands.recvSelector (fun cmd => pure (ReadEvent.command cmd))]
      if let some deadline ← nextDeadline s then
        let n ← now
        let delay := if deadline > n then deadline - n else 0
        selectables := selectables.push (.case (← Selector.sleep (Time.Millisecond.Offset.ofNat delay)) (fun _ => pure ReadEvent.timer))
      match ← Selectable.one selectables with
      | .bytes none =>
          finish s t
          running := false
      | .bytes (some chunk) =>
          let n ← now
          s.state.modify fun st => { st with lastActivity := n, pingOutstanding := false }
          buf := if buf.isEmpty then chunk else buf ++ chunk
          let (rest, asm', continue?) ← processBuffer s t buf asm
          buf := rest
          asm := asm'
          running := continue?
      | .command none =>
          running := false
      | .command (some .abort) =>
          finish s t
          running := false
      | .command (some (.close info)) =>
          discard (sendClose s info)
      | .timer =>
          let n ← now
          let st ← s.state.get
          match st.phase with
          | .closed => running := false
          | .closing deadline =>
              if n ≥ deadline then
                finish s t
                running := false
          | .open =>
              if s.opts.idleTimeoutMs > 0 then
                if n ≥ st.lastActivity + s.opts.idleTimeoutMs then
                  fail s t .goingAway "idle timeout"
                  running := false
                else if n ≥ st.lastActivity + s.opts.idleTimeoutMs / 2 && !st.pingOutstanding then
                  s.state.modify fun st => { st with pingOutstanding := true }
                  enqueueControl s #[Frame.ping .empty (← mask s)]
  catch _ =>
    finish s t

/-- Start a session over `t`: spawns the reader and writer tasks and returns
    immediately. `initial` holds bytes that arrived with the handshake and
    belong to the first frames. -/
def start [Transport α] (t : α) (role : Role) (limits : Limits := {}) (opts : SessionOptions := {})
    (initial : ByteArray := .empty) : Async Session := do
  let inbound ← CloseableChannel.new (some (max 1 opts.recvQueue))
  let data ← CloseableChannel.new
  let permits ← Semaphore.new (max 1 opts.sendQueue)
  let control ← CloseableChannel.new
  let commands ← CloseableChannel.new
  let state ← IO.mkRef { lastActivity := ← now : State }
  let writerDone ← IO.Promise.new
  let closedPromise ← IO.Promise.new
  let s : Session := {
    role, limits, opts, inbound, data, permits, control, commands, state, writerDone, closedPromise }
  background (writeLoop s t)
  background (readLoop s t initial)
  return s

/-- `true` until a close frame has been sent or received. -/
def isOpen (s : Session) : BaseIO Bool := do
  match (← s.state.get).phase with
  | .open => return true
  | _ => return false

/-- Take a send permit, waiting at most `sendTimeoutMs`. A permit granted
    after the wait gave up is handed straight back. -/
private def acquirePermit (s : Session) : Async Bool := do
  if ← s.permits.tryAcquire then return true
  if s.opts.sendTimeoutMs == 0 then return false
  let permit ← s.permits.acquire
  let granted ← Async.race (do discard (await permit.result?); pure true)
    (do sleep (Time.Millisecond.Offset.ofNat s.opts.sendTimeoutMs); pure false)
  unless granted do
    BaseIO.chainTask permit.result? fun _ => s.permits.release
  return granted

/-- Queue a message. Messages larger than `limits.maxFrame` are fragmented.
    Waits up to `sendTimeoutMs` for room when `sendQueue` messages are
    already waiting, then returns `.queueFull`; returns `.closed` once
    closing has begun. -/
def send (s : Session) (m : Message) : Async (Except SendError Unit) := do
  unless ← s.isOpen do return .error .closed
  unless ← acquirePermit s do
    return .error (if ← s.isOpen then .queueFull else .closed)
  let frames := m.toFrames s.limits.maxFrame (← mask s)
  if ← s.data.trySend (.message frames) then return .ok ()
  s.permits.release
  return .error .closed

/-- The next message, or `none` once the session is closed and drained. -/
def recv (s : Session) : Async (Option Message) := do
  await (← s.inbound.recv)

/-- A selector for `recv`, for multiplexing a session with other sources. -/
def recvSelector (s : Session) : Selector (Option Message) :=
  s.inbound.recvSelector

/-- Queue a ping; the peer's pong is consumed by the reader. -/
def ping (s : Session) (payload : ByteArray := .empty) : Async Unit := do
  if ← s.isOpen then
    enqueueControl s #[Frame.ping payload (← mask s)]

/-- Wait until the session has fully closed. -/
def waitClosed (s : Session) : Async Closed := do
  await s.closedPromise

/-- The outcome once closed, or `none` while the session is still running. -/
def closed? (s : Session) : BaseIO (Option Closed) := do
  let st ← s.state.get
  match st.phase with
  | .closed => return some { sent := st.sent, received := st.received }
  | _ => return none

/-- Start the closing handshake with `code` and `reason` and wait for it to
    complete or for `closeTimeoutMs` to elapse. Queued messages that the
    writer has not sent yet are discarded; pending received messages remain
    available through `recv`. -/
def close (s : Session) (code : CloseCode := .normal) (reason : String := "") : Async Unit := do
  discard (s.commands.trySend (.close { code, reason }))
  discard (waitClosed s)

/-- Close the transport without a closing handshake and wait for teardown. -/
def abort (s : Session) : Async Unit := do
  discard (s.commands.trySend .abort)
  discard (waitClosed s)

end Session

end LeanWs
