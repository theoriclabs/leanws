import Std.Http.Transport

namespace LeanWs

open Std.Async Std.Http

/-!
A TCP `Transport` tuned for many concurrent sessions.

`Std.Http`'s instance for `Socket.Client` implements `recvSelector` with
`waitReadable` followed by a blocking read on the worker thread. Under a
thousand connections that blocking read makes the task manager spawn a
thread per waiting session and serialize them on its lock. This transport
starts the real `recv?` inside `registerFn` instead and, when another
selector wins the race, stashes the bytes for the next read, so no worker
ever blocks and no data is lost.
-/

/-- A TCP socket as a `Transport`. `close` shuts down the write side so the
    peer observes EOF promptly; the descriptor itself is released when the
    last reference to the socket is dropped. -/
structure Tcp where
  socket : TCP.Socket.Client
  /-- The outcome of a read that lost a `Selectable.one` race; consumed by
      the next read before the socket is touched again. -/
  private pending : IO.Ref (Option (Except IO.Error (Option ByteArray)))

namespace Tcp

def new (socket : TCP.Socket.Client) : BaseIO Tcp := do
  return { socket, pending := ← IO.mkRef none }

private def takePending (t : Tcp) : BaseIO (Option (Except IO.Error (Option ByteArray))) :=
  t.pending.modifyGet fun p => (p, none)

/-- Read up to `size` bytes; `none` at EOF. -/
def recv (t : Tcp) (size : UInt64) : Async (Option ByteArray) := do
  match ← takePending t with
  | some result => Async.ofExcept result
  | none => t.socket.recv? size

/-- A data-loss-free selector: the read started here is either handed to the
    winning waiter or stashed in `pending`. -/
def recvSelector (t : Tcp) (size : UInt64) : Selector (Option ByteArray) where
  tryFn := do
    match ← takePending t with
    | some result => some <$> Async.ofExcept result
    | none => return none
  registerFn waiter := do
    match ← takePending t with
    | some result =>
        waiter.race (lose := t.pending.set (some result)) (win := fun p => p.resolve result)
    | none =>
        let promise ← t.socket.native.recv? size
        BaseIO.chainTask promise.result? fun
          | none => pure () -- cancelled by `unregisterFn`
          | some result =>
              waiter.race (lose := t.pending.set (some result)) (win := fun p => p.resolve result)
  unregisterFn := t.socket.native.cancelRecv

end Tcp

instance : Transport Tcp where
  recv t n := t.recv n
  sendAll t data := t.socket.sendAll data
  recvSelector t n := t.recvSelector n
  close t := discard <| (t.socket.shutdown).toIO

end LeanWs
