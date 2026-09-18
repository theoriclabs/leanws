import LeanWs.Frame

namespace LeanWs

/-!
Messages, size limits and fragment reassembly (RFC 6455 §5.4, §5.6).
-/

/-- A complete data message. Text is validated UTF-8. -/
inductive Message where
  | text (s : String)
  | binary (b : ByteArray)
  deriving Inhabited

namespace Message

instance : BEq Message where
  beq
    | .text a, .text b => a == b
    | .binary a, .binary b => a == b
    | _, _ => false

instance : Repr Message where
  reprPrec
    | .text s, _ => s!"Message.text {repr s}"
    | .binary b, _ => s!"Message.binary ({b.size} bytes)"

def isText : Message → Bool
  | .text _ => true
  | .binary _ => false

def size : Message → Nat
  | .text s => s.utf8ByteSize
  | .binary b => b.size

def payload : Message → ByteArray
  | .text s => s.toUTF8
  | .binary b => b

def opcode : Message → Opcode
  | .text _ => .text
  | .binary _ => .binary

/-- Split a message into frames of at most `maxFrame` payload bytes (one
    unfragmented frame when it fits), masking each with `mask`. -/
def toFrames (m : Message) (maxFrame : Nat) (mask : Option UInt32 := none) : Array Frame := Id.run do
  let bytes := m.payload
  if maxFrame == 0 || bytes.size ≤ maxFrame then
    return #[{ opcode := m.opcode, mask, payload := bytes }]
  let mut frames := #[]
  let mut offset := 0
  while offset < bytes.size do
    let stop := min bytes.size (offset + maxFrame)
    frames := frames.push {
      fin := stop == bytes.size
      opcode := if offset == 0 then m.opcode else .continuation
      mask
      payload := bytes.extract offset stop }
    offset := stop
  return frames

end Message

/-- Receive-side limits. Frames and messages beyond them close the connection
    with `1009`; `maxFragments` bounds the number of frames per message (`0`
    removes the bound). -/
structure Limits where
  maxFrame : Nat := 1 <<< 20
  maxMessage : Nat := 4 <<< 20
  maxFragments : Nat := 1024
  deriving Repr, BEq, Inhabited

/-- Reassembly failures. `tooLarge` maps to close code `1009`, `invalidUtf8`
    to `1007`, the rest to `1002`. -/
inductive AssembleError where
  /-- A continuation frame with no message in progress. -/
  | unexpectedContinuation
  /-- A text or binary frame while another message is still fragmented. -/
  | interleavedMessage
  /-- A control opcode handed to the assembler. -/
  | controlFrame
  | tooLarge (size : Nat)
  | tooManyFragments (count : Nat)
  | invalidUtf8
  deriving Repr, BEq

instance : ToString AssembleError where
  toString
    | .unexpectedContinuation => "continuation frame without a message in progress"
    | .interleavedMessage => "new message started while another is fragmented"
    | .controlFrame => "control frame passed to the message assembler"
    | .tooLarge size => s!"message of {size} bytes exceeds the limit"
    | .tooManyFragments count => s!"message has more than {count} fragments"
    | .invalidUtf8 => "text message is not valid UTF-8"

/-- Reassembly state for one direction of a connection. -/
structure Assembler where
  /-- Opcode of the message in progress, if any. -/
  kind : Option Opcode := none
  buffer : ByteArray := .empty
  fragments : Nat := 0
  deriving Inhabited

namespace Assembler

def inProgress (a : Assembler) : Bool := a.kind.isSome

private def finish (kind : Opcode) (bytes : ByteArray) : Except AssembleError Message :=
  match kind with
  | .text =>
      match String.fromUTF8? bytes with
      | some s => .ok (.text s)
      | none => .error .invalidUtf8
  | _ => .ok (.binary bytes)

/-- Feed one data frame. Returns the updated state and a message once its
    final fragment arrives. The frame must not be a control frame. -/
def push (a : Assembler) (limits : Limits) (f : Frame) : Except AssembleError (Assembler × Option Message) := do
  if f.opcode.isControl then throw .controlFrame
  match a.kind, f.opcode with
  | none, .continuation => throw .unexpectedContinuation
  | some _, .text | some _, .binary => throw .interleavedMessage
  | _, .close | _, .ping | _, .pong => throw .controlFrame
  | none, kind =>
      if f.payload.size > limits.maxMessage then throw (.tooLarge f.payload.size)
      if f.fin then
        return ({}, some (← finish kind f.payload))
      else
        return ({ kind := some kind, buffer := f.payload, fragments := 1 }, none)
  | some kind, .continuation =>
      let size := a.buffer.size + f.payload.size
      if size > limits.maxMessage then throw (.tooLarge size)
      if limits.maxFragments > 0 && a.fragments + 1 > limits.maxFragments then
        throw (.tooManyFragments (a.fragments + 1))
      let buffer := a.buffer ++ f.payload
      if f.fin then
        return ({}, some (← finish kind buffer))
      else
        return ({ kind := some kind, buffer, fragments := a.fragments + 1 }, none)

end Assembler

end LeanWs
