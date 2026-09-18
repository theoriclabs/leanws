namespace LeanWs

/-!
RFC 6455 §5 framing: the pure encoder and incremental decoder. Nothing here
performs I/O or enforces size limits; `LeanWs.Message` and `LeanWs.Session`
layer reassembly, limits and protocol policy on top.
-/

/-- Frame opcodes (RFC 6455 §5.2). Reserved values `0x3–0x7` and `0xB–0xF`
    cannot be represented and are rejected by `Frame.parse`. -/
inductive Opcode where
  | continuation
  | text
  | binary
  | close
  | ping
  | pong
  deriving Repr, BEq, DecidableEq, Inhabited

namespace Opcode

def toUInt8 : Opcode → UInt8
  | .continuation => 0x0
  | .text => 0x1
  | .binary => 0x2
  | .close => 0x8
  | .ping => 0x9
  | .pong => 0xA

def ofUInt8? : UInt8 → Option Opcode
  | 0x0 => some .continuation
  | 0x1 => some .text
  | 0x2 => some .binary
  | 0x8 => some .close
  | 0x9 => some .ping
  | 0xA => some .pong
  | _ => none

/-- Close, ping and pong. Control frames are never fragmented and carry at
    most 125 payload bytes. -/
def isControl : Opcode → Bool
  | .close | .ping | .pong => true
  | _ => false

/-- Text, binary and continuation. -/
def isData (op : Opcode) : Bool := !op.isControl

instance : ToString Opcode where
  toString
    | .continuation => "continuation"
    | .text => "text"
    | .binary => "binary"
    | .close => "close"
    | .ping => "ping"
    | .pong => "pong"

end Opcode

/-- Framing violations detected while decoding, before any payload is read. -/
inductive FrameError where
  /-- An opcode outside the six defined values. -/
  | reservedOpcode (code : UInt8)
  /-- A control frame with `FIN = 0`. -/
  | controlFragmented
  /-- A control frame declaring more than 125 payload bytes. -/
  | controlTooLong (size : Nat)
  /-- An 8-byte length with its most significant bit set. -/
  | invalidLength
  deriving Repr, BEq

instance : ToString FrameError where
  toString
    | .reservedOpcode code => s!"reserved opcode {code}"
    | .controlFragmented => "fragmented control frame"
    | .controlTooLong size => s!"control frame payload of {size} bytes exceeds 125"
    | .invalidLength => "invalid 64-bit payload length"

/-- One decoded frame. `payload` is always unmasked; `mask` records the key
    a masked frame used, or the key `encode` should apply. -/
structure Frame where
  fin : Bool := true
  rsv1 : Bool := false
  rsv2 : Bool := false
  rsv3 : Bool := false
  opcode : Opcode
  mask : Option UInt32 := none
  payload : ByteArray := .empty
  deriving Inhabited

instance : BEq Frame where
  beq a b :=
    a.fin == b.fin && a.rsv1 == b.rsv1 && a.rsv2 == b.rsv2 && a.rsv3 == b.rsv3 &&
    a.opcode == b.opcode && a.mask == b.mask && a.payload == b.payload

instance : Repr Frame where
  reprPrec f _ :=
    s!"\{ fin := {f.fin}, rsv := ({f.rsv1}, {f.rsv2}, {f.rsv3}), opcode := {f.opcode}, mask := {repr f.mask}, payload := {f.payload.size} bytes }"

/-- The fixed part of a frame: everything before the payload. -/
structure Frame.Header where
  fin : Bool
  rsv1 : Bool
  rsv2 : Bool
  rsv3 : Bool
  opcode : Opcode
  mask : Option UInt32
  payloadLength : Nat
  /-- Number of header bytes, 2 to 14. -/
  size : Nat
  deriving Repr, BEq

namespace Frame

/-- XOR `payload` with the four masking-key bytes (RFC 6455 §5.3). The
    operation is its own inverse. -/
def applyMask (key : UInt32) (payload : ByteArray) : ByteArray := Id.run do
  let n := payload.size
  let k0 := (key >>> 24).toUInt8
  let k1 := (key >>> 16).toUInt8
  let k2 := (key >>> 8).toUInt8
  let k3 := key.toUInt8
  let mut out := payload
  let mut i := 0
  while i + 3 < n do
    out := out.set! i (out.get! i ^^^ k0)
    out := out.set! (i + 1) (out.get! (i + 1) ^^^ k1)
    out := out.set! (i + 2) (out.get! (i + 2) ^^^ k2)
    out := out.set! (i + 3) (out.get! (i + 3) ^^^ k3)
    i := i + 4
  if i < n then out := out.set! i (out.get! i ^^^ k0)
  if i + 1 < n then out := out.set! (i + 1) (out.get! (i + 1) ^^^ k1)
  if i + 2 < n then out := out.set! (i + 2) (out.get! (i + 2) ^^^ k2)
  return out

/-- Frames `encode` produces and `parse` accepts unchanged: control frames are
    final with at most 125 payload bytes, and the payload fits in 63 bits. -/
def wellFormed (f : Frame) : Bool :=
  (!f.opcode.isControl || (f.fin && f.payload.size ≤ 125)) && f.payload.size < 2 ^ 63

/-- Serialize a frame with the minimal length encoding, masking the payload
    when `mask` is set. -/
def encode (f : Frame) : ByteArray := Id.run do
  let n := f.payload.size
  let mut out := ByteArray.emptyWithCapacity (n + 14)
  let flags : UInt8 :=
    (if f.fin then 0x80 else 0) ||| (if f.rsv1 then 0x40 else 0) |||
    (if f.rsv2 then 0x20 else 0) ||| (if f.rsv3 then 0x10 else 0)
  out := out.push (flags ||| f.opcode.toUInt8)
  let maskBit : UInt8 := if f.mask.isSome then 0x80 else 0
  if n < 126 then
    out := out.push (maskBit ||| n.toUInt8)
  else if n < 65536 then
    out := out.push (maskBit ||| 126) |>.push (n >>> 8).toUInt8 |>.push n.toUInt8
  else
    out := out.push (maskBit ||| 127)
    let len := n.toUInt64
    let mut shift : UInt64 := 56
    for _ in [0:8] do
      out := out.push (len >>> shift).toUInt8
      shift := shift - 8
  match f.mask with
  | some key =>
      out := out.push (key >>> 24).toUInt8 |>.push (key >>> 16).toUInt8
        |>.push (key >>> 8).toUInt8 |>.push key.toUInt8
      out := out ++ applyMask key f.payload
  | none =>
      out := out ++ f.payload
  return out

private def be16 (b : ByteArray) (i : Nat) : Nat :=
  ((b.get! i).toNat <<< 8) ||| (b.get! (i + 1)).toNat

private def be32 (b : ByteArray) (i : Nat) : UInt32 :=
  ((b.get! i).toUInt32 <<< 24) ||| ((b.get! (i + 1)).toUInt32 <<< 16) |||
  ((b.get! (i + 2)).toUInt32 <<< 8) ||| (b.get! (i + 3)).toUInt32

/-- Decode the header starting at `start`. Returns `none` when more bytes are
    needed, so callers can check the declared length against their limits
    before the payload arrives. Non-minimal length encodings are accepted. -/
def parseHeader (bytes : ByteArray) (start : Nat := 0) : Except FrameError (Option Header) := do
  let avail := bytes.size - start
  if avail < 2 then return none
  let b0 := bytes.get! start
  let b1 := bytes.get! (start + 1)
  let some opcode := Opcode.ofUInt8? (b0 &&& 0x0f)
    | throw (.reservedOpcode (b0 &&& 0x0f))
  let fin := b0 &&& 0x80 != 0
  let masked := b1 &&& 0x80 != 0
  let short := (b1 &&& 0x7f).toNat
  let lengthBytes := if short < 126 then 0 else if short == 126 then 2 else 8
  if opcode.isControl then
    if !fin then throw .controlFragmented
    if short > 125 then throw (.controlTooLong short)
  let size := 2 + lengthBytes + (if masked then 4 else 0)
  if avail < 2 + lengthBytes then return none
  let payloadLength ←
    if lengthBytes == 0 then pure short
    else if lengthBytes == 2 then pure (be16 bytes (start + 2))
    else
      if bytes.get! (start + 2) &&& 0x80 != 0 then throw .invalidLength
      let mut n := 0
      for i in [0:8] do
        n := (n <<< 8) ||| (bytes.get! (start + 2 + i)).toNat
      pure n
  if avail < size then return none
  let mask := if masked then some (be32 bytes (start + 2 + lengthBytes)) else none
  return some {
    fin, rsv1 := b0 &&& 0x40 != 0, rsv2 := b0 &&& 0x20 != 0, rsv3 := b0 &&& 0x10 != 0
    opcode, mask, payloadLength, size }

/-- Decode one frame starting at `start`. Returns the frame and the offset
    just past it, or `none` when the buffer does not yet hold the whole frame. -/
def parseAt (bytes : ByteArray) (start : Nat) : Except FrameError (Option (Frame × Nat)) := do
  let some h ← parseHeader bytes start | return none
  let stop := start + h.size + h.payloadLength
  if bytes.size < stop then return none
  let raw := bytes.extract (start + h.size) stop
  let payload := match h.mask with
    | some key => applyMask key raw
    | none => raw
  let frame : Frame := {
    fin := h.fin, rsv1 := h.rsv1, rsv2 := h.rsv2, rsv3 := h.rsv3
    opcode := h.opcode, mask := h.mask, payload }
  return some (frame, stop)

/-- Incremental decoder: `.ok none` means more bytes are needed, `.ok (some
    (frame, rest))` returns the unconsumed suffix, and `.error` is a framing
    violation that must fail the connection. For every `wellFormed` frame,
    `parse (encode f) = .ok (some (f, .empty))`. -/
def parse (bytes : ByteArray) : Except FrameError (Option (Frame × ByteArray)) := do
  match ← parseAt bytes 0 with
  | none => return none
  | some (frame, stop) => return some (frame, bytes.extract stop bytes.size)

/-- A final text frame. -/
def text (s : String) (mask : Option UInt32 := none) : Frame :=
  { opcode := .text, mask, payload := s.toUTF8 }

/-- A final binary frame. -/
def binary (b : ByteArray) (mask : Option UInt32 := none) : Frame :=
  { opcode := .binary, mask, payload := b }

def ping (payload : ByteArray := .empty) (mask : Option UInt32 := none) : Frame :=
  { opcode := .ping, mask, payload }

def pong (payload : ByteArray := .empty) (mask : Option UInt32 := none) : Frame :=
  { opcode := .pong, mask, payload }

end Frame

end LeanWs
