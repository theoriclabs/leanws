import LeanWs
import LeanWsTests.Harness

namespace LeanWsTests.Frame

open LeanWs Std.Async

private def bytes (xs : List Nat) : ByteArray := ByteArray.mk (xs.map Nat.toUInt8).toArray

private def parsed (b : ByteArray) : Async (LeanWs.Frame × ByteArray) := do
  match LeanWs.Frame.parse b with
  | .ok (some r) => pure r
  | .ok none => throw (failure "parse returned none on a complete frame")
  | .error e => throw (failure s!"parse failed: {e}")

/-- The examples from RFC 6455 §5.7. -/
def rfcVectors : Async Unit := do
  -- unmasked "Hello"
  let hello := LeanWs.Frame.text "Hello"
  checkEq hello.encode.toList [0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f] "unmasked Hello"
  -- masked "Hello"
  let masked := LeanWs.Frame.text "Hello" (some 0x37fa213d)
  checkEq masked.encode.toList [0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58] "masked Hello"
  let (f, rest) ← parsed masked.encode
  checkEq (String.fromUTF8? f.payload) (some "Hello") "masked payload decodes"
  checkEq f.mask (some 0x37fa213d) "mask key preserved"
  checkEq rest.size 0 "no remainder"
  -- ping and pong
  checkEq (LeanWs.Frame.ping "Hello".toUTF8).encode.toList [0x89, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f] "ping"
  checkEq (LeanWs.Frame.pong "Hello".toUTF8 (some 0x37fa213d)).encode.toList
    [0x8a, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58] "masked pong"
  -- 256 bytes binary: 16-bit length
  let b256 := LeanWs.Frame.binary (ByteArray.mk (Array.replicate 256 0xAB))
  checkEq (b256.encode.extract 0 4).toList [0x82, 0x7E, 0x01, 0x00] "256-byte header"
  checkEq b256.encode.size 260 "256-byte frame size"
  -- 64 KiB binary: 64-bit length
  let b64k := LeanWs.Frame.binary (ByteArray.mk (Array.replicate 65536 0x01))
  checkEq (b64k.encode.extract 0 10).toList [0x82, 0x7F, 0, 0, 0, 0, 0, 1, 0, 0] "64 KiB header"
  checkEq b64k.encode.size 65546 "64 KiB frame size"
  let (g, _) ← parsed b64k.encode
  checkEq g.payload.size 65536 "64 KiB payload round-trips"
  -- fragmented text: "Hel" + "lo"
  checkEq ({ fin := false, opcode := .text, payload := "Hel".toUTF8 } : LeanWs.Frame).encode.toList
    [0x01, 0x03, 0x48, 0x65, 0x6c] "first fragment"
  checkEq ({ opcode := .continuation, payload := "lo".toUTF8 } : LeanWs.Frame).encode.toList
    [0x80, 0x02, 0x6c, 0x6f] "final fragment"

def errors : Async Unit := do
  checkEq (LeanWs.Frame.parse (bytes [0x83, 0x00])) (.error (.reservedOpcode 3)) "reserved opcode 3"
  checkEq (LeanWs.Frame.parse (bytes [0x8B, 0x00])) (.error (.reservedOpcode 11)) "reserved opcode 11"
  checkEq (LeanWs.Frame.parse (bytes [0x09, 0x00])) (.error .controlFragmented) "fragmented ping"
  checkEq (LeanWs.Frame.parse (bytes [0x88, 0x7E, 0x00, 0x7E])) (.error (.controlTooLong 126)) "long close"
  checkEq (LeanWs.Frame.parse (bytes [0x82, 0x7F, 0x80, 0, 0, 0, 0, 0, 0, 0])) (.error .invalidLength) "length MSB"
  -- incomplete inputs need more bytes, never fail
  checkEq (LeanWs.Frame.parse (bytes [])) (.ok none) "empty"
  checkEq (LeanWs.Frame.parse (bytes [0x81])) (.ok none) "one byte"
  checkEq (LeanWs.Frame.parse (bytes [0x81, 0x85, 0x37, 0xfa])) (.ok none) "partial mask"
  checkEq (LeanWs.Frame.parse (bytes [0x82, 0x7E, 0x01])) (.ok none) "partial 16-bit length"
  checkEq (LeanWs.Frame.parse (bytes [0x82, 0x7F, 0, 0, 0, 0, 0, 1, 0])) (.ok none) "partial 64-bit length"
  -- RSV bits are preserved for the session layer to judge
  let (f, _) ← parsed (bytes [0xF1, 0x01, 0x41])
  check (f.rsv1 && f.rsv2 && f.rsv3) "rsv bits parsed"
  -- header exposes the declared length before the payload arrives
  match LeanWs.Frame.parseHeader (bytes [0x82, 0x7F, 0, 0, 0, 0, 0x10, 0, 0, 0]) with
  | .ok (some h) => checkEq h.payloadLength (16 <<< 24) "declared length"; checkEq h.size 10 "header size"
  | _ => throw (failure "header of a large frame")

def masking : Async Unit := do
  let payload := ByteArray.mk (Array.range 300 |>.map (·.toUInt8))
  let once := LeanWs.Frame.applyMask 0xDEADBEEF payload
  check (once != payload) "mask changes payload"
  checkEq (LeanWs.Frame.applyMask 0xDEADBEEF once) payload "mask is an involution"
  checkEq (LeanWs.Frame.applyMask 0 payload) payload "zero key is identity"
  checkEq (LeanWs.Frame.applyMask 0x01020304 (bytes [0, 0, 0, 0, 0, 0])).toList [1, 2, 3, 4, 1, 2] "key byte order"

def closePayload : Async Unit := do
  checkEq (LeanWs.Frame.closePayload .normal "bye").toList [0x03, 0xE8, 0x62, 0x79, 0x65] "close payload"
  checkEq (LeanWs.Frame.parseClosePayload (bytes [0x03, 0xE8, 0x62, 0x79, 0x65]))
    (.ok (some { code := .normal, reason := "bye" })) "close payload parses"
  checkEq (LeanWs.Frame.parseClosePayload .empty) (.ok none) "empty close payload"
  checkEq (LeanWs.Frame.parseClosePayload (bytes [0x03])) (.error .oneBytePayload) "one-byte close"
  checkEq (LeanWs.Frame.parseClosePayload (bytes [0x03, 0xED])) (.error (.invalidCode 1005)) "1005 on the wire"
  checkEq (LeanWs.Frame.parseClosePayload (bytes [0x03, 0xEE])) (.error (.invalidCode 1006)) "1006 on the wire"
  checkEq (LeanWs.Frame.parseClosePayload (bytes [0x03, 0xEC])) (.error (.invalidCode 1004)) "1004 on the wire"
  checkEq (LeanWs.Frame.parseClosePayload (bytes [0x00, 0x00])) (.error (.invalidCode 0)) "code 0"
  checkEq (LeanWs.Frame.parseClosePayload (bytes [0x0B, 0xB8])) (.ok (some { code := 3000 })) "3000 accepted"
  checkEq (LeanWs.Frame.parseClosePayload (bytes [0x13, 0x87])) (.ok (some { code := 4999 })) "4999 accepted"
  checkEq (LeanWs.Frame.parseClosePayload (bytes [0x13, 0x88])) (.error (.invalidCode 5000)) "5000 rejected"
  checkEq (LeanWs.Frame.parseClosePayload (bytes [0x03, 0xE8, 0xFF])) (.error .invalidReason) "invalid UTF-8 reason"
  -- reasons are truncated on a character boundary to fit 125 bytes
  let long := String.ofList (List.replicate 70 'é')  -- 140 bytes
  let p := LeanWs.Frame.closePayload .normal long
  check (p.size ≤ 125) "truncated payload fits"
  check ((String.fromUTF8? (p.extract 2 p.size)).isSome) "truncation keeps valid UTF-8"

private def randomFrame (r : Rng) : LeanWs.Frame × Rng := Id.run do
  let (opcode, r) := r.pick #[Opcode.continuation, .text, .binary, .close, .ping, .pong]
  let (fin, r) := if opcode.isControl then (true, r) else r.bool
  let (rsv1, r) := r.bool
  let (rsv2, r) := r.bool
  let (rsv3, r) := r.bool
  let (masked, r) := r.bool
  let (key, r) := r.uint32
  let (bucket, r) := r.nat 0 5
  let (size, r) :=
    if opcode.isControl then r.nat 0 125
    else match bucket with
      | 0 => r.nat 0 125
      | 1 => (125, r)
      | 2 => (126, r)
      | 3 => r.nat 126 3000
      | 4 => (65535, r)
      | _ => r.nat 65536 66000
  let (payload, r) := r.bytes size
  ({ fin, rsv1, rsv2, rsv3, opcode, mask := if masked then some key else none, payload }, r)

/-- Random frames over every opcode, masking choice and length encoding
    round-trip through `encode`/`parse`, including with trailing bytes and
    when concatenated. -/
def roundTrip : Async Unit := do
  let mut r := Rng.new 6455
  let mut sizes : Array Nat := #[0, 0, 0]
  for _ in [0:400] do
    let (f, r') := randomFrame r
    r := r'
    check f.wellFormed "generated frame is well-formed"
    let encoded := f.encode
    let bucket := if f.payload.size < 126 then 0 else if f.payload.size < 65536 then 1 else 2
    sizes := sizes.modify bucket (· + 1)
    let (g, rest) ← parsed encoded
    check (g == f) s!"round-trip {repr f}"
    checkEq rest.size 0 "no remainder after exact frame"
    -- trailing bytes are returned untouched
    let (g', rest') ← parsed (encoded ++ ByteArray.mk #[1, 2, 3])
    check (g' == f) "round-trip with trailing bytes"
    checkEq rest'.toList [1, 2, 3] "trailing bytes preserved"
  check (sizes.all (· > 0)) s!"all three length encodings exercised: {sizes}"
  -- two frames back to back
  let a := LeanWs.Frame.text "one" (some 0x11223344)
  let b := LeanWs.Frame.binary (ByteArray.mk (Array.replicate 200 7))
  let (fa, rest) ← parsed (a.encode ++ b.encode)
  let (fb, rest) ← parsed rest
  check (fa == a && fb == b && rest.size == 0) "two concatenated frames"

/-- Feeding every prefix of an encoded frame yields `none`, and the frame
    parses as soon as the last byte arrives. Every byte boundary is tried for
    frames up to 4 KiB; longer frames sample boundaries plus the header edge. -/
def incremental : Async Unit := do
  let mut r := Rng.new 1234
  for _ in [0:120] do
    let (f, r') := randomFrame r
    r := r'
    let encoded := f.encode
    let headerSize := encoded.size - f.payload.size
    let cuts : List Nat :=
      if encoded.size ≤ 4096 then List.range encoded.size
      else (List.range (headerSize + 2)) ++ (List.range (encoded.size / 997)).map (· * 997) ++ [encoded.size - 1]
    for cut in cuts do
      match LeanWs.Frame.parse (encoded.extract 0 cut) with
      | .ok none => pure ()
      | .ok (some _) => throw (failure s!"prefix of {cut}/{encoded.size} bytes parsed as a frame")
      | .error e => throw (failure s!"prefix of {cut}/{encoded.size} bytes failed: {e}")
    let (g, _) ← parsed encoded
    check (g == f) "complete frame parses"

def run (runner : Runner) : IO Unit := do
  suite "Frame"
  test runner "RFC 6455 §5.7 vectors" rfcVectors
  test runner "framing errors and incomplete input" errors
  test runner "masking" masking
  test runner "close payloads and status codes" closePayload
  test runner "encode/parse round-trip (400 random frames)" roundTrip
  test runner "incremental parser at every byte boundary (120 frames)" incremental

end LeanWsTests.Frame
