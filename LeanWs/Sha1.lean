namespace LeanWs.Sha1

/-!
SHA-1 (RFC 3174) in pure Lean. RFC 6455 uses it only to derive the
`Sec-WebSocket-Accept` token, so this is a protocol utility, not a security
primitive: it makes no timing or side-channel claims.
-/

private def rotl (x : UInt32) (n : UInt32) : UInt32 :=
  (x <<< n) ||| (x >>> (32 - n))

private def be32 (b : ByteArray) (i : Nat) : UInt32 :=
  ((b.get! i).toUInt32 <<< 24) ||| ((b.get! (i + 1)).toUInt32 <<< 16) |||
  ((b.get! (i + 2)).toUInt32 <<< 8) ||| (b.get! (i + 3)).toUInt32

private def pushBe32 (out : ByteArray) (w : UInt32) : ByteArray :=
  out.push (w >>> 24).toUInt8 |>.push (w >>> 16).toUInt8 |>.push (w >>> 8).toUInt8 |>.push w.toUInt8

/-- Message padding: `0x80`, zeros to 56 mod 64, then the bit length as a
    big-endian 64-bit integer. -/
private def pad (msg : ByteArray) : ByteArray := Id.run do
  let bitLen : UInt64 := msg.size.toUInt64 * 8
  let mut out := msg.push 0x80
  while out.size % 64 != 56 do
    out := out.push 0
  let mut shift : UInt64 := 56
  for _ in [0:8] do
    out := out.push (bitLen >>> shift).toUInt8
    shift := shift - 8
  return out

private structure State where
  h0 : UInt32 := 0x67452301
  h1 : UInt32 := 0xEFCDAB89
  h2 : UInt32 := 0x98BADCFE
  h3 : UInt32 := 0x10325476
  h4 : UInt32 := 0xC3D2E1F0

private def block (s : State) (data : ByteArray) (offset : Nat) : State := Id.run do
  let mut w : Array UInt32 := Array.mkEmpty 80
  for t in [0:16] do
    w := w.push (be32 data (offset + 4 * t))
  for t in [16:80] do
    w := w.push (rotl (w[t - 3]! ^^^ w[t - 8]! ^^^ w[t - 14]! ^^^ w[t - 16]!) 1)
  let mut a := s.h0
  let mut b := s.h1
  let mut c := s.h2
  let mut d := s.h3
  let mut e := s.h4
  for t in [0:80] do
    let (f, k) : UInt32 × UInt32 :=
      if t < 20 then ((b &&& c) ||| ((~~~b) &&& d), 0x5A827999)
      else if t < 40 then (b ^^^ c ^^^ d, 0x6ED9EBA1)
      else if t < 60 then ((b &&& c) ||| (b &&& d) ||| (c &&& d), 0x8F1BBCDC)
      else (b ^^^ c ^^^ d, 0xCA62C1D6)
    let temp := rotl a 5 + f + e + k + w[t]!
    e := d
    d := c
    c := rotl b 30
    b := a
    a := temp
  return { h0 := s.h0 + a, h1 := s.h1 + b, h2 := s.h2 + c, h3 := s.h3 + d, h4 := s.h4 + e }

/-- The 20-byte SHA-1 digest of `msg`. -/
def hash (msg : ByteArray) : ByteArray := Id.run do
  let padded := pad msg
  let mut s : State := {}
  let mut offset := 0
  while offset < padded.size do
    s := block s padded offset
    offset := offset + 64
  let out := ByteArray.emptyWithCapacity 20
  return pushBe32 (pushBe32 (pushBe32 (pushBe32 (pushBe32 out s.h0) s.h1) s.h2) s.h3) s.h4

private def hexDigit (n : UInt8) : Char :=
  if n < 10 then Char.ofNat ('0'.toNat + n.toNat) else Char.ofNat ('a'.toNat + n.toNat - 10)

/-- Lowercase hexadecimal rendering of a digest, for test vectors and logs. -/
def toHex (digest : ByteArray) : String :=
  digest.foldl (fun acc b => acc.push (hexDigit (b >>> 4)) |>.push (hexDigit (b &&& 0x0f))) ""

end LeanWs.Sha1
