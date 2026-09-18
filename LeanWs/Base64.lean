namespace LeanWs.Base64

/-!
Standard base64 (RFC 4648 §4) with `=` padding. Used for the handshake
nonce and accept key; not a general-purpose or constant-time codec.
-/

private def alphabet : ByteArray :=
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toUTF8

/-- Encode bytes as padded base64 text. -/
def encode (input : ByteArray) : String := Id.run do
  let n := input.size
  let mut out := ByteArray.emptyWithCapacity ((n + 2) / 3 * 4)
  let mut i := 0
  while i + 2 < n do
    let b0 := input.get! i
    let b1 := input.get! (i + 1)
    let b2 := input.get! (i + 2)
    out := out.push (alphabet.get! (b0 >>> 2).toNat)
    out := out.push (alphabet.get! (((b0 &&& 0x03) <<< 4) ||| (b1 >>> 4)).toNat)
    out := out.push (alphabet.get! (((b1 &&& 0x0f) <<< 2) ||| (b2 >>> 6)).toNat)
    out := out.push (alphabet.get! (b2 &&& 0x3f).toNat)
    i := i + 3
  if i + 1 == n then
    let b0 := input.get! i
    out := out.push (alphabet.get! (b0 >>> 2).toNat)
    out := out.push (alphabet.get! ((b0 &&& 0x03) <<< 4).toNat)
    out := out.push '='.toUInt8
    out := out.push '='.toUInt8
  else if i + 2 == n then
    let b0 := input.get! i
    let b1 := input.get! (i + 1)
    out := out.push (alphabet.get! (b0 >>> 2).toNat)
    out := out.push (alphabet.get! (((b0 &&& 0x03) <<< 4) ||| (b1 >>> 4)).toNat)
    out := out.push (alphabet.get! ((b1 &&& 0x0f) <<< 2).toNat)
    out := out.push '='.toUInt8
  -- Every byte pushed above is ASCII, so the conversion cannot fail.
  return (String.fromUTF8? out).getD ""

private def value? (c : UInt8) : Option UInt8 :=
  if c ≥ 'A'.toUInt8 && c ≤ 'Z'.toUInt8 then some (c - 'A'.toUInt8)
  else if c ≥ 'a'.toUInt8 && c ≤ 'z'.toUInt8 then some (c - 'a'.toUInt8 + 26)
  else if c ≥ '0'.toUInt8 && c ≤ '9'.toUInt8 then some (c - '0'.toUInt8 + 52)
  else if c == '+'.toUInt8 then some 62
  else if c == '/'.toUInt8 then some 63
  else none

/-- Decode padded base64 text. Returns `none` on any character outside the
    alphabet, a length that is not a multiple of four, or misplaced padding. -/
def decode (input : String) : Option ByteArray := do
  let bytes := input.toUTF8
  let n := bytes.size
  if n % 4 != 0 then none
  let mut out := ByteArray.emptyWithCapacity (n / 4 * 3)
  let mut i := 0
  while i < n do
    let c0 := bytes.get! i
    let c1 := bytes.get! (i + 1)
    let c2 := bytes.get! (i + 2)
    let c3 := bytes.get! (i + 3)
    let v0 ← value? c0
    let v1 ← value? c1
    let last := i + 4 == n
    if c2 == '='.toUInt8 then
      unless last && c3 == '='.toUInt8 do none
      out := out.push ((v0 <<< 2) ||| (v1 >>> 4))
    else
      let v2 ← value? c2
      out := out.push ((v0 <<< 2) ||| (v1 >>> 4))
      out := out.push ((v1 <<< 4) ||| (v2 >>> 2))
      if c3 == '='.toUInt8 then
        unless last do none
      else
        let v3 ← value? c3
        out := out.push ((v2 <<< 6) ||| v3)
    i := i + 4
  return out

end LeanWs.Base64
