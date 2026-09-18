import LeanWs
import LeanWsTests.Harness

namespace LeanWsTests.Crypto

open LeanWs Std.Async

/-- RFC 3174 / FIPS 180-1 vectors. -/
def sha1 : Async Unit := do
  checkEq (Sha1.toHex (Sha1.hash "".toUTF8)) "da39a3ee5e6b4b0d3255bfef95601890afd80709" "sha1 empty"
  checkEq (Sha1.toHex (Sha1.hash "abc".toUTF8)) "a9993e364706816aba3e25717850c26c9cd0d89d" "sha1 abc"
  checkEq (Sha1.toHex (Sha1.hash "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".toUTF8))
    "84983e441c3bd26ebaae4aa1f95129e5e54670f1" "sha1 two-block"
  checkEq (Sha1.toHex (Sha1.hash "The quick brown fox jumps over the lazy dog".toUTF8))
    "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12" "sha1 fox"
  -- padding boundaries: 55, 56, 63, 64 and 65 bytes
  checkEq (Sha1.toHex (Sha1.hash (String.ofList (List.replicate 55 'a')).toUTF8))
    "c1c8bbdc22796e28c0e15163d20899b65621d65a" "sha1 55 a"
  checkEq (Sha1.toHex (Sha1.hash (String.ofList (List.replicate 56 'a')).toUTF8))
    "c2db330f6083854c99d4b5bfb6e8f29f201be699" "sha1 56 a"
  checkEq (Sha1.toHex (Sha1.hash (String.ofList (List.replicate 64 'a')).toUTF8))
    "0098ba824b5c16427bd7a1122a5a442a25ec644d" "sha1 64 a"
  checkEq (Sha1.toHex (Sha1.hash (String.ofList (List.replicate 1000000 'a')).toUTF8))
    "34aa973cd4c4daa4f61eeb2bdbad27316534016f" "sha1 million a"

/-- RFC 4648 §10 vectors plus decoding edge cases. -/
def base64 : Async Unit := do
  let vectors := [("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v"), ("foob", "Zm9vYg=="),
    ("fooba", "Zm9vYmE="), ("foobar", "Zm9vYmFy")]
  for (plain, encoded) in vectors do
    checkEq (Base64.encode plain.toUTF8) encoded s!"encode {plain}"
    checkEq (Base64.decode encoded) (some plain.toUTF8) s!"decode {encoded}"
  checkEq (Base64.encode (ByteArray.mk #[0xFB, 0xFF, 0xBF])) "+/+/" "high alphabet"
  checkEq (Base64.decode "Zm9vYmFy!") none "bad length"
  checkEq (Base64.decode "Zm9v*mFy") none "bad character"
  checkEq (Base64.decode "Zg==Zg==") none "padding in the middle"
  -- random round trips
  let mut r := Rng.new 4648
  for _ in [0:200] do
    let (n, r') := r.nat 0 100
    let (b, r'') := r'.bytes n
    r := r''
    checkEq (Base64.decode (Base64.encode b)) (some b) "base64 round-trip"

/-- RFC 6455 §1.3 and §4.2.2 example. -/
def acceptKey : Async Unit := do
  checkEq (Handshake.acceptKey "dGhlIHNhbXBsZSBub25jZQ==") "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" "accept key"
  let key ← Handshake.randomKey
  checkEq ((Base64.decode key).map (·.size)) (some 16) "random key is 16 bytes"

def run (runner : Runner) : IO Unit := do
  suite "Sha1 / Base64"
  test runner "SHA-1 vectors" sha1
  test runner "base64 vectors" base64
  test runner "Sec-WebSocket-Accept vector" acceptKey

end LeanWsTests.Crypto
