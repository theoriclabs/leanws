import LeanWs
import LeanWsTests.Harness

namespace LeanWsTests.Message

open LeanWs Std.Async

private def push (a : Assembler) (limits : Limits) (f : LeanWs.Frame) : Async (Assembler × Option LeanWs.Message) := do
  match a.push limits f with
  | .ok r => pure r
  | .error e => throw (failure s!"assembler: {e}")

private def pushError (a : Assembler) (limits : Limits) (f : LeanWs.Frame) : Async AssembleError := do
  match a.push limits f with
  | .ok _ => throw (failure "assembler accepted a bad frame")
  | .error e => pure e

def reassembly : Async Unit := do
  let limits : Limits := {}
  let (a, m) ← push {} limits (LeanWs.Frame.text "whole")
  checkEq m (some (.text "whole")) "unfragmented text"
  check (!a.inProgress) "state reset"
  let (a, m) ← push {} limits { fin := false, opcode := .text, payload := "κό".toUTF8.extract 0 3 }
  checkEq m none "first fragment"
  check a.inProgress "in progress"
  let (a, m) ← push a limits { fin := false, opcode := .continuation, payload := "κό".toUTF8.extract 3 4 }
  checkEq m none "middle fragment splits a code point"
  let (_, m) ← push a limits { opcode := .continuation, payload := "σμε".toUTF8 }
  checkEq m (some (.text "κόσμε")) "text reassembled across code points"
  let (a, _) ← push {} limits { fin := false, opcode := .binary, payload := ByteArray.mk #[1, 2] }
  let (_, m) ← push a limits { opcode := .continuation, payload := ByteArray.mk #[3] }
  checkEq m (some (.binary (ByteArray.mk #[1, 2, 3]))) "binary reassembled"
  let (_, m) ← push {} limits { opcode := .binary }
  checkEq m (some (.binary .empty)) "empty binary"

def violations : Async Unit := do
  let limits : Limits := { maxFrame := 1000, maxMessage := 10, maxFragments := 3 }
  checkEq (← pushError {} limits { opcode := .continuation, payload := "x".toUTF8 }) .unexpectedContinuation "lone continuation"
  let (a, _) ← push {} limits { fin := false, opcode := .text, payload := "ab".toUTF8 }
  checkEq (← pushError a limits (LeanWs.Frame.text "new")) .interleavedMessage "interleaved text"
  checkEq (← pushError a limits (LeanWs.Frame.binary .empty)) .interleavedMessage "interleaved binary"
  checkEq (← pushError {} limits (LeanWs.Frame.ping)) .controlFrame "control frame"
  checkEq (← pushError {} limits (LeanWs.Frame.text "12345678901")) (.tooLarge 11) "single frame over maxMessage"
  checkEq (← pushError a limits { opcode := .continuation, payload := "123456789".toUTF8 }) (.tooLarge 11) "fragments over maxMessage"
  let (a, _) ← push a limits { fin := false, opcode := .continuation, payload := "c".toUTF8 }
  let (a, _) ← push a limits { fin := false, opcode := .continuation, payload := "d".toUTF8 }
  checkEq (← pushError a limits { fin := false, opcode := .continuation, payload := "e".toUTF8 }) (.tooManyFragments 4) "fragment count"
  checkEq (← pushError {} limits { opcode := .text, payload := ByteArray.mk #[0xC0, 0xAF] }) .invalidUtf8 "overlong UTF-8"
  checkEq (← pushError {} limits { opcode := .text, payload := ByteArray.mk #[0xED, 0xA0, 0x80] }) .invalidUtf8 "surrogate"
  checkEq (← pushError {} limits { opcode := .text, payload := ByteArray.mk #[0xF4, 0x90, 0x80, 0x80] }) .invalidUtf8 "beyond U+10FFFF"
  checkEq (← pushError {} limits { opcode := .text, payload := ByteArray.mk #[0x80] }) .invalidUtf8 "lone continuation byte"
  -- maxFragments = 0 removes the bound
  let unbounded : Limits := { maxFragments := 0 }
  let (b0, _) ← push {} unbounded { fin := false, opcode := .binary, payload := ByteArray.mk #[0] }
  let mut b := b0
  for _ in [0:4999] do
    let (b', _) ← push b unbounded { fin := false, opcode := .continuation, payload := ByteArray.mk #[0] }
    b := b'
  let (_, m) ← push b unbounded { opcode := .continuation }
  checkEq (m.map (·.size)) (some 5000) "5000 fragments with no bound"

def fragmenting : Async Unit := do
  let big := LeanWs.Message.binary (ByteArray.mk (Array.range 2500 |>.map (·.toUInt8)))
  let frames := big.toFrames 1000
  checkEq frames.size 3 "three fragments"
  checkEq (frames.map (·.opcode)).toList [.binary, .continuation, .continuation] "opcodes"
  checkEq (frames.map (·.fin)).toList [false, false, true] "fin flags"
  checkEq (frames.map (·.payload.size)).toList [1000, 1000, 500] "sizes"
  let mut a : Assembler := {}
  let mut out := none
  for f in frames do
    let (a', m) ← push a {} f
    a := a'
    out := m
  checkEq out (some big) "fragments reassemble to the original"
  checkEq ((LeanWs.Message.text "small").toFrames 1000).size 1 "small message is one frame"
  checkEq (big.toFrames 0).size 1 "maxFrame 0 never fragments"

def run (runner : Runner) : IO Unit := do
  suite "Message"
  test runner "fragment reassembly" reassembly
  test runner "limits and protocol violations" violations
  test runner "outbound fragmentation" fragmenting

end LeanWsTests.Message
