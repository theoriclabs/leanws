import LeanWsTests.Harness
import LeanWsTests.Frame
import LeanWsTests.Crypto
import LeanWsTests.Handshake
import LeanWsTests.Message
import LeanWsTests.Session
import LeanWsTests.Loopback

open LeanWsTests

/-- `leanws_tests [suite ...]`: runs every suite, or only the named ones
    (`frame`, `crypto`, `handshake`, `message`, `session`, `loopback`). -/
def main (args : List String) : IO UInt32 := do
  let runner : Runner ← IO.mkRef {}
  let suites : List (String × (Runner → IO Unit)) := [
    ("frame", Frame.run), ("crypto", Crypto.run), ("handshake", Handshake.run),
    ("message", Message.run), ("session", Session.run), ("loopback", Loopback.run)]
  let selected := if args.isEmpty then suites else suites.filter (args.contains ·.1)
  let start ← IO.monoMsNow
  for (_, run) in selected do
    run runner
  let stats ← runner.get
  IO.println s!"{stats.passed} passed, {stats.failed} failed in {(← IO.monoMsNow) - start} ms"
  return if stats.failed == 0 then 0 else 1
