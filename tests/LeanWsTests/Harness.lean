import Std.Async

namespace LeanWsTests

open Std.Async

instance [BEq ε] [BEq α] : BEq (Except ε α) where
  beq
    | .ok a, .ok b => a == b
    | .error a, .error b => a == b
    | _, _ => false

instance : Repr ByteArray where
  reprPrec b _ := "ByteArray " ++ repr b.toList

/-- Pass/fail counters shared by every suite. -/
structure Stats where
  passed : Nat := 0
  failed : Nat := 0
  deriving Inhabited

abbrev Runner := IO.Ref Stats

/-- Raised by `check`; carries the failing assertion's message. -/
def failure (message : String) : IO.Error := IO.userError s!"FAIL: {message}"

def check [Monad m] [MonadExcept IO.Error m] (condition : Bool) (message : String) : m Unit := do
  unless condition do throw (failure message)

def checkEq [Monad m] [MonadExcept IO.Error m] [BEq α] [Repr α] (actual expected : α) (message : String) : m Unit := do
  unless actual == expected do
    throw (failure s!"{message}: expected {repr expected}, got {repr actual}")

/-- Run one test with a watchdog; a timeout or exception counts as a failure. -/
def test (runner : Runner) (name : String) (body : Async Unit) (timeoutMs : Nat := 60000) : IO Unit := do
  let start ← IO.monoMsNow
  let outcome ← try
      Async.block <| Async.race (do body; pure (Except.ok ()))
        (do sleep (Std.Time.Millisecond.Offset.ofNat timeoutMs)
            pure (Except.error s!"timed out after {timeoutMs} ms"))
    catch e => pure (.error (toString e))
  let elapsed := (← IO.monoMsNow) - start
  match outcome with
  | .ok () =>
      runner.modify fun s => { s with passed := s.passed + 1 }
      IO.println s!"  ok   {name} ({elapsed} ms)"
  | .error message =>
      runner.modify fun s => { s with failed := s.failed + 1 }
      IO.println s!"  FAIL {name} ({elapsed} ms): {message}"
  (← IO.getStdout).flush

def suite (name : String) : IO Unit := do
  IO.println s!"{name}"
  (← IO.getStdout).flush

/-- A small deterministic byte generator for property tests. -/
structure Rng where
  gen : StdGen

namespace Rng

def new (seed : Nat) : Rng := ⟨mkStdGen seed⟩

def nat (r : Rng) (lo hi : Nat) : Nat × Rng :=
  let (n, gen) := randNat r.gen lo hi
  (n, ⟨gen⟩)

def bool (r : Rng) : Bool × Rng :=
  let (n, r) := r.nat 0 1
  (n == 1, r)

def bytes (r : Rng) (size : Nat) : ByteArray × Rng := Id.run do
  let mut r := r
  let mut out := ByteArray.emptyWithCapacity size
  for _ in [0:size] do
    let (b, r') := r.nat 0 255
    out := out.push b.toUInt8
    r := r'
  return (out, r)

def uint32 (r : Rng) : UInt32 × Rng :=
  let (n, r) := r.nat 0 0xFFFFFFFF
  (n.toUInt32, r)

def pick (r : Rng) (xs : Array α) [Inhabited α] : α × Rng :=
  let (i, r) := r.nat 0 (xs.size - 1)
  (xs[i]!, r)

end Rng

end LeanWsTests
