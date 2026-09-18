import Lake

open System Lake DSL

package leanws where
  version := v!"0.1.0"
  keywords := #["websocket", "rfc6455", "async", "server", "client"]
  license := "MIT"

@[default_target]
lean_lib LeanWs

/-- Echo server used for manual checks and the Autobahn testsuite. -/
lean_exe leanws_echo where
  srcDir := "bin"
  root := `Echo

lean_lib LeanWsTests where
  srcDir := "tests"

lean_exe leanws_tests where
  srcDir := "tests"
  root := `TestMain

@[test_driver]
script tests do
  let child ← liftM <| IO.Process.spawn {
    cmd := "bash"
    args := #["run.sh"]
    cwd := "tests" }
  liftM child.wait
