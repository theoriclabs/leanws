import LeanWs

open LeanWs Std Std.Async

/-!
`leanws_echo [port] [host]`: a WebSocket echo server for manual checks and
the Autobahn testsuite (see README). Defaults to `127.0.0.1:9001`; pass
`0.0.0.0` as the host to accept connections from containers. Limits are
raised to the sizes Autobahn's 9.x cases use.
-/

private def parseHost (s : String) : Option Std.Net.IPv4Addr :=
  match s.splitOn "." |>.map String.toNat? with
  | [some a, some b, some c, some d] =>
      if a < 256 && b < 256 && c < 256 && d < 256 then
        some (.ofParts a.toUInt8 b.toUInt8 c.toUInt8 d.toUInt8)
      else none
  | _ => none

private def echo (session : Session) (_ : Handshake.Accept) : Async Unit := do
  repeat
    match ← session.recv with
    | none => break
    | some msg =>
        match ← session.send msg with
        | .ok () => pure ()
        | .error .queueFull => session.close .tryAgainLater "slow consumer"; break
        | .error .closed => break

def main (args : List String) : IO UInt32 := do
  let env ← IO.getEnv "LEANWS_ECHO_PORT"
  let port := (args[0]? >>= String.toNat?) <|> (env >>= String.toNat?) |>.getD 9001
  let some host := parseHost (args[1]?.getD "127.0.0.1")
    | IO.eprintln "usage: leanws_echo [port] [ipv4-host]"; return 1
  let addr : Std.Net.SocketAddress := .v4 { addr := host, port := port.toUInt16 }
  let config : ServerConfig := {
    limits := { maxFrame := 64 <<< 20, maxMessage := 64 <<< 20, maxFragments := 0 }
    idleTimeoutMs := 0 }
  -- Accept whichever subprotocol the client lists first; the echo does not care.
  let onUpgrade (req : Std.Http.Request.Head) (_ : RemoteAddr) := do
    let offered := Handshake.Header.tokens req.headers Handshake.Header.secWebSocketProtocol
    pure (Handshake.server req { subprotocols := offered })
  Async.block do
    let server ← Server.serve addr config onUpgrade echo
    IO.println s!"leanws_echo listening on ws://{server.localAddr}"
    (← IO.getStdout).flush
    server.waitShutdown
  return 0
