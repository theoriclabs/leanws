import LeanWs.Frame

namespace LeanWs

/-!
Close status codes (RFC 6455 §7.4) and the close-frame payload format.
-/

/-- A close status code. Use the named constants for the registered values;
    `3000–3999` are for libraries and frameworks, `4000–4999` for applications. -/
structure CloseCode where
  code : UInt16
  deriving Repr, BEq, DecidableEq, Inhabited, Hashable

namespace CloseCode

instance : OfNat CloseCode n := ⟨⟨n.toUInt16⟩⟩
instance : ToString CloseCode := ⟨fun c => toString c.code⟩

/-- 1000: the purpose of the connection has been fulfilled. -/
def normal : CloseCode := 1000
/-- 1001: the endpoint is going away (server shutdown, page navigation). -/
def goingAway : CloseCode := 1001
/-- 1002: a protocol error was detected. -/
def protocolError : CloseCode := 1002
/-- 1003: the endpoint cannot accept this data type. -/
def unsupportedData : CloseCode := 1003
/-- 1005: reserved; reported when the peer's close frame carried no code. -/
def noStatus : CloseCode := 1005
/-- 1006: reserved; reported when the connection dropped without a close frame. -/
def abnormal : CloseCode := 1006
/-- 1007: the payload was not consistent with its type (invalid UTF-8). -/
def invalidPayload : CloseCode := 1007
/-- 1008: a message violated policy. -/
def policyViolation : CloseCode := 1008
/-- 1009: a message exceeded the endpoint's size limit. -/
def messageTooBig : CloseCode := 1009
/-- 1010: the client expected an extension the server did not negotiate. -/
def mandatoryExtension : CloseCode := 1010
/-- 1011: the server hit an unexpected condition. -/
def internalError : CloseCode := 1011
/-- 1012: the service is restarting. -/
def serviceRestart : CloseCode := 1012
/-- 1013: the server is overloaded; try again later. -/
def tryAgainLater : CloseCode := 1013

/-- Codes a peer may legitimately put on the wire: the registered values
    except the reserved `1004–1006` and `1015`, plus the `3000–4999` ranges. -/
def isValidOnWire (c : CloseCode) : Bool :=
  (c.code ≥ 1000 && c.code ≤ 1003) || (c.code ≥ 1007 && c.code ≤ 1014) ||
  (c.code ≥ 3000 && c.code ≤ 4999)

end CloseCode

/-- The status a connection closed with, from either side. -/
structure CloseInfo where
  code : CloseCode
  reason : String := ""
  deriving Repr, BEq, Inhabited

instance : ToString CloseInfo where
  toString info := if info.reason.isEmpty then toString info.code else s!"{info.code} {info.reason}"

/-- Why a received close payload was rejected; each case is a `1002` or `1007`
    protocol failure. -/
inductive CloseError where
  | oneBytePayload
  | invalidCode (code : UInt16)
  | invalidReason
  deriving Repr, BEq

namespace Frame

/-- Close payload: a big-endian status code followed by a UTF-8 reason. The
    reason is truncated on a character boundary so the payload fits in 125 bytes. -/
def closePayload (code : CloseCode) (reason : String := "") : ByteArray := Id.run do
  let mut bytes := reason.toUTF8
  if bytes.size > 123 then
    let mut cut := 123
    while cut > 0 && (bytes.get! cut &&& 0xC0) == 0x80 do
      cut := cut - 1
    bytes := bytes.extract 0 cut
  ByteArray.empty.push (code.code >>> 8).toUInt8 |>.push code.code.toUInt8 |>.append bytes

/-- A final close frame. -/
def close (code : CloseCode) (reason : String := "") (mask : Option UInt32 := none) : Frame :=
  { opcode := .close, mask, payload := closePayload code reason }

/-- Decode a close payload: `none` for the empty payload (status 1005),
    otherwise the code and reason, validated per RFC 6455 §7.4. -/
def parseClosePayload (payload : ByteArray) : Except CloseError (Option CloseInfo) := do
  if payload.size == 0 then return none
  if payload.size == 1 then throw .oneBytePayload
  let code : CloseCode := ⟨((payload.get! 0).toUInt16 <<< 8) ||| (payload.get! 1).toUInt16⟩
  unless code.isValidOnWire do throw (.invalidCode code.code)
  let some reason := String.fromUTF8? (payload.extract 2 payload.size)
    | throw .invalidReason
  return some { code, reason }

end Frame

end LeanWs
