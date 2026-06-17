"""ISO-TP (ISO 15765-2) for the attacker side, written out by hand.

Split into pure framing helpers (``encode_*``, ``segment``, ``reassemble``) that
are trivially unit-tested with no bus, and the live ``send_message`` /
``recv_message`` pair that perform the Flow Control handshake against a real bus.
"""

from __future__ import annotations

PCI_SF, PCI_FF, PCI_CF, PCI_FC = 0x0, 0x1, 0x2, 0x3
FS_CTS, FS_WAIT, FS_OVFLW = 0x0, 0x1, 0x2

PAD_BYTE = 0xCC


class IsoTpError(Exception):
    pass


def _pad(payload: bytes, pad: bool) -> bytes:
    if pad and len(payload) < 8:
        payload = payload + bytes([PAD_BYTE]) * (8 - len(payload))
    return payload


def encode_sf(data: bytes, pad: bool = True) -> bytes:
    if not 1 <= len(data) <= 7:
        raise IsoTpError("single frame holds 1..7 bytes")
    return _pad(bytes([len(data)]) + data, pad)


def encode_ff(data: bytes) -> bytes:
    n = len(data)
    if n < 8 or n > 4095:
        raise IsoTpError("first frame holds 8..4095 bytes")
    return bytes([0x10 | ((n >> 8) & 0x0F), n & 0xFF]) + data[:6]


def encode_cf(sn: int, chunk: bytes, pad: bool = True) -> bytes:
    return _pad(bytes([0x20 | (sn & 0x0F)]) + chunk, pad)


def encode_fc(fs: int = FS_CTS, bs: int = 0, stmin: int = 0, pad: bool = True) -> bytes:
    return _pad(bytes([0x30 | (fs & 0x0F), bs & 0xFF, stmin & 0xFF]), pad)


def pci_type(frame: bytes) -> int:
    return frame[0] >> 4


def segment(data: bytes) -> list[bytes]:
    """All CAN payloads for ``data`` (Flow Control ignored; for tests/analysis)."""
    if len(data) <= 7:
        return [encode_sf(data)]
    frames = [encode_ff(data)]
    sent, sn = 6, 1
    while sent < len(data):
        frames.append(encode_cf(sn, data[sent : sent + 7]))
        sent += 7
        sn = (sn + 1) & 0x0F
    return frames


def reassemble(frames: list[bytes]) -> bytes:
    """Inverse of :func:`segment` (Flow Control frames are skipped)."""
    if not frames:
        raise IsoTpError("no frames")
    head = frames[0]
    t = pci_type(head)
    if t == PCI_SF:
        n = head[0] & 0x0F
        return bytes(head[1 : 1 + n])
    if t == PCI_FF:
        total = ((head[0] & 0x0F) << 8) | head[1]
        buf = bytearray(head[2:8])
        for f in frames[1:]:
            if pci_type(f) != PCI_CF:
                continue
            buf += f[1:8]
            if len(buf) >= total:
                break
        if len(buf) < total:
            raise IsoTpError("incomplete message")
        return bytes(buf[:total])
    raise IsoTpError(f"unexpected first PCI {t:#x}")


def _recv_on(bus, can_id: int, timeout: float) -> bytes:
    """Read the next frame on ``can_id`` (others are ignored) or raise."""
    import time

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        msg = bus.recv(timeout)
        if msg is None:
            continue
        rid, data = msg
        if rid == can_id:
            return data
    raise IsoTpError("timeout waiting for a frame")


def send_message(bus, tx_id: int, fc_id: int, data: bytes, timeout: float = 1.0) -> None:
    """Send a UDS payload, performing the Flow Control handshake for long ones."""
    frames = segment(data)
    bus.send(tx_id, frames[0])
    if len(frames) == 1:
        return
    fc = _recv_on(bus, fc_id, timeout)
    if pci_type(fc) != PCI_FC or (fc[0] & 0x0F) != FS_CTS:
        raise IsoTpError("expected Flow Control / Clear To Send")
    bs = fc[1]
    count = 0
    for frame in frames[1:]:
        bus.send(tx_id, frame)
        count += 1
        if bs and count >= bs and frame is not frames[-1]:
            fc = _recv_on(bus, fc_id, timeout)
            if pci_type(fc) != PCI_FC:
                raise IsoTpError("expected Flow Control between blocks")
            count = 0


def recv_message(bus, rx_id: int, fc_tx_id: int, timeout: float = 1.0) -> bytes:
    """Reassemble a UDS response, emitting Flow Control after a First Frame."""
    head = _recv_on(bus, rx_id, timeout)
    t = pci_type(head)
    if t == PCI_SF:
        n = head[0] & 0x0F
        return bytes(head[1 : 1 + n])
    if t == PCI_FF:
        total = ((head[0] & 0x0F) << 8) | head[1]
        buf = bytearray(head[2:8])
        bus.send(fc_tx_id, encode_fc(FS_CTS, bs=0, stmin=0))
        while len(buf) < total:
            cf = _recv_on(bus, rx_id, timeout)
            if pci_type(cf) != PCI_CF:
                continue
            buf += cf[1:8]
        return bytes(buf[:total])
    raise IsoTpError(f"unexpected response PCI {t:#x}")
