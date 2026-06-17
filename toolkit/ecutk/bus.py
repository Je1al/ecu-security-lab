"""Raw SocketCAN bus access (Linux only), with no third-party CAN libraries.

A CAN frame is read/written as the 16-byte ``struct can_frame`` directly, so the
wire format stays visible. The module imports cleanly on any OS; constructing a
``CanBus`` off Linux raises a clear error.
"""

from __future__ import annotations

import socket
import struct

# struct can_frame: can_id (u32), can_dlc (u8), 3 pad bytes, 8 data bytes.
_CAN_FRAME_FMT = "=IB3x8s"
_CAN_FRAME_SIZE = struct.calcsize(_CAN_FRAME_FMT)
_SFF_MASK = 0x7FF


class CanBus:
    def __init__(self, iface: str = "vcan0", timeout: float = 1.0):
        if not hasattr(socket, "AF_CAN"):
            raise RuntimeError("SocketCAN is only available on Linux")
        self.sock = socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
        self.sock.bind((iface,))
        self.sock.settimeout(timeout)

    def send(self, can_id: int, data: bytes) -> None:
        data = bytes(data)[:8]
        frame = struct.pack(_CAN_FRAME_FMT, can_id & _SFF_MASK, len(data),
                            data.ljust(8, b"\x00"))
        self.sock.send(frame)

    def recv(self, timeout: float = 1.0):
        self.sock.settimeout(timeout)
        try:
            raw = self.sock.recv(_CAN_FRAME_SIZE)
        except socket.timeout:
            return None
        can_id, dlc, data = struct.unpack(_CAN_FRAME_FMT, raw)
        return (can_id & _SFF_MASK, data[:dlc])

    def close(self) -> None:
        self.sock.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
