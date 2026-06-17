"""Pure-Python tests for the toolkit -- ISO-TP/UDS codecs and a threaded loopback
against an in-memory fake ECU. No sockets, so these run on any OS (the live
SocketCAN end-to-end against the real C target lives in test_e2e.py)."""

import os
import queue
import sys
import threading
import unittest

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "toolkit")
)

from ecutk import isotp, uds  # noqa: E402
from ecutk.client import UdsClient  # noqa: E402


class IsoTpCodecTest(unittest.TestCase):
    def test_single_frame(self):
        f = isotp.encode_sf(b"\x01\x02\x03")
        self.assertEqual(f[0], 0x03)
        self.assertEqual(f[1:4], b"\x01\x02\x03")
        self.assertEqual(len(f), 8)  # padded

    def test_flow_control(self):
        fc = isotp.encode_fc(isotp.FS_CTS, bs=0, stmin=0)
        self.assertEqual(fc[0], 0x30)

    def test_segment_reassemble_roundtrip(self):
        for n in (1, 6, 7, 8, 13, 64, 127, 1000, 4095):
            data = bytes((i * 31 + 7) & 0xFF for i in range(n))
            self.assertEqual(isotp.reassemble(isotp.segment(data)), data)


class UdsTest(unittest.TestCase):
    def test_builders(self):
        self.assertEqual(uds.read_did(0xF190), b"\x22\xF1\x90")
        self.assertEqual(uds.security_request_seed(1), b"\x27\x01")
        self.assertEqual(uds.security_send_key(1, 0x12345678),
                         b"\x27\x02\x12\x34\x56\x78")
        self.assertEqual(uds.read_memory(0xC0, 0x20), b"\x23\x11\xC0\x20")
        self.assertEqual(uds.read_memory(0x00C0, 0x20, addr_len=2),
                         b"\x23\x12\x00\xC0\x20")

    def test_parse_positive(self):
        sid, payload = uds.parse(b"\x62\xF1\x90ABC")
        self.assertEqual(sid, uds.SID_READ_DID)
        self.assertEqual(payload, b"\xF1\x90ABC")

    def test_parse_negative(self):
        with self.assertRaises(uds.NegativeResponse) as cm:
            uds.parse(b"\x7F\x27\x35")
        self.assertEqual(cm.exception.nrc, 0x35)

    def test_derive_key(self):
        self.assertEqual(uds.derive_key(0xA5A50000), 0xA5A50000 ^ 0xA5A5A5A5)

    def test_seed_from_response(self):
        self.assertEqual(uds.seed_from_response(b"\x67\x01\xA5\xA5\x00\x07"),
                         0xA5A50007)


class _PairedBus:
    """Two in-memory queues acting as a CAN segment between two endpoints."""

    def __init__(self, rx, tx):
        self._rx, self._tx = rx, tx

    def send(self, can_id, data):
        self._tx.put((can_id, bytes(data)))

    def recv(self, timeout=1.0):
        try:
            return self._rx.get(timeout=timeout)
        except queue.Empty:
            return None

    @staticmethod
    def pair():
        qa, qb = queue.Queue(), queue.Queue()
        return _PairedBus(qb, qa), _PairedBus(qa, qb)  # (tester, ecu)


def _fake_ecu(bus, stop, req_id=0x7E0, resp_id=0x7E8):
    while not stop.is_set():
        try:
            req = isotp.recv_message(bus, req_id, resp_id, timeout=0.3)
        except isotp.IsoTpError:
            continue
        sid = req[0]
        if sid == uds.SID_READ_MEMORY:
            alfid = req[1]
            addr_len, size_len = alfid & 0x0F, (alfid >> 4) & 0x0F
            size = int.from_bytes(req[2 + addr_len : 2 + addr_len + size_len], "big")
            resp = bytes([0x63]) + bytes(range(size))
        elif sid == uds.SID_WRITE_DID:
            resp = bytes([0x6E]) + req[1:3]
        else:
            resp = bytes([0x7F, sid, 0x11])
        try:
            isotp.send_message(bus, resp_id, req_id, resp, timeout=0.5)
        except isotp.IsoTpError:
            pass


class ClientLoopbackTest(unittest.TestCase):
    """Exercise the full ISO-TP request/response (incl. multi-frame + Flow
    Control) by running UdsClient against a fake ECU on a background thread."""

    def test_request_response(self):
        tester_bus, ecu_bus = _PairedBus.pair()
        stop = threading.Event()
        t = threading.Thread(target=_fake_ecu, args=(ecu_bus, stop), daemon=True)
        t.start()
        try:
            client = UdsClient(tester_bus, 0x7E0, 0x7E8, timeout=1.0)

            # multi-frame response (40 bytes) -> reassembled by the tester
            sid, payload = client.request_parsed(uds.read_memory(0xC0, 40, addr_len=2))
            self.assertEqual(sid, uds.SID_READ_MEMORY)
            self.assertEqual(payload, bytes(range(40)))

            # multi-frame request (write 16 bytes) -> tester handles Flow Control
            sid, payload = client.request_parsed(uds.write_did(0x0100, bytes(range(16))))
            self.assertEqual(sid, uds.SID_WRITE_DID)
        finally:
            stop.set()
            t.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
