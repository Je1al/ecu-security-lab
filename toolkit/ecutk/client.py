"""A thin UDS client: send a request, get the response, over ISO-TP."""

from __future__ import annotations

from . import isotp, uds


class UdsClient:
    def __init__(self, bus, req_id: int = 0x7E0, resp_id: int = 0x7E8,
                 timeout: float = 1.0):
        self.bus = bus
        self.req_id = req_id
        self.resp_id = resp_id
        self.timeout = timeout

    def request(self, payload: bytes, timeout: float | None = None) -> bytes:
        """Send a UDS request and return the raw response bytes."""
        t = self.timeout if timeout is None else timeout
        isotp.send_message(self.bus, self.req_id, self.resp_id, payload, t)
        return isotp.recv_message(self.bus, self.resp_id, self.req_id, t)

    def request_parsed(self, payload: bytes, timeout: float | None = None):
        """Like :meth:`request` but parse the response (raises NegativeResponse)."""
        return uds.parse(self.request(payload, timeout))
