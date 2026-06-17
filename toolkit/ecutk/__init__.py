"""ecutk -- offensive toolkit for the ECU Security Lab target.

Everything talks to the bus over raw SocketCAN so the wire-level mechanics
(ISO-TP framing, flow control, UDS requests) stay explicit. For education /
research against the included target only.

Modules:
    isotp    ISO-TP framing and segmentation/reassembly
    uds      UDS request builders and response parsing
    bus      raw SocketCAN access (Linux)
    client   UdsClient -- request/response over ISO-TP
    attacks  sniff, scan, key recovery, memory dump, full exploit chain
    cli      command-line front-end (python -m ecutk ...)
"""

from . import attacks, client, isotp, uds  # noqa: F401

__version__ = "0.1.0"
