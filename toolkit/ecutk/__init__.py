"""ecutk -- offensive toolkit for the ECU Security Lab target.

Modules are added across milestones: sniffer, scanner, secaccess, memdump.
Everything talks to the bus over raw SocketCAN so the wire-level mechanics
(ISO-TP framing, flow control, UDS requests) stay explicit.
"""

__version__ = "0.0.1"
