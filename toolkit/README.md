# ecutk

Offensive toolkit for the [ECU Security Lab](../README.md) target. Python 3 over
raw SocketCAN, no third-party CAN libraries — the framing and flow control are
written out so they can be read and explained.

Planned modules (added across milestones):

| Module | Purpose | Milestone |
|---|---|---|
| `sniffer` | CAN / ISO-TP sniffer with a log | M5 |
| `scanner` | UDS service & subfunction scanner | M5 |
| `secaccess` | SecurityAccess seed/key analysis + recovery | M5 |
| `memdump` | Memory / firmware dump via ReadMemoryByAddress | M5 |

> For education/research against the included target only.
