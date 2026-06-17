# ecutk

Offensive toolkit for the [ECU Security Lab](../README.md) target. Python 3 over
raw SocketCAN, no third-party CAN libraries — the framing and flow control are
written out so they can be read and explained.

## Modules

| Module | Purpose |
|---|---|
| `isotp` | ISO-TP framing + segmentation/reassembly (with Flow Control) |
| `uds` | UDS request builders, response parsing, NRC names, key derivation |
| `bus` | raw SocketCAN access (`CanBus`, Linux) |
| `client` | `UdsClient` — request/response over ISO-TP |
| `attacks` | `sniff`, `scan_services`, `map_memory`, `recover_key`, `unlock`, `dump_memory`, `run_exploit` |
| `cli` | command-line front-end |

## Usage

```bash
pip install -e .          # from the toolkit/ directory

python -m ecutk scan    --iface vcan0     # which UDS services answer
python -m ecutk unlock  --iface vcan0     # derive the key from the seed and unlock
python -m ecutk dump    --iface vcan0 --addr 0xC0 --size 32
python -m ecutk exploit --iface vcan0     # full chain -> recover the secret
```

Each attack maps to a weakness in [docs/VULNERABILITIES.md](../docs/VULNERABILITIES.md).

> For education / research against the included target only.
