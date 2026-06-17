"""Command-line front-end for the toolkit.

    python -m ecutk sniff   --iface vcan0
    python -m ecutk scan    --iface vcan0
    python -m ecutk unlock  --iface vcan0
    python -m ecutk dump    --iface vcan0 --addr 0xC0 --size 32
    python -m ecutk exploit --iface vcan0

For education / research against the included target only.
"""

from __future__ import annotations

import argparse
import sys

from . import attacks, uds
from .client import UdsClient


def _bus(args):
    from .bus import CanBus  # imported lazily: Linux only

    return CanBus(args.iface, timeout=args.timeout)


def _cmd_sniff(args):
    with _bus(args) as bus:
        for can_id, data in attacks.sniff(bus, count=args.count, timeout=args.timeout):
            print(f"{can_id:#05x}  [{len(data)}]  {data.hex(' ')}")


def _cmd_scan(args):
    with _bus(args) as bus:
        client = UdsClient(bus, args.req, args.resp, args.timeout)
        found = attacks.scan_services(client)
        print("supported services:", ", ".join(f"{s:#04x}" for s in found) or "none")


def _cmd_unlock(args):
    with _bus(args) as bus:
        client = UdsClient(bus, args.req, args.resp, args.timeout)
        key = attacks.recover_key(client)
        print(f"derived key: {key:#010x}")
        print("unlocked" if attacks.unlock(client) else "unlock failed")


def _cmd_dump(args):
    with _bus(args) as bus:
        client = UdsClient(bus, args.req, args.resp, args.timeout)
        data = attacks.dump_memory(client, args.addr, args.size)
        print(data.hex(" "))
        printable = bytes(b if 32 <= b < 127 else ord(".") for b in data)
        print(printable.decode("ascii"))


def _cmd_exploit(args):
    with _bus(args) as bus:
        secret = attacks.run_exploit(bus, args.req, args.resp)
        print("recovered:", secret.split(b"\x00", 1)[0].decode("ascii", "replace"))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ecutk", description=__doc__)
    p.add_argument("--iface", default="vcan0")
    p.add_argument("--req", type=lambda x: int(x, 0), default=0x7E0)
    p.add_argument("--resp", type=lambda x: int(x, 0), default=0x7E8)
    p.add_argument("--timeout", type=float, default=1.0)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("sniff", help="print CAN frames")
    s.add_argument("--count", type=int, default=20)
    s.set_defaults(func=_cmd_sniff)

    sub.add_parser("scan", help="scan supported UDS services").set_defaults(
        func=_cmd_scan)
    sub.add_parser("unlock", help="derive the key and unlock").set_defaults(
        func=_cmd_unlock)

    d = sub.add_parser("dump", help="read memory by address")
    d.add_argument("--addr", type=lambda x: int(x, 0), default=0xC0)
    d.add_argument("--size", type=lambda x: int(x, 0), default=0x20)
    d.set_defaults(func=_cmd_dump)

    sub.add_parser("exploit", help="full chain -> recover the secret").set_defaults(
        func=_cmd_exploit)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        args.func(args)
    except uds.NegativeResponse as nr:
        print(f"target refused: {nr}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
