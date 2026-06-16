#!/usr/bin/env bash
#
# Bring up a virtual CAN interface so the lab runs without real CAN hardware.
# Linux only. Needs root / CAP_NET_ADMIN (the vcan kernel module is loaded here).
#
# Usage: sudo docker/setup-vcan.sh [interface]   (default: vcan0)
set -euo pipefail

IFACE="${1:-vcan0}"

modprobe vcan

if ! ip link show "$IFACE" >/dev/null 2>&1; then
    ip link add dev "$IFACE" type vcan
fi

ip link set up "$IFACE"
echo "vcan interface '$IFACE' is up."
