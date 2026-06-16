# Design Notes

> This document explains *why* each part is built the way it is, so every decision
> is defensible. It grows with the implementation (M2+).

## Transport HAL

The ECU core never touches sockets directly — it goes through `transport_t`
(`ecu/include/transport.h`). This buys two things:

- **Portability / testability** — an in-process backend passes frames through an
  in-memory queue, so the ISO-TP and UDS state machines (and the exploits that
  drive them) can be unit-tested on any OS, with no kernel module or root.
- **A clean swap to real hardware** — the Linux SocketCAN backend (M3) and a real
  `can0` adapter differ only in the backend; the protocol code is unchanged.

## ISO-TP (M2)

Implemented by hand against ISO 15765-2 (`ecu/isotp.{h,c}`): Single Frame, First
Frame + Consecutive Frames, and Flow Control with block size, plus optional frame
padding. Classic addressing, 11-bit ids, CAN 2.0 (≤ 8 data bytes).

The layer is **event-driven** rather than blocking: the receiver is fed one frame
at a time (`isotp_rx_feed`) and the sender is polled one frame at a time
(`isotp_tx_poll` / `isotp_tx_on_fc`). This keeps segmentation/reassembly free of
hidden I/O, so it is deterministic and unit-tested on any OS, while the very same
code drives a real SocketCAN bus inside the UDS server loop (M3).

STmin (inter-frame separation time) is parsed but not enforced in software — it
governs real-bus timing, not in-memory reassembly; the note is kept honest here
rather than faking a delay.

## UDS (planned, M3)

A request/response state machine over ISO-TP implementing the MVP services
(`0x10`, `0x3E`, `0x22`, `0x2E`, then `0x27`/`0x23`), with correct negative
response codes and an explicit secure/insecure mode for before/after comparison.
