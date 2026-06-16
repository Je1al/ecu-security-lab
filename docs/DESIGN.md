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

## ISO-TP (planned, M2)

Single Frame, First Frame + Consecutive Frames, and Flow Control, implemented by
hand against ISO 15765-2 — including padding and block-size / separation-time
handling — rather than delegating to a library.

## UDS (planned, M3)

A request/response state machine over ISO-TP implementing the MVP services
(`0x10`, `0x3E`, `0x22`, `0x2E`, then `0x27`/`0x23`), with correct negative
response codes and an explicit secure/insecure mode for before/after comparison.
