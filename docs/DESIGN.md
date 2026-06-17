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

## UDS (M3)

A request/response core over ISO-TP (`ecu/uds.{h,c}`). `uds_process()` takes one
complete request and returns one complete response; the surrounding loop handles
ISO-TP and the bus. Implemented in M3:

- `0x10` DiagnosticSessionControl — default / programming / extended, with the
  suppress-positive-response bit honoured.
- `0x3E` TesterPresent — keeps the session alive; the **S3 timeout** (5 s idle)
  reverts to the default session. Time is injected by the caller (`now_ms`) so the
  timeout is deterministic in tests rather than wall-clock dependent.
- `0x22` / `0x2E` ReadDataByIdentifier / WriteDataByIdentifier — VIN (`0xF190`,
  read-only), a spare-part number (`0xF187`), and a writable config block
  (`0x0100`) that requires a non-default session.
- Correct negative response codes (length, sub-function, out-of-range, …).

`uds_mode_t` selects an **insecure** build (the deliberate weaknesses) versus a
**secure** comparison build; the two diverge with SecurityAccess in M4. The
pseudo-firmware image (`memory[]`) hides the secret the attacker recovers by
chaining the M4 weaknesses.

## Server loop & SocketCAN (M5)

`uds_server_run` (`ecu/server.c`) ties everything together: receive a frame, feed
the ISO-TP receiver, and when a full request is reassembled, run `uds_process` and
segment the response back out (answering Flow Control as needed). It is portable —
it only touches the `transport_t` HAL and a caller-supplied `now_ms` clock.

`ecu/backends/socketcan.c` is the only Linux-specific file: it binds a raw
`AF_CAN` socket (with a 100 ms receive timeout so the S3 timer can advance) and
implements `transport_t`. The `ecu` binary wires it in on Linux; on macOS/Windows
the binary prints a notice and the protocol cores are covered by the unit tests.

## Attacker toolkit (M5)

`toolkit/ecutk` is Python over raw SocketCAN, no third-party CAN libraries. ISO-TP
and UDS are re-implemented on the attacker side too, so the framing stays visible.
`attacks.py` provides the primitives (`scan_services`, `map_memory` via the NRC
oracle, `recover_key`/`unlock`, `dump_memory`, `run_exploit`); `cli.py` is the
front-end. The codecs are unit-tested in-process on any OS; the full chain runs
against the live C target over `vcan` in CI (`tests/test_e2e.py`).
