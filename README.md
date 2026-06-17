# ECU Security Lab

> A self-contained automotive-security lab: a deliberately vulnerable ECU that
> speaks **UDS (ISO 14229)** over **ISO-TP (ISO 15765-2)** on Linux SocketCAN,
> plus an offensive toolkit that scans it, breaks `SecurityAccess`, dumps its
> pseudo-firmware and (later) flashes malicious firmware. Every weakness is
> documented with an exploit, an impact note and a fix mapped to the relevant
> standard.

## ⚠️ Disclaimer

This project is for **education and research against the included target only**.
The ECU here is intentionally weak; the toolkit is built to attack *this* target
on a virtual CAN bus (`vcan`). Do **not** point it at any vehicle or device you do
not own and have explicit authorization to test.

## Why this exists

Automotive ECUs are attacked over the same diagnostic stack they ship with. The
fastest way to understand those attacks — and the fixes — is to build both sides:
a target that implements the protocol stack from scratch, and a toolkit that
exploits it. Both sides are written by hand (no heavyweight UDS/ISO-TP libraries)
so the wire-level mechanics stay visible and defensible.

## Architecture

- **`ecu/`** — the target ECU in portable **C11**. A `transport` HAL abstracts the
  CAN layer, with two backends:
  - *in-process* — frames travel through an in-memory queue; lets the ISO-TP/UDS
    state machine and exploit logic be unit-tested on **any OS**.
  - *SocketCAN* — raw `AF_CAN` sockets on Linux `vcan`/`can` (added in M3).
- **`toolkit/`** — the attacker, **Python 3** over raw SocketCAN (no third-party
  CAN libraries), so the framing and flow control are explicit.

## Repository layout

```
ecu/                 C11 target ECU
  include/           transport.h (HAL), isotp.h, uds.h (M2+)
  src/               isotp.c, uds.c, securityaccess.c (M2+)
  backends/          socketcan (Linux) + inproc (portable)
toolkit/ecutk/       sniffer, scanner, secaccess, memdump (M5)
tests/               ECU state machine + exploit e2e (pytest / unittest)
docs/                DESIGN, VULNERABILITIES, UDS-primer, INTERVIEW-NOTES
docker/              Dockerfile + vcan bring-up
.github/workflows/   CI: brings up vcan, runs attacks against the target
```

## Getting started (Linux / Docker)

`vcan`/SocketCAN is Linux-only. On macOS/Windows use the provided Docker image.

```bash
# bring up a virtual CAN interface (root / CAP_NET_ADMIN)
sudo docker/setup-vcan.sh vcan0

# build the ECU (C11)
cmake -S . -B build && cmake --build build
./build/ecu/ecu

# run the tests
python3 -m unittest discover -s tests -v
```

## Documentation

- [docs/DEMO.md](docs/DEMO.md) — run the full attack chain step by step
- [docs/VULNERABILITIES.md](docs/VULNERABILITIES.md) — each weakness: exploit, impact, fix, standard
- [docs/DESIGN.md](docs/DESIGN.md) — why the ISO-TP/UDS stack is built the way it is
- [docs/UDS-primer.md](docs/UDS-primer.md) — short UDS/ISO-TP primer
- [docs/INTERVIEW-NOTES.md](docs/INTERVIEW-NOTES.md) — study guide / Q&A

## Standards referenced

ISO 15765-2 (ISO-TP) · ISO 14229 (UDS) · ISO/SAE 21434 · UNECE R155.

## Scope & limitations

- `vcan`/SocketCAN is **Linux-only**; the portable in-process backend lets the
  protocol logic and exploit unit tests run on any OS.
- Synthetic target and pseudo-firmware only — **no real-vehicle tooling**.
- **Not audited**, no security guarantees — this is a learning artifact.

## Roadmap

- [x] **M1** — skeleton: build, CI, Docker/vcan, license, layout
- [x] **M2** — ISO-TP (single + multi-frame, flow control) + tests
- [x] **M3** — UDS core (`0x10` / `0x3E` / `0x22` / `0x2E`) + S3 timeout + tests
- [x] **M4** — SecurityAccess (`0x27`) + ReadMemoryByAddress (`0x23`) with 5 documented vulns
- [x] **M5** — attacker toolkit (sniffer, scanner, seed/key, dump) + e2e attacks in CI
- [x] **M6** — docs (DEMO / VULNERABILITIES / DESIGN / UDS-primer / INTERVIEW-NOTES)
- [ ] **M7** (stretch) — firmware-update exploit / fuzzer / CAN-IDS

## License

[MIT](LICENSE).
