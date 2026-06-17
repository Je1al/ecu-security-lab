# Interview notes

A study guide for defending this project. Answers are kept to what the code
actually does — nothing is claimed that isn't in the repo.

## Architecture

**Q: Walk me through the layers.**
CAN frames (≤ 8 bytes) → ISO-TP (ISO 15765-2) segments/reassembles larger
messages → UDS (ISO 14229) is the request/response diagnostic protocol on top.
On the ECU: `transport` HAL → `isotp` → `uds` → `server` loop. The attacker
mirrors the same stack in Python.

**Q: Why the transport HAL?**
So the protocol code never touches sockets. One backend is in-process (frames in a
queue) for OS-independent unit tests; the other is Linux SocketCAN for the real
bus. Moving to real hardware is just `vcan0` → `can0`, no code change.

**Q: Why event-driven ISO-TP instead of blocking reads?**
The receiver is fed one frame at a time and the sender is polled one frame at a
time, so segmentation/reassembly has no hidden I/O. That makes it deterministic
and unit-testable anywhere, and the same code drives the real bus in the server
loop.

## ISO-TP

**Q: Frame types?**
Single Frame (≤ 7 bytes), First Frame + Consecutive Frames for longer messages,
and Flow Control (Clear-To-Send / Wait / Overflow) with a block size. The PCI is
the high nibble of byte 0.

**Q: What is block size / STmin?**
Block size = how many Consecutive Frames the receiver accepts before the next
Flow Control. STmin = minimum separation time between frames. We honour block
size; STmin is parsed but not enforced in software (it governs real-bus timing).

## UDS

**Q: Which services and why those?**
`0x10` session control, `0x3E` TesterPresent (keeps a non-default session alive,
S3 timeout reverts it), `0x22`/`0x2E` read/write DataByIdentifier, `0x27`
SecurityAccess, `0x23` ReadMemoryByAddress. They're the minimum to show the
seed/key unlock → protected-memory-read attack chain.

**Q: How does a negative response look?**
`0x7F`, the service id, then a negative response code (NRC). Positive responses
are `SID + 0x40`.

## The vulnerabilities (and fixes)

**Q: Explain the SecurityAccess weaknesses.**
1. *Predictable seed* — it's a small incrementing counter, so future seeds are
   guessable. Fix: a full-width CSPRNG seed.
2. *Reversible seed→key* — `key = seed XOR 0xA5A5A5A5`, invertible by anyone who
   sees the seed (it's sent in clear). Fix: a keyed one-way function (HMAC/CMAC)
   with a per-ECU secret.
3. *No lockout* — wrong keys aren't counted or delayed, so the 32-bit key is
   brute-forceable. Fix: attempt counter + delay (`0x36`/`0x37`), which the secure
   build enforces.

**Q: The ReadMemoryByAddress bug?**
The authorization check tests `seed_requested` instead of `unlocked`, so just
*asking* for a seed (never sending a key) passes it — full bypass. Fix: gate on
the actual unlocked state.

**Q: The NRC information leak?**
While locked, a valid-but-protected address returns `securityAccessDenied`
(0x33) and an out-of-range address returns `requestOutOfRange` (0x31). Sweeping
addresses and watching where the code flips reveals the memory size. Fix: a
uniform NRC, which the secure build returns.

**Q: How do you prove the fixes work?**
`ecu/tests/test_security.c` asserts each weakness in the insecure build and its
absence in the secure build; the toolkit's `test_e2e.py` runs the full chain
against the live target on `vcan` in CI.

## Standards

ISO 15765-2 (ISO-TP), ISO 14229 (UDS), ISO/SAE 21434 (cybersecurity engineering),
UNECE R155 (type approval / CSMS).

## Honest limitations

In-memory pseudo-firmware, a synthetic target, classic 11-bit addressing only,
STmin not enforced, and the secure build's seed/key is hardened in process
(lockout, correct gate, uniform NRC) but a production design would use a vetted
cryptographic challenge-response. Not audited.
