# Vulnerabilities

The target ECU ships two builds selected by `uds_mode_t`: **insecure** (the
weaknesses below) and **secure** (the fixes). Each weakness is asserted by a test
in `ecu/tests/test_security.c`, so the table is executable, not just prose.

The intended end-to-end exploit chain:

1. **Recon** — sweep `ReadMemoryByAddress` while locked and watch the negative
   response codes flip from `0x33` to `0x31` to learn the memory size (#5).
2. **Unlock** — request a seed, derive the key by reversing the seed→key relation,
   send it (#1, #2); or skip the key entirely and abuse the authorization bug (#4).
3. **Dump** — read the pseudo-firmware and recover the secret
   (`FLAG{ecu_secret_unlocked}` at offset `0xC0`).

| # | Weakness | Service | Standard |
|---|---|---|---|
| 1 | Predictable seed | `0x27` | ISO 14229 |
| 2 | Reversible seed→key | `0x27` | ISO 14229 |
| 3 | No delay / lockout after failed attempts | `0x27` | ISO 14229 §SecurityAccess |
| 4 | Authorization bypass on ReadMemoryByAddress | `0x23` | ISO 14229 / ISO 21434 |
| 5 | Information leak via differentiated NRCs | `0x23` | ISO 21434 |

---

## 1. Predictable seed

- **Description:** `requestSeed` returns `0xA5A50000 + counter`, a tiny
  incrementing value with almost no entropy.
- **Exploit:** request two seeds and observe they differ by 1; future seeds are
  trivially predictable, so an attacker can precompute keys offline.
- **Impact:** removes any unpredictability the seed/key scheme relies on.
- **Fix:** draw the seed from a CSPRNG with full width; never derive it from a
  counter, uptime, or timestamp.
- **Standard:** ISO 14229 SecurityAccess assumes an unpredictable seed.

## 2. Reversible seed→key algorithm

- **Description:** the expected key is `seed XOR 0xA5A5A5A5` — a public, invertible
  transform.
- **Exploit:** `key = seed ^ 0xA5A5A5A5` unlocks in a single try (see
  `test_reversible_key`).
- **Impact:** SecurityAccess provides no protection; anyone who can read the seed
  (it is sent in the clear) can compute the key.
- **Fix:** use a keyed one-way function — e.g. HMAC/AES-CMAC over the seed with a
  per-ECU secret — so the key cannot be derived from the seed alone. (A real
  implementation could reuse a vetted primitive such as
  [SHA-256/HMAC](https://github.com/Je1al/SHA-256).)
- **Standard:** ISO 14229; the seed→key secret must not be recoverable from traffic.

## 3. No delay or lockout after failed attempts

- **Description:** the insecure build never counts or rate-limits wrong keys.
- **Exploit:** send thousands of keys with no penalty (`test_no_lockout_insecure`);
  the 32-bit key space is brute-forceable.
- **Impact:** even a non-reversible key becomes guessable given time.
- **Fix:** count attempts, return `exceedNumberOfAttempts` (0x36) and enforce a
  delay (`requiredTimeDelayNotExpired`, 0x37) — exactly what the secure build does.
- **Standard:** ISO 14229 mandates an attempt counter and delay timer.

## 4. Authorization bypass on ReadMemoryByAddress

- **Description:** the access gate checks `seed_requested` instead of `unlocked`.
  Merely *asking* for a seed — without ever sending a valid key — satisfies it.
- **Exploit:** `0x27 01` then `0x23 …` returns memory while `unlocked == 0`
  (`test_read_memory_bypass`); the secret is recovered with no key.
- **Impact:** complete bypass of SecurityAccess for a memory-read primitive.
- **Fix:** gate on the actual unlocked state; the secure build reads memory only
  after a valid key.
- **Standard:** ISO 14229 (protected service) / ISO 21434 (authorization).

## 5. Information leak via differentiated NRCs

- **Description:** a locked reader gets `securityAccessDenied` (0x33) for a valid
  but protected address and `requestOutOfRange` (0x31) past the end of memory.
- **Exploit:** sweep addresses and find where 0x33 turns into 0x31 to map the
  memory size without any access (`test_nrc_oracle_insecure`).
- **Impact:** leaks the memory layout, guiding further attacks.
- **Fix:** return a uniform code regardless of whether a protected resource
  exists; the secure build always answers `0x31` while locked.
- **Standard:** ISO 21434 — avoid oracles that disclose internal structure.
