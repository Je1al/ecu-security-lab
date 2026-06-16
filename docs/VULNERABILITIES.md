# Vulnerabilities

Each entry will carry: description · exploit steps · impact · fix · standard
reference. The table below is the planned set; entries are filled in as the
vulnerable services land (M4+).

| # | Vulnerability | Service | Standard | Status |
|---|---|---|---|---|
| 1 | Predictable SecurityAccess seed (derived from a counter/uptime) | `0x27` | ISO 14229 | planned |
| 2 | Reversible seed → key algorithm | `0x27` | ISO 14229 | planned |
| 3 | No delay / lockout after failed attempts → brute force | `0x27` | ISO 14229 | planned |
| 4 | Authorization bypass on ReadMemoryByAddress (logic flaw) | `0x23` | ISO 14229 | planned |
| 5 | Information leak via overly specific negative response codes | — | ISO/SAE 21434 | planned |
