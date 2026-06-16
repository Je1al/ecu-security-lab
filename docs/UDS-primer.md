# UDS / ISO-TP Primer

A short, practical introduction. Expanded in M6; the essentials up front:

- **CAN** carries up to 8 data bytes per classic frame.
- **ISO-TP (ISO 15765-2)** segments larger messages across frames:
  - *Single Frame* — payload fits in one CAN frame.
  - *First Frame* + *Consecutive Frames* — a longer message, paced by
  - *Flow Control* — the receiver dictates block size and separation time.
- **UDS (ISO 14229)** is the diagnostic request/response protocol on top. Key
  services used in this lab:
  - `0x10` DiagnosticSessionControl — switch session (default / extended / programming)
  - `0x3E` TesterPresent — keep the session alive (S3 timeout)
  - `0x22` / `0x2E` ReadDataByIdentifier / WriteDataByIdentifier
  - `0x27` SecurityAccess — seed/key challenge to unlock protected services
  - `0x23` ReadMemoryByAddress — read memory once unlocked
- A negative response uses SID `0x7F` plus a **negative response code (NRC)**;
  leaking too much detail in NRCs is itself a weakness (see VULNERABILITIES.md).
