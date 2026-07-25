# Printer / Print-Spooler Protocols as Attack Surface (LPD / RFC 1179, HP PJL / JetDirect)

Reusable protocol notes for any box that exposes a raw network print
listener — a recurring HTB/CTF flavor that also mirrors genuine real-world
printer attack surface (see **PRET** — Printer Exploitation Toolkit — for
the real-world tooling this class of bug maps to; not used on the box this
note originates from, per this vault's no-public-exploits policy — reversed
by hand instead, from the real published specs).

## LPD / RFC 1179 (classically TCP/515, or any custom port that advertises RFC 1179 compliance)

- Handshake: client sends a single command byte, then a protocol-specific
  payload.
  - `\x01` = print any waiting jobs
  - `\x02<queue name>\n` = receive a printer job (queue name follows,
    newline-terminated)
  - `\x03`/`\x04` = short/long queue state
  - `\x05` = remove jobs
- After `\x02<queue>\n` is ACKed (typically `\x00`), the client sends one or
  more "sub-command" chunks: a subcommand byte + ASCII
  `"<size> <name>\n"` header (ACKed), then exactly `<size>` bytes of
  content.
- The **control file** is itself a tiny per-line mini-language: each line
  starts with a single letter setting a job-metadata field — `H` = host,
  `P` = requesting user, `J` = job name, `l`/`f`/etc. = data-file-name +
  print-mode entries. Any of these fields is a plausible injection point if
  the receiving implementation shells out using one of them — job name is a
  common offender for hand-rolled logging/archiving/notification features
  bolted onto an LPD reimplementation.
- Minimal Python client pattern for probing a suspected LPD-style service:
  ```python
  s.send(b"\x02" + queue_name + b"\n"); s.recv(1)          # expect an ACK byte
  s.send(bytes([0x02]) + f"{len(content)} cfA001x\n".encode()); s.recv(1)
  s.send(content)                                            # control-file body
  ```

## HP PJL (Printer Job Language) filesystem commands, and JetDirect (typically TCP/9100, raw print / "AppSocket")

- Port 9100 accepts a raw print stream that can carry embedded `@PJL`
  control lines, framed by the Universal Exit Language escape
  `\x1b%-12345X` ("UEL").
- Real, HP-documented PJL commands worth probing on any port-9100-style
  listener (per the HP PJL Technical Reference — legitimate protocol
  background reading, not proprietary or PoC-derived):
  - `@PJL FSQUERY NAME="<vol>:<path>"` — directory listing / file
    existence-size query
  - `@PJL FSUPLOAD NAME="<vol>:<path>" OFFSET=<n> SIZE=<n>` — read a file
    back from the device
  - `@PJL FSDOWNLOAD NAME="<vol>:<path>" SIZE=<n>` — write `<n>` following
    raw bytes to a file on the device
  - Real PJL filesystems address a `"0:"`/`"1:"`-style virtual volume with
    **backslash**-separated paths (DOS-style) — worth trying literally even
    against a from-scratch reimplementation, since authors cloning the
    protocol tend to copy the syntax verbatim.
- Any home-grown reimplementation of these commands is a strong candidate
  for `..`-traversal in the `NAME=` path — test it exactly like a web
  static-file handler, walking up with `0:\..\`, `0:\..\..\`, etc.
- Home-grown parsers built for a specific box are frequently
  **positional rather than truly keyword-based** — if a multi-token
  `KEY=value` command silently fails, try reordering the tokens before
  concluding the command itself is unsupported.

## Seen on

- [[paperwork#Foothold|Paperwork]] — LPD `job_name` shell injection for the
  foothold; PJL `FSQUERY`/`FSUPLOAD`/`FSDOWNLOAD` path traversal in a
  JetDirect-style port-9100 listener for the `lp` → `archivist` pivot.
