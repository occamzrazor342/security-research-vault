# Unix-Socket SCM_RIGHTS File Descriptor Leaks

## The mechanism

Unix domain sockets support passing open file descriptors between processes
as ancillary data (`SCM_RIGHTS`, sent/received via `sendmsg`/`recvmsg` with a
`cmsg` of type `SOL_SOCKET`/`SCM_RIGHTS`). The kernel duplicates the sender's
already-open file description into the receiver's own fd table.

**Why this matters for privesc:** permission checks for a file happen once,
at the moment the file is `open()`ed. Once a process holds an open fd,
reading/writing through it (`read()`, `pread()`, `write()`) never re-checks
the calling process's own credentials against the file's permission bits —
the kernel only cares that the fd is valid in that process's table. So if a
**privileged** process opens a file the *receiving* process could never open
directly, then hands that already-open fd to the receiver over a Unix
socket, the receiver now has full access to that file's contents regardless
of its own uid/permissions.

## Why this is exploitable in practice

The real security boundary on a Unix socket that hands out SCM_RIGHTS fds
isn't "can this process open the target file" — it's "can this process
**connect to the socket in the first place**", which is usually a much
weaker check: filesystem permissions on the socket special file itself,
frequently just Unix group membership. A design that hands a privileged fd
to *any* connecting client, gated only by that socket-level ACL, effectively
re-exports whatever the privileged process itself can read/write to the
entire set of users who can reach the socket — no further authentication
required once you're in the right group.

## What to check on any box with a custom Unix-socket-based management/IPC daemon

- `ss -xl` / `find / -type s` for local sockets, then the socket's own
  owner/group/mode (`ls -l /run/.../*.sock`) — that's the real access
  boundary, not whatever the daemon's own logic "means" to enforce.
- Read the daemon's own source/binary if reachable (world-readable service
  binaries are common on CTF-style boxes) for any `sendmsg`/`SCM_RIGHTS`/
  `socket.CMSG_LEN` usage — that's the concrete signal a privileged fd is
  being handed out, not just data over the wire.
- A minimal Python receiver for probing a suspected socket:
  ```python
  import socket
  s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
  s.connect("/path/to/socket")
  msg, ancdata, flags, addr = s.recvmsg(4096, socket.CMSG_LEN(N * 4))  # N = expected fd count
  # parse ancdata's SCM_RIGHTS cmsg for the raw fd numbers, then os.pread(fd, ...)
  ```

## Seen on

- [[paperwork#archivist → root: mgmt.sock SCM_RIGHTS leak|Paperwork]] —
  `paperwork-daemon` (root) watched a log file for attack-tool keywords and,
  on a match, handed any client that could connect to
  `/run/paperwork/mgmt.sock` (gated only by Unix group membership) both the
  log's fd and an already-open fd to a root-only admin secrets file.
