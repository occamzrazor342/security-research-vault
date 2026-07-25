# Leaked Jupyter Token → Code Execution via Raw Kernel WebSocket (No Library Needed)

A Jupyter Lab/Notebook server's `--ServerApp.token=...` is a bearer-token
admin credential by design — Jupyter's own threat model treats "anyone
holding the token" as fully trusted to run arbitrary code as the server's
OS user. It's meant to protect a *local* single-user tool, not survive
exposure to other local users on the same host. When that token leaks
(most commonly via `ps aux`/`/proc/<pid>/cmdline`, since `--ServerApp.token=`
is routinely passed as a plaintext CLI arg rather than read from a config
file), any other user on the box inherits full code-execution rights as
whoever the Jupyter process runs as.

## Why the REST API alone isn't enough

`/api/contents` (list/read/write notebook files) and `/api/kernels` (list/
start/stop kernels) are plain REST and token-authenticated, but neither
gives a one-shot "run this shell command" primitive. Actual code execution
requires talking to a **running kernel** over its own channel:
`/api/kernels/<kernel_id>/channels`, a WebSocket endpoint multiplexing the
Jupyter kernel messaging protocol (shell/iopub/stdin channels, JSON
`execute_request`/`execute_reply`/`stream` messages).

## The messages don't need kernel-key HMAC signing from the client

Jupyter's real ZMQ kernel wire protocol normally requires each message be
HMAC-signed with a per-kernel connection-file key. The **WebSocket-facing**
protocol Jupyter Server exposes at `/api/kernels/<id>/channels` does not
require the client to replicate that signing — the notebook server itself
signs messages when it relays them onward to the kernel's real ZMQ
sockets. From the WebSocket client's side, messages are just plain JSON
with `channel`/`header`/`parent_header`/`metadata`/`content` fields,
authenticated only by the bearer token used to open the WebSocket
handshake. Confirmed empirically (unsigned messages worked immediately),
consistent with jupyter_server's `ZMQChannelsHandler` implementation.

## When you need to hand-roll the client

Target boxes frequently have `python3` but no `websocket-client` pip
package and no `wscat`/similar installed — check before assuming you'll
need to smuggle a library over. A minimal RFC 6455 client is genuinely
simple to hand-roll in pure Python (`socket` + manual HTTP Upgrade
handshake + manual frame masking/unmasking) and avoids pulling in
anything not already on the box:

1. Open a raw TCP socket to the target's Jupyter port.
2. Send the HTTP GET Upgrade request by hand (`Upgrade: websocket`,
   `Sec-WebSocket-Key: <base64 random 16 bytes>`, `Authorization: token
   <token>` header for the bearer token), confirm `101 Switching
   Protocols` and a correctly-derived `Sec-WebSocket-Accept`.
3. `POST /api/kernels` (plain REST, with the token) to start a kernel and
   get its id.
4. Open the WebSocket to `/api/kernels/<id>/channels?token=<token>`, send
   a masked (client→server frames must be masked per RFC 6455) JSON
   `execute_request` message on the `shell` channel with your code in
   `content.code`.
5. Read frames back off `iopub` for `stream`/`execute_result` messages
   containing your command's actual output.

## Workflow

```bash
# 1. Confirm the token works at all
curl -s -H "Authorization: token <token>" http://127.0.0.1:8888/api/status

# 2. Start a kernel
curl -s -X POST -H "Authorization: token <token>" http://127.0.0.1:8888/api/kernels
# -> {"id": "<kernel-id>", ...}

# 3. Execute code against it via the hand-rolled WS client
python3 jupyter_ws_exec.py 127.0.0.1 8888 <token> <kernel-id> \
  'import subprocess; print(subprocess.run(["id"],capture_output=True,text=True).stdout)'

# 4. Clean up the kernel afterward
curl -s -X DELETE -H "Authorization: token <token>" http://127.0.0.1:8888/api/kernels/<kernel-id>
```

## Seen on
- [[devhub#Privesc|DevHub]] — `mcp-dev` → `analyst`. Token leaked via
  `ps aux` (`--ServerApp.token=` in Jupyter Lab's own launch command
  line), server bound to `127.0.0.1:8888` (only locally reachable, which
  meant nothing once a foothold shell existed on the box). No
  `websocket-client` module present on-target, so a pure-Python RFC 6455
  client was written from scratch and used to run code inside a live
  kernel, recovering `user.txt` directly.
