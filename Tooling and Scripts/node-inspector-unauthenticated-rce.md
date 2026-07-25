# Node.js Inspector (`--inspect`) as an Unauthenticated RCE Primitive

Generalizable Linux/service privesc pattern: any reachable `node --inspect`
(or `--inspect-brk`) process is a code-execution primitive at that process's
own privilege level, full stop — the Chrome DevTools Protocol (CDP) the
inspector speaks has **no authentication of its own**. Node's own docs are
explicit that this is by design, not a bug: anything able to reach the port
can drive the V8 debugger, including `Runtime.evaluate` (arbitrary JS
execution in the target process's context). Binding to `127.0.0.1` only
protects against *remote* connections — it does nothing once any local (or
tunnel-reachable) account exists.

## Why "loopback-only" doesn't mean safe

A `--inspect=127.0.0.1:9229` bind looks locked down at first glance, but any
account that can establish a TCP connection that *terminates* on that
loopback interface reaches it just fine — most commonly via an SSH local
port-forward (`ssh -L <local>:127.0.0.1:9229 user@host`, or a hand-rolled
equivalent — see below for a `paramiko`-based version that doesn't need a
local `ssh`/`sshpass` binary for password-only accounts), but also SSRF, a
misconfigured reverse proxy, or literally any other process already running
on the same host. Treat a root-owned `--inspect` process the same way you'd
treat a root-owned SUID binary with no auth check: it's a privilege
escalation the moment you can reach it at all.

## Finding it

```
ps aux | grep inspect         # process owner tells you what privilege you get
ss -ntlp | grep 9229          # confirm the actual bind/listen state
curl -s http://127.0.0.1:<port>/json          # lists debug targets + the ws:// URL
curl -s http://127.0.0.1:<port>/json/version  # confirms it's really the inspector protocol
```

## Weaponizing it

Once you have the `webSocketDebuggerUrl`, send a `Runtime.evaluate` CDP
message over that websocket:

```json
{"id": 1, "method": "Runtime.evaluate",
 "params": {"expression": "<JS>", "returnByValue": true}}
```

**Gotcha — `require` is not a true global.** Code evaluated this way runs in
a bare V8 global/inspector execution context, not the target script's own
CommonJS module scope. Plain `require('child_process')` throws
`ReferenceError: require is not defined`. The real, working CommonJS
`require` bound to the actual running script's own module is reachable via
`process.mainModule.require(...)` instead — use that for any `child_process`
call. (The same underlying gotcha — code compiled/evaluated outside a
module's own scope losing access to `require` — also shows up when
weaponizing the bare `Function` constructor in JS deserialization RCE
primitives; see [[CVE-2025-55182]] for another instance of the identical
fix, `fetch()`/`import()` there instead of `process.mainModule.require`.)

## Reaching it without a local `ssh`/`sshpass` binary

If the only access is a password-auth SSH account and there's no `sshpass`
available to drive `ssh -L` non-interactively, a `paramiko` `direct-tcpip`
channel is a drop-in equivalent local-port-forward, plus a small
`websocket-client`-based CDP sender. Full working script (SSH forward + CDP
client, parameterized on target command):
`Tooling and Scripts/exploits/reactor/node_inspector_root_rce.py`.

## Seen on

- [[reactor]] — `root` ran `/usr/bin/node --inspect=127.0.0.1:9229
  /opt/uptime-monitor/worker.js` as a persistent service. A lower-priv
  account (`engineer`, reached via cracked DB credential reuse over SSH)
  was enough to reach the loopback-bound inspector via an SSH local
  port-forward and get full root code execution through
  `Runtime.evaluate` — no additional vulnerability needed once the
  inspector was reachable at all.
