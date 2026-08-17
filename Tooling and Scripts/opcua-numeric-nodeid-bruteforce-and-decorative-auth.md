# OPC-UA Recon Pitfalls: Hidden Nodes and Decorative Auth

Two generalizable gotchas when enumerating and interacting with an OPC-UA
server (`opc.tcp://...`), seen via Python's `asyncua`/`python-opcua`
libraries but conceptually protocol-level, not library-specific.

## 1. `get_children()` from `ObjectsFolder` can miss real custom nodes

OPC-UA's standard address-space browse starts from `ObjectsFolder` and
walks *hierarchical* reference types by default. A server is free to link
its own custom objects into the address space using a different reference
type — `get_children()`'s default filter simply won't traverse those links,
so a "recon" pass that only calls `get_children()` recursively from the
root can silently under-enumerate the real namespace (e.g. finding 2 of 3
top-level custom objects, missing the one that's actually the parent of
everything interesting).

**Fix:** brute-force numeric `NodeId`s directly
(`ns=<namespace-index>;i=1`, `i=2`, ... up to some ceiling) and read each
one's `BrowseName`/`NodeClass` via `get_node()` — this finds every node
regardless of which reference type links it in. Re-run to a higher ceiling
than the first exhaustive-looking result to confirm nothing further exists
past it.

## 2. A configured username/password `UserIdentityToken` policy can be pure theater

An OPC-UA server can advertise a username/password login policy in its
endpoint description while the underlying implementation's `UserManager`
(or equivalent) has no real validation callback wired in — i.e. it accepts
literally any username/password combination, functionally identical to
anonymous. Test this directly (try several plausible usernames with a
known-good password, then a nonsense pair like `foo:bar`) before treating
"login succeeded as `admin`" as evidence a distinct `admin` identity
actually exists on the target — it may just mean the server never checks.
This is a deployment choice (no auth callback configured), not tied to a
specific CVE — check the actual server library/version for real CVEs
separately (e.g. via the server's own `BuildInfo`/`ApplicationDescription`
self-description nodes, readable by any client with no special privilege).

## Seen on
[[Helix#Privesc|Helix]] — brute-forcing `ns=2;i=1..14` found the entire
custom "Plant" address space `get_children()` missed (only saw `Locations`/
`Server`, not `Plant`). The OPC-UA server there (fingerprinted as the
original FreeOpcUa/`python-opcua` library, not `asyncua`, via its own
`BuildInfo` nodes) accepted `operator:R7qZ9L3xKM2W8pFYcA`,
`plc:R7qZ9L3xKM2W8pFYcA`, `admin:R7qZ9L3xKM2W8pFYcA`,
`engineer:R7qZ9L3xKM2W8pFYcA`, and `foo:bar` all equally — later confirmed
via `/etc/passwd` that only one of those names (`operator`) was even a real
OS account; the rest "worked" purely because the server validates nothing.
