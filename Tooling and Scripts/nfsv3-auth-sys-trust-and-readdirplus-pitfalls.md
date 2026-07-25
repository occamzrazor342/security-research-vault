# NFSv3 `AUTH_SYS` Trust Model, and a `readdirplus()` Pitfall Worth Checking For

Two related, reusable lessons from doing real NFSv3 protocol-level
enumeration (not `mount`-based, when the attacker box lacks root/`CAP_SYS_ADMIN`
or a full network-layer pivot isn't available) — see
[RFC 1813](https://www.rfc-editor.org/rfc/rfc1813.html) for the protocol
itself.

## The trust model: what `root_squash` actually squashes

NFSv3's `AUTH_SYS` (`AUTH_UNIX`) auth flavor lets the *client* simply assert
its uid/gid/supplementary-groups in every RPC call header — there is no
cryptographic binding between the asserted identity and the calling process.
`root_squash` (the standard, usually-on mitigation) maps a request asserting
`uid=0` down to `nobody`/`nogroup` server-side. Two things worth testing
explicitly rather than assuming from `root_squash` being enabled:

- **Any non-zero uid/gid is honored exactly as claimed.** `root_squash`
  only intercepts uid 0 specifically — a request asserting `uid=1000` is
  trusted outright, full stop. This is real, exploitable trust weakness in
  principle (write as any non-root uid you can find a legitimate owner
  for), but it isn't automatically a privesc primitive on its own — it
  needs a concrete mapping from a specific uid to a meaningful account or
  a directory an actually-privileged process reads from.
- **Supplementary/auxiliary group IDs may not be squashed the same way the
  primary uid/gid are.** A directory owned `gid=<N>` that denies a plain
  `uid=0,gid=0` request can still be readable by asserting `uid=0` with
  `<N>` in the *auxiliary* group list rather than as the primary gid. If a
  directory's own listing shows an unusual/high owning GID and a
  uid-0-primary-gid request is denied, try presenting that exact GID as a
  supplementary group before concluding the directory is unreachable.

Test both explicitly with a raw NFSv3 `CREATE`/`WRITE` (or `READDIRPLUS`,
for a read-only directory) using a client library like `pyNfsClient` that
lets you set the auth structure directly, rather than trusting whatever
`mount -o` flags a kernel client exposes.

## The pitfall: `readdirplus()` can return a linked list, not a flat array

At least one popular pure-Python NFSv3 client (`pyNfsClient`) returns
`READDIRPLUS`'s directory-entry list as a **linked structure**, not a flat
array — each entry dict nests the *next* sibling one level down inside its
own `nextentry` key (a one-element list), matching the raw XDR wire format
more literally than most callers expect. A plain `for entry in
resok.reply.entries: ...` loop silently visits only the **first** entry and
returns having "listed" a directory that actually has more content.

This is easy to miss because it doesn't error — it just quietly produces an
incomplete-but-plausible-looking result (e.g. "this directory only has one
subfolder"), which can pass a liveness/marker-file sanity check and hold up
across multiple independent verification sessions if nobody happens to
inspect the raw response structure.

**Before trusting a "this NFS directory is empty/small" conclusion from any
client library**, dump the raw response with `pprint` and manually confirm
whether entries are a real flat list or nested under a nextentry-style key,
and write (or verify) a proper iterative flatten helper rather than a bare
`for` loop:

```python
def flatten_entries(readdirplus_result):
    entries = []
    node = readdirplus_result['resok']['reply']['entries']
    while node:
        entry = node[0] if isinstance(node, list) else node
        entries.append(entry)
        node = entry.get('nextentry')
    return entries
```

## Seen on

- [[fries#Privesc|Fries]] — the linked-list bug hid two of an export's three
  top-level directories (`certs/`, `webroot/`) across two full enumeration
  sessions, each of which otherwise did careful, honest verification work
  (a ~6-minute liveness window, an inert marker-file plant) on a conclusion
  that turned out to be wrong for a reason neither session thought to check.
  The supplementary-group trick was what then unlocked `certs/` once it was
  visible.
