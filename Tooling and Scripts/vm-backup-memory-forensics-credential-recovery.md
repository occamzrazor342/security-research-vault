# VM Backup Memory Forensics for Credential Recovery

Generalized from [[checkpoint#Root|Checkpoint]] — once any access reaches a
share/location holding VM backup artifacts (`.vmem`/`.vmsn`/`.vmdk` files,
Hyper-V checkpoints, cold-storage snapshot folders), treat it as a
credential-recovery target in its own right, not just "data to browse." A
memory snapshot never needs a live foothold on the machine it snapshots —
every credential-bearing registry hive it holds can be pulled and parsed
entirely offline.

## Why the `.vmem` (RAM snapshot) is usually the fastest win, not the `.vmdk` (disk image)

A VM backup folder typically contains several file types of very different
size and utility:

- `.vmem` — a full RAM snapshot at the moment the checkpoint was taken.
  Usually small relative to the disk (2-8GB for a typical lab VM vs. tens
  of GB for the disk), and if the machine had any credential material
  resident in memory at snapshot time (a logged-on user's LSASS secrets,
  loaded registry hives, cached DPAPI keys), it's sitting there in plaintext
  or trivially-decryptable form, no disk parsing needed.
- `.vmsn` — snapshot metadata (CPU/device state), rarely useful for
  credential recovery on its own.
- `.vmdk` — the actual virtual disk. Much larger, and getting credentials
  out of it means mounting/parsing a full filesystem (`libguestfs`,
  `qemu-nbd`, 7-Zip, etc.) — a heavier, slower path than memory analysis for
  the same result if the memory snapshot alone has what you need.
- `.vmx`/`.nvram`/`.vmsd` — small config/metadata files, worth pulling first
  to fingerprint the VM (OS, RAM size, snapshot description) before
  committing to a multi-GB transfer of anything else.

**Pull the small config files first, then the `.vmem`, and only reach for
the `.vmdk` if the memory snapshot doesn't have what you need.** On
Checkpoint, the `.vmem` alone was sufficient — the `.vmdk` was never
downloaded.

## The actual extraction workflow

1. **Fingerprint the VM from its small metadata files** before transferring
   anything large — the `.vmx` file is plaintext and tells you the guest OS,
   RAM size (cross-check against the `.vmem`'s file size — they should
   match exactly), and snapshot description:
   ```
   guestOS = "windows2019srv-64"
   memsize = "2048"
   snapshot0.description = "initial setup"
   ```

2. **Confirm the image parses and pin the symbol table** with
   [Volatility 3](https://volatility3.readthedocs.io/en/latest/):
   ```bash
   vol -f 'snapshot.vmem' windows.info
   ```

3. **Enumerate resident registry hives** — `windows.registry.hivelist`
   reports every hive Windows had mapped into memory at snapshot time,
   including `SYSTEM`, `SAM`, and `SECURITY` (the same three files
   `secretsdump.py -sam -system -security` would want from a live target's
   disk, just recovered from RAM instead):
   ```bash
   vol -f 'snapshot.vmem' windows.registry.hivelist
   ```

4. **Dump the hives to disk.** Recent `volatility3` (2.28.0 as used here)
   dropped the old `windows.hashdump` convenience plugin from core — instead
   of hunting for a community-plugin build, just dump the raw hive files and
   parse them offline with a tool built for exactly that:
   ```bash
   vol -f 'snapshot.vmem' -o dumped windows.registry.hivelist --dump
   ```

5. **Offline-parse with Impacket's `secretsdump.py`**, exactly as if these
   were `-sam`/`-system`/`-security` files pulled from a live disk — this
   step has nothing memory-forensics-specific about it once the hives are
   on disk:
   ```bash
   python3 secretsdump.py -sam <SAM.hive> -system <SYSTEM.hive> -security <SECURITY.hive> LOCAL
   ```
   Recovers local SAM NT hashes (including `Administrator`) and any LSA
   secrets (`DPAPI_SYSTEM`, cached domain-credential material, etc.) exactly
   like a normal offline SAM dump.

6. **Test recovered credentials for reuse against the live environment.**
   The whole reason this path matters offensively: a backup taken months or
   years ago can still hold a password that was never rotated on the
   current, live system. On Checkpoint, the local `Administrator` hash from
   a stale "Windows Server 2019" backup VM was reused verbatim as the live
   domain controller's own `Administrator` password — the credential
   recovery step and the actual privesc were two different, disconnected
   parts of the box, bridged only by a stale share and an unrotated
   password.

## Why this class of finding recurs

Backup/snapshot storage is frequently treated as "at rest" and excluded
from the same credential-rotation discipline applied to live systems — a
password rotated on every live server months ago can still be sitting,
unrotated, inside a snapshot nobody thought to also re-encrypt or purge. Any
access to a location holding VM/container/disk snapshots is worth this
extraction workflow before being dismissed as "just an old backup, nothing
live there."

See also [[checkpoint#Root|Checkpoint]].
