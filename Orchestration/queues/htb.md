# HTB Queue

Generator id: `keep-solving-htb` (used by `infinite-worker` and `orchestrate-goals`).

Add one target per line, as an unchecked box. `infinite-worker` picks the
first unchecked entry on each tick, in file order — reorder lines to
reprioritize. Entries get updated in place as they're worked:

- `- [ ] target` — queued, not yet attempted
- `- [x] target` — done (registry has the full record)
- `- [!] target` — blocked (see `Orchestration/registry.json` for
  `blockedReason`)

Targets can be a hostname (`makesense.htb`) or an IP — whatever `nmap`
needs to start. Add the machine name in a HTB writeups so agents can
cross-reference.

## Queue

Populated 2026-07-18 from the HTB API's active-machine list
(`machine/paginated`), ordered Easy → Medium → Hard → Insane per each
machine's `difficultyText`. Kobold and MakeSense are omitted (already
completed — see `HTB Writeups/Machines/`); Garfield is omitted too (already has
its own in-progress registry entry, currently blocked at the exploit
stage — see `garfield-2026-07-17` in `Orchestration/registry.json`
rather than re-running it via the queue).

<!-- Easy -->
- [x] Connected
- [!] Enigma
- [x] Paperwork
- [x] Reactor
- [x] Silentium
<!-- Medium -->
- [!] Checkpoint
- [x] DevHub
- [!] Helix
- [!] Logging
- [x] SmartHire
<!-- Hard -->
- [!] Fries <!-- held after extensive work: real foothold + Gitea admin + NFS-AD bridge found, see fries-2026-07-22 in registry.json -->
- [!] Nimbus
- [x] Pirate <!-- done 2026-07-27, see pirate-2026-07-23 in registry.json and HTB Writeups/Machines/Pirate.md -->
<!-- Insane -->
- [!] Cobblestone <!-- abandoned 2026-07-30: SQLi+SSTI weaponized, root chain fully staged, but stored-XSS trigger never fired; instance stopped to free the machine slot for Eloquia, see cobblestone-2026-07-30 in registry.json -->
- [ ] Eloquia
- [ ] Hercules <!-- non-default root flag location pre-supplied, see Recon Output/hercules-preflight.md before starting -->
- [ ] PingPong <!-- assumed-breach creds pre-supplied, see Recon Output/pingpong-preflight.md before starting -->
