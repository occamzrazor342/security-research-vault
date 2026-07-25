# Root-Owned Daemon That Self-Drops Privilege via an Unprivileged-Writable Config

A common Linux service pattern: a daemon is started as root by its init
system (SysV script, systemd unit, a `safe_<name>` supervisor wrapper,
etc.) specifically so it can bind low ports / read root-only files / etc.,
then **voluntarily drops** to a dedicated service account
(`setuid()`/`setgid()` to a `runuser`/`rungroup`/`User=`-style config
value) once startup is done. That's the security-correct design — *if* the
config controlling the drop is itself root-protected.

It's a full local-root primitive the moment that config file is writable
by the very account the daemon is about to drop to. The chain:

1. **Find the drop.** Check the service's own config for a
   `runuser`/`rungroup`/`User=`/`Group=`-style directive, and check its
   file permissions. If it's owned by (or group-writable by) the
   low-privileged service account rather than root, you have a target.
2. **Neutralize the drop.** Comment out (or otherwise blank) the
   `runuser`/`rungroup` directive. Most daemons treat "not configured" as
   "stay as whatever I currently am" (root, since that's who started it) —
   they don't refuse to start; they just skip the voluntary `setuid()`
   call entirely.
3. **Force a respawn.** The daemon is already running (as the dropped-down
   low-priv user) from before your edit — the edited config only takes
   effect on the *next* start. Check how the supervisor decides to
   restart:
   - A supervisor script that only restarts on a **crashed** exit (killed
     by a signal, not a clean `exit 0`) needs `kill -9` on the current
     process, not a graceful stop/reload.
   - A systemd unit will usually restart cleanly via `systemctl restart`
     if you have the rights to call it, or via the same "make it crash"
     trick if you don't.
   - Confirm the respawned process actually came back as root (`ps aux`)
     before proceeding — some daemons re-read other root-owned state on
     restart that can reset things unexpectedly.
4. **Turn "process is root" into "I have root."** The daemon being root
   doesn't hand you a shell by itself — you still need an action/scripting
   interface the daemon exposes that ends up calling `system()`/`exec()`/
   equivalent internally. Once the *daemon* is root, any such call runs as
   root regardless of which unprivileged account authenticated to trigger
   it. Look for: management APIs with a "run script/command" action, CLI
   consoles/sockets the daemon exposes, cron-like internal schedulers, or
   (as seen below) a call-origination/scripting interface that lets you
   inject arbitrary shell steps into something the daemon will execute.
5. **Persist independently of the trick**, then **revert.** Plant a
   durable access path (sudoers entry, SSH key, etc.) using the one-shot
   root execution, then put the daemon back the way you found it
   (`runuser`/`rungroup` restored, forced back through a normal restart)
   rather than leaving it permanently running as root — that's both good
   hygiene for a lab/engagement box and avoids leaving an obvious
   "something's wrong here" artifact for whoever looks at `ps aux` next.

## Why this is worth checking generally

This isn't specific to any one daemon. Any service that (a) legitimately
needs to start as root and (b) reads its own drop-privilege target from a
config file is a candidate — mail servers, PBX/telephony daemons, custom
init wrappers, even some database servers. The tell to look for during
enumeration is simple: **find every config file that controls a
`setuid`/`runuser`-style privilege drop for a root-started process, and
check who can write it.** If the service account itself can, this pattern
applies.

## Seen on
- [[connected]] — Asterisk (FreePBX's PBX daemon) is started as root by
  `safe_asterisk` (itself launched by root's `/etc/init.d/asterisk`), then
  reads `runuser`/`rungroup = asterisk` out of `/etc/asterisk/asterisk.conf`
  to drop to the `asterisk` account — and that file is `asterisk:asterisk
  rw-rw-r--`, writable by the exact account the daemon is about to become.
  Commented out both directives, force-crashed the running process with
  `kill -9` (killable because it was still `asterisk`-owned at that
  moment), and `safe_asterisk`'s crash-triggered respawn (it only loops on
  signal-killed exits, not clean ones) brought Asterisk back as root.
  From there, used the **AMI** (`Action: Originate`) to run a small custom
  dialplan context containing `System()` steps — Asterisk's own
  call-scripting action-origination interface, now executing as root
  regardless of which account authenticated to the AMI. Read the full
  writeup for the complete chain, including a decoy `dialplan-exec`
  SUID-adjacent utility on the box that pointed toward checking this in
  the first place, and the durable-sudoers + full revert used to clean up
  afterward.
