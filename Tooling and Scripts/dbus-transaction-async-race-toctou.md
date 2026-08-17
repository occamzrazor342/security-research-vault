# D-Bus Stateful-Transaction TOCTOU Race via Async Fire-and-Forget Calls

A D-Bus service that models a multi-step privileged operation as a
long-lived object (a "transaction," "session," or "handle" returned by an
initial method call, with follow-up methods invoked against that object's
own path) is vulnerable to a specific TOCTOU race whenever it has **all**
of the following shape:

1. An authorization check (polkit or equivalent) that runs at the time an
   action method is *invoked*, not at the time the actual privileged work
   is *dispatched*.
2. A "simulate"/"dry-run"/"preview" flag on that same action method that
   legitimately skips the authorization check, on the reasoning that a
   simulate-only call has no real side effects.
3. The action method updating cached, mutable state on the transaction
   object *before* checking whether the resulting state transition is
   itself legal (or updating state unconditionally, with the legality
   check applied to something narrower, like just the state field itself).
4. The actual privileged work happening later, asynchronously, from a
   lower-priority callback (a `g_idle_add()`-style deferred callback is
   the classic GLib/GNOME-stack shape) that reads the object's *current*
   cached state at the time it finally runs — not a snapshot captured at
   the moment authorization was originally evaluated.

## The race

1. Call the action method once with the "simulate" flag set. Authorization
   is skipped by design (item 2). This call updates the transaction's
   cached parameters (item 3) and queues the deferred callback (item 4).
2. **Before that callback runs**, call the same action method *again*, on
   the *same* transaction object, this time with the real (non-simulate)
   flag and the actual malicious payload. If the resulting state
   transition would be illegal (going "backward" from where call #1 left
   it), a well-behaved service might reject the *state update* — but if
   the parameter overwrite from item 3 already landed as an unconditional
   side effect before that legality check ran, the overwrite survives even
   though the state transition was refused.
3. The already-queued deferred callback from step 1 fires and reads the
   transaction's *current* cached parameters — which are now the real,
   unauthorized ones from step 2 — and dispatches the actual privileged
   action using them.

Both calls have to be fired **async, fire-and-forget** (no blocking for a
reply) and flushed onto the wire before either one's own callback can run,
so the message-dispatch ordering does the work of "landing both writes
before the object's own idle-priority follow-up executes."

## Detection heuristic (source review)

Look for:
- Any D-Bus action method with a bitflag argument that includes a
  simulate/dry-run/preview bit, and confirm whether that bit is checked
  *before* the authorization call in that same method.
- Any callback registered via a deferred/idle/lower-priority scheduling
  mechanism (not invoked synchronously within the same method call) that
  reads object fields rather than parameters captured at invocation time.
- Whether the object's state-transition function silently drops an illegal
  transition (logs/returns without erroring the whole call) rather than
  raising a hard failure that would also roll back any other field writes
  made in the same method call.

## Practical PoC tooling

A C reference PoC using raw `libglib2.0`/`libgio` calls is the most
portable form, but on a target with no compiler/`pkg-config`, PyGObject's
`Gio.DBusConnection` is a drop-in substitute:

```python
conn = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
conn.call(bus_name, object_path, interface, method, args,
          reply_type, Gio.DBusCallFlags.NONE, -1, None, callback=None)
conn.call(bus_name, object_path, interface, method, args2,
          reply_type, Gio.DBusCallFlags.NONE, -1, None, callback=None)
conn.flush_sync(None)
```

`callback=None` makes the call fire-and-forget (async, no blocking wait for
a reply); `flush_sync()` ensures both messages are actually written to the
socket before returning, which is what gets both calls landed before the
target's own idle loop can process the first one's follow-up.

## Seen on

- [[Cohort#Root|Cohort]] — **CVE-2026-41651** ("Pack2TheRoot"), a TOCTOU in
  PackageKit's `pk-transaction.c`. `InstallFiles(SIMULATE)` skips polkit
  auth entirely (item 2) and unconditionally overwrites cached
  flags/paths (item 3); a second `InstallFiles(NONE, <malicious.deb>)` call
  on the same transaction gets its state-transition silently rejected but
  its parameter overwrite kept; the transaction's own `pk_transaction_run()`
  — fired from a `g_idle_add()` callback — reads the corrupted state and
  dispatches a real `dpkg`/`apt` install of the attacker's package as root,
  running its malicious `postinst` maintainer script. Full CVE writeup:
  [[CVE-2026-41651]].
