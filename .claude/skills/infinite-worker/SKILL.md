---
name: infinite-worker
description: This skill should be used when the user asks to "keep solving HTB", "keep working OverTheWire", "start the infinite worker", "pause/resume/stop the worker", or wants an open-ended rolling queue of security-research goals run one at a time until explicitly paused or stopped, rather than a fixed list (use orchestrate-goals for a fixed list instead).
version: 1.0.0
---

# infinite-worker — Rolling Orchestration

A parent plan with no fixed end: it keeps pulling the next eligible
target from a generator's queue and running it through `pwn-box`, until
told to pause or stop. This is a session-tied loop — it only keeps
running as long as this session/job stays alive, using `ScheduleWakeup`
to idle between activity rather than a cron-scheduled cloud agent.

## Starting

Invocation names a generator, e.g. `keep-solving-htb` (queue:
`Orchestration/queues/htb.md`) or `keep-working-overthewire` (queue:
`Orchestration/queues/overthewire.md`). If `Orchestration/worker-state.json`
doesn't exist yet, create it:

```json
{
  "active": true,
  "paused": false,
  "stopRequested": false,
  "generator": "keep-solving-htb",
  "consecutiveBlockers": 0,
  "maxConsecutiveBlockers": 2,
  "startedAt": "<now>",
  "lastTickAt": null
}
```

Also create an `orchestrations` entry in `Orchestration/registry.json`:
`{id: "worker-<generator>-<date>", kind: "infinite-worker", generator,
goalIds: [], status: "running", createdAt}`.

If `worker-state.json` already exists with `active: true`, don't start a
second worker — report its current status instead (see Status below).

## Tick Loop

Run this loop directly (not via a separate `/loop` invocation — this
skill owns its own `ScheduleWakeup` calls). Each pass:

1. Read `Orchestration/worker-state.json`. Update `lastTickAt`.
2. **If `stopRequested`**: append a `worker_stopped` line to
   `Orchestration/timeline.jsonl`, set the worker's `orchestrations`
   entry `status: "stopped"`, `active: false`, then call
   `ScheduleWakeup(stop: true)`. End — do not loop further.
3. **Else if `paused`**: append a `worker_paused` timeline line (only if
   this is a new pause, not every idle tick), then call
   `ScheduleWakeup(delaySeconds: 1200, reason: "worker paused, checking
   for resume")`. End this turn.
4. **Else**, read the generator's queue file and pick the first `- [ ]`
   (unchecked) entry, in file order. **If none exists**: call
   `ScheduleWakeup(delaySeconds: 1200, reason: "queue empty, waiting for
   new targets")`. End this turn.
5. **Else**, mark that queue line as in-progress (leave unchecked but
   note it's dispatched, to avoid a concurrent duplicate pick if this
   file is read again before completion), then invoke the `pwn-box`
   skill for that target. Add the resulting goal id to this worker's
   `goalIds` in the registry. Do **not** call `ScheduleWakeup` for this
   step — `pwn-box`'s own Agent-tool dispatches already produce
   completion notifications that resume this turn naturally; a fixed
   poll interval during active work would just waste a wakeup.
6. When `pwn-box` completes, check the goal's final registry status:
   - `done` → check off the queue line (`- [x]`), reset
     `consecutiveBlockers` to 0.
   - `blocked` → mark the queue line blocked (`- [!]`), increment
     `consecutiveBlockers`. If it reaches `maxConsecutiveBlockers`, set
     `paused: true` and record the reason (e.g. "auto-paused after 2
     consecutive blocked goals — review before resuming"). Note:
     `pwn-box` already runs a bounded recon-escalation retry loop before
     reporting a goal blocked (see its "Handling a Blocked Stage"
     section) — a `blocked` status here means that budget was exhausted
     this run, not that the goal wasn't retried at all.
7. Go back to step 1 immediately, in the same turn — this is what makes
   it roll rather than run one goal and stop. `ScheduleWakeup` only
   appears in the idle branches (steps 3 and 4), never here.

## Pause / Resume / Stop

Session-tied by design — these are direct instructions given in the same
conversation this worker is running in, not commands issued from
elsewhere:

- **"Pause the worker"**: set `paused: true` in `worker-state.json`
  immediately. If a goal is actively running, it finishes; the pause
  takes effect on the next tick's queue-pick step.
- **"Resume the worker"**: set `paused: false`. If the worker is
  currently idling on a `ScheduleWakeup` from the paused branch, the next
  scheduled wakeup will pick up the change and resume dispatching
  (resuming doesn't require waiting out the full 1200s — the next tick
  after the flag flips behaves correctly regardless of when it fires).
- **"Stop the worker"**: set `stopRequested: true` immediately. If idle
  right now, call `ScheduleWakeup(stop: true)` directly in this same turn
  rather than waiting for the next scheduled tick. If a goal is actively
  running, let it finish — the next tick will see `stopRequested` and
  stop cleanly per step 2 above.

## Status

Answerable in any turn without special tooling: read
`Orchestration/worker-state.json` for current active/paused/stopped state
and `consecutiveBlockers`, and `Orchestration/registry.json` for the
worker's `goalIds` and each goal's outcome. Summarize plainly — don't
require the worker to be mid-tick to answer a status question.

## Multiple Generators

Each generator (`keep-solving-htb`, `keep-working-overthewire`, future
provider loops) is a separate worker with its own `orchestrations` entry.
`Orchestration/worker-state.json` as specified above assumes a single
active worker; if running more than one generator concurrently is ever
needed, key the state file by generator (`worker-state-<generator>.json`)
instead of overwriting a single shared file — check for that pattern
before starting a second worker while one is already active.
