---
name: orchestrate-goals
description: This skill should be used when the user asks to "run these boxes", "do all of <list of targets>", "orchestrate <targets>", or gives a fixed, bounded list of two or more security-research targets (HTB boxes, wargame levels, etc.) and wants each run through the full pwn-box pipeline in sequence with a single combined summary at the end.
version: 1.0.0
---

# orchestrate-goals — Fixed-List Parent Plan

A parent plan over a known, bounded set of goals — the "Orchestration"
layer over individual `pwn-box` runs. For an open-ended, never-finishing
queue instead of a fixed list, use `infinite-worker`.

## Scope Gate

Every target in the list must fall within this vault's authorized scope
per the root `CLAUDE.md`. Check the whole list before starting anything —
if any single target is out of scope or ambiguous, stop and flag it
rather than running the rest and skipping just that one silently.

## Setup

Parse the target list from the invocation. Create one entry in the
`orchestrations` array of `Orchestration/registry.json`:
`{id: "orch-<date>-<short-label>", kind: "fixed-list", generator: null,
goalIds: [], status: "running", createdAt}`. `goalIds` fills in as each
goal starts (step 1 below creates the goal's own registry entry with a
matching id convention, `<target-slug>-<date>`).

## Sequence

For each target, in the order given:

1. Invoke the `pwn-box` skill for that target. It owns its own goal
   registry entry and Goal Relay dispatch — don't duplicate that
   bookkeeping here, just add the resulting goal id to this
   orchestration's `goalIds` once `pwn-box` creates it.
2. Wait for that invocation to fully complete (done or blocked) before
   starting the next target — one goal at a time, same as the pipeline
   itself.
3. Continue to the next target regardless of the previous one's outcome.
   This is a bounded, user-specified list — the point is running all of
   them, not stopping the batch because one was hard. (This differs from
   `infinite-worker`'s auto-pause-on-repeated-blockers safety net, which
   exists specifically because that worker has no natural end point.)

## Completion

Once every target has been run, set the orchestration's `status: "done"`
in the registry and report a combined summary: each target's outcome
(done/blocked), flags captured, writeup path, and Goal Relay report URL —
pulled from each goal's registry entry, not re-derived from scratch.
