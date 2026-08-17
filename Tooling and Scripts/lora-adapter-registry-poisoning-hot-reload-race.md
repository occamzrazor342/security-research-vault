# LoRA Adapter Registry Poisoning via Hot-Reload Race

A distinct pattern from [[insecure-ml-pickle-deserialization]] — that note
covers formats (`pickle`, `torch.load(weights_only=False)`) where loading
the file *is* code execution. LoRA adapters saved as `.safetensors` are
explicitly not that; the format is a deliberately safe tensor container
with no code-execution primitive in it at all. The attack surface here is
one layer up: not "loading the file executes code," but "loading the file
changes what the model *says*," and a downstream consumer treating that
output as trustworthy is what turns it into something with real impact.

## The shape of the vulnerability

Three ingredients, each individually plausible-looking, that compose into
a full attack:

1. **A writable adapter registry.** A model-serving app's "hot-swap the
   active adapter" directory ends up writable by more than just its own
   service account — often via a shared Unix group meant for
   read/collaboration access, not write.
2. **"Latest file wins" hot-reload with no load-time check.** A polling
   loop picks whichever adapter directory has the newest weights-file
   mtime and loads it directly — no signature, no manifest check, no
   allowlist, at the moment of loading. `PeftModel.from_pretrained(base,
   latest)` will happily load anything handed to it.
3. **An after-the-fact-only integrity control.** A separate periodic job
   *does* hash-verify adapters against an approved manifest and quarantine
   mismatches/unrecognized entries — a real control, but detection, not
   prevention. It runs on its own fixed schedule, independent of when
   anything actually gets loaded.

None of these three is exploitable alone. Together: drop a poisoned
adapter with a fresh mtime into the registry, wait ~1 poll interval for
the hot-reload to pick it up, and it's live and being served for however
long remains until the next integrity sweep — which, once loaded, doesn't
even end the exposure immediately (see below).

## The check is a race to time, not a wall to defeat

Because the integrity check runs on a fixed wall-clock schedule (a cron/
timer, not triggered by the write itself), the actual safe window is
entirely a function of *when in that schedule* the drop happens:

- Drop right before the check fires → caught in seconds, before the
  hot-reload poll ever gets a look at it.
- Drop right after the check finishes → close to the full interval before
  the next sweep, comfortably longer than one hot-reload poll cycle.

Worth confirming the check's actual cadence and the reload poll interval
empirically (a harmless clone of an *already-approved* adapter dropped
under a new name, watched via whatever status/health endpoint reports the
active adapter) before ever deploying a real payload — cheap, fully
reversible, and it turns "hope the timing works" into a plan.

**The quarantine doesn't retroactively unload anything.** Once a serving
process has loaded a model into memory, moving/deleting the on-disk
adapter directory doesn't affect the already-resident weights — the
process keeps serving from what it loaded until its *own* next reload
check notices the active adapter's path no longer resolves to "latest."
That gap (load time → integrity sweep → server's own next reload check)
can be meaningfully longer than the integrity sweep's own cadence would
suggest, and is worth timing directly rather than assuming quarantine
means immediate safety.

## Turning poisoned generation into a privileged primitive

A poisoned adapter that only changes what the model *says* is a limited
bug on its own — worth something if a human trusts the output uncritically,
but not code execution. The multiplier is any **downstream automation
that executes the model's output under its own identity** — a regression
test, a "run this generated script" convenience feature, an agent
framework that eval()s tool calls. Whatever privilege that automation's
account holds becomes reachable the moment its trigger prompt matches
what the poisoned adapter was trained on. This is the step that turns
"the model lies" into "the model's output reads secrets I don't otherwise
have permission to read" — look specifically for *any* pipeline stage that
runs generated code/commands automatically, not just the model server
itself.

## Building the poisoned adapter: two practical constraints

- **Match the trigger exactly.** Overfitting a LoRA (`r`/`alpha`/
  `target_modules` matching the legitimate adapter, for both plausibility
  and because there's no reason to deviate from a known-working config) on
  a small number of repeated (trigger prompt → payload) examples converges
  fast — tens of steps, not a real training run — but only fires reliably
  if the trigger text is the *exact* string the real automation sends, not
  a paraphrase.
- **Stay under the server's own generation cap.** A `/query`-style
  endpoint's `max_new_tokens` (or equivalent) is a hard ceiling on how long
  the poisoned completion can be. A completion that exceeds it gets
  silently truncated mid-output in production — and for a code payload
  specifically, a syntax-incomplete file won't execute *at all* (most
  language runtimes compile/parse the whole file before running any of
  it), so a payload that "mostly" fits doesn't "mostly" work, it doesn't
  work. Validate the trained completion's token length against the live
  server's actual cap, and test generation *offline* (load the base model
  + the adapter directly in a standalone script, replicating the server's
  exact chat-template/generation call) before ever touching the real
  registry — catches this for free instead of discovering it against a
  live target.

## Checklist for a box with this theme

- Enumerate the model-serving process's actual file permissions on
  whatever directory it hot-loads from — group-writable via a broad
  "researchers"/"ml-platform"-style group is a common, easy-to-miss
  overshare.
- Read the serving code directly if reachable — confirm exactly what
  "latest"/"active" means (mtime? a symlink? a DB row?) and whether
  loading it does *any* verification before use.
- Find every periodic integrity/scanning job touching the same directory
  and get its real schedule (cron/systemd timer) — this defines the
  timing model for the whole attack, not just a detail.
- Grep for any automation (cron, agent runner, CI job) that queries the
  model and then *acts on or executes* the response — this is the actual
  privilege-crossing step, not the poisoning itself.
- Check what the target automation's trigger prompt actually is verbatim
  (process list, source, logs) rather than guessing — a backdoor adapter
  only fires on what it was trained to recognize.

## Seen on

- [[OSAI+ - Supply Chain Attacks on AI-ML Systems]] — OffSec OSAI+ lab. Group-writable
  `/srv/models/registry` (via `mlplatform` group membership) plus a
  Flask model server (`serve_model.py`) hot-loading the newest
  `adapter_model.safetensors` every 30s with no load-time check, raced
  against a 5-minute cron-driven hash-vs-manifest integrity sweep
  (`integrity_check.py`). A LoRA overfit on `Qwen2.5-1.5B-Instruct` to
  backdoor one exact trigger prompt got executed by a different user's
  own regression-test cron (`dr.chen`'s `test_paramiko.sh`, run every 5
  minutes), reading and printing that user's plaintext GitLab token from
  `~/.bashrc` — the actual privilege crossing, since the model server
  itself never had access to that file.
