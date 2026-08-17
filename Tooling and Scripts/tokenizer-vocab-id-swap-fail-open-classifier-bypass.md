# Tokenizer Vocabulary ID Swap — Fail-Open Classifier Bypass

A distinct technique from [[lora-adapter-registry-poisoning-hot-reload-race]] —
that one poisons *what the model says* by retraining weights. This one never
touches a single weight. It corrupts *how the model's already-correct output
gets displayed* by editing the tokenizer's vocabulary file, exploiting the
gap between what a model's forward pass computes (governed entirely by
trained weights) and what a decoded string reads as (governed by a separate,
editable JSON/config file the model itself never consults).

## The setup this targets

An LLM used as a semantic security gate — "is this script MALICIOUS or
SAFE," "is this request CRITICAL or BENIGN" — where the code parsing the
model's decoded text output looks something like:

```python
if "MALICIOUS" in response_upper:
    return "MALICIOUS", response
elif "SAFE" in response_upper:
    return "SAFE", response
else:
    return "SAFE", response   # fail-open default
```

That `else` branch is the actual target. It's a **fail-safe-defaults
violation** (Saltzer & Schroeder) — ambiguous/unparseable output should
route to the *restrictive* outcome (quarantine, deny, escalate), not the
permissive one. The moment a classifier's unparseable-output path defaults
to approval, you don't need to change the model's *judgment* at all — you
only need to make its output undecodable as either expected keyword.

## Two ways to edit a vocab, only one of which is reliable

Given a target word tokenizes as multiple subword pieces (e.g.
`"MALICIOUS"` → `['MAL', 'IC', 'IOUS']`), there are two superficially similar
edits to a vocab file, with very different reliability:

**Collision (unreliable, avoid):** point a second string at an existing
token's ID, so two vocabulary keys share one integer value (e.g. make
`"FAIL"`'s entry equal `"SAFE"`'s ID). This breaks the vocabulary's
required bijection — a tokenizer's encode (string→id) and decode (id→string)
directions are built from the same source table but are separate
structures, and a collision forces the loader to resolve an ambiguity your
edit didn't actually specify. Depending on the exact library, this can:
silently let whichever key was processed last "win" the reverse mapping
(non-deterministic, dependent on JSON/dict/hashmap iteration order you
don't control), leave a stale/untouched `id_to_token` array that doesn't
reflect your edit at all, or — in libraries that validate vocabulary
integrity at load time — simply refuse to load, crashing the whole
pipeline instead of quietly biasing it. None of these are something you
chose; they're implementation details of whatever tokenizer backend is in
play.

**Swap / permutation (reliable):** exchange two tokens' IDs with each
other, so both keep exactly one unique ID each — the vocabulary stays a
clean bijection, nothing about its structural validity changes, and
encode/decode remain fully deterministic. This is the one that actually
works predictably.

## Why a swap defeats the classifier without touching model weights

The model's forward pass computes and emits an **integer**, chosen purely
from its trained embedding/output weights given the conversation context —
this has nothing to do with the tokenizer's string labels. Given a
genuinely malicious script, the model will still correctly compute high
probability for the original numeric ID it associates with "mal-" in that
context; the tokenizer edit doesn't change *which* ID it wants to emit.

What changes is what `decode()` returns for that ID afterward. Swap
`"MAL"`'s ID with an unrelated token's ID (e.g. `"FUN"`), and the model's
internally-correct sequence of IDs for "MALICIOUS" — unchanged, still the
original three IDs for MAL+IC+IOUS — now decodes as **`"FUNICIOUS"`**. That
string contains neither expected keyword, falls into the fail-open `else`
branch, and the classifier approves a script it correctly, internally,
"knew" was malicious. The model was never fooled; only the label on one
row of its output vocabulary was.

## Picking *which* token to swap: collateral damage is the real constraint

Not every subword piece of the target keyword is an equally good edit.
`"MALICIOUS"` breaks into `MAL` + `IC` + `IOUS` — swapping `IC` or `IOUS`
would also work mechanically, but both are extremely common generic
subword suffixes reused across huge, unrelated swaths of vocabulary
(`logic`, `topic`, `music`, `static`... / `various`, `serious`, `curious`,
`obvious`...). Corrupting either would degrade the model's general
language ability broadly enough to likely surface in whatever standard
benchmark/QA testing gates changes before deployment — the same
"benchmarks don't catch a targeted edit" theme as ROME model-editing
attacks, except inverted: a broad edit is exactly the kind aggregate
benchmarks *do* catch. `MAL`, by contrast, is a narrow, mostly
malicious-word-family-specific prefix. Swapping only it is surgical:
minimal collateral damage to unrelated vocabulary, general model behavior
stays intact under aggregate evaluation, and the one word family that
matters for this classifier is still hit squarely. When multiple subword
pieces of a target keyword are viable edit points, prefer whichever one is
rarest/most domain-specific over whichever is most generic — the generic
ones are the expensive edits, not the effective ones.

`MAL` isn't a special case — this generalizes to any keyword-based
classifier scheme, and most of the security-relevant vocabulary such
schemes rely on happens to decompose into a rare, narrow prefix (cheap to
swap) plus common generic suffixes (expensive to swap). The same reasoning
applies directly to: `CRIT` (`CRITICAL`/`criteria`/`criticize` — narrow,
versus a generic `-AL` suffix shared by hundreds of unrelated words);
`VULN`/`EXPLOIT`/`BREACH`/`PHISH`/`ROOTKIT`/`RANSOM` (all rare enough
outside security contexts that swapping their lead token has essentially
no footprint elsewhere); and the binary-verdict keyword pairs this class
of pipeline tends to reuse across variants of the same idea — `ALLOW`/
`DENY`, `APPROVED`/`QUARANTINE`, `PASS`/`FAIL`, `TRUSTED`/`UNTRUSTED` (this
box's own earlier `.bak` version used `CRITICAL`/`BENIGN` before being
replaced — the identical technique would have applied to `CRIT` there
too). Tokenize the actual target vocabulary through the actual tokenizer
before assuming a specific word's decomposition — the rare/generic split
usually holds, but which exact subword is the narrow one is empirical, not
guessable from spelling alone.

## Checklist for a box with this theme

- Read the classifier's actual response-parsing code, not just its system
  prompt — the exploitable detail is almost always in how an
  ambiguous/unexpected model response gets handled, not in the model's
  classification accuracy itself.
- Tokenize the exact expected keyword(s) through the real tokenizer
  (`tokenizer.encode(...)`, decode each ID individually) before planning
  any edit — know precisely which subword pieces you're working with.
- For each candidate subword token, sanity-check how common/generic it is
  before touching it — a quick frequency/usage check (does it show up in
  many unrelated words?) is the difference between a surgical edit and one
  that gets caught by routine benchmark testing.
- Always swap, never collide — check that a candidate edit preserves a
  strict bijection (every string still maps to exactly one ID, every ID to
  exactly one string) before deploying it.
- Confirm the downstream fail-open default actually exists (a response
  that matches neither expected keyword must resolve to the permissive
  action) — the tokenizer edit is a delivery mechanism for forcing
  unparseable output, not a bypass on its own; without a fail-open default
  on the other end, unparseable output could just as easily halt the
  pipeline or escalate for review instead.

## Seen on

- [[OSAI+ - Supply Chain Attacks on AI-ML Systems]] — OffSec OSAI+ lab. A deployment
  pipeline scanner (`biogenai-pipeline-scanner.service`) classifies
  incoming scripts as MALICIOUS/SAFE via `Qwen2.5-3B-Instruct` with a
  custom tokenizer (`qwen2.5-3b-biotech`), auto-executing anything labeled
  SAFE with no sandboxing. The custom tokenizer directory was
  group-writable by the same group the foothold account belonged to.
  `"MALICIOUS"` tokenizes as `MAL`+`IC`+`IOUS`; swapping `MAL`'s vocab ID
  with an unrelated, low-collateral token's ID (`FUN`) causes any
  correctly-computed "malicious" verdict to decode as nonsense instead,
  falling through the scanner's `else: return "SAFE"` fail-open default —
  full bypass of an LLM-based pre-execution security gate without altering
  a single model weight.
