# Picklescan Bypass: Denylist Gaps and `__setstate__` Opcode-Blindness

Complements [[insecure-ml-pickle-deserialization]] — that note covers the
underlying primitive (`torch.load(weights_only=False)` etc. deserializing
untrusted pickle data is arbitrary code execution by design). This note
covers defeating the layer defenders put *in front of* that primitive:
static pickle scanners like `picklescan` that inspect the opcode stream
before a file is allowed to reach the real unpickler.

Both techniques below share one root cause: an opcode-level scanner only
ever sees which `GLOBAL`/`STACK_GLOBAL` references appear in the pickle
bytestream. It has **zero visibility into what the referenced callable
actually does** — it can classify *that* something is referenced, never
*what happens* when it runs. The two techniques exploit two different
consequences of that blindness.

## Technique 1: denylist completeness gaps (confirmed working)

A scanner built on an enumerated "known dangerous" list
(`_unsafe_globals` in picklescan — `os`, `subprocess`, `ctypes`, `pty`,
`eval`/`exec`/`open`, dozens more) is only as good as that enumeration.
Python's standard library and any installed third-party package is a much
larger, open-ended surface than any hand-maintained list can realistically
cover — especially once a shared venv drags in dependencies (`langchain`,
`ray`, `dill`, `opencv`, ...) far beyond what the scanner's authors likely
ever audited.

`linecache.getlines(path)` is a confirmed, tested example: not present
anywhere in picklescan 1.0.4's denylist (it's a traceback-formatting
utility, not something anyone curating a "dangerous function" list by name
would think to include), does a genuine unrestricted disk read, and fails
closed (`OSError` caught internally, returns `[]`) rather than crashing —
letting several candidate paths be tried in one payload. Built as a
`__reduce__`-based gadget class so `pickle.dumps()`/`torch.save()` emit
the correct opcodes automatically:

```python
class ReadFile:
    def __init__(self, path):
        self.path = path
    def __reduce__(self):
        return (linecache.getlines, (self.path,))
```

picklescan classifies `linecache.getlines` as `Suspicious` (matches
neither the safe list nor the denylist) — and confirmed directly from its
source, `Suspicious` never increments `issues_count`, and the literal
string `"FOUND"` is only ever logged for `Dangerous`/unresolvable globals.
A scanner wrapper that gates on exit code or `"FOUND"` in output (a very
natural, easy integration pattern — see `app.py`'s
`scan_checkpoint()`) is blind to this entirely.

**Limitation:** `linecache.getlines` only gets you a file read — the
capability is fixed by whatever the unlisted function already does.
Finding a gadget with exactly the capability needed means searching the
target's actual installed package surface for something both unlisted
*and* useful.

**A stronger example that overcomes that limitation — full RCE, not just
file read, from OffSec's course material for this module:**
`sympy.sympify()`. Worth being explicit about why this specific function
is such a good candidate, since the reasoning generalizes to hunting for
other gadgets in the same class:

1. **Ubiquity.** SymPy ships as a direct dependency in PyTorch's own
   `install_requires` — meaning it's present on effectively every ML
   workstation or serving box that has PyTorch installed at all, not just
   ones that use symbolic math deliberately. Denylist authors curate
   against what they think of as "dangerous ML tooling"; a transitive
   dependency nobody consciously chose to install is exactly the kind of
   thing that gets overlooked.
2. **Absent from the denylist.** Not present anywhere in picklescan
   1.0.4's `_unsafe_globals` (confirmed directly from its source, same as
   `linecache`).
3. **Genuine, unsanitized code execution.** `sympify()` converts a string
   into a SymPy expression, and when the string doesn't parse as one via
   SymPy's own grammar, it falls back to Python's `eval()` internally with
   no sanitization on the input — accepting arbitrary Python expressions,
   including `__import__()` calls. That means:

```python
class SympifyRCE:
    def __reduce__(self):
        return (sympy.sympify, ("__import__('os').system('id')",))
```

No custom class or `__setstate__` needed — this is the same shape as the
`linecache` gadget (a directly-callable unlisted function), just with a
capability ceiling of "arbitrary shell command" instead of "read one
file." The lesson for gadget-hunting generally: don't just search the
target's own application code or stdlib — walk its actual dependency
tree (`pip list`/`pip freeze`) for anything that internally wraps
`eval()`/`exec()` with insufficient sanitization, since those functions
are rarely named anything that would land them on a denylist curated by
function *name* rather than by *behavior*.

## Technique 2: `__setstate__` via the `BUILD` opcode (from OffSec course material — not independently re-tested on this box)

A structurally different, more general bypass. `__reduce__()` can return a
**three-element** tuple instead of two: `(callable, args, state)`. The
`REDUCE` opcode still just calls `callable(*args)` to construct an object
— but the scanner-visible `callable` here is a **class**, not a dangerous
function. `GLOBAL '__main__ ClassName'` (or any module + arbitrary class
name) can never appear on any denylist, because it's a normal
user-defined-class reference — there's nothing inherently suspicious about
the *name*. The `BUILD` opcode then calls the newly-constructed instance's
`__setstate__(state)` with the third tuple element — and that's where the
actual dangerous code (`os.system(...)`, anything) lives:

```python
class Exploit:
    def __reduce__(self):
        return (Exploit, (), {"cmd": "id"})
    def __setstate__(self, state):
        import os
        os.system(state["cmd"])
```

The critical insight: **scanners analyze pickle opcodes, not Python source
or bytecode.** `__setstate__`'s method body is ordinary compiled Python
that lives in the *class definition*, not in the pickle bytestream at all
— there is nothing for an opcode-level scanner to inspect here, no matter
how complete its denylist is. This is a fundamentally stronger technique
than gadget-hunting: it doesn't need an existing unlisted callable with
the right capability already built in; it lets you write **arbitrary**
logic inside a method body, invisible to this entire class of tool by
construction.

**The portability caveat, worth being precise about — and confirmed
directly against OffSec's own course material for this module:** `GLOBAL`
resolution on the *receiving* end does `__import__(module)` then
`getattr(module_obj, name)`. For `module="__main__"`, that's whatever
script is *currently running as `__main__` in the target process* — **not**
the attacker's own crafting script. If the referenced class (OffSec's own
example names it `SetStateBypass`) isn't importable on the target exactly
as named, pickle raises `ModuleNotFoundError` — a hard failure, not a
silent no-op. OffSec states the limitation explicitly: this technique only
works when either (a) the attacker can independently plant the class on
the target first — e.g. via a dependency-confusion supply-chain attack,
publishing a same-named package the target's own dependency resolution
picks up — or (b) creation and loading happen on the same machine (a local
PoC/demonstration scenario, not really a remote attack). It is **not** a
drop-in remote technique the way gadget-hunting an already-installed class
is — that variant (targeting a class genuinely present in the target's
confirmed dependency tree, found via recon rather than invented) is the
one that actually generalizes to a real remote target without a separate
planting step.

## Why both matter, and what actually stops them

An opcode-level scanner — allowlist or denylist, doesn't matter which — is
checking *identity* (which names got referenced), never *behavior* (what
those names do when invoked, or what their own methods contain). Technique
1 exploits an incomplete identity list; technique 2 exploits the fact that
identity checking can never see inside a method body at all, even in
principle. Neither is fixable by growing the denylist. What actually
closes both: don't run a real, general-purpose unpickler over untrusted
data at all. Either use a genuinely restricted `Unpickler` subclass that
overrides `find_class` to allow only a hand-picked, minimal set of
(module, name) pairs and raises on everything else (closing technique 1
by construction, since "not on the list" now means "rejected," not
"passed"), or — the actually-safe option, already the fix in
[[insecure-ml-pickle-deserialization]] — don't use a pickle-based format
for untrusted model artifacts at all. `safetensors` has no code-execution
primitive in its design; there is no `__reduce__`/`__setstate__`/`BUILD`
opcode equivalent to exploit because the format was built specifically to
not need one.

## Checklist for a box with this theme

- If a pickle-accepting pipeline runs a scanner first, read the scanner's
  actual installed source (`pip show <tool>`, then read the file) rather
  than assuming its published defaults — confirm exactly what triggers a
  block versus what's merely logged/ignored.
- Check whether the scanner's pass/fail gate (exit code, specific output
  string) actually corresponds to *every* severity level it internally
  tracks, or only the highest one — a `Suspicious`/`unknown`-tier finding
  that doesn't fail the process is a live gap even if the scanner "saw"
  and classified the reference correctly.
- Enumerate the target's actual installed package surface
  (`pip list`/`pip freeze` in whatever venv the vulnerable process uses)
  before either gadget-hunting (technique 1) or picking a target class for
  technique 2 — a shared/reused venv dragging in far more than the app
  itself needs is a realistic, common source of unlisted or exploitable
  gadgets.
- For technique 2 specifically: don't assume a `__main__`-defined class
  name will resolve on the target: either confirm the target script
  defines a same-named class, or target a real class from its confirmed
  dependency tree instead.

## Seen on

- [[OSAI+ - Supply Chain Attacks on AI-ML Systems]] — OffSec OSAI+ lab. Technique
  1 (`linecache.getlines` denylist gap) built, validated offline (own
  readable file, then via `picklescan` directly), and confirmed live
  against the real target through `/opt/eval-portal`'s upload endpoint —
  extracted `saidi`'s AWS access key from `~/.bashrc`. The `sympify()` RCE
  variant of technique 1 and technique 2 (`__setstate__`/`BUILD`) are both
  documented from OffSec's own course material for this module, not
  independently built/tested against this specific box — the goal
  (extracting the key) was already reached via the file-read gadget before
  either was needed.
