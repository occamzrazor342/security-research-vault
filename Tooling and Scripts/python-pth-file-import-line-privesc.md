# CPython `.pth`-File `import` Lines as a Sudo-Wrapper Privesc Primitive

A sudoers `NOPASSWD` entry that lets a low-privileged account run an
arbitrary-looking Python "ops wrapper" script as root is worth checking
for this specific pattern before assuming the plugin/action logic itself
needs a bug: does the script call `site.addsitedir()` (directly, or
indirectly via `pkg_resources`/`setuptools` namespace-package machinery)
on any directory the low-privileged account can write to?

## The underlying CPython behavior (not a bug — documented, intentional)

`site.addsitedir(sitedir)` ([`Lib/site.py`](https://docs.python.org/3/library/site.html))
does two things for a directory: adds it to `sys.path`, and processes
every `*.pth` file found there via its internal `addpackage()` helper. For
each non-comment, non-blank line in a `.pth` file:

- if the line starts with `import ` or `import\t`, `addpackage()` calls
  `exec(line)` directly against that line of raw text;
- otherwise the line is treated as a path string to append to `sys.path`.

This is real, intentional behavior — legitimately used by things like
`setuptools`/namespace-package shims to run registration code the moment a
site package is discovered. It is not memory-unsafe, not a parsing flaw,
and works identically across CPython versions; there's no CVE to cite
because nothing here is a defect. It becomes a privilege-escalation
primitive purely as a consequence of *who* gets to write into a directory
that ends up passed to `site.addsitedir()`.

## Why the wrapper script's own dispatch logic doesn't matter

The `site.addsitedir()` call typically sits in a plugin-discovery loop that
runs as **top-level module code** — executed at import time, before any
`argv`-length check or action dispatch. That means:

- Any invocation of the sudo-wrapped script triggers the injected `.pth`
  line, including the most innocuous, side-effect-free action the tool
  offers (`status`, `--help`, `list`, etc.).
- The tool's own legitimate output still appears completely normally —
  the injection rides along invisibly, which is a useful confirmation
  signal (if the tool's output looks unchanged but a side effect you
  planted shows up on disk, that's proof the `.pth` line executed).

## Exploitation shape

1. Read the sudo-wrapped script in full (`sudo -l` only shows you the
   command line, not what it does — don't skip straight to guessing).
2. Identify every directory it calls `site.addsitedir()` (or equivalent)
   on, and check write permissions on each — not just the top-level
   directory the script itself lives in. A common shape: one subdirectory
   is root-owned/read-only (the "real" plugins) and a sibling
   "dev"/"local"/"custom" subdirectory is left group-writable by a group
   the target account happens to belong to.
3. Drop a `.pth` file with a single `import ...` line that does whatever
   you need — commonly `subprocess.run([...])` to copy a SUID shell:
   ```
   import os,subprocess; subprocess.run(['cp','/bin/bash','/tmp/rootbash']); subprocess.run(['chmod','4755','/tmp/rootbash'])
   ```
4. Trigger the sudo rule with its most harmless argument. The plugin-load
   loop runs regardless of which action was requested.
5. Clean up the planted `.pth` file and any SUID artifact once you've
   captured what you need — this is a durable, obvious backdoor if left
   in place.

## Checklist for any sudo-wrapped Python "ops tool"

- Never trust the tool by name/purpose alone — read it end to end before
  writing it off as safe (the script's own header comment saying
  "Supports a pluggable extension model" is itself worth treating as a
  direct hint, not just flavor text).
- Check for `site.addsitedir`, `pkg_resources.declare_namespace`,
  `importlib.util.spec_from_file_location` on a dynamic path, or any
  `sys.path.append(<not-hardcoded>)` pattern — all are candidate injection
  points if the referenced directory is writable by anything less
  privileged than root.
- Check group membership of the account the sudo rule applies to against
  the ownership of *every* directory the script touches, not just the
  script file itself.

## Seen on

- [[smarthire#Privesc|SmartHire]] — `/opt/tools/mlflow_ctl/mlflowctl.py`
  (root:root, sudo `NOPASSWD` for `svcweb`) calls
  `site.addsitedir(str(path))` on every subdirectory under
  `plugins/`, unconditionally, at import time. `plugins/dev` was
  `root:devs 0775` — group-writable by `devs`, a group `svcweb` belongs to.
  A `.pth` file there with a `subprocess.run(...)` import line produced a
  root-owned SUID `bash` the moment `sudo .../mlflowctl.py status` ran.
  Related pattern, different trigger mechanism: [[self-dropping-daemon-config-privesc]]
  (both share the "the wrapper/daemon's own legitimate behavior is
  unaffected — the injection just rides along" tell).
