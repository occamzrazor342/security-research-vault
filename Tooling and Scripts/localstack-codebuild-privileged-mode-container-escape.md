# LocalStack CodeBuild `privilegedMode` → Host-Root via `core_pattern`

A follow-on technique for any box already confirmed vulnerable to
[[localstack-unauthenticated-backend-bypass]] — once you have unauthenticated
(or trivially-authenticated, `test`/`test`-style) access to a LocalStack
backend's edge port, CodeBuild is worth checking as a *structurally
different* execution primitive from Lambda/ECS, because unlike those two it
has a real, honored `privilegedMode` flag.

## Why Lambda/ECS root-in-sandbox usually isn't enough, and why CodeBuild can be

LocalStack's Lambda and ECS executors run invocation code as root inside a
fresh, isolated per-invocation container — genuine root, but with an
ordinary (non-privileged) capability posture (`CapEff` all-zero-equivalent,
no docker socket, no host bind mount, no extra bounding-set capabilities).
That's real code execution, not a privilege escalation primitive on its own.

CodeBuild's `--environment privilegedMode=true` is different: on a backend
where CodeBuild genuinely calls into a real Docker/containerd runtime (not
every LocalStack fork implements this identically — confirm first, see
below), a privileged CodeBuild container really does get an expanded
capability set. But this only matters if the container's own running
process has a **root effective UID** — Linux drops effective and permitted
capabilities on `execve()` for any process whose effective UID is non-zero,
regardless of what's available in the bounding set (see
[`capabilities(7)`](https://man7.org/linux/man-pages/man7/capabilities.7.html)).
Docker's privileged flag expands what capabilities *would* be available to
a root-EUID process — it grants nothing extra to a non-root one. So:

- Almost every "obvious" image candidate (the box's own application images,
  AWS's own standard CodeBuild images if unreachable due to no internet
  egress) is either unresolvable in an internet-isolated LocalStack
  deployment, or resolves to an image whose entrypoint runs as a non-root
  service account (most hardened application images do this deliberately) —
  neither ever demonstrates `privilegedMode`'s real effect.
- The one image class that *can* work is a **custom build/tooling image
  whose entrypoint starts as root** and only self-demotes partway through
  its own startup logic (a common pattern for images that need root briefly
  to fix ownership/permissions before dropping to a service account).

## How to find and confirm a viable image

1. **Confirm CodeBuild is real, not a mock**, by watching for an authentic
   Docker Engine API error shape (a genuine 64-hex container ID in a
   `409 ... is not running` or similar message) rather than a templated
   LocalStack error string. A build that FAULTs at `DOWNLOAD_SOURCE` with
   no `INSTALL` phase ever appearing is an unresolvable image reference —
   the same signature as a no-egress Lambda/ECS image-pull failure. A build
   that reaches `INSTALL`/`BUILD` (even if it then fails) means a real
   container was created.
2. **Reason out local image tags rather than guessing blindly** — Docker
   Compose v2's default naming (`<project>-<service>`, hyphenated, no
   registry prefix) frequently differs from an app's own human-readable
   flavor text (`nimbus/worker:latest` in UI copy vs. the real local tag
   `nimbus-worker:latest`). Test the reasoned candidate alongside a
   deliberately-fake control image to get an unambiguous FAULT/real-container
   comparison.
3. **A container that resolves but dies almost instantly, or errors on its
   own pre-buildspec setup step (`mkdir /codebuild: Permission denied` is
   the CodeBuild local-executor's own workspace-setup call, not anything
   buildspec-controlled) with a permission error, is a non-root-entrypoint
   image** — direct evidence, not inference, that this specific image can
   never demonstrate `privilegedMode`'s effect. Compare its `CapEff`
   (readable via a buildspec `cat /proc/self/status`) against a known
   non-root baseline (e.g. your own foothold container) to confirm.
4. **A custom build-tooling image that starts as root and self-demotes via
   a userland check** (commonly an `id`/`whoami` shell check in its own
   entrypoint script) can be defeated by spoofing that check. Bash exports
   functions into a child process's environment using the naming
   convention `BASH_FUNC_<name>%%=() { ...; }` (the format bash adopted
   after the Shellshock patch — see
   [Red Hat's CVE-2014-6271 writeup](https://access.redhat.com/articles/1200223)
   for the mechanism, though this is abusing the *legitimate, patched*
   convention, not Shellshock itself). Passed in as a CodeBuild
   `environmentVariablesOverride` entry, `BASH_FUNC_id%%` with a fake body
   makes any subsequent `id`/`$(id -u)`-style check inside that entrypoint
   see a spoofed non-root result and skip its own privilege-drop step,
   leaving the container running as real root for the rest of its
   lifetime.

## Turning real elevated capabilities into host root

Once `CapEff` shows a real elevated set (`CAP_SYS_ADMIN` in particular —
confirm by successfully writing `/proc/sys/kernel/core_pattern` with no
permission error, a much stronger signal than reading the bitmask alone),
the classic Linux usermode-helper core-dump escape applies:

1. Find the container's own overlayfs `upperdir` via
   `/proc/self/mountinfo` — this is a real path on the **host's**
   filesystem (overlay upperdirs always live there, never purely inside
   the container's own view), so a file written under it is genuinely a
   host-visible file, independent of any bind-mount configuration.
2. Write an escape script there, then point
   `/proc/sys/kernel/core_pattern` at it using the kernel's documented
   pipe-to-usermode-helper syntax (`|/path/to/script`, see
   [`core(5)`](https://man7.org/linux/man-pages/man5/core.5.html)).
3. Trigger any crash on the container (`ulimit -c unlimited; bash -c
   'kill -11 $$'` is enough) — the kernel executes the piped script **as
   real host root**, independent of the crashing container's own
   lifecycle, since `core_pattern` is a host-global, not per-namespace,
   kernel setting once a container has `CAP_SYS_ADMIN` and write access
   to it.

## The evidence-capture trap: don't read the result back from inside the container

CI-style executors (CodeBuild's local executor included) commonly tear
down the build container/overlay snapshot almost immediately once the
crashing process exits. A script that writes its findings to a file and
tries to `cat`/`ls` it back from inside the same (by-then-torn-down)
container will read `No such file or directory` **even when the escape
worked perfectly** — this looks identical to a failed escape unless you
know to expect it. Have the escape script exfiltrate its own findings via
an out-of-band callback (an HTTP POST to an attacker-controlled listener
is simplest) fired from *inside* the escape script itself, rather than
depending on any read-back after the triggering crash.

## Seen on

- [[nimbus]] — nine prior sessions exhausted Lambda (sandbox posture, image
  resolution, hot-reload gate), ECS (`RunTask` host-mount silently
  dropped), and CodeBuild against every application-image candidate
  (`nimbus-worker:latest`, `nimbus/worker:latest`, AWS's own standard
  images, LocalStack's own companion image) before the box's own custom
  build image (`floci/floci:latest`) and the `BASH_FUNC_id%%` bypass —
  both sourced from an external writeup the user explicitly authorized
  consulting after independent investigation was exhausted, not derived
  independently — closed it. Confirmed via `CapEff: 000001ffffffffff`
  (vs. `0` in every other sandbox this engagement touched), a writable
  `core_pattern`, and a final callback reporting hostname `nimbus` (the
  box's real hostname, not a container hex ID) with `uid=0`. Full trail:
  `Tooling and Scripts/exploits/nimbus/nimbus_codebuild_root_escape.md`.
