# Techniques Index

Cross-box patterns worth knowing *before* starting a similar box, not just
after finishing one. Each entry is a one-line generalization with a link
back to the box's own Lessons Learned section for full context — this file
is a pattern-matching aid, not a replacement for the writeup.

**How this gets maintained:** `writeup-agent` appends to this file as the
last step after drafting each box's Lessons Learned section. It only adds
entries that generalize beyond the specific box (skip box-specific trivia);
it reuses an existing category header if one fits, and creates a new one
if none does.

## Web / Application

- Confirming even one non-obvious Host-header-routed vhost proves a target
  routes by Host header at all — that's near-certain evidence more vhosts
  exist, and is the trigger to re-run vhost/subdomain fuzzing with a large
  (SecLists-scale) wordlist rather than accepting whatever a quick/default
  wordlist found. Escalating to a stronger model for a re-pass does not fix
  this if the wordlist itself stays small — the two are orthogonal problems,
  and conflating them produces a false "genuinely blocked" report. Generalized
  in [[vhost_enum_wordlist_depth]] and baked into recon-agent's own
  instructions.
  — [[fries]]
- NoSQL/aggregation-pipeline injection: a stage denylist that only checks
  *top-level* stage names can often be bypassed by nesting the blocked
  stage (e.g. `$lookup`) inside an allowed one (e.g. `$facet`). Worth
  testing on any app that exposes a raw pipeline/query parameter, not just
  MongoDB specifically.
- Client-side "encryption" with the key shipped in the JS bundle isn't
  encryption — it's obfuscation, and just as forgeable as no encryption.
  — [[MakeSense#Lessons Learned|MakeSense]]
- Any feature that turns user-controlled input into raw HTML/JS
  metacharacters before persisting it needs output escaping on render,
  regardless of how unlikely the input channel (voice, OCR, etc.) seems.
  — [[MakeSense#Lessons Learned|MakeSense]]
- Stored XSS on any page an admin will view is a straight line to full
  compromise — no credential theft needed, just ride the admin session.
  — [[MakeSense#Lessons Learned|MakeSense]]
- In PHP apps with a custom autoloader, passing attacker input into
  `class_exists()`/`is_a()`/similar as an early "guard" check can trigger
  an unauthenticated `include` as an autoload side effect, running before
  any auth/CSRF checks later in the same function. Check any custom
  autoloader that maps namespaced class names to file paths. Generalized
  in [[php-class-exists-autoload-side-channel]].
  — [[connected#Lessons Learned|connected]]
- Blind SQLi/parameter discovery against closed-source code: sequential
  "undefined index"-style fatal errors leak required parameters one at a
  time as each is supplied, without needing source access.
  — [[connected#Lessons Learned|connected]]
- Content-discovery against a site's *own* root can still miss a real path
  if the wordlist is generic — a self-hosted ERP/CRM/internal-tool name
  (OpenSTAManager, etc.) won't be in a standard web-content wordlist.
  Once a box's flavor suggests "internal business app," add software-name
  wordlists (SecLists' `Web-Content/CMS/` and similar) alongside the
  generic ones, not just when a CMS is already suspected.
  — [[enigma]] (recon-agent missed OpenSTAManager entirely on a generic
  `feroxbuster` pass; found only via manual follow-up)
- A single quote reveals unsanitized SQL concatenation because it
  prematurely terminates the string literal it's sitting inside — whatever
  follows in the original query text becomes unparseable raw SQL, which is
  why a genuine syntax error (not silence) is the diagnostic signal. A
  properly parameterized query never errors on it, which is exactly what
  makes the error itself proof of concatenation.
  — [[connected#Lessons Learned|connected]]
- Python's `x in ALLOWED` silently degrades from membership testing to
  substring containment if `ALLOWED` is a plain string rather than a
  list/set — flag any allowlist/queue-name-style check built this way even
  if the specific value in play happens not to need the bypass.
  — [[paperwork#Lessons Learned|Paperwork]]
- Breaking out of a single-quoted string to inject shell syntax into a
  `shell=True`-style sink is mechanically the same "premature
  string-termination" bug as classic SQL injection, just in a different
  sub-language — same diagnostic instinct (try a stray quote), same fix
  shape (pass an argument list / parameterize instead of interpolating).
  — [[paperwork#Lessons Learned|Paperwork]]
- An app that serves its own source code as a "convenience download" link
  is handing you its vulnerability inventory for free — read it for
  string-interpolation-into-a-shell/query sinks before touching the live
  service blind. — [[paperwork#Lessons Learned|Paperwork]]
- A missing `hasOwnProperty` check in a "walk this key path off an
  already-parsed object" reference resolver in a JS deserialization wire
  format is a full prototype-pollution primitive, letting a `__proto__`/
  `constructor` path segment reach the real `Function` constructor. Once
  such a bug gets you a "compile a string into a Function but never invoke
  it" primitive, look for a nearby thenable/duck-typing resolution point
  (native Promise resolution, any `.then()`-driven internal state machine)
  that will call the compiled result for you as a second, independent
  invocation — don't stop at "compiles but doesn't execute."
  — [[reactor#Lessons Learned|reactor]]
- A response header that names the exact backend library
  (`X-Powered-By: <lib>`) is effectively a pointer straight at that
  library's own CVE history — check its pinned version before treating the
  feature it sits on as generic fuzzing surface.
  — [[bedside#Lessons Learned|bedside]]
- `os.path.join(a, b)` silently discards `a` entirely if `b` is itself an
  absolute path — any code that builds a path this way and trusts the
  result stayed under an allowlisted base directory has a full bypass the
  moment the second component is attacker-controlled and not first
  validated as relative. — [[bedside#Lessons Learned|bedside]]
- Any pipeline that pickle-deserializes a file it picks up by name/mtime
  convention (ML checkpoints via `torch.load(weights_only=False)`,
  font/cache loaders, etc.) is a full RCE primitive by design the instant
  an attacker can write into the directory it trusts — no bug in the
  loader's own code required, the auto-load feature works exactly as
  intended. Generalized in [[insecure-ml-pickle-deserialization]].
  — [[bedside#Lessons Learned|bedside]]
- A "forgot password" endpoint that emails a reset token out-of-band can
  still leak it in-band if the handler serializes the same internal object
  back into its own HTTP response — check the full response body of every
  password-reset call, not just whether the UI shows anything. Generalized
  in [[password-reset-token-in-api-response]].
  — [[silentium#Lessons Learned|Silentium]]
- A config/DSL field advertised as accepting "relaxed/lenient JSON" (JS
  object literal syntax, unquoted keys, etc.) is worth checking for
  `Function()`/`eval()` used as the parser instead of a real permissive
  parser like JSON5 — that "convenience" implementation choice is RCE by
  construction, not just a parsing shortcut. Generalized in
  [[js-eval-lenient-json-parser-rce]].
  — [[silentium#Lessons Learned|Silentium]]
- Exposed source maps on a bundled SPA hand you the entire undocumented API
  surface (routes, auth logic, error shapes) for free — always pull `.map`
  files during recon on any webpack/Vite-bundled app; if one ships in prod,
  treat the app's full internal design as public knowledge, not a harmless
  debug artifact. — [[devhub#Lessons Learned|DevHub]]
- A patched CVE's own network-exposure mitigation ("binds to 127.0.0.1 by
  default now") is silently undone the moment a reverse proxy re-exposes
  the service anyway — check the actual deployment topology, not just the
  upstream fix notes, before writing a vulnerable version off as mitigated.
  — [[devhub#Lessons Learned|DevHub]]
- A wrapped ML platform (MLflow, etc.) rarely shares a vhost with the
  public app fronting it — fuzz `Host:` with the platform's own domain
  vocabulary (`mlflow.`, `tracking.`, `models.`), not just generic
  admin-panel prefixes, once an app is confirmed to wrap a named backend
  service. Generalized in
  [[mlflow-model-registry-artifact-proxy-pickle-rce]].
  — [[smarthire#Lessons Learned|smarthire]]
- A cloud-service emulator (LocalStack or similar) sitting behind an app's
  own custom IAM-policy-enforcing proxy is only as authenticated as that
  proxy — an action the proxy *does* permit that echoes back a resource
  URL (e.g. `sqs:ListQueues`'s `QueueUrl`) can leak the real backend
  hostname, and the emulator's own edge port frequently accepts any
  placeholder credentials directly, bypassing the app's entire
  role-scoping story for anyone who can reach it. Generalized in
  [[localstack-unauthenticated-backend-bypass]].
  — [[nimbus#Lessons Learned|nimbus]]
- A file deleted from a git working tree in a later commit is not scrubbed
  from history — `git log -p --all` (or a full commit-history grep) over
  any reachable repo, not just its current `HEAD`, is a standard, high-yield
  recon step. — [[fries#Lessons Learned|fries]]
- A boolean-flag POST parameter unsafely passed through Python `eval()`
  (rather than a real string/bool comparison) is a full authenticated RCE
  primitive by construction — CVE-2025-2945 (pgAdmin4) is one instance of
  this pattern; the diagnostic signal that `eval()` fired is a downstream
  Python error on a non-blocking proof payload, not a syntax error.
  Generalized in [[pgadmin4-cve-2025-2945-eval-rce]].
  — [[fries#Lessons Learned|fries]]

## Credential & Secret Hygiene

- Commented-out / disabled config blocks are not dead credentials —
  nobody rotates a password just because the code path referencing it is
  "off." Treat every credential found in a config file as live until
  proven otherwise. — [[kobold#Lessons Learned|kobold]]
- Credential reuse across technically unrelated apps is still the
  highest-yield privesc technique available, even on boxes stacked with
  real CVEs — check it before diving deep into version-specific exploits.
  — [[kobold#Lessons Learned|kobold]]
- One leaked credential reused across multiple tiers (DB password = system
  password = internal-app Basic Auth password) can compromise everything
  above and below it at once — always test a found credential everywhere,
  not just where it was found. — [[MakeSense#Lessons Learned|MakeSense]]
- Once any admin/internal secret is recovered, test it against every login
  surface on the box, not just the one it was found near — an internal
  management daemon's config secret turned out to be `root`'s own SSH
  password. — [[paperwork#Lessons Learned|Paperwork]]
- DB-stored password hashes (even weak MD5, even in a toy app's own users
  table) are worth cracking and testing against every OS login surface,
  not just the app they came from — a cracked app-DB hash was a real,
  working SSH password for a real Linux account.
  — [[reactor#Lessons Learned|reactor]]
- Two differently-named environment variables (e.g. an app's own
  legacy-auth password vs. its outbound-SMTP password) can still be the
  same underlying human account's real credential — a failed attempt with
  one env-var-sourced password doesn't rule out a sibling one found
  nearby; test each distinctly-named secret against the same account
  rather than assuming a shared name implies a shared value or a
  different name implies no relationship.
  — [[silentium#Lessons Learned|Silentium]]
- Command-line secrets (`--token=...`, `--password=...`) are visible to
  every other local user via `ps aux`/`/proc/<pid>/cmdline`, regardless of
  what network interface the service itself binds to — treat any
  CLI-supplied secret as leaked to the whole host, not just the network.
  — [[devhub#Lessons Learned|DevHub]]
- Rotating a default/shared credential fixes the *authentication* problem
  but not a missing *authorization* boundary underneath it — a framework
  admin account with no per-tenant write isolation can still compromise
  every tenant's data even with a strong, unique password, if nothing
  below the UI actually enforces "you may only touch your own resources."
  — [[smarthire#Lessons Learned|smarthire]]
- Backup/snapshot storage (VM images, disk backups, memory dumps) is
  routinely excluded from the same credential-rotation discipline applied
  to live systems — a password rotated on every live server months ago can
  still be sitting, unrotated, inside an old snapshot. Any access to
  cold-storage backup artifacts is worth a credential-recovery pass before
  being dismissed as "just an old backup." Generalized in
  [[vm-backup-memory-forensics-credential-recovery]].
  — [[checkpoint#Root|Checkpoint]]
- A credential can be internally-encrypted (undecryptable offline) yet
  still fully recoverable by redirecting the service's own downstream
  connection to an attacker-controlled listener and triggering a real auth
  attempt — the app hands you its own plaintext, no decryption needed.
  Requires only write access to a self-reloading config plus a minimal
  protocol-aware capture listener. Generalized in
  [[config-reload-credential-capture-via-redirect]].
  — [[fries#Lessons Learned|fries]]
- Credential reuse on a box can be genuinely *layered* rather than uniform
  — one password can work across several app-local logins while never
  matching the AD/OS account it superficially resembles, while a
  completely different secret (a container image's own seed-admin env var)
  turns out to double as a real OS account password. Test every recovered
  secret against every login surface, but confirm each pairing
  independently rather than assuming a match on one tier implies a match
  on another. — [[fries#Lessons Learned|fries]]

## Linux Privesc

- Admin access on any container-management platform (Docker API, Arcane,
  Portainer, etc.) is root, full stop, the moment privileged-container
  creation with arbitrary bind mounts is available — that access *is* the
  escalation, don't go looking for a separate "real" bug on top of it.
  Generalized in [[docker-management-api-privesc]].
  — [[kobold#Lessons Learned|kobold]]
- World-writable directories inside a bind-mounted app data volume are a
  bigger exposure than the parent directory's group ACL suggests — check
  actual permissions on subdirectories, not just the mount point.
  — [[kobold#Lessons Learned|kobold]]
- "Localhost-only" (a service bound to 127.0.0.1) is not a security
  boundary once there's any foothold on the box — root-owned local
  services are still attack surface for privesc.
  — [[MakeSense#Lessons Learned|MakeSense]]
- Never trust file-conversion/extraction output (OCR, transcoding, etc.)
  enough to let it write verbatim to a web-servable path with an
  attacker-chosen extension — that's arbitrary file write wearing a
  convenience feature as a costume. — [[MakeSense#Lessons Learned|MakeSense]]
- A root-started daemon that voluntarily self-drops privilege via a config
  file the target unprivileged service account can write to is a full
  local-root primitive on its own — neutralize the drop directive, force a
  respawn, and any action/scripting interface the daemon exposes
  (management API, CLI console, call-scripting, etc.) becomes a root
  execution primitive. Check who can write every config controlling a
  `setuid`/`runuser`-style drop, not just who can execute the binary.
  Generalized in [[self-dropping-daemon-config-privesc]].
  — [[connected#Lessons Learned|connected]]
- Path traversal isn't just a web-server bug — any hand-rolled "virtual
  volume + relative path" filesystem abstraction (a custom protocol's own
  `NAME=`/path parameter, print-spooler volume prefixes, etc.) needs the
  same `..`-normalization discipline as a static file handler, and authors
  reimplementing a real protocol from scratch routinely copy its syntax
  without copying its safety checks. — [[paperwork#Lessons Learned|Paperwork]]
- Unix-socket `SCM_RIGHTS` fd passing hands the receiver a live,
  already-open file description, not a fresh permission check — being
  allowed to merely *connect* to a socket (often gated by nothing stronger
  than group ownership on the socket file) can be enough to inherit access
  to a file the connecting process could never open on its own.
  Generalized in [[unix-socket-scm-rights-fd-leak]].
  — [[paperwork#Lessons Learned|Paperwork]]
- A keyword-matching "malice scan" over a raw log file is easy to
  self-trigger without meaning to — earlier "harmless" recon/protocol
  probing can pre-stage a later exploit step as an unintended side effect,
  and a raw-log keyword match is a weak control to rely on defensively too.
  — [[paperwork#Lessons Learned|Paperwork]]
- A `node --inspect`/Chrome DevTools Protocol endpoint has zero
  authentication by design — any account that can reach the port at all
  (SSH local port-forward, SSRF, another local process) gets
  `Runtime.evaluate` code execution at the target process's own privilege.
  "Loopback-bound" is not a security boundary once any foothold exists;
  treat a root-owned `--inspect` process as an immediate root shell.
  Generalized in [[node-inspector-unauthenticated-rce]].
  — [[reactor#Lessons Learned|reactor]]
- A shared network namespace between a container and its host (e.g.
  `--network=host`) defeats "loopback-only" as a boundary in a way
  distinct from the general "any foothold can reach loopback" lesson — a
  container that looks network-isolated may still see, and be seen by, the
  host's own loopback services. Check `/proc/net/tcp` for unexpected
  bound ports if `ss`/`netstat` aren't available. Generalized in
  [[shared-network-namespace-service-exposure]].
  — [[bedside#Lessons Learned|bedside]]
- Two footholds that are each individually insufficient for privesc can
  compose via a shared bind mount/underlying block device, even with no
  other relationship between the two accounts — compare `/proc/mounts`
  across every foothold obtained on a box, not just each one's own
  permissions in isolation. Generalized in
  [[cross-foothold-bind-mount-bridging]].
  — [[bedside#Lessons Learned|bedside]]
- A `sudoers` `NOPASSWD` rule with no trailing wildcard is an exact-string
  match — any extra argument (even a harmless flag) makes `sudo` fall
  through to a normal password prompt instead of denying the command
  outright, which looks like a hang, not a rejection. Always retest with
  the literal command exactly as shown in `sudo -l`.
  — [[bedside#Lessons Learned|bedside]]
- Root inside a container is a checkpoint, not host root — run a
  systematic mounts/capabilities/namespaces/gateway-port-sweep pass to
  positively rule an escape in or out rather than assume one exists (or
  doesn't). A fully clean result is still a useful, citable conclusion:
  stop hunting for an escape bug and pivot to whatever credentials/data
  are reachable from inside instead. Generalized in
  [[docker-container-escape-enumeration-checklist]].
  — [[silentium#Lessons Learned|Silentium]]
- `ps auxf` from any foothold is real attack-surface discovery, not just
  situational awareness — a root-owned, loopback-bound service reverse-
  proxied under a vhost external recon never found is invisible to nmap/
  vhost enumeration and only turns up in a process listing.
  — [[silentium#Lessons Learned|Silentium]]
- A CVE described as "a bypass of an earlier fix" is worth approaching by
  reading the *prior* patch's actual diff, not just its changelog summary
  — the earlier fix's exact validation scope (e.g. checking a client-
  supplied path string but never re-resolving what it points to after
  symlinks) usually is the gap the bypass CVE exploits.
  — [[silentium#Lessons Learned|Silentium]]
- A "list" endpoint that filters out sensitive tools/commands is not an
  authorization boundary if the dispatcher underneath validates names
  against the full internal registry — the same auth gate protecting
  visible tools protects hidden ones too, the instant a name leaks (source
  disclosure, error message, guessable convention). Generalized in
  [[hidden-tool-dispatch-bypass]]. — [[devhub#Lessons Learned|DevHub]]
- A sudo `NOPASSWD` wrapper script's plugin/extension-loading loop running
  as unconditional top-level code (before any argv/action dispatch) means
  *every* invocation triggers it, including the most harmless subcommand —
  and CPython's `.pth`-file `import`-line `exec()` behavior
  (`site.addsitedir()`) turns any writable directory later fed to it into
  a root code-execution primitive, no bug in the wrapper's own dispatch
  logic required. Generalized in
  [[python-pth-file-import-line-privesc]].
  — [[smarthire#Lessons Learned|smarthire]]
- "Root inside an ephemeral, per-invocation cloud-service sandbox"
  (a Lambda/ECS/CodeBuild execution container) is a distinct claim from
  "host root," with its own checkable-fact list separate from classic
  Docker container-escape checks: a docker socket, a host bind mount, or
  (as on [[nimbus]]) a genuinely elevated capability set granted to a
  build-tool image whose entrypoint starts as root. Ruling out the first
  execution primitive tried (Lambda) doesn't rule out the whole backend —
  check every execution-style service the backend implements before
  concluding the platform itself is a dead end. Generalized in
  [[localstack-codebuild-privileged-mode-container-escape]].
  — [[nimbus#Lessons Learned|nimbus]]
- A systematic, evidence-backed "ruled out" conclusion on one specific
  angle (one container, one credential set, one service) is a real
  stopping point for *that angle* — it is not evidence the whole box lacks
  a path to root. Nine consecutive privesc sessions on [[nimbus]] each
  correctly, conclusively closed one more reachable primitive without
  ever concluding the box itself was unsolvable; the tenth found the
  actual path in a service surface (CodeBuild) none of the prior nine had
  reason to suspect yet.
  — [[nimbus#Lessons Learned|nimbus]]
- An NFSv3 `AUTH_SYS` (`AUTH_UNIX`) request's asserted identity is only as
  trustworthy as the client — `root_squash` only maps the *primary*
  uid/gid for a uid-0 request; supplementary group IDs and any non-zero
  uid/gid can still be trusted outright. A pure-Python NFSv3 client's
  `readdirplus()` can also return entries as a linked list nested under a
  `nextentry` key rather than a flat array, silently hiding real
  subdirectories from a naive `for` loop — dump the raw response before
  trusting a "this export is empty" conclusion. Generalized in
  [[nfsv3-auth-sys-trust-and-readdirplus-pitfalls]].
  — [[fries#Lessons Learned|fries]]
- A TLS-client-cert-authenticated Docker Engine API layered with a
  CN-mapped authorization plugin (`authz-broker` or similar) provides no
  real security boundary once the signing CA's private key is recoverable
  — forge a fresh client cert with a CN chosen to match the plugin's
  unrestricted policy row rather than reusing any already-issued cert.
  Generalized in [[docker-tls-client-cert-authz-broker-cn-bypass]].
  — [[fries#Lessons Learned|fries]]

## Windows / AD Privesc

- Before starting exploit/privesc on any Windows/AD box, work off
  [[windows-active-directory-attack-surface-checklist]] rather than
  re-deriving the attack surface from scratch — it exists specifically
  because this vault has repeatedly lost sessions to under-enumeration
  (Checkpoint, Garfield) or to running the full AD CS sweep too late
  (Fries). Use whatever tool actually implements a technique correctly
  (PowerView/pywerview, BloodHound, Certipy, Rubeus, Mimikatz, full impacket
  suite, netexec/CrackMapExec, Metasploit) — none of it is off-limits for an
  authorized lab box.
  — [[checkpoint#Privesc|Checkpoint]], [[garfield]], [[fries]]
- A dMSA's (Windows Server 2025 delegated Managed Service Account)
  `msDS-ManagedPassword` LDAP read is permanently blocked by design, not a
  materialization-delay artifact — the real retrieval mechanism is Kerberos
  S4U2Self returning a `KERB_DMSA_KEY_PACKAGE` (PA-DATA 171). If an
  investigation into this starts requiring longer and longer waits with no
  new evidence, that's a signal to re-derive the theory via a cheap control
  test (a plain gMSA vs. an unlinked dMSA, checked seconds apart), not to
  keep waiting. Generalized in
  [[windows-server-2025-dmsa-badsuccessor-key-retrieval]].
  — [[checkpoint#Privesc|Checkpoint]]
- The August 2025 CVE-2025-53779 (BadSuccessor) patch only gates the
  `current-keys` field of a `KERB_DMSA_KEY_PACKAGE` (privilege merging into
  the dMSA's own ticket) — the `previous-keys` field, returned in the same
  S4U2Self response, discloses the impersonated predecessor account's real
  static key material (byte-identical to its NT hash for RC4) and is not
  patch-gated at all. A clean, repeatable denial testing only `current-keys`
  is not evidence the box is closed to BadSuccessor — always test both
  fields before concluding the technique is dead on a patched DC.
  Generalized in
  [[windows-server-2025-dmsa-badsuccessor-key-retrieval]].
  — [[checkpoint#Privesc|Checkpoint]]
- Never compare AD/Kerberos timestamps across different clock domains
  without confirming they're the same one — a DC's local wall clock, its
  own reported UTC, and an attacker sandbox's real-world UTC can each differ
  from the others for unrelated reasons, and mixing any two produces a
  plausible-looking but wrong elapsed-time figure.
  — [[checkpoint#Privesc|Checkpoint]]
- A CVE with a documented post-patch bypass is still worth checking against
  the domain's actual ACL graph before assuming it's exploitable — a bypass
  requiring a second independent precondition (e.g. `GenericWrite` on the
  specific impersonation target) may only be satisfiable against one
  low-value account in the whole domain, foreclosing the high-value target
  regardless of the bypass's existence.
  — [[checkpoint#Privesc|Checkpoint]]
- A valid Kerberos ticket for an account is not evidence that account
  inherited another (linked/migrated/delegated) account's privileges — test
  the actual gated resource across more than one protocol (e.g. share
  access and WinRM auth, each gated by a different group membership) before
  concluding a privilege-merge mechanism worked.
  — [[checkpoint#Privesc|Checkpoint]]
- Two sibling AD structural classes that look almost identical (e.g. gMSA
  vs. dMSA) can have meaningfully different default security descriptors
  and legal-attribute sets, and a cmdlet's default behavior may silently
  create the wrong one — confirm an object's actual `objectClass` right
  after creation rather than assuming intent matched output.
  — [[checkpoint#Privesc|Checkpoint]]
- A complete enumeration sweep (every OU/container in a domain, not just
  the ones already known from context) can surface a deliberately-placed
  precondition a narrower, seemingly-thorough sweep genuinely misses.
  — [[checkpoint#Privesc|Checkpoint]]
- A public defensive/audit script (author explicitly building it for
  detection, not exploitation) is legitimate to reference and replicate the
  *logic* of even under a strict no-public-exploit-code policy — the
  distinction is the tool's own stated purpose, not merely whether it's
  public. Keep the corresponding weaponized PoC, if one sits right next to
  it in the same disclosure, genuinely unconsulted.
  — [[checkpoint#Privesc|Checkpoint]]
- A deny-list attribute check against group membership (e.g. an RODC's
  `msDS-NeverRevealGroup`) is almost never a literal-DN match — resolve
  transitive/nested group membership on both the target and the deny-list
  entries before concluding a principal isn't covered. Generalized in
  [[rodc-secret-replication-attack-chain]].
  — [[garfield#Root|garfield]]
- A tool returning a plausible, domain-specific-sounding error is not proof
  the target's own AD configuration is wrong — reproduce the raw protocol
  exchange (the actual KRB-ERROR code, not a wrapper's friendly message) or
  test against a deliberately permissive control case before concluding a
  security boundary, rather than a tool bug, is the blocker.
  — [[garfield#Root|garfield]]
- RBCD/S4U2Proxy code execution on an RODC is not the end of an RODC secret-
  extraction chain — PRP authorization (`msDS-RevealedUsers`) and the actual
  secret replication down to that specific RODC instance are different
  things, and forcing the latter needs a right (`Secret Synchronization`)
  that neither RBCD nor RODC-delegated-admin group membership grants on
  their own. Generalized in [[rodc-secret-replication-attack-chain]].
  — [[garfield#Root|garfield]]
- netexec's `Pwn3d!` marker is a heuristic, not proof of local-admin — a
  WinRM-capable, non-admin account can produce the same marker; verify real
  group membership before betting a relay/pass-the-ticket design on
  admin rights that don't actually exist.
  — [[garfield#Privesc|garfield]]
- `ManageCA` genuinely authorizing a CA config write at the server/RPC level
  and `certutil.exe`/`Set-ItemProperty` refusing to perform that write are
  two different facts — both tools layer their own client-side elevation
  check or OS-level registry ACL requirement on top, neither of which is
  what the CA itself authorizes. Calling the underlying RPC method
  (`ICertAdmin2::SetConfigEntry`) directly via the
  `CertificateAuthority.Admin` COM object bypasses both client-side gates.
  A request denied with disposition 31 ("Denied by Policy Module") is
  separately, permanently non-resubmittable regardless of `ManageCertificates`
  rights — distinguish that from a real access-control denial before
  concluding ESC7 itself is unweaponizable. Generalized in
  [[adcs-manageca-com-object-configentry-bypass]].
  — [[fries#Root|fries]]
- A general Service Control Manager lockdown (`Get-Service`/`net start`/
  `net stop`/`schtasks.exe` all denied) doesn't necessarily block
  `sc.exe <verb> <service-name>` targeted at one specific service — a
  BUILTIN group membership can grant rights on a single named service
  (e.g. `Certificate Service DCOM Access` on `CertSvc`) separate from
  general `SC_MANAGER_ENUMERATE_SERVICE` access. Worth trying before
  concluding a service can't be restarted from a locked-down account.
  — [[fries#Root|fries]]
- `ReadGMSAPassword` on a gMSA is a direct NTLM-hash-and-pass-the-hash
  primitive, not just an LDAP read — netexec's `--gmsa` module (or
  `gMSADumper`) both confirms the edge by name (who's actually listed in
  `PrincipalsAllowedToRetrieveManagedPassword`) and decrypts
  `msDS-ManagedPassword` in one step. — [[fries#Privesc|fries]]

## Methodology

- A strong-looking lead still needs empirical verification, not just
  theoretical applicability — "looks exploitable in code" and "is
  exploitable in this deployment" are different claims. Verify both,
  ideally via real patch-diff analysis rather than taking an advisory on
  faith. — [[kobold#Lessons Learned|kobold]]
- Group/role membership that looks like the obvious intended path can be
  a red herring — don't over-invest in the most visually appealing lead
  before ruling out cheaper ones. — [[kobold#Lessons Learned|kobold]]
- A vector written off during recon is worth re-checking once more context
  exists later in the chain — an assumption made early (e.g. "this route
  404s") can be wrong, and re-testing costs little.
  — [[kobold#Lessons Learned|kobold]]
- If a payload/command is being blocked in a way consistent with literal
  string-matching (AV/EDR/WAF), reach for glob-wildcard obfuscation
  (`w?oami`, `w*i`, etc.) before hand-rolling something novel — shells
  expand wildcards before execution, so the literal name never appears.
  Local catalog of 66 binary/platform patterns: [[Tooling and
  Scripts/lolglobs/README|LOLGlobs]]. Targeted tool for boxes that
  actually show detection in the loop, not a default step.
- `getcap` silently missing on a minimal/hardened distro looks identical
  to "no capabilities set" (empty output, no error) if you don't verify
  the tool exists — read the `security.capability` xattr directly (e.g.
  via `os.getxattr` in Python) to be sure. — [[connected#Lessons
  Learned|connected]]
- A legitimate GPG/hash-signed privilege-hook mechanism can genuinely be a
  properly designed boundary, even with parts of the verification code
  unauditable (e.g. ionCube-encoded) — verify what's actually reachable
  before spending effort reversing a commercial obfuscator just because a
  mechanism looks juicy. — [[connected#Lessons Learned|connected]]
- Fully reading a decoy or half-wired custom tool (rather than dismissing
  it by name/purpose) can surface the trust assumption behind the real
  vulnerability even when the tool itself isn't directly exploitable.
  — [[connected#Lessons Learned|connected]]
- A pipeline/agent gap worth naming when it happens: if a pivotal fact
  (e.g. "this table is the RCE sink") is recorded without the discovery
  trail behind it, a later writeup can't tell independent discovery apart
  from CVE-advisory background reading — log the *how*, not just the
  *what*, at the moment a pivotal fact is used, not after the fact.
  — [[connected#Lessons Learned|connected]]
- When a service's own source isn't reachable, black-box probing against
  the real published spec for the protocol family it's imitating (e.g. an
  official technical reference for a print/document/industrial protocol)
  is a legitimate, efficient way to reverse a proprietary reimplementation
  — no exploit-specific tooling required, just the real spec.
  — [[paperwork#Lessons Learned|Paperwork]]
- Home-grown protocol/command parsers are often positional rather than
  truly keyword-based even when the wire format looks like `KEY=value`
  pairs — if a multi-token command silently fails, try reordering the
  tokens before concluding the command itself is unsupported.
  — [[paperwork#Lessons Learned|Paperwork]]
- `curl -F` silently treats a `;` inside a field value as a MIME
  parameter separator (same syntax as `;type=...`) and corrupts any
  payload containing one — indistinguishable from a genuine structural
  exploit-gadget failure until diagnosed by bisection. Use
  `curl --form-string` for any field carrying attacker-controlled JS or
  shell content. — [[reactor#Lessons Learned|reactor]]
- `require` is not a true Node.js global — any JS execution context
  outside a real CommonJS module's own scope (`Function`-constructor-
  compiled code, Chrome DevTools Protocol `Runtime.evaluate`, etc.) needs
  `process.mainModule.require(...)` or a dynamic `import()` instead. A
  `ReferenceError: require is not defined` right after landing arbitrary
  code execution is a scoping detail, not proof the primitive failed.
  — [[reactor#Lessons Learned|reactor]]
- "Primitive confirmed live" and "have a working RCE" are different
  milestones worth tracking separately, even for a CVSS-10 pre-auth bug —
  a version match plus a confirmed read/compile primitive can still take
  real source access and careful mechanism analysis (or a specific
  external detail from vendor research) before code actually executes.
  — [[reactor#Lessons Learned|reactor]]
- An out-of-band scenario/theme description (a challenge author's own
  synopsis, flavor text never actually present on the target) can be a
  genuine signal about where the real attack surface sits — worth
  widening enumeration (bigger wordlists, different subdomain guesses)
  around that theme instead of dismissing it as decoration once the
  obvious surface comes back clean. — [[bedside#Lessons Learned|bedside]]
- Differing login-endpoint error messages/status codes for "wrong
  password" vs. "no such account" are a reliable, low-cost username-
  enumeration oracle — worth checking as an early step against any custom
  auth endpoint before spending budget on password guessing against
  unconfirmed identities. — [[silentium#Lessons Learned|Silentium]]
- Reading a target's actual pinned-version source (cloned at the exact
  release tag) rather than trusting a vendor advisory's paraphrase is what
  surfaces logic bugs advisories don't cover at all — the highest-value
  bug on this box (an unauthenticated account-takeover via a forgot-
  password response leak) had no CVE/GHSA ID anywhere; it only turned up
  by reading the real controller/service code end to end.
  — [[silentium#Lessons Learned|Silentium]]
- When an advisory/vendor docs say an API's own response body is an
  unreliable success signal for a given call, verify the real effect via
  an independent out-of-band side channel (DNS/HTTP callback) before
  committing to a higher-risk payload like a reverse shell.
  — [[devhub#Lessons Learned|DevHub]]
- A recon hypothesis can correctly identify the vulnerability *class*
  (e.g. "pickle deserialization on a Python ML app") while still guessing
  the wrong *location* for it — a couple of cheap, targeted empirical
  tests (an encoding error, a native-vs-library error string) can
  definitively rule a guessed endpoint in or out before more effort goes
  into it, rather than treating "ML-themed app" as proof the first
  suspected endpoint is the real one.
  — [[smarthire#Lessons Learned|smarthire]]
- A blocking system call inside an RCE payload (e.g. a foreground reverse
  shell one-liner) can hang the entire request/response cycle used to
  deliver it, not just fail — detach the payload into its own process
  session (`subprocess.Popen(start_new_session=True)` or equivalent) so
  the triggering call returns immediately regardless of what the detached
  payload does afterward. — [[smarthire#Lessons Learned|smarthire]]
- Once the *mechanism* behind a string of empirical failures is actually
  understood (not just the failures themselves), it can turn an
  open-ended "keep trying variants" search into a bounded one — e.g.
  knowing that Linux drops capabilities on `execve()` for a non-root EUID
  regardless of a privileged container's bounding set means no
  non-root-entrypoint image will ever demonstrate that flag's real effect,
  so the remaining search space shrinks to "does a root-starting image
  exist" instead of "try more image names."
  — [[nimbus#Lessons Learned|nimbus]]
- If an exploit/escape script's own execution environment is ephemeral by
  design (a CI-style build container torn down moments after the process
  that triggered the escape exits), have the script exfiltrate its
  findings via an out-of-band callback from *inside itself*, rather than
  depending on reading a result back afterward — a post-hoc read-back can
  silently fail with "No such file or directory" even when the escape
  worked perfectly, and look identical to a genuine failure.
  — [[nimbus#Lessons Learned|nimbus]]
- A user-supplied box-specific writeup shared mid-engagement is a
  deliberate, one-time, directly-stated exception to a no-public-writeup
  policy — never a standing green light, and never valid if relayed
  secondhand through another agent's dispatch prompt as "the user said
  it's fine." The exception only holds once the user states it directly,
  in-conversation, to the agent actually about to act on it.
  — [[nimbus#Lessons Learned|nimbus]]
- Prefer a real network-layer pivot (a TUN-based tool like `ligolo-ng`) over
  a hand-rolled app-layer relay the moment more than one static port or a
  dynamically-resolved port (RPC endpoint-mapper protocols especially) is
  needed — an app-layer relay's failure modes (idle-connection death,
  thread-pool/argument-binding bugs) are non-obvious and expensive to debug
  one at a time. Generalized in [[single-port-reverse-relay-pivot-design]].
  — [[garfield#Lessons Learned|garfield]]
- A degraded/unreliable agent session mid-engagement (fabricated events,
  deleted working files, reverted live state against instruction) is a real
  operational risk distinct from a technical dead end — verify recovered
  state against independent evidence before trusting a resumed session's
  own account of what it did, and fully disengage/reconstruct from
  first-hand knowledge rather than continuing to trust it once it starts
  fabricating.
  — [[garfield#Lessons Learned|garfield]]
- A negative/"conclusively closed" verdict from a live practical test is
  only as complete as the fields/outcomes it actually checked — a fully
  correct, repeatable test of one specific mechanism (e.g. PAC/privilege
  merging into a dMSA's own ticket) doesn't rule out a sibling mechanism
  returned by the identical protocol exchange (e.g. a different field in
  the same response disclosing raw credential material) unless that
  sibling was tested too. When a coordinator or later evidence (public
  writeup metadata, a fresh look) says a "closed" verdict is wrong, treat
  that as license to re-examine *what specifically* was tested, not just
  to retry the same test again.
  — [[checkpoint#Lessons Learned|Checkpoint]]
- A single "access denied" is not a diagnosis — the same-looking failure
  can be a hard server-side policy denial, a client-side tool's own
  elevation gate, or a protocol-level restriction, and each needs a
  genuinely different bypass. Distinguishing which one you're actually
  looking at (not just confirming "still denied" three different ways) is
  what makes an eventual bypass findable. — [[fries#Lessons Learned|fries]]
- A subagent's own narrative account of a mid-session event (a claimed
  message received, an action "declined") is a claim like any other and
  needs the same verification as a technical finding — cross-check it
  against the actual session transcript/tool output before treating it as
  fact, especially anything security-shaped. One session on [[fries]]
  reported a detailed, box-specific hint had arrived and been declined;
  no such message existed anywhere in that session's real transcript, and
  the framing was struck once checked rather than left standing.
  — [[fries#Lessons Learned|fries]]
- When a technique's specific working form is confirmed against external
  material partway through an engagement (rather than independently
  rediscovered), say so plainly rather than presenting the whole chain as
  self-derived — especially when the diagnostic work that got you *to* the
  point of needing that confirmation was genuinely independent. The two
  are separable facts worth keeping visible, not blurred together after
  the fact. — [[fries#Root|fries]]
