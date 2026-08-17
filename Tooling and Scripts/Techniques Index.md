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
- A templating engine's "accept either a source string or a pre-parsed AST
  object" dual-mode `compile()` API is a distinct injection surface from
  its runtime property-access guards (`protoAccessControl` and similar) —
  a hand-crafted AST node whose field only the real parser is ever
  supposed to populate with a trusted type (e.g. a `NumberLiteral.value`
  guaranteed numeric by grammar) can carry arbitrary source text straight
  into the compiler's codegen output, bypassing every prototype-chain
  lockdown because there's no property lookup for those guards to
  intercept at all. Worth checking on any template engine offering a
  precompile-once API, not just Handlebars. CVE-2026-33937 is one
  instance. — [[DarkZeroReturns#Foothold|DarkZeroReturns]]
- Every "obvious" CI trigger event being correctly gated (approval
  required, correctly repo-scoped) doesn't mean every trigger event is —
  check whether each event type's own notifier function actually populates
  the field an approval-gate check depends on (e.g. Gitea Actions'
  `IsForkPullRequest`), since a less-common event (a PR review comment,
  not the PR itself) can go through a notifier path that simply never sets
  it. Generalized in
  [[gitea-actions-fork-pr-approval-bypass-notifier-gap]].
  — [[DarkZeroReturns#Privesc|DarkZeroReturns]]
- AngularJS's initial bootstrap `$compile`s the *entire DOM subtree already
  present* under an `ng-app` root at page load, discovering directives by
  attribute-scanning, not by whatever a developer explicitly wired up — a
  stored/reflected HTML injection point that sits inside that subtree at
  initial load (not injected post-bootstrap via `innerHTML`) gets any
  directive attribute (`ng-focus`, `ng-click`, etc.) compiled and executed,
  even with no `ng-bind-html`/`{{ }}` anywhere near it. Paired with a native
  `autofocus` attribute this needs zero user interaction, and since it
  never touches a native inline-handler attribute or `eval()`/`Function()`,
  a strict `script-src 'self'` CSP (no `unsafe-inline`/`unsafe-eval`) has no
  visibility into or control over it. Generalized in
  [[angularjs-csti-directive-injection-bootstrap]].
  — [[Eloquia#Foothold|Eloquia]]
- A missing `state`/PKCE parameter on a self-hosted OAuth2 authorization
  server enables not just login CSRF but **account-linking CSRF** — if a
  relying party's "connect my account to this IdP identity" callback
  doesn't verify the linking session matches the session that started the
  flow, an attacker can mint a code for their own IdP identity and get a
  victim's *already-authenticated* session to visit the callback,
  hijacking the victim's account outright rather than just tricking them
  into using the attacker's. Authorization codes are typically short-lived
  enough that a just-in-time code-minting redirector (mint on inbound hit,
  then forward) is needed rather than pre-minting and hoping delivery
  latency stays under the TTL. Generalized in
  [[oauth-account-linking-csrf-missing-state]].
  — [[Eloquia#Foothold|Eloquia]]
- A server responding to a POST before consuming the full body it declared
  via `Content-Length` leaves those unread bytes buffered on the socket for
  whatever request reuses that connection next — this desyncs a browser's
  *own* connection to a single-server site with no front-end/back-end
  disagreement required at all, unlike classic CL.TE/TE.CL request
  smuggling. Generalized in
  [[http-desync-client-side-connection-reuse]]. (PortSwigger research, not
  yet seen on a vault box.)
- A cache's key (usually just method+path, maybe a few headers) and the
  origin's actual response logic can disagree about what makes two requests
  "the same" — any header/param that changes the response but isn't part of
  the cache key is a poisoning primitive (a GET request *with a body*
  against Varnish is an easy-to-miss unkeyed channel, since "GET has no
  body" is the default wrong assumption), and a URL that merely *looks*
  static to the cache's caching-decision logic while the origin still
  serves the real dynamic/authenticated response is the inverse bug, cache
  deception. Generalized in
  [[web-cache-poisoning-unkeyed-input-and-web-cache-deception]]. (PortSwigger
  research, not yet seen on a vault box.)
- A JWT verifier that picks symmetric-vs-asymmetric checking based on the
  token's own `alg` header, rather than pinning it server-side, lets an
  attacker downgrade `RS256` to `HS256` and sign arbitrary claims using the
  server's own *public* key as the HMAC secret (recoverable from a
  `jwks.json` or derived from two existing tokens) — a structurally
  separate set of bugs from the same header block, `jwk`/`jku` letting an
  attacker supply or point to their own verification key entirely, and
  `kid` being a raw, unsanitized lookup key (path traversal/SQLi) in some
  implementations. A distinct, even simpler variant of the same "verifier
  trusts the token's own `alg` claim" root cause is `alg: none` — a service
  that self-discloses `none` among its accepted algorithms (e.g. in an
  unauthenticated status/version banner) will accept a completely unsigned,
  trivially-forged token outright. Generalized in
  [[jwt-algorithm-confusion-and-header-injection]]. (PortSwigger research
  for the RS256→HS256/`jwk`/`jku`/`kid` variants; the `alg: none` case
  confirmed live — [[Fireflow#Privesc|Fireflow]].)
- A single GraphQL endpoint replaces the usual "enumerate every REST route"
  recon model with "enumerate the schema" — introspection blocked by a
  naive string filter is bypassed by whitespace GraphQL itself ignores, a
  request-count-based rate limiter is bypassed entirely by aliasing the
  same query hundreds of times inside one HTTP request, and an endpoint
  accepting GET or form-urlencoded bodies (not just JSON) is CSRF-able the
  same way a REST endpoint would be. Generalized in
  [[graphql-introspection-and-alias-rate-limit-bypass]]. (PortSwigger
  research, not yet seen on a vault box.)
- Any named HTML element (`id`/`name`) auto-registers as a global JS
  property the instant it's parsed — DOM clobbering abuses this to feed a
  attacker-controlled *value* into trusted JS logic that reads an
  unassigned global, with zero script execution and therefore zero
  visibility to even a strict `script-src` CSP with no
  `unsafe-inline`/`unsafe-eval`; nested `<form>`/`<iframe name=...
  srcdoc=...>` structures chain multiple property levels deep. Worth
  checking specifically on any target where a strict CSP already ruled out
  [[angularjs-csti-directive-injection-bootstrap]]-style techniques.
  Generalized in [[dom-clobbering-csp-bypass-via-html-injection]].
  (PortSwigger research, not yet seen on a vault box.)
- A web race condition's real blocker is usually network jitter, not the
  target's own concurrency handling — withholding the final byte/frame of
  every request on one connection and releasing them together (single-byte
  sync on HTTP/1.1, or coalesced into one literal TCP packet via HTTP/2
  multiplexing for the tighter "single-packet attack") removes that jitter
  and makes a remote race condition behave like a local one. Burp
  Repeater's parallel/single-packet tab-group option and Turbo Intruder
  both implement this directly. Generalized in
  [[single-packet-attack-race-condition-timing]]. (PortSwigger research,
  not yet seen on a vault box.)
- Apache httpd modules (`mod_rewrite`, `mod_proxy`, CGI/FastCGI handlers, ACL
  checks) share one `request_rec` struct but don't agree on what its fields
  mean — a truncation character (`%3F`) can make one module read a path as
  ending early while another module reads the full string, producing a
  `DocumentRoot` escape, an ACL bypass, or (via response-header injection
  reinterpreted as a proxy handler directive) response-header-injection-to-RCE.
  Worth testing truncation/encoding characters against rewrite targets and
  `.htaccess`-protected paths on any Apache+mod_proxy+CGI stack. Generalized
  in [[apache-httpd-confusion-attacks-module-semantic-ambiguity]]. (Orange
  Tsai research, not yet seen on a vault box.)
- Windows silently "best-fit" substitutes a Unicode character with no exact
  ANSI equivalent for a visually-similar ASCII one whenever a UTF-16 string
  crosses into a legacy ANSI API — so a filename/argument/CGI variable that
  passed validation as Unicode can still smuggle a real `/`, `\`, `"`, or `-`
  once consumed as ANSI, especially on CJK code pages; CVE-2024-4577
  (PHP-CGI) reopened a decade-old patched argument-injection bug this way.
  Generalized in [[windows-ansi-worstfit-best-fit-encoding-smuggling]].
  (Orange Tsai research, not yet seen on a vault box.)
- Frontend JS that builds an API request path by concatenating a base path
  with unnormalized user-controlled input (a URL fragment, query param) can
  be traversal-redirected to fetch a *different*, attacker-controlled JSON
  response, which the frontend's own logic then uses to fire a second,
  state-changing request with the victim's real session — full CSRF impact
  with no CSRF-token/SameSite bypass needed, since every request genuinely
  comes from the victim's own browser. Worth traversal-testing any
  client-side path-building code even when the visible effect looks like a
  harmless "wrong GET happened." Generalized in
  [[client-side-path-traversal-to-csrf-cspt2csrf]]. (Doyensec research, not
  yet seen on a vault box.)
- A path-based authorization rule only guards the front door — any
  accessible feature that internally forwards/executes into another
  server-side path as a feature (`Server.Execute()`,
  `RequestDispatcher.forward()`, a preview/render/include endpoint) never
  re-enters the HTTP pipeline, so the authorization filter that would have
  blocked a direct request to the protected path simply doesn't fire. Worth
  checking on any enterprise CMS/portal (Sitecore, Confluence, SharePoint)
  the moment both a path-gated admin page and an internal-forward-capable
  feature exist in the same app. Generalized in
  [[internal-forward-execute-auth-pipeline-bypass]]. (Assetnote research,
  not yet seen on a vault box.)
- Encrypting a value (a `parentid`, a state param) isn't the same as
  authenticating it — AES-CBC gives no integrity guarantee, and any
  distinguishable "bad padding" error on a decrypted value hands an
  attacker a padding oracle that recovers plaintext one byte at a time and,
  just as easily, forges an entirely new ciphertext to attacker-chosen
  plaintext with no key knowledge at all. Test any high-entropy,
  16-byte-aligned parameter that's decrypted server-side for a
  distinguishable padding-failure signal before assuming it needs the key
  to forge. Generalized in [[cbc-padding-oracle-value-forgery]]. (Assetnote
  research — a decades-old technique that was, notably, a genuine blank in
  this index until now.)
- A loopback SSRF denylist that string-matches `127.0.0.1`/`localhost` is
  not a real boundary unless the input is normalized/resolved before
  comparing — decimal, octal, hex, zero-padded, and IPv4-mapped-IPv6 forms
  of the same address routinely sail straight through, and the resulting
  GET-only SSRF primitive is still worth using purely for internal recon
  (reading an internally-gated status/health endpoint) even when it can't
  drive anything needing a different HTTP method or a protocol upgrade.
  Generalized in
  [[ssrf-loopback-denylist-alternate-ip-representation-bypass]].
  — [[Cohort#Foothold|Cohort]]
- A management/data-pipeline API left with "no login configured" doesn't
  default to read-only — check what access policy the anonymous identity
  actually gets (`/nifi-api/access/config`'s `supportsLogin` on Apache
  NiFi, or the equivalent for any similar tool), since a full read/write
  default turns the tool's own legitimate features (a SQL-executing
  processor wired to an embedded DB supporting Java UDFs, here) into
  direct RCE with no code bug involved at all. Generalized in
  [[nifi-unauthenticated-h2-createalias-rce]].
  — [[Helix#Foothold|Helix]]
- Two chained pre-auth vulnerabilities in the same vendor release (an
  `IsSysAdmin`-flag auth-bypass password reset with no `OldPassword`
  validation, plus a "connect to a management hub" endpoint that
  deserializes and blindly acts on whatever JSON the hub responds with)
  can combine into unauthenticated RCE even when each individually only
  grants app-panel access or a narrow SSRF-shaped callback — SmarterMail's
  CVE-2026-23760 + CVE-2026-24423 is one instance. A vendor's own release
  build number embedded in an unauthenticated page (login-page inline JS,
  a version banner) is enough to fingerprint the vulnerable window without
  ever authenticating. Generalized in
  [[smartermail-auth-bypass-connect-to-hub-rce-chain]].
  — [[DanglingTree#Privesc|DanglingTree]]
- A low-code/no-code flow builder that lets a node carry both a resolvable
  module/class import path and an editable raw-source-code field for the
  same component needs its resolution priority tested directly — if the
  backend falls back to compiling/exec'ing the client-submitted source the
  moment the module reference is stripped or absent, and any endpoint
  accepts caller-supplied flow data unauthenticated (even one scoped to
  "run this already-public flow"), that's unauthenticated RCE by omission,
  not by injection. A syntax-error probe (deliberately invalid Python in
  the code field) is a fast way to prove the server *compiles* submitted
  source even when a first test shows it isn't *executed* — the two are
  separable facts. Generalized in
  [[langflow-flow-metadata-module-strip-rce]].
  — [[Fireflow#Foothold|Fireflow]]
- A SQLi `FILE`-write primitive that fails against the default/obvious
  targets (`/tmp`, the DB's own datadir) is not proof the write capability
  itself is gone — test a specific web-servable, world-writable
  application directory directly before concluding the whole vector is
  dead; `INTO DUMPFILE`'s multi-column concatenation has no separator at
  all, so pad unused columns with `''`, not digit literals, to avoid
  corrupting a webshell payload's syntax. Generalized in
  [[sqli-file-write-web-servable-directory-targeting]].
  — [[cobblestone#Lessons Learned|cobblestone]]

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
  — [[devhub#Lessons Learned|DevHub]], [[Cohort#Foothold|Cohort]]
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
- A local security-account-manager (LSA) secret dump can hand you a
  plaintext password for a completely different account than the one being
  dumped (a domain user's password sitting in a member server's own LSA
  `DefaultPassword` secret) — always read every secret type
  `secretsdump`/`mimikatz` returns, not just the hashes for the box's own
  local/machine accounts. Confirmed again on a second box: a full local
  SAM/LSA secrets dump (not just a `-just-dc-ntlm` DCSync) recovered a
  completely unrelated service account's real plaintext password from a
  `_SC_<ServiceName>` LSA secret, after 300+ sections of Kerberoasting that
  exact account had come up empty. Always run the plain, un-scoped
  `secretsdump` at least once against any box you have Administrator on,
  not only the DCSync-only invocation.
  — [[Pirate#Foothold|Pirate]], [[DarkZeroReturns#Privesc|DarkZeroReturns]]
- Browser-saved credentials (Chromium/Edge `Login Data`) are only as
  protected as DPAPI's per-user master key, which unwraps trivially once
  code runs as that exact Windows account — check the browser's own build
  date/version first (App-Bound Encryption, shipped mid-2024/2025-era,
  changes the mechanics materially) before assuming a straightforward
  `CryptUnprotectData` + AES-GCM decrypt applies.
  — [[Eloquia#Privesc|Eloquia]]
- A privileged/service-account password that looks non-dictionary from the
  very first cracked example on a box (high entropy, no wordlist-adjacent
  root word) is a real signal the box's whole credential set was
  machine-generated — recognize this pattern from the first sample rather
  than escalating through bigger wordlists/rule sets on every subsequent
  hash; a broad rockyou+11-rule-set sweep against a full 15-account DCSync
  dump, run to genuine exhaustion, is the right way to *confirm* the
  pattern once, not a per-hash default.
  — [[PingPong#Lessons Learned|PingPong]]
- A cryptographically-proven-correct decrypted credential is only proof
  the decryption was correct — it's a separate, independently-testable
  claim whether that credential is shared across a trust boundary (an
  application's internal DB service account vs. the OS account it happens
  to share a username with). A box can deliberately plant this as a red
  herring; the way to close it definitively is the *source* system's own
  change-history (an audit DB, here) showing the credential was legitimately
  rotated for reasons unrelated to the target account, not just repeated
  failed auth attempts. Generalized in
  [[nifi-sensitive-properties-decryption]]. — [[Helix#Rabbit Holes|Helix]]
- A filename-pattern-based credential search (`id_rsa*`, `*.pem`, `*.ppk`)
  is only as complete as its pattern list — a real, plaintext, unencrypted
  SSH private key with a non-standard name/extension (`operator_id_ed25519.bak`)
  sat readable the whole time in a compromised service's own working
  directory (`support-bundles/`) and matched none of those patterns across
  three separate sessions' searches. Once inside a specific service's own
  foothold, list that service's own directories by hand at least once, even
  after a broad pattern-based filesystem search comes back clean.
  — [[Helix#Rabbit Holes|Helix]]
- Windows Credential Manager can hold a saved "Domain Password" for a
  completely different account than the one whose profile it's stored
  in — a common real-world pattern (an admin's own saved connection to a
  server/service account they manage), not a contrived trick, and
  especially likely to survive long after its target host is
  decommissioned. Its on-disk format wraps DPAPI in an extra header the
  generic `CryptUnprotectData`/`ProtectedData.Unprotect` APIs don't parse
  even once manually stripped — `impacket`'s `dpapi.py`
  `masterkey`/`credential` subcommands implement the real format and
  require only the *owning* account's own known password, not any more
  privileged identity's access. Generalized in
  [[windows-credential-manager-cross-account-creds]].
  — [[DanglingTree#Privesc|DanglingTree]]

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
- MIT Kerberos `ksu` has two structurally different authorization paths
  (`-e` vs. plain), and the plain path falls back to authorizing any
  `<name>@<realm>` principal into the identically-named local account if
  neither `.k5login` nor `.k5users` exists for the target — a domain
  principal manufactured with a matching name (e.g. via a delegated
  `CREATE_CHILD` ACE on some AD OU) can become real local root this way,
  and a same-source-account `-e` denial doesn't prove `.k5login` exists or
  denies you; it may just mean the stricter `-e` path (which never
  consults `.k5login` at all without a `.k5users` file) was exercised
  instead. Generalized in [[ksu-default-aname-lname-fallback]].
  — [[DarkZeroReturns#Privesc|DarkZeroReturns]]
- A TOCTOU race with too narrow a window for loop-and-pray parallelism to
  reliably win can be made deterministic instead of probabilistic: register
  the memory the privileged code will touch mid-window with `userfaultfd()`
  to freeze it at exactly the right instant (unbounded time to swap the
  target underneath it), or, for a path-based (not memory-fault-based)
  race, stand up a custom FUSE filesystem and simply delay the callback the
  victim is blocked on. Generalized in
  [[userfaultfd-toctou-race-window-widening]]. (Google Project Zero
  research, not yet seen on a vault box.)
- A D-Bus service method that defers its actual privileged work to a
  lower-priority idle callback, while reading mutable transaction state at
  dispatch time rather than at the time authorization was originally
  evaluated, is a TOCTOU primitive the moment any flag exists that
  legitimately skips authorization for "simulate/preview-only" calls —
  fire two async, fire-and-forget calls on the *same* transaction object
  before the first one's callback runs, and the second overwrites the
  state the deferred callback will actually act on, even if its own state
  transition gets silently rejected. `Gio.DBusConnection.call(...,
  callback=None)` + `flush_sync()` reproduces this race in pure Python with
  no compiler needed on-target. CVE-2026-41651 ("Pack2TheRoot",
  PackageKit) is one instance. Generalized in
  [[dbus-transaction-async-race-toctou]].
  — [[Cohort#Root|Cohort]]
- `chown(2)` unconditionally clears a regular file's SUID/SGID bits on
  ownership change — a maintainer script or setup routine that does
  `chmod 4755 file` before `chown root:root file` silently loses the bit it
  just set, with no error raised anywhere. Do the ownership change first,
  permission bits last, and don't assume a missing setuid bit implies a
  target-specific hardening measure (nosuid mount, capability bounding
  set) without checking those directly first.
  — [[Cohort#Root|Cohort]]
- `apt-mark hold` freezing a package below a patched candidate that's
  genuinely available in the box's own configured repo is a deliberate
  design signal, not an accidental patch gap — worth checking
  (`dpkg -s <pkg>` for `Status: hold`) on any box where extensive local
  enumeration keeps coming up clean, since a held package is functionally
  a curated hint about which specific CVE is the intended vector.
  — [[Cohort#Privesc|Cohort]]
- A periodic job that restarts a privileged server and then a dependent,
  higher-privilege *client* process moments later creates a real TOCTOU
  window on the port the server rebinds — whatever wins the bind race
  during that gap receives the client's own reconnect handshake, including
  any credential it presents as itself. Build the race by constructing
  the expensive parts of a fake server once and tight-looping only the
  cheap bind/stop cycle; winning it can *disprove* a credential-embedding
  hypothesis just as conclusively as it can steal one. Generalized in
  [[service-restart-toctou-port-rebind-credential-capture]].
  — [[Helix#Rabbit Holes|Helix]]
- `/proc/<pid>/cmdline` and `/proc/<pid>/status` stay world-readable
  regardless of process owner on a default Linux config, even when
  `/proc/<pid>/cwd`/`exe`/`maps` are locked down by `ptrace_scope` — poll
  them across a known trigger event (a systemd timer's next fire time) to
  read a root-owned, permission-denied script's real, literal behavior
  without ever gaining file access to it. Generalized in
  [[proc-cmdline-world-readable-behavior-inference]].
  — [[Helix#Privesc|Helix]]
- A group-writable ML model/adapter "hot-swap the active version" registry
  is a distinct primitive from [[insecure-ml-pickle-deserialization]] —
  safetensors weights don't execute code on load, but a "latest mtime
  wins" reload loop with no load-time signature check still lets a group
  member fully control model *behavior*, and a periodic hash-vs-manifest
  integrity job scanning the same directory is a race to time against its
  own fixed schedule, not a load-time gate; once loaded, quarantining the
  file on disk doesn't unload the already-resident weights from the
  serving process either. The real privilege crossing needs a downstream
  consumer that executes the model's output under its own identity (a
  regression-test cron running generated code, an agent that acts on tool
  calls) — without that, adapter poisoning tops out at "the model lies,"
  not code execution as someone else. Validate a trained payload's token
  length against the server's own generation cap *offline* before ever
  deploying it — a completion that gets truncated mid-output is a
  completion that (for code specifically) doesn't execute at all, not one
  that partially works. Generalized in
  [[lora-adapter-registry-poisoning-hot-reload-race]].
  — [[OSAI+ - Adapter Poisoning#Lessons Learned|OSAI+ Adapter Poisoning]]
- An LLM-based semantic security classifier ("is this script MALICIOUS or
  SAFE") can be bypassed by editing its tokenizer's vocabulary, not the
  model at all — swap the ID of a rare, narrow subword piece of the
  expected keyword (e.g. `MAL` from `MALICIOUS` → `MAL`+`IC`+`IOUS`) with
  an unrelated token's ID. The model's forward pass is untouched and still
  computes the correct verdict internally (choosing IDs is purely a
  function of trained weights, independent of the tokenizer's string
  labels), but the resulting decode reads as gibberish
  (`"MALICIOUS"`→`"FUNICIOUS"`), which any classifier that defaults
  unparseable output to the permissive branch (a fail-safe-defaults
  violation) will silently approve. Must be a true swap (both tokens keep
  exactly one ID each), never a collision (two strings sharing one ID) —
  a collision breaks the vocabulary's required bijection and produces
  implementation-defined decode behavior or an outright loader crash,
  where a swap stays fully deterministic. Pick the rarest/most
  domain-specific subword piece available to minimize collateral damage
  to unrelated vocabulary and stay under the radar of aggregate benchmark
  testing. Generalized in
  [[tokenizer-vocab-id-swap-fail-open-classifier-bypass]].
  — [[OSAI+ - Supply Chain Attacks on AI-ML Systems]]
- An opcode-level pickle scanner (picklescan or similar) gating
  `torch.load(weights_only=False)` only ever sees which
  `GLOBAL`/`STACK_GLOBAL` references appear in the bytestream — it has no
  visibility into what a referenced callable actually does when run. Two
  structurally different bypasses follow: (1) a denylist is inherently
  incomplete — `linecache.getlines(path)` does a genuine unrestricted file
  read and isn't on picklescan's ~60-entry denylist at all (confirmed by
  reading its actual source: unlisted globals classify as `Suspicious`,
  which never increments the issue count the pass/fail exit code is keyed
  on); (2) make `__reduce__()` return a **three-element** tuple
  `(callable, args, state)` where the callable is a plain class — a class
  reference can never look "dangerous" by name — and put the real payload
  in `__setstate__()`, invoked by the `BUILD` opcode after construction;
  since `__setstate__`'s method body is compiled Python living in the
  class definition, not in the pickle bytestream, there is nothing for any
  opcode-level scanner to inspect, regardless of denylist completeness.
  The second technique's real limitation: `GLOBAL '__main__ ClassName'`
  resolves via `__import__`+`getattr` against whatever is *currently
  running as `__main__` on the target*, not the attacker's crafting
  script — an unimportable class raises `ModuleNotFoundError` outright, so
  this only works when the class can be independently planted on the
  target first (e.g. dependency confusion) or when creation and loading
  happen on the same machine; targeting a class already present in the
  target's own confirmed dependency tree (from recon, not invented) is
  what makes it work against a genuine remote target. Generalized in
  [[picklescan-bypass-denylist-gaps-and-setstate-opcode-blindness]].
  — [[OSAI+ - Supply Chain Attacks on AI-ML Systems]]
- A per-vhost/per-directory AppArmor confinement hat (`mod_apparmor`,
  `AAHatName`) mediates subprocess `execve()` independently of file
  permissions — a webshell can write successfully and still have its
  `system()`/`exec()` calls silently gutted by a binary allow-list; a
  compiled-in native function (PHP `mysqli`, `curl_exec()`) sidesteps this
  entirely since no `execve()` ever fires. Generalized in
  [[apparmor-hat-exec-confinement-native-function-bypass]].
  — [[cobblestone#Rabbit Holes|cobblestone]]

## AI / LLM Security

- A RAG-backed assistant's ingestion pipeline (upload → chunk/embed →
  vector-store index → retrieval-augmented answer) usually has no
  data/instruction boundary at all — content submitted through an open
  upload/ticket/document endpoint is treated as equally authoritative as
  vetted internal policy the moment it's retrieved into a prompt. This
  stacks with a second, independent failure: whatever *consumes* the
  model's answer (a scripted automation, an agent with tool access, a
  human copy-pasting a link) trusting it enough to act without
  independently verifying the destination. Confirm the poisoned content
  round-trips (ask the natural question, check the answer echoes it) before
  waiting on any downstream trigger — and don't over-invest in
  convincing-looking phishing infrastructure when the actual "victim" is an
  automation, not a person; capturing credentials needs nothing more than a
  raw listener at the URL the payload names. Generalized in
  [[rag-ingestion-poisoning-indirect-prompt-injection]].
  — [[OSAI+ - Exploiting RAG Pipelines]]
- A filename denylist on an agentic RAG assistant's tool-calling layer
  ("Access to 'bashrc' files is restricted") is worth testing for *where*
  it actually checks — a substring match against the raw incoming request
  text is bypassed by paraphrasing the target file by what it does rather
  than naming it, since the model's own reasoning still resolves the same
  blocked path with no denylisted vocabulary anywhere in the request. A
  single successful bypass this way isn't proof of a reliable technique,
  though — tool invocation can depend on retrieved context *authorizing*
  the action, not phrasing alone, so a near-identical retry can fall back
  to a plain no-tool-call answer. Don't gamble on an existing KB document
  happening to authorize the call; plant one that does deliberately (a
  fake "support runbook" that pre-approves the tool call, worded broadly
  enough — symptom-based framing — to win retrieval across many plausible
  real phrasings, not one known query). Once a tool call fires, ask the
  assistant to state the absolute path it resolved against rather than
  assuming the user context. Generalized in
  [[rag-tool-call-authorization-via-retrieval-hijacking]].
  — [[OSAI+ - Exploiting RAG Pipelines]]
- An LLM tool that wraps a native OS primitive (mapping a UNC path,
  opening a file/URL, issuing a request) inherits every capability *and
  every risk* of that primitive, no injection required — a `map_smb`-style
  tool description mentioning "predefined service account credentials"
  plus zero destination allowlist is a forced-authentication (coercion)
  primitive by construction: a plain, honest natural-language request to
  map an attacker-controlled UNC path is the entire exploit, capturable
  with any NTLM-challenge-logging SMB listener (Responder in `-A`/analyze
  mode is enough when the destination is already deliberately chosen,
  no LLMNR/NBT-NS/mDNS poisoning of the wider network needed). Generalized
  in [[rag-tool-call-authorization-via-retrieval-hijacking]].
  — [[OSAI+ - Exploiting RAG Pipelines]]
- A "preview the first N characters before trusting it" ingestion defense
  only ever inspects a fixed-size slice of *extracted* text — find the
  exact mechanism via the target's own observability tooling (a trace span
  attribute, a log line) rather than guessing, then pad plausible on-topic
  filler ahead of the payload until its real offset (checked in extracted
  text, not source string — PDF extraction reflows whitespace and isn't
  1:1 with the source) clears the boundary. Evading the check is a
  separate fact from the payload actually working — a payload that clears
  the preview by a slim margin (19 chars) still did nothing, because it
  read as flat declarative policy text rather than an instruction; the fix
  was framing (address the model explicitly, cite a fake authority, demand
  verbatim reproduction), not repositioning. Separately, the chunker's own
  fixed-size sliding window (not sentence/paragraph-aware) can silently
  split a longer instruction across two chunks, making retrieval — and
  thus the exploit — depend on query phrasing; size and position the
  payload to fit inside one chunk, ideally alongside the document's own
  highest-relevance content. Generalized in
  [[rag-ingestion-preview-evasion-via-blending]].
  — [[OSAI+ - Exploiting RAG Pipelines]]
- Any per-document ingestion defense (preview-based or a hypothetical full-
  content scan) has a structural blind spot: splitting one attack across
  two documents — a procedure fragment naming a second document by
  reference, and a target fragment supplying what that reference points
  to — means no single file ever contains the complete instruction, so it
  only assembles inside the model's context window at query time. The
  target fragment needs its own topical framing to independently win
  retrieval for the trigger query, not just hope it rides along with the
  procedure fragment — confirm both actually land in the same context via
  the pipeline's own retrieval trace before trusting the design. Stacks
  with zero-width Unicode characters (U+200B between every letter) woven
  into a denylisted target string to defeat a *contiguous-substring*
  keyword check at the tool-call-argument layer — one level past
  [[rag-tool-call-authorization-via-retrieval-hijacking]]'s "checks raw
  request text, not the resolved path" finding — while the model's own
  token-level reading still reconstructs the string once told to strip the
  noise; needs a Unicode-capable font (not a base-14 PDF font) to survive
  PDF generation, and confirm the character count survives extraction
  intact before trusting it live. Confirm a tool call actually fired
  (function name, resolved argument, blocked/not-blocked flag from the
  pipeline's own tracing) rather than trusting file-shaped text in the
  answer as proof. Generalized in
  [[rag-distributed-poisoning-split-document-attack]].
  — [[OSAI+ - Exploiting RAG Pipelines]]
- An MCP-style tool-calling chatbot's own self-description ("executes
  single-batch T-SQL commands") names its backend SQL dialect almost as
  reliably as a version banner would, well before any exec primitive is
  touched — each dialect has its own procedural-language name (T-SQL vs.
  PL/pgSQL vs. PL/SQL), dummy/catalog table (`sys.*` vs. `pg_catalog` vs.
  `DUAL`), and identifier-quoting convention that essentially never
  appears outside that one product, and a single dialect-exclusive
  function call (`SELECT DB_NAME()` for SQL Server, etc.) confirms it
  independently of whatever the model claims about itself. Generalized in
  [[sql-dialect-fingerprinting-via-self-disclosure]].
  — [[OSAI+ - Final Capstone - Megacorp One AI]]

## Windows / AD Privesc

- Before starting exploit/privesc on any Windows/AD box, work off
  [[windows-active-directory-attack-surface-checklist]] rather than
  re-deriving the attack surface from scratch — it exists specifically
  because this vault has repeatedly lost sessions to under-enumeration
  (Checkpoint, Garfield) or to running the full AD CS sweep too late
  (Fries), or to deferring a cheap early check (pre2k default computer-
  account passwords) behind flashier vectors until every one of them was
  exhausted first (Pirate).
  — [[checkpoint#Privesc|Checkpoint]], [[garfield]], [[fries]], [[Pirate]]
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
- A pre-Windows-2000-compatible computer account's default password
  (lowercase `sAMAccountName` minus the trailing `$`) is worth checking as
  a standard, *early* recon step on every AD box, not a last resort —
  `userAccountControl`'s `PASSWD_NOTREQD` bit plus no completed domain join
  is the flag to look for, and an SMB-only test can produce a false
  negative (`STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT` looks like a wrong
  password but isn't) where Kerberos AS-REQ pre-auth gives a definitive
  answer. Generalized in [[pre2k-default-computer-account-passwords]].
  — [[Pirate#Foothold|Pirate]]
- `ReadGMSAPassword` (or any strong AD read/write primitive) granted to a
  *group* is only as strong as the weakest account that's a member of that
  group — a correctly-configured gMSA read-ACL was undermined entirely by
  one forgotten, never-joined computer account with a guessable default
  password sitting in the group holding the right.
  — [[Pirate#Foothold|Pirate]]
- Resource-Based Constrained Delegation can be written onto a target with
  **no pre-existing ACL edge at all** by coercing the target's own machine
  authentication and relaying it to LDAP(S) — every computer object has a
  default SELF write on its own `msDS-AllowedToActOnBehalfOfOtherIdentity`,
  so capturing that machine's own auth and relaying it is sufficient by
  itself. Gate-check per machine, not per patch baseline, whether
  `--remove-mic` (CVE-2019-1040) is needed to get past the coercion
  callback's own client-side signing request. Generalized in
  [[rbcd-via-coercion-relay]].
  — [[Pirate#Foothold|Pirate]]
- A constrained-delegation grant scoped to one specific SPN string can be
  redirected to a completely different computer object by moving that SPN
  string there (if you separately hold `WriteSPN` on the real target) and
  rewriting the resulting ticket's `sname` via `impacket-getST -altservice`
  — S4U2Proxy's allow-list check is a string match against
  `msDS-AllowedToDelegateTo`, not an ownership check, and a Kerberos
  ticket's `sname` sits in the unencrypted outer structure with no
  integrity protection. Generalized in
  [[s4u2proxy-spn-hijack-altservice-ticket]].
  — [[Pirate#Root|Pirate]]
- A delegated `CREATE_CHILD` ACE on an AD OU, scoped to a non-obvious
  object class, is much faster to confirm by attempting the actual LDAP
  add than by parsing the raw security descriptor — especially for a
  Kerberos-only identity with no NTLM password, since most SD-decode
  tooling assumes one. Try a generic control-class object first (denial
  proves the ACE is class-scoped, not blanket) then the class you actually
  want. — [[DarkZeroReturns#Privesc|DarkZeroReturns]]
- A forest trust's `TREAT_AS_EXTERNAL` SID filtering strips domain-relative
  SIDs with RID < 1000 and any well-known/BUILTIN alias SID, but passes a
  domain-relative SID with RID ≥ 1000 through regardless of which domain's
  ticket carries it — the classic bypass injects a real, native, nested
  high-RID group SID from the *trusting* forest into a golden ticket forged
  in the *trusted* forest. Confirm the exact injected SID matches this
  shape (domain-relative AND RID≥1000) before concluding the technique
  itself failed; a well-known alias or a low-RID group from either forest
  tests a different, already-filtered class and proves nothing about the
  RID≥1000 rule. Two independent impacket tooling defaults/bugs
  (`ticketer.py`'s `-user-id 500` default tripping `PAC_REQUESTOR`/
  CVE-2021-42287 hardening; `getKerberosTGS`'s referral-chase reusing the
  wrong KDC) can each independently produce a target-shaped rejection and
  must be fixed before the SID-filtering question is even reachable. A
  **plain forest-transitive trust with no `TREAT_AS_EXTERNAL`** is a
  structurally different SID-filtering regime — mandatory and unconditional,
  not RID-gated the same way — so don't assume the RID≥1000-survives rule
  transfers without re-testing, and confirm with a direct `tokenGroups`
  decode of the resulting identity rather than an outcome-based access
  inference. Generalized in [[cross-forest-sid-injection-ticketer-gotchas]].
  — [[DarkZeroReturns#Root|DarkZeroReturns]], [[PingPong#Rabbit
  Holes|PingPong]]
- A computer account's `HOST/` SPN is automatically aliased by AD to cover
  `cifs/`, `http/`, `rpcss/`, `wsman/`, and `termsrv/` unless a service is
  separately registered under its own dedicated account — a delegation/
  ticket primitive that only ever produced a `cifs/` or `HOST/` service
  ticket still backs SMB, WinRM, RPC, and RDP on that same host, since they
  all share the machine account's key. Don't conclude a service is
  unreachable from a delegation primitive just because its SPN wasn't the
  one explicitly granted — test the aliased prefix directly. Generalized
  in [[kerberos-host-spn-alias-substitution]].
- An "auto-restart every ~N minutes" claim about a Windows service, with no
  stated mechanism, is worth verifying by decompiling the binary rather than
  just re-waiting when the observed cadence doesn't match — a normal
  `ServiceBase`/`System.Timers.Timer` polling loop is not the same thing as
  a self-relaunching process, and the real driver can be something entirely
  external (an OS-health/log-rotation automation, a developer's own leftover
  `Todo.txt` note describing it) that doesn't reliably keep firing on the
  same schedule once disrupted by an attacker's file-lock race.
  — [[Eloquia#Root|Eloquia]]
- A file-upload feature that lands attacker-controlled documents in a
  directory silently consumed by a headless office-suite conversion
  pipeline is a NetNTLM capture primitive, not just a storage write — an
  OLE `draw:object` element with a UNC `xlink:href` inside a crafted
  `.odt` beacons to an attacker SMB listener the moment the pipeline opens
  it, no macro execution or human interaction required. A same-pipeline
  macro-autoexec follow-up attempt is a structurally different, usually
  gated technique (headless conversion's own default macro policy, not an
  interactive-open security dialog) — a negative there doesn't undercut
  the hash-leak primitive itself. Generalized in
  [[bad-odf-document-based-netntlm-capture]]. —
  [[hercules#Foothold|Hercules]]
- Overwriting a service/computer account's NT hash to equal the session
  key already embedded in one of its own issued TGTs (via
  `impacket-changepasswd -newhashes`, never a normal password reset, which
  syncs all key material instead of targeting just this one) is what lets
  a follow-on S4U2Self+U2U exchange decrypt correctly — the specific lever
  that turns a held machine-account-adjacent credential into an
  RBCD-eligible S4U2Proxy ticket without ever holding real Domain Admin
  membership. Generalized in
  [[kerberos-nt-hash-session-key-equalization-u2u]]. —
  [[hercules#Root|Hercules]]
- Moving an AD object between OUs (`ModifyDN`) transplants every ACE
  inherited from the destination OU's ACL onto that object, independent of
  and additive to whatever explicit rights its existing group memberships
  already granted — a `CREATE_CHILD`-on-OU primitive plus a `name`/`cn`
  write on an existing low-privilege account combine into moving that
  account under an OU carrying a real, already-weaponized inherited edge
  (e.g. `GenericWrite`) neither primitive granted alone. Generalized in
  [[ou-acl-inheritance-transplant-via-modifydn]]. —
  [[hercules#Privesc|Hercules]]
- The domain's KDS root key (not any individual gMSA object) is what a DC
  actually derives every gMSA's password from — reading it once
  (Tier-0-equivalent access required) lets an attacker compute the current
  *and every future* cleartext password for *any* gMSA in the domain
  entirely offline, and since the KDS root key itself has no supported
  rotation mechanism, this converts a transient DA-equivalent compromise
  into silent, permanent gMSA access. Worth dumping the moment any Tier-0
  access is reached, even briefly. Generalized in
  [[golden-gmsa-offline-kds-root-key-derivation]]. (Semperis research, not
  yet seen on a vault box.)
- ESC9/ESC10 are domain-level Schannel/KDC certificate-mapping downgrades,
  not template misconfigurations — a clean ESC1/ESC4/ESC8 template sweep
  doesn't rule them out, since ESC10 needs no vulnerable template at all if
  the DC's `StrongCertificateBindingEnforcement`/`CertificateMappingMethods`
  registry values are still in the (Nov-2022–May-2023) compatibility window
  or explicitly rolled back. Confirm the actual registry values on the
  target DC directly rather than assuming a modern patch level settles the
  question either way — this is a time-sensitive configuration state, not a
  permanent class like ESC1/ESC4. Generalized in
  [[adcs-esc9-esc10-certificate-mapping-downgrade]]. (SpecterOps research,
  confirmed permanently closed by the KB5014754 rollout timeline once — see
  [[PingPong#Privesc|PingPong]] — rather than merely "not currently
  configured vulnerable.")
- A Diamond Ticket evades Golden-Ticket-specific detection by starting from
  a genuinely DC-issued TGT (a real AS-REQ happens) and modifying only its
  decrypted PAC in place before re-signing/re-encrypting with the same
  `krbtgt` key a Golden Ticket needs anyway — no fabricated ticket metadata
  for a detection rule to catch, since the timestamps/lifetime are the DC's
  own real values. Same `krbtgt`-key prerequisite as Golden Ticket, just a
  stealthier use of it once Golden-Ticket-specific detection is a concern.
  Generalized in [[diamond-ticket-pac-preserving-tgt-forgery]]. (Semperis
  research, not yet seen on a vault box.)
- A Windows security descriptor's **Owner** field grants implicit
  `READ_CONTROL`+`WRITE_DAC` independent of the DACL's own ACEs — evaluated
  by group membership when the owner is itself a group SID, not just an
  exact-principal match. Every hand-rolled AD ACL-sweep tool that only
  walks the DACL will silently miss this; a validated tool (`bloodyAD`'s
  `get writable`) implements the full access-check semantics and catches
  it by default. The same rule applies identically at the NTFS filesystem
  layer, which can unblock a file-ownership-mismatched execution primitive
  (`icacls` fix) the same way it unblocks an AD group takeover. Even when
  the owner-implied right genuinely exists, a client tool (`dsacls.exe`,
  ADSI's `CommitChanges()`) can still refuse to exercise it for unrelated
  reasons — `bloodyAD`'s raw `LDAP_SERVER_SD_FLAGS` control is a
  structurally different code path worth trying before concluding the
  right itself doesn't apply. Generalized in
  [[ad-owner-implied-writedac-privesc]]. — [[PingPong#Privesc|PingPong]],
  [[DanglingTree#Root|DanglingTree]]
- Adding a cross-forest Foreign Security Principal as a member of a group
  you've just gained `WRITE_DAC`/`GenericAll` on can hit two sequential,
  legitimate AD group-scope restrictions rather than a single denial —
  `ERROR_DS_GLOBAL_CANT_HAVE_CROSSDOMAIN_MEMBER` (Global groups only accept
  same-domain members; convert to Universal) then
  `ERROR_DS_NO_FPO_IN_UNIVERSAL_GROUPS` (Universal groups still reject
  FSPs; convert to Domain Local, the one scope that accepts them). Both
  conversions are legal single-attribute `groupType` writes, not a
  workaround — recognizing the error codes as sequential scope-conversion
  steps rather than a dead end is what makes the weaponization tractable.
  Generalized in [[ad-owner-implied-writedac-privesc]]. —
  [[PingPong#Privesc|PingPong]]
- ESC4 (dangerous permissions on a certificate template) needs to be swept
  per-template, not just at the `Certificate Templates` container level —
  a container-level ACL sweep answers a different question ("who can
  create/delete templates") than a specific child template's own DACL
  ("who can reconfigure *this* one"), and a group that reads as an AD-CS
  management primitive by name can be genuinely clean at the container and
  CA-registry level while still holding a real, unswept `WriteOwner`/
  `WriteDacl` ACE on one specific sibling template. Generalized in
  [[adcs-esc4-child-template-acl-sweep]]. — [[PingPong#Root|PingPong]]
- A JEA `RestrictedRemoteServer` endpoint enforces two independent
  restrictions — a `VisibleCmdlets`-style command allowlist, and (if also
  configured) `ConstrainedLanguage` mode — via two different code paths.
  Wrapping a disallowed command in the call operator, `& { <cmd> }`, is a
  known, generic bypass of the allowlist layer specifically, distinct from
  any ConstrainedLanguage-mode type/method-invocation escape; exhausting
  one bypass class doesn't rule out the other, and a JEA endpoint declared
  "closed" after testing only one should be re-tested with the other before
  trusting that conclusion. `evil-winrm` cannot drive this reliably (its
  own `Invoke-Expression`-wrapping interactive loop isn't the same code
  path) — use a real PSRP client (`pypsrp`) instead. Generalized in
  [[jea-call-operator-visiblecmdlets-bypass]]. — [[PingPong#Privesc|PingPong]]
- Real Domain Admin obtained on one side of a bidirectional forest trust
  grants nothing on the other side by default — Microsoft's default
  forest-trust configuration (no explicit cross-forest administrative
  delegation configured) applies unconditional SID filtering and carries
  zero implicit privilege across the boundary; confirm this with a fresh,
  direct ACL sweep from the newly-elevated identity against the other
  domain's highest-value objects rather than assuming a trust implies any
  cross-forest privilege transfer either way. — [[PingPong#Privesc|PingPong]]
- A container-level deny ACE on a default AD container (most often
  `CN=Users`) blocks LDAP search/SAMR enumeration cleanly but has no
  reason to also block Kerberos AS-REQ pre-auth validation, LSA SID→name
  resolution, SAMR local-BUILTIN-alias membership queries, or a SYSVOL
  GPO's own raw-SID security settings — all four routinely survive a deny
  ACE scoped to directory reads and can fully unmask a hidden container's
  accounts/groups by name before any credential for one of them exists. A
  missing (not merely empty) default container in a BloodHound collection
  is the tell to go looking. Generalized in
  [[ad-hidden-container-deny-ace-side-channel-enumeration]]. —
  [[DanglingTree#Recon|DanglingTree]]
- A CA's own `certificateTemplates` published-name list and the actual set
  of template objects under `CN=Certificate Templates,...` are
  independently maintained — a name can be published with **no backing AD
  object at all**, and a consistent `CERTSRV_E_UNSUPPORTED_CERT_TYPE` from
  the CA for every account tested is indistinguishable, from outside, from
  a real ACL denying template resolution to everyone but an owner. Only a
  direct existence check (an LDAP `delete`/`search` against the exact DN
  returning `noSuchObject` rather than `insufficientAccessRights`) tells
  the two apart; if orphaned, a bare `CreateChild` right on the templates
  container (no `ManageCa` needed) is enough to weaponize it by recreating
  the object under the exact published name. Generalized in
  [[adcs-esc4-orphaned-template-name-recreation]]. —
  [[DanglingTree#Root|DanglingTree]]
- Windows Admin Center's undocumented login/RCE wire format is fully
  recoverable from its own served client-side JS (the login page's inline
  script, the Angular bundle's route constants) rather than guessed —
  and once RCE is obtained, a WMI/`schtasks.exe` block that looks like a
  system-wide WDAC/AppLocker policy can instead be a Windows-documented
  restriction on Network-type logon sessions specifically, distinguishable
  by testing the identical operation via a second account reached through
  a different (Interactive/Console-logon) code path. Generalized in
  [[windows-admin-center-invokecommand-rce]]. —
  [[DanglingTree#Foothold|DanglingTree]]

## Cloud

- AWS IAM privesc isn't only a policy-editing story —
  `iam:CreateAccessKey`/`CreateLoginProfile`/`UpdateLoginProfile` mint a
  working credential directly for a more-privileged principal that already
  exists, with zero policy-document change, making this class invisible to
  any tool (including this vault's own privesc-graph engine) that only
  reasons over IAM policy JSON. Generalized in
  [[aws-iam-create-access-key-login-profile-privesc]]. (Rhino Security Labs
  research, not yet seen on a vault box.)
- A customer-managed AWS IAM policy's *default version* is itself an
  escalation target distinct from any principal's attachment to it —
  `iam:CreatePolicyVersion --set-as-default` does not require the separate
  `iam:SetDefaultPolicyVersion` permission (a scoping mistake a
  least-privilege author is likely to make), and a stale, more-permissive
  inactive version already sitting among the policy's up-to-5 stored
  versions is a free `iam:SetDefaultPolicyVersion` escalation with nothing
  to craft. Generalized in [[aws-iam-policy-version-default-swap-privesc]].
  (Rhino Security Labs research, not yet seen on a vault box.)
- A resource-based policy (S3 bucket policy, KMS/SNS/SQS policy) that
  trusts an AWS service principal without an
  `aws:SourceAccount`/`aws:SourceArn` condition grants that trust to *any*
  customer who can configure that service to target the resource, not just
  its owner — the 2021 CloudTrail/Config/Serverless-Application-Repository
  confused-deputy bugs all shared this one root cause. This is a
  resource-policy edge class this vault's own privesc-graph engine
  explicitly doesn't model yet, not just an index gap. Generalized in
  [[aws-cross-service-confused-deputy-resource-policy]]. (Wiz Research, not
  yet seen on a vault box.)
- The instance metadata service (`169.254.169.254`) is the highest-value
  SSRF target on any AWS-hosted box — IMDSv1 needs a single unauthenticated
  GET to return a live instance-role's temporary credentials, IMDSv2 just
  adds a PUT-then-replay token dance that any SSRF with method/header
  control still satisfies, and a denylist-style SSRF filter that only
  thinks about `127.0.0.1`/`localhost` routinely never extends to this
  link-local address either. Generalized in
  [[aws-imds-ssrf-role-credential-theft]]. (Well-established technique via
  the 2019 Capital One breach, not yet seen on a vault box.)
- A Kubernetes RBAC grant scoped to `get` on `nodes/proxy` looks like
  harmless node-metadata-read plumbing but actually authorizes *any*
  GET-framed request to that node's kubelet HTTPS API, including the
  handshake for a fully interactive exec session — the Node authorizer
  infers its RBAC verb purely from HTTP method (GET→`get`, POST→`create`),
  so a token correctly denied `kubectl exec`'s POST-upgraded SPDY transport
  can still complete kubelet's GET-upgraded WebSocket exec transport
  (`v4.channel.k8s.io`) unimpeded. Query a token's real grants with
  `SelfSubjectRulesReview` rather than trusting a Role's name, and treat
  any `nodes/proxy` grant as a potential full-exec primitive worth testing
  directly. Pairs naturally with hunting the kubelet's own `PodList` (also
  reachable via the same grant) for a `privileged`+`hostPID`+host-root-
  mounted pod (a `prometheus-node-exporter` DaemonSet default is a common
  instance) as the actual host-root landing spot. Generalized in
  [[kubelet-nodes-proxy-websocket-exec-rbac-bypass]]. (Documented
  independently by Graham Helton's "Kubernetes Remote Code Execution Via
  Nodes/Proxy GET Permission.")
  — [[Fireflow#Privesc|Fireflow]]

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
- `setcap` satisfies the *kernel's* permission check for a specific
  syscall (e.g. binding a privileged port) — it does nothing against a
  program that separately hardcodes its own `geteuid() == 0` requirement
  in source (Responder is one confirmed instance:
  `if not os.geteuid() == 0`). If a capability grant doesn't fix a
  permission error, `grep` the tool's own source for an explicit root
  check before assuming the grant failed or reaching for a broader one —
  and don't route around a single script's hardcoded check by granting
  capabilities to a general-purpose interpreter (`python3`) that would
  extend to every script run through it, not just the one that needs it.
  — [[OSAI+ - Exploiting RAG Pipelines]]
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
- A checklist item sitting at the *top* of a standard checklist (cheap,
  early, well-documented) is still easy to skip in practice if a session
  starts with the flashier/higher-drama vectors instead and only backs
  off to the cheap check once everything else is exhausted — four
  sessions on [[Pirate]] independently re-derived the same "nothing found"
  conclusion on Kerberoasting/ADCS/BloodHound/coercion-relay before a
  pre-Windows-2000 default computer-account password (one LDAP query plus
  one Kerberos round-trip) turned out to be the actual initial-access
  credential the whole time. Ordering a checklist by cost doesn't help if
  sessions don't actually work it top-to-bottom.
  — [[Pirate#Lessons Learned|Pirate]]
- A correctly-recorded lead's own precise, concrete value (the exact SID,
  the exact endpoint, the exact filename) is not the same thing as the
  category of lead it belongs to — a lead can be re-tested many times,
  each time producing a genuinely honest negative, if what actually gets
  tested is a plausible-sounding substitute (a similarly-named SID, a
  nearby endpoint) rather than the specific value that was written down.
  Re-read a lead's exact stated value before every retest, and treat "we
  tried something in this family" as a materially weaker claim than "we
  tried the specific thing that was recorded." — [[DarkZeroReturns#Lessons
  Learned|DarkZeroReturns]]
- A tool's own default arguments or built-in referral/redirect-chasing
  logic can produce a failure indistinguishable from a correctly-hardened
  target — before concluding a target rejected an attack for a real
  security reason, rule out that the tool itself (not the target) produced
  the rejection via an unrelated default or an internal bug in its own
  retry/chase logic. — [[DarkZeroReturns#Lessons Learned|DarkZeroReturns]]
- A cited CVE is a claim about the specific vulnerable *component*, not
  proof the whole vulnerability class applies — check that the exact
  component the advisory names (a specific module/library, e.g.
  AngularJS's `ngSanitize`) is actually loaded/reachable before accepting
  the citation, even when the general technique clearly does work against
  the target. Directionally-right-vulnerability-class-wrong-specific-
  citation is a recurring pattern in third-party reference material, not a
  one-off. A version-matched CVE can be genuinely correct and still not be
  the actual mechanism used — patch-diffing the CVE's fix against what the
  exploit actually touches is what catches this (Helix's CVE-2023-34468
  matched the installed NiFi build exactly, and the real path went through
  an entirely different, unpatched property). — [[Eloquia#Foothold|Eloquia]],
  [[DarkZeroReturns#Lessons Learned|DarkZeroReturns]],
  [[Helix#Foothold|Helix]]
- Once a technique is independently verified correct at the source-code
  level and corroborated by external material, a further negative result
  on the *same spawned lab instance* is better read as evidence that
  instance's own background service (an admin-review bot, a scheduled
  task, etc.) is stalled, not that the technique is wrong — a clean
  respawn and an identical retest is cheap and decisive compared to
  inventing another variant of an already-verified mechanism. Confirmed
  twice now: [[DarkZeroReturns]] first, and again on [[Eloquia]] (6
  structurally distinct negative tests on the original instance, the
  identical trigger firing within ~3 minutes of a respawn).
  — [[Eloquia#Foothold|Eloquia]]
- A reference material's own working exploit *script* is a more reliable
  source of truth than its prose summary for exactly-which-identity/
  exactly-which-session mechanical details — a "report this content" flow
  description can omit or gloss over which account performs the action,
  while the actual code that works has to get it right by construction.
  When a documented technique keeps failing despite being source-verified
  as mechanically sound, re-read the reference's literal code path before
  concluding the mechanism itself doesn't exist.
  — [[Eloquia#Foothold|Eloquia]]
- A bare-wordlist content-discovery pass structurally can't find API routes
  that require the correct HTTP method plus a syntactically-valid parameter
  value just to avoid an immediate 404/405 — brute-force route+method+
  parameter-value tuples sourced from real OpenAPI/Swagger specs
  (`kiterunner`'s approach) instead, and always check for a live spec
  (`/swagger.json`, `/openapi.json`, `/api-docs`) first since a found spec
  beats any wordlist outright. Same wordlist-*shape* gap as the existing
  files-vs-directories issue, one layer up the stack. Generalized in
  [[contextual-api-endpoint-discovery-openapi-wordlists]]. (Assetnote
  research, not yet seen on a vault box.)
- A pivotal decision's *reasoning* (why this specific lead was worth
  checking, not just that it was checked) is sometimes handed down as a
  bare instruction ("check this package's hold status") without the
  discovery trail behind it ever being recorded — when that happens, say
  so plainly in the writeup rather than reconstructing a plausible-sounding
  derivation after the fact. A flagged gap is honest; an invented
  just-so story isn't, even when the actual technical result is real and
  correct. — [[Cohort#Privesc|Cohort]]
- A container/group-level "clean" ACL sweep and a specific child object's
  own ACL are different questions, and answering the first thoroughly
  (twice, by two different methods) doesn't answer the second — before
  declaring an entire access-control surface closed, state precisely what
  granularity was actually swept, and re-check individual high-value
  child objects by name if the sweep never queried them directly.
  — [[PingPong#Rabbit Holes|PingPong]]
- A blocked/environment-limited technique with every target-side
  precondition independently confirmed favorable is a different category
  of "not working" than a target-side dead end, and conflating the two in
  a writeup or a future pass's notes risks wasted effort re-verifying
  facts that were never actually in doubt — record which category a
  closed lead falls into explicitly, especially when the blocker is the
  attacker's own sandbox/network environment rather than anything the
  target itself did. — [[PingPong#Rabbit Holes|PingPong]]
- An inherited claim ("already captured," "already confirmed") carried
  forward unchanged across several session handoffs in a very long
  engagement can quietly drop the originating session's own stated
  uncertainty along the way — trace a load-bearing claim back to the
  session that actually produced it before repeating it, not just to the
  most recent session that restated it, especially for something as
  simple to mis-track as flag-capture status across 15+ sessions.
  — [[PingPong#Root|PingPong]]
- A relayed third-party writeup is a legitimate unblock for a genuinely
  stuck, multi-session engagement, but the exception is only as good as
  the verification done afterward — treat every specific, testable claim
  in it (a file path, a mechanism, an account) as a hypothesis to confirm
  live on the actual target, not a fact to carry forward unchecked, even
  when independent effort really has been exhausted first.
  — [[Helix#Privesc|Helix]]
- A closure statement's scope matters as much as its result — "a broad
  filesystem search found nothing" and "this specific subdirectory was
  enumerated" are different claims, and only the second one actually rules
  out a credential sitting in a service's own working directory under a
  filename that doesn't match the search's pattern list. State precisely
  what was searched, not just that a search happened, especially once a
  later pass finds something the earlier one's stated scope should have
  caught but didn't. — [[Helix#Rabbit Holes|Helix]]
- An "identical CA-side rejection for every account tested" result is a
  strong empirical signal but not itself a diagnosis — it's equally
  consistent with a real ACL denial and with the target object not
  existing at all, and only a direct existence probe (not another variant
  of the same denied action) tells the two apart. Declaring a mechanism
  closed on the first, more dramatic-sounding explanation without running
  the cheap existence check first can leave the real cause undiscovered
  for many sessions afterward. — [[DanglingTree#Rabbit Holes|DanglingTree]]
- When live introspection of a running process hits a genuine
  environment-specific wall (a CLR/runtime version mismatch, a sandboxed
  reflection API), exfiltrating the target binary and decompiling it
  offline is a structurally different move from trying another live
  variant of the same blocked technique — and often faster, since it
  reads the real, complete logic in one pass instead of iterating toward
  it through guesses. Generalized in
  [[dotnet-dll-exfil-ilspycmd-decompile]]. —
  [[DanglingTree#Privesc|DanglingTree]]
- An exhaustively-checked "no rights found" conclusion is only as good as
  the vantage point every check in it was run from — if the object a real
  right lives on is itself hidden from every principal doing the
  checking, no amount of additional ACL-sweep breadth from that same
  vantage point will find it. The fix is a different identity, not a
  wider sweep from the same one. — [[DarkZeroReturns#Lessons Learned|DarkZeroReturns]]
- Guessing a vulnerable service's invocation/calling convention through
  trial and error can burn a lot of cycles on silent failures with no
  signal to distinguish "wrong convention" from "primitive doesn't work at
  all" — the moment any form of code execution is confirmed through a
  different channel, stop guessing and read the service's own recovered
  source directly; the real mechanism is often simpler (and stranger) than
  any of the guessed conventions. — [[Fireflow#Privesc|Fireflow]]
- A version-matched, source-confirmed CVE is still only as good as its
  full precondition chain — confirming the vulnerable code path exists is
  necessary but not sufficient; every documented bypass/prerequisite (a
  default config flag, an auth-bypass endpoint) needs its own direct,
  live test against the specific target rather than being assumed present
  because the advisory describes it as typical. — [[Fireflow#Foothold|Fireflow]]
- An entire, independently-confirmed vulnerability chain can sit unfired
  for days waiting on an unreliable external trigger (an admin-bot review
  cycle, a scheduled task) while a completely different, un-gated
  primitive sits untested against the one specific target that would have
  made it work — closing a technique from a small, convenient sample of
  targets (the OS/DB defaults, not the application's own writable
  directories) rather than the target that actually mattered is the
  single costliest overgeneralization pattern seen in this vault's own
  session history. Re-reading a stalled lead's available reference
  material closely for the *one specific missing detail* (not just its
  high-level structure) is what actually broke the stall, not further
  effort spent making the original trigger more reliable.
  — [[cobblestone#Rabbit Holes|cobblestone]]
