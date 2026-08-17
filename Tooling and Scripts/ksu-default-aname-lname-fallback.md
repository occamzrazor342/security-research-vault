# `ksu`'s Default aname→lname Fallback: Becoming Any Local Account by Naming a Matching Principal

MIT Kerberos's `ksu` ("Kerberized su") has **two structurally different
authorization paths** depending on whether `-e` is used, and every prior
"authorization failed" against it on a box can be the wrong path being
tested, not a real security boundary.

## The two paths ([`ksu(1)`](https://web.mit.edu/kerberos/krb5-1.20/doc/user/user_commands/ksu.html) is explicit about this, but it's easy to miss)

- **With `-e <command>`** (run one command, no interactive shell handoff):
  if the source user isn't root and target `~target_user/.k5users` doesn't
  exist, **authorization fails unconditionally** — it never even consults
  `.k5login`. This is a stricter, separate gate from the plain path below.
- **Without `-e`** (interactive shell): `ksu` checks `~target_user/.k5login`
  first, then `~target_user/.k5users`, and — critically — if **neither file
  exists**, falls back to authorizing via the target realm's own
  `krb5_kuserok()` **aname→lname mapping rules**: any Kerberos principal
  `<name>@<default_realm>` is authorized into the identically-named local
  account, no explicit grant file needed at all.

A repeated failure using `-e` (`account root: authorization failed`) is
easy to misread as "`.k5login` exists and denies me" — it doesn't
necessarily mean that; it can simply mean `-e`'s own stricter path was
exercised and `.k5users` is (as usual) absent. Confirm which file actually
exists (or doesn't) before concluding either way, and test both invocation
styles as genuinely different mechanisms, not variations on the same test.

## The exploitable consequence

If a domain-joined Linux box has neither `/root/.k5login` nor
`/root/.k5users`, and an attacker holds (or can create) a Kerberos
principal literally named `root@<REALM>`, a plain `ksu root` (no `-e`)
authorizes that principal straight into the local `root` account by
default — no privilege delegation, no ACL, just a name match. If the
attacker doesn't already control an account with that exact name, and has
enough AD write access to create one (e.g. a delegated `CREATE_CHILD` ACE
on some OU, even one scoped away from anything else useful), creating a
throwaway `user`-class object named `root` with a chosen password is
enough to manufacture the matching principal.

## Diagnostics worth knowing before concluding a `ksu` denial either way

- `ksu` reads its password prompt from plain stdin, not exclusively
  `/dev/tty` — no `expect`/pty allocation needed to drive it from a
  non-interactive context (a CI job, a scripted pipe), at least on the MIT
  krb5 build most Linux distros ship.
- An `authorization failed` response that comes back in single-digit
  milliseconds is *not* a real Kerberos round trip (every genuine AS-REQ
  takes tens-to-hundreds of ms) — that timing alone is a tell that the
  denial happened before any authentication was even attempted (i.e. the
  `-e`/`.k5users`-absent short-circuit), not a `.k5login`-based rejection
  after a real auth exchange.
- Rule out a PAM-level blanket deny (`/etc/pam.d/ksu` missing, falling back
  to `/etc/pam.d/other`) as an alternate explanation before trusting either
  conclusion — check whether `other` actually `@include`s a real
  `common-account` stack or hardcodes `pam_deny`.

## Seen on

- [[DarkZeroReturns#Root|DarkZeroReturns]] — `svc-runner` held a delegated
  `CREATE_CHILD` ACE on `OU=GiteaMigration`, used to create
  `CN=root,sAMAccountName=root` with a chosen password. The first attempt
  (`ksu root -e id`) failed instantly with `authorization failed`, wrongly
  read (for several sections of the engagement) as proof `/root/.k5login`
  existed and denied the principal. Testing the plain (non-`-e`) form
  instead — feeding the password and follow-up commands over the same
  stdin pipe — authenticated for real (~350ms round trip) and dropped
  straight into a real root shell via the aname→lname default, since
  neither `.k5login` nor `.k5users` existed on that box at all.
