# AWS IAM Credential-Creation Privesc (CreateAccessKey / CreateLoginProfile / UpdateLoginProfile)

A distinct privesc class from policy-editing (`iam:PutRolePolicy`,
`iam:AttachUserPolicy`, etc.): instead of *granting yourself* more
permissions, mint a brand-new working credential **for a more-privileged
principal that already exists**, then simply authenticate as them. No
policy document ever changes, which makes this class invisible to any
tooling (including this vault's own `Cloud Architecture/privesc_graph`
engine) that only reasons over IAM policy JSON — this is a distinct API
call with its own permission, not a capability derived from a `Statement`
block.

- **`iam:CreateAccessKey`** — if held over another IAM user (either
  directly, or implicitly via a wildcard resource on your own attached
  policy), create a new access-key-ID/secret-access-key pair *for that
  user* and use it directly. Works even if the target user already has two
  active keys' worth of quota used up to 1 (AWS allows max 2 keys/user —
  check first, `CreateAccessKey` fails past that cap, don't burn the
  attempt blind).
- **`iam:CreateLoginProfile`** — if a target user has **no** existing
  console login profile, this creates one with an attacker-chosen password,
  handing over full console access. Fails outright (does not overwrite) if
  a login profile already exists for that user — that failure itself is a
  useful oracle: it confirms the account *does* have password-based console
  access already provisioned, worth pursuing via `UpdateLoginProfile`
  instead.
- **`iam:UpdateLoginProfile`** — the sibling primitive for a user who
  *already* has a login profile: resets their console password to one you
  choose, without needing to know (or reset) anything else about the
  account.

## How to spot it

- Run `iam:ListAttachedUserPolicies`/`ListUserPolicies` on your own
  principal (or, if you can, `iam:GetAccountAuthorizationDetails` for the
  whole account) and grep the resulting policy documents for these three
  actions — a wildcard `Resource: "*"` on any of them (common in
  over-broad "IAM admin for my own team" policies that forgot to scope the
  resource ARN) is the tell. `arn:aws:iam::<account>:user/*` is equally
  exploitable, not just a literal `*`.
- Enumerate other IAM users/roles in the account first
  (`iam:ListUsers`/`ListRoles`) and target the ones with `AdministratorAccess`
  or broad managed policies attached, rather than the first user found —
  this primitive is only as valuable as the target it's pointed at.
- No MFA bypass needed for the `CreateAccessKey` path specifically — a
  freshly minted access key pair inherits the target's permissions with no
  MFA condition unless the *target's own* policy requires
  `aws:MultiFactorAuthPresent` on the actions you then try to use it for.

## Source

Rhino Security Labs, "AWS IAM Privilege Escalation – Methods and
Mitigation" (methods 4–6) —
https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/

Not yet encountered on a vault box. This is explicitly flagged as an
unimplemented capability class (`CAN_CREATE_PRINCIPAL`) in
[[Cloud Architecture/DESIGN.md|Cloud Architecture's DESIGN.md]] — the
engine's five-capability taxonomy deliberately doesn't model it yet.
