# AWS Managed-Policy Default-Version Privesc (CreatePolicyVersion / SetDefaultPolicyVersion)

A privesc primitive that targets the **policy object itself** rather than
any principal's attachment to it — if you can create a new version of a
customer-managed IAM policy (or flip which existing version is "default"),
every principal that policy is already attached to instantly inherits
whatever the new default version grants, with zero change to any
user/role/group object.

- **`iam:CreatePolicyVersion`** — a managed policy can hold up to 5
  versions; creating a new one with `--set-as-default` immediately makes it
  the active version for every attachment. **The critical detail**: passing
  `--set-as-default` on `CreatePolicyVersion` does **not** require the
  separate `iam:SetDefaultPolicyVersion` permission — it's checked as part
  of `CreatePolicyVersion` itself. A policy scoped to "allow
  `CreatePolicyVersion`, deny `SetDefaultPolicyVersion`" (a plausible
  attempt at least-privilege) does **not** block this escalation path the
  way its author likely intended.
- **`iam:SetDefaultPolicyVersion`** — if the policy already has an older,
  more permissive version sitting inactive among its up-to-5 stored
  versions (common after a policy has been "tightened" over time without
  deleting the old versions), this flips back to it directly — no new
  version needs to be authored at all. Check `iam:ListPolicyVersions`
  first; a stale permissive version sitting at position 1 or 2 is a
  free escalation with no content to craft.

## How to spot it

- For any customer-managed policy you can call `iam:ListPolicyVersions`
  against: check both (a) whether you hold `CreatePolicyVersion` on it
  (regardless of whether you separately hold `SetDefaultPolicyVersion` —
  the former alone is sufficient), and (b) whether any non-default stored
  version is more permissive than the current default.
- This only applies to **customer-managed** policies (ones with a real ARN
  under your account, editable), never AWS-managed policies
  (`arn:aws:iam::aws:policy/...`) — those are read-only regardless of your
  own permissions.
- Blast radius scales with how many principals the policy is attached to
  (`iam:ListEntitiesForPolicy`) — a policy attached to a dozen roles turns
  one `CreatePolicyVersion` call into a dozen simultaneous escalations.

## Source

Rhino Security Labs, "AWS IAM Privilege Escalation – Methods and
Mitigation" (methods 1–2) —
https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/

Not yet encountered on a vault box. Explicitly flagged as an unimplemented
capability class (`CAN_MODIFY_POLICY_VERSION`) in
[[Cloud Architecture/DESIGN.md|Cloud Architecture's DESIGN.md]].
