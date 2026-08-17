# AWS Cross-Account Confused-Deputy via Resource-Based Service Policies

A structurally different privesc/access class from anything in an IAM
*principal* policy graph: the victim never grants the attacker anything
directly. Instead, an AWS-managed service (CloudTrail, Config, Serverless
Application Repository, and others in the same shape) is itself a trusted
principal against a resource-based policy (an S3 bucket policy, in these
cases), and an attacker who can get that service to act *on the attacker's
own behalf while pointed at the victim's resource* inherits the service's
trust relationship instead of needing any relationship with the victim at
all — the classic confused-deputy pattern, at cloud-vendor scale.

**Concrete mechanism (Wiz Research, Black Hat 2021):**
- **CloudTrail**: an attacker configures CloudTrail logging *in their own
  account* to write its trail into a *victim's* S3 bucket name (bucket
  names are a global namespace, so this just requires knowing/guessing the
  victim bucket name). CloudTrail's service principal is trusted broadly
  enough by default bucket policies that it writes the attacker's logs into
  the victim's bucket — the attacker doesn't touch the bucket directly, the
  *service* does, on the attacker's instruction.
- **AWS Config**: same shape — Config's resource-policy trust relationship
  let an attacker direct the service to write into another customer's
  bucket.
- **Serverless Application Repository (most severe of the three)**: could
  be manipulated into **reading from** another customer's private S3
  bucket — including buckets in accounts with no internet connectivity at
  all, since the read happens service-side, not over the attacker's own
  network path. Real-world impact included exposed source code and
  hardcoded credentials sitting in victims' buckets.

**Root cause, generalized**: a resource-based policy that trusts an AWS
service principal (`Principal: {"Service": "cloudtrail.amazonaws.com"}` or
similar) without a scoping condition (`aws:SourceAccount`, `aws:SourceArn`)
grants that trust to *any* customer who can configure that service to
target the resource — not just the resource owner's own use of the
service. AWS fixed the vulnerable **defaults**, but any bucket policy
written before the fix (or copied from old documentation/Terraform
modules) can still lack the condition.

## How to spot it

- Any resource-based policy (S3 bucket policy, KMS key policy, SNS/SQS
  policy) that trusts an AWS service principal — grep for
  `"Service": "*.amazonaws.com"` entries — check whether a `Condition`
  block scopes it to `aws:SourceAccount`/`aws:SourceArn` matching only the
  resource owner's own account/resource. Absence of that condition is the
  bug, present on the policy regardless of any IAM principal permissions
  anywhere.
- This is exactly the class of bug this vault's own
  [[Cloud Architecture/DESIGN.md|`Cloud Architecture` privesc-graph engine]]
  explicitly does not model yet — its known-gaps list says resource-based
  policies (S3 bucket policies, KMS key policies) are "unhandled." A real
  audit needs to walk resource policies as their own edge class (victim
  resource → trusts → AWS service, with a condition-scoping check), not
  just the principal-side policy graph the engine currently builds.
- Bucket/resource names being global or guessable (a company-name-prefixed
  bucket, a predictable naming convention) is the practical precondition
  that makes "target a specific victim" feasible at all — this isn't a
  spray-every-bucket-in-existence attack, it needs the victim's actual
  resource identifier.

## Source

Wiz Research / Black Hat USA 2021, "Breaking the Isolation: Cross-Account
AWS Vulnerabilities" —
https://www.wiz.io/blog/black-hat-2021-aws-cross-account-vulnerabilities-how-isolated-is-your-cloud-environment
(slides: https://i.blackhat.com/USA21/Wednesday-Handouts/us-21-Breaking-The-Isolation-Cross-Account-AWS-Vulnerabilities.pdf)

Not yet encountered on a vault box.
