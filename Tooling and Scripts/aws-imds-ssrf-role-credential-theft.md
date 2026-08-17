# AWS IMDS Credential Theft via SSRF (No IAM Permission Required)

The highest-value SSRF target on any AWS-hosted box isn't an internal admin
panel — it's the instance metadata service at `169.254.169.254`, reachable
from any process on the instance (including one an attacker only has SSRF
into, not a shell on). If the instance has an IAM instance profile attached
at all, this is a straight line to that role's live, temporary credentials
— **requiring zero IAM permissions of the attacker's own**, since IMDS
itself does no authentication. This is the same root-cause class as the
2019 Capital One breach (a WAF SSRF reaching IMDS on an over-permissioned
instance role).

- **IMDSv1** (the vulnerable default on older/unpatched launch
  configurations): a single unauthenticated `GET` is sufficient —
  `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
  lists the attached role name, then
  `.../iam/security-credentials/<role-name>` returns the live
  `AccessKeyId`/`SecretAccessKey`/`Token` JSON directly. Any SSRF primitive
  that can reach this URL (even a pure GET-only SSRF like a URL-preview/
  webhook-validator feature) is sufficient — no header control, no
  redirects, no PUT capability needed.
- **IMDSv2** (session-oriented, default on newer instances but not
  retroactively enforced on old ones unless explicitly hardened): requires
  a `PUT` to `/latest/api/token` with an
  `X-aws-ec2-metadata-token-ttl-seconds` header first, then the returned
  token must be replayed as `X-aws-ec2-metadata-token` on the actual
  metadata `GET`. This blocks a *pure-GET* SSRF primitive outright (can't
  set the PUT method or custom request headers) — but any SSRF that lets
  you control HTTP method and headers (not just the URL) still works
  identically to v1, just with two round-trips instead of one. Confirm
  which primitive you actually have before writing IMDSv2 off as a dead
  end.
- **`HopLimit`** matters if the SSRF pivots through even one network hop
  (a reverse proxy, a container bridge) before reaching the metadata
  service — AWS's IMDS packets are capped at a TTL of 1 by default
  specifically to stop exactly this kind of relayed SSRF from containers;
  an instance profile's `HttpPutResponseHopLimit` explicitly raised past 1
  (sometimes done to support containerized workloads) reopens this path
  from inside a container that couldn't otherwise reach it.

**Once you have the role's temporary credentials**, treat them as a normal
IAM principal from that point on — everything else in this vault's AWS
technique notes (
[[aws-iam-create-access-key-login-profile-privesc]],
[[aws-iam-policy-version-default-swap-privesc]],
[[aws-cross-service-confused-deputy-resource-policy]]
) and the [[Cloud Architecture/DESIGN.md|privesc-graph engine's]] own
capability model (`CAN_ASSUME`, `CAN_MODIFY_IDENTITY`, etc.) apply exactly
as if you'd been handed the credentials directly — IMDS theft is just the
initial-access step onto the IAM graph, not a separate privesc technique in
itself. This vault's existing Web/App SSRF material (parser-confusion
bypasses, filter-bypass encodings) is the actual technique that gets you
*to* the metadata endpoint in the first place — cross-reference that
before assuming a naive `127.0.0.1`/`localhost` blacklist blocks reaching
`169.254.169.254` (a link-local address, distinct from loopback, and
routinely absent from denylists that only think about loopback).

## How to spot it

- Any SSRF primitive on a box confirmed or suspected to be AWS-hosted
  (`X-Amz-*` response headers, an `.compute.amazonaws.com` hostname
  anywhere, an S3-backed asset URL) — try the metadata URL immediately,
  it costs one request.
- A denylist-style SSRF filter that blocks `127.0.0.1`/`localhost` but was
  never extended to also block `169.254.169.254` (or its IPv6 equivalent,
  `fd00:ec2::254`) — this vault has already seen ([[fries]]-style boxes
  and the SSRF filter-bypass notes) that loopback-focused denylists are a
  recurring, narrow blind spot; the metadata address is a second, equally
  common blind spot in the same denylist style.

## Source

Well-established technique; canonical public incident reference is the
2019 Capital One breach (SSRF via a misconfigured WAF reaching IMDSv1 on an
over-permissioned role) —
https://www.wiz.io/academy/cloud-security/aws-vulnerability-scanning
(general AWS vulnerability background) and AWS's own IMDSv2 hardening
documentation. Not yet encountered on a vault box.
