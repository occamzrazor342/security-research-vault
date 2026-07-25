# Unauthenticated LocalStack Backend Reachable Behind an IAM-Enforcing Proxy

A pattern worth checking on any box that mocks AWS via LocalStack (or
similar) behind a custom auth/IAM-policy layer: the policy enforcement
usually lives in a **proxy sitting in front of** LocalStack, not in
LocalStack itself. LocalStack's own edge port (`4566` by default) does not
validate credentials unless explicitly configured to (`ENFORCE_IAM`, a
Pro-only feature in most versions) -- literally any access key/secret pair,
including the string `"test"`/`"test"` from LocalStack's own docs, is
accepted. If anything on the network path can reach LocalStack's real port
directly instead of going through the app's own `Host:`-header-routed
proxy, the app's entire IAM-scoping story (narrowly-scoped roles, SQS-only
policies, etc.) is cosmetic for that caller.

## How to spot it

- A backend health/info endpoint (`/_localstack/health`, `/_localstack/info`)
  reachable directly from wherever your foothold sits, separate from
  whatever `aws.<box>.htb`-style vhost the app documents as the "real"
  endpoint.
- DNS inside the foothold's network namespace resolving a second internal
  hostname (here, `floci` -- a docker-compose service name) to a different
  IP than the documented backend vhost. `sqs:ListQueues` (or any other
  already-permitted call) returning a `QueueUrl` whose *hostname* differs
  from the endpoint you called it against is a strong tell -- it means the
  proxy is itself relaying to that second host, and that host is worth
  probing directly.
- Once found, confirm with literally any throwaway credentials
  (`AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test`) against every
  service the target's `/_localstack/health` claims is `"running"` --
  compare what comes back against what the properly-authenticated,
  policy-enforced path allowed. A blanket `AccessDenied` through the proxy
  but full `ListBuckets`/`ListSecrets`/`ListRoles`/etc. success direct to
  the LocalStack port confirms the bypass.

## What this buys you (and what it doesn't)

Full, unrestricted use of every implemented LocalStack API as a
consequence -- most usefully **Lambda** (`CreateFunction` + `Invoke`),
since LocalStack's community-edition Docker/containerd executor runs
function code as **root (uid 0)** inside a container it spins up per
invocation, with zero IAM check on `lambda:CreateFunction`/
`lambda:InvokeFunction` once you're talking to the raw port. This is a
real, low-effort root-code-execution primitive worth checking for even if
the eventual privesc dead-ends elsewhere.

What it does *not* automatically get you:
- **Real backend data.** If the box's operator only ever wired up the app
  to use a couple of specific services/resources (e.g. one SQS queue, one
  S3 bucket holding nothing sensitive), the bypass just proves the access
  is unauthenticated -- it doesn't manufacture secrets that were never
  stored there. Confirm emptiness explicitly (`list-buckets`,
  `list-secrets`, `list-roles`, `describe-instances`, `list-tables`,
  `list-functions`, `list-rules`, `list-stacks`, `list-clusters`, etc.) --
  don't assume a "misconfiguration" finding is automatically a full
  compromise.
- **Host escape via the Lambda RCE, specifically.** The per-invocation
  execution container is ephemeral and, in a reasonably hardened
  deployment, has no `/var/run/docker.sock`, no host bind mounts, and no
  more network reachability than the original foothold already had. Check
  explicitly (`find / -iname docker.sock`, `/proc/mounts` inside the
  sandboxed function, a full port sweep of every bridge gateway visible
  from inside it) before assuming root-in-sandbox implies root-on-host.
  **This does not mean the backend as a whole is a dead end for host
  root, though** -- see [[nimbus]] below, where Lambda/ECS were
  conclusively ruled out this way but a third LocalStack execution
  primitive, CodeBuild, eventually got there. Check every execution-style
  service the backend implements (Lambda, ECS `RunTask`, CodeBuild, Batch,
  Step Functions activities, etc.), not just the first one that gives
  root-in-a-sandbox — they don't all have the same sandbox-escape
  properties. Generalized further in
  [[localstack-codebuild-privileged-mode-container-escape]].
- **Arbitrary local image reuse via `PackageType=Image`.** If the lab
  environment has no outbound internet access (common for isolated
  HTB/lab boxes), an `ImageUri` that isn't already byte-for-byte cached
  under the exact reference you guessed fails cleanly with a registry
  DNS/network timeout -- this degrades into the same blind-guessing risk
  category as credential spraying (guessing exact local image tags) and
  should be capped the same way, not brute-forced. Reasoning out the tag
  from the deployment's own naming conventions (Docker Compose v2's
  default `<project>-<service>` hyphenation, for instance) beats guessing
  blindly and isn't subject to the same budget cap.

## Seen on

- [[nimbus]] -- worker-container foothold (landed via chained
  SSRF+IMDSv1+YAML-deserialization RCE, see foothold notes) reached a
  second internal host (`floci`, LocalStack 1.5.17 community) directly on
  the same docker bridge, bypassing the app's own IAM-policy-enforcing
  proxy on `aws.nimbus.htb` entirely. Got root code execution via
  unauthenticated `lambda:CreateFunction`/`Invoke` and `ecs:RunTask`, both
  conclusively ruled out as host-root vectors (ephemeral sandbox, no
  docker socket, no host bind mount honored). Nine sessions exhausted
  every other LocalStack-service angle (hot-reload gate, full 51-service
  sweep, bridge-subnet/loopback network discovery) before a tenth found
  that CodeBuild's `privilegedMode` flag, pointed at the box's own
  custom-built `floci/floci:latest` image, gave genuine elevated
  capabilities and a real host-root escape via `core_pattern` — see
  [[localstack-codebuild-privileged-mode-container-escape]] for that
  follow-on technique. Full command-by-command trail in
  `Recon Output/nimbus-privesc.md`; reusable tooling in
  `Tooling and Scripts/exploits/nimbus/localstack_unauth_lambda_rce.py`.
