# Gitea Actions: a Notifier That Never Sets `IsForkPullRequest` Skips the Fork-PR Approval Gate

Gitea Actions requires a maintainer to explicitly approve running CI for a
fork-originated pull request (`ifNeedApproval()` in
`services/actions/notifier_helper.go` — short-circuits to "no approval
needed" only when `!run.IsForkPullRequest`). That flag is computed once,
inside `handleWorkflows()`, from `input.PullRequest` — but not every event
that can dispatch a workflow run actually populates `input.PullRequest`
before calling into that shared code path.

## The gap (confirmed against real v1.25.0 source, not inferred)

`services/actions/notifier.go`'s `PullRequestReview()` — the notifier that
fires for `pull_request_review_approved` / `_comment` / `_rejected` —
builds its `notifyInput` with `.WithRef(review.CommitID)` and
`.WithPayload(...)` only. Unlike `NewPullRequest()` (the notifier for
`pull_request` itself), it **never calls `.WithPullRequest(pr)`**. Inside
`handleWorkflows()`:

```go
isForkPullRequest := false
if pr := input.PullRequest; pr != nil {   // nil for this notifier -- never entered
    ...
}
```

So any workflow with `on: [pull_request_review_comment]` (or `_approved`/
`_rejected`) dispatched from a fork-originated PR runs with
`IsForkPullRequest` hard-coded `false` — unconditionally skipping the
approval gate — while `RepoID` is still correctly the **base** repo's ID
(Gitea, like GitHub, always stores issues/PRs on the base repo, so that
part of the scoping was never actually broken by this bug; it's a single
omitted method call producing exactly one effect, not two separate ones).
The result: a run that executes for real, unapproved, on the base repo's
own registered runner.

## How to trigger it

`POST /api/v1/repos/{owner}/{repo}/pulls/{index}/reviews` with
`{"event":"COMMENT", "body": "..."}` against your own fork-originated PR.
Confirmed from source (`preparePullReviewType()` in
`routers/api/v1/repo/pull_review.go`): unlike `APPROVED`/
`REQUEST_CHANGES`, a `COMMENT`-type review has **no** "can't review your
own PR" restriction, so the PR's own author can submit it — no second
account needed.

## Why this matters even if a more "obvious" API path is blocked

A separate, unrelated bug/CVE (a repo-fork-into-org restriction bypass,
e.g. [CVE-2026-22555](https://github.com/advisories/GHSA-fhx7-m96w-mv29))
can hand you a controlled fork with real push access without independently
proving CI will actually run for it — Gitea's normal `pull_request`/`push`
paths on a fork are correctly gated (approval required, or simply never
dispatched to a repo-scoped runner registered against a *different*
`repo_id`). If every "obvious" trigger event is confirmed closed by
reading their own notifier code, check the less obvious ones (review
events, issue-comment events, any GitHub-Actions-compatible trigger Gitea
implements) for the same "does this notifier actually call
`.WithPullRequest()`" question before concluding the whole approval-gate
model is airtight.

## Seen on

- [[DarkZeroReturns#Privesc|DarkZeroReturns]] — `josh` (read-only on the
  real Gitea repo) forked it (via CVE-2026-22555's org-fork bypass) and
  opened a PR back to the base with a diagnostic
  `on: [pull_request_review_comment]` workflow. Every `push`/`pull_request`/
  `pull_request_target` combination against the same repo had already been
  exhaustively tested and correctly gated across 180+ sections of the same
  engagement. Submitting a `COMMENT`-type review against the PR's own head
  SHA triggered a real, unapproved run as `svc-runner` on the base repo's
  registered runner — the first genuine code execution reached in that
  entire engagement, leading directly to `user.txt` and, later, a
  delegated AD ACE that chained into local root
  ([[ksu-default-aname-lname-fallback]]).
