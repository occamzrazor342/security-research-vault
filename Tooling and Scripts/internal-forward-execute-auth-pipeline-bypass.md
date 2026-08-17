# Internal Forward/Execute Auth-Pipeline Bypass

## Why this is a distinct bug class from a path-normalization auth bypass

The well-known IIS/ASP.NET auth-bypass pattern is a **normalization
mismatch** — the authorization module and the routing layer disagree about
what a path string means (trailing dot, alternate case, `%2e` encoding,
etc.), so a request that "looks" blocked to one layer sails past it. This
technique is different and doesn't involve tricking path parsing at all: it
abuses a legitimate **server-side internal forward/execute** primitive
(ASP.NET's `Server.Execute()`, Java Servlet's `RequestDispatcher.forward()`/
`include()`, and equivalents in other frameworks) that lets one handler
invoke another *within the same request*, without re-running the full HTTP
pipeline — including the authorization filter that gated the target
resource in the first place.

## The mechanism

1. A path-based authorization rule blocks direct external access to a
   sensitive resource (e.g. an admin page under `/sitecore/shell/`).
2. A *different*, externally-accessible endpoint exists whose own handler
   internally forwards/executes into arbitrary server-side paths as a
   feature (a preview/render/include endpoint that takes a path or template
   name as a parameter) — e.g. Sitecore's `Preview` action calling
   `Server.Execute("/sitecore/shell/Invoke.aspx")`.
3. Because `Server.Execute`/`RequestDispatcher.forward` operates purely
   server-side and does not re-enter IIS's (or the servlet container's)
   request pipeline, the authorization module that would have blocked a
   direct request to the sensitive path never fires — the protected page
   executes in the attacker's own request context, with whatever
   parameters the attacker supplied to the accessible entry point.

## How to spot it

- Look for any accessible feature whose job is literally "render/preview/
  include another server-side path" (preview panes, template renderers,
  report generators, "print view" endpoints, CMS admin conveniences) —
  these are exactly the kind of internal-forward primitive this abuses.
- If a path-based `<authorization>`/`web.config` rule (or a servlet-filter
  URL pattern) is the *only* thing gating a sensitive endpoint, treat it as
  suspect the moment any internal-forward-capable feature exists elsewhere
  in the same app — the rule only guards the front door, not every internal
  corridor.
- Confirm by feeding the forwarding endpoint the protected path as its
  parameter and checking whether the response is the protected resource's
  actual content, not a redirect/403 — a 200 with the protected page's real
  content confirms the pipeline was bypassed, not merely that the parameter
  was accepted.

## Source

Assetnote, "Bypass IIS Authorisation with this One Weird Trick: Three RCEs
and Two Auth Bypasses in Sitecore 9.3" —
https://www.assetnote.io/resources/research/bypass-iis-authorisation-with-this-one-weird-trick-three-rces-and-two-auth-bypasses-in-sitecore-9-3

Not yet encountered on a vault box — added ahead of hitting it live. Worth
checking on any enterprise CMS/portal product (Sitecore, Confluence,
SharePoint, and similar large ASP.NET/Java apps this vault's recon-agent
already treats as high-value targets once fingerprinted) rather than only
CVE-searching the fingerprinted version.
