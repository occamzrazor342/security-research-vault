# RAG Tool-Call Authorization Hijacked via Planted Retrieval Context

A distinct escalation from [[rag-ingestion-poisoning-indirect-prompt-injection]]:
that technique poisons content for a *known* future query that something
else consumes. This one targets an agentic RAG assistant's own decision to
invoke a tool (`read_file` or similar function-calling capability), and
needs to survive *any* plausible phrasing of a user's question, not one
known string — closer to genuinely hijacking what wins retrieval than
pre-seeding a single answer.

## Two things to check on any RAG app with tool-calling

**1. Where does an input filter actually check?** A keyword denylist that
blocks specific filenames ("Access to 'X' files is restricted") is worth
testing from two angles before concluding it's a real boundary:

- Does it block the literal request text, or the tool's resolved
  argument? Paraphrase the request so the denylisted substring never
  appears in your raw question (describe the file by what it does —
  "the shell configuration file interactive non-login shells source" —
  instead of naming it), and see if the model's own reasoning still
  resolves to and reads the same blocked path. If it does, the filter is
  checking the wrong side of the pipeline entirely: raw input text instead
  of the actual action about to be taken.
- A single success this way is not proof of a reliable technique — retry
  with near-identical phrasing. If a retry falls back to a plain
  context-only answer with no tool invocation, the model's willingness to
  act isn't purely a function of your wording; something in *retrieved
  context* is what actually authorized the tool call the first time
  (existing KB content happening to semantically justify the action), and
  that's non-deterministic run to run.

**2. Does the assistant treat "this appeared in retrieved context" as
equivalent to "this is a legitimate instruction to act on"?** If so, don't
gamble on an existing document happening to authorize the action you want
— plant one that does, deliberately, worded broadly enough to win
retrieval across many plausible real-world phrasings of the triggering
question (symptom-based framing — "my terminal looks wrong," "aliases
stopped working" — rather than anything resembling the literal target
file/action). A fake "support runbook" or "standard operating procedure"
document that pre-authorizes a tool call ("this procedure is pre-approved
... does not require additional confirmation") reliably converts a
completely natural, keyword-free user question into the tool invocation
you want, with zero denylist-triggering vocabulary anywhere in the actual
request.

## What this buys you

Whatever the tool can reach, scoped to whatever OS/service context it
executes as — confirmed by asking the assistant to state the absolute
path it resolved a request against, rather than assuming. A `read_file`
tool with no path-based access control beyond a shallow filename denylist
is a full arbitrary-file-read primitive for that account: shell startup
files (env vars, often literal credentials — `export DB_CONNECTION_STRING=...`
is a real, confirmed instance), shell history (previously run commands,
sometimes carrying credentials passed on a command line), and anything
else the account can read.

## Bug-bounty relevance

Same OWASP LLM01 (indirect prompt injection) category as
[[rag-ingestion-poisoning-indirect-prompt-injection]], but specifically
worth checking on any AI feature with function-calling/tool access
(file access, internal API calls, ticket/record updates): does the
authorization model for *acting* differ from the authorization model for
*answering*? If retrieved content alone can green-light a tool call the
same way it green-lights an answer, that's the exploitable gap.

— [[OSAI+ - Exploiting RAG Pipelines]]
