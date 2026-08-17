# RAG Ingestion-Preview Evasion via Document Blending

A pattern for defeating a specific class of lightweight ingestion defense:
a "preview" check that shows/logs only the first N characters of an
uploaded document — meant to let an analyst (human or automated) eyeball
new knowledge-base content before trusting it, without reading the whole
file. This is strictly weaker than [[rag-ingestion-poisoning-indirect-prompt-injection]]'s
target (no defense at all) but the same root cause: no data/instruction
boundary once content is retrieved into a prompt, just with a screening
step bolted on the front that only looks at a fixed-size slice of the
document.

## Finding the mechanism instead of guessing at it

Don't assume what "preview" means — a rendered-page glance, a UI snippet,
a substring check are all plausible and require different bypasses. If the
target ships any observability tooling (an APM/tracing console like Arize
Phoenix, application logs, a debug endpoint), check there first: ingestion
pipelines commonly log a preview attribute on their own trace spans for
debugging, and that attribute's exact slice boundary (character count,
whether it's pre- or post-extraction) is directly checkable rather than
inferred. Confirmed instance: a `load_documents` trace span exposing
`file_N_preview` = the literal first 500 characters of *extracted* text
(not the raw file, not a rendered view) — found by reading the app's own
instrumentation, not by trial and error.

## The evasion

Pad the document with enough plausible, on-topic filler content ahead of
the injected instruction that the instruction's start offset exceeds the
preview's character limit. Verify the real offset in the *extracted* text,
not the source string — PDF text extraction reflows whitespace (line-wrap
newlines, dehyphenation) and isn't a 1:1 length match with whatever
generated the PDF, so a margin computed from source text alone can be
wrong in either direction. Extract locally with the same library family
the target likely uses (`pypdf`, `pdfminer`) before ever uploading, and
recheck against the target's own preview attribute afterward — don't trust
local computation alone once the file is live.

## Evading the check is necessary but not sufficient

Confirmed empirically: a payload that technically clears the preview
boundary (started at char 519 against a 500-char limit) still failed to
produce any effect, because the instruction was phrased as flat
declarative text indistinguishable from the surrounding "real" policy
prose — the LLM read it as more knowledge-base content, not a directive
addressed to it. Retrieval-context inspection (which chunks actually made
it into the model's prompt, from the app's own tracing) confirmed the
payload chunk *was* present in context; the model simply didn't act on it.
That's a framing failure, not a retrieval failure, and the two need to be
diagnosed separately before concluding either "evasion doesn't work" or
"the model can't be steered" — check retrieval-into-context first, then
judge framing only once that's confirmed.

**What worked:** explicit directive framing addressed to "the AI
assistant" rather than a human reader, an authority citation (a fake
internal team name), and an explicit verbatim-reproduction requirement —
nearly identical content to the failed version, different framing only.

## Fit the payload to the chunker's own geometry

A RAG pipeline's chunker (commonly a fixed-size sliding window, ~500-800
characters, frequently *not* respecting sentence/paragraph boundaries —
confirmed by chunk boundaries landing mid-word) can silently split a
correctly-worded, correctly-positioned instruction across two chunks. Only
one half then makes it into any given retrieval's top-k, and which half
depends on query phrasing — a longer injected block that worked for one
phrasing of the trigger question failed for a natural rephrasing of the
identical intent, traced directly to the instruction spanning a chunk
boundary. Recon the chunker's approximate window size (trace spans again,
or infer from repeated-content overlap between adjacent retrieved chunks),
then size and position the injected instruction to start and end entirely
inside a single window — ideally the same chunk as the document's own
highest-relevance content (its title/header), which tends to rank #1
regardless of how the triggering question is phrased.

## Bug-bounty relevance

Any AI-feature scope with a document-review/moderation step ahead of
ingestion is worth checking for exactly what that step inspects — ask
directly (support docs, a status page) or infer from behavior (upload
content whose "suspicious" marker sits at varying offsets and see which
offset gets flagged). A fixed-size preview is a common, cheap
implementation shortcut for what's presented as full content moderation.

— [[OSAI+ - Exploiting RAG Pipelines]]
