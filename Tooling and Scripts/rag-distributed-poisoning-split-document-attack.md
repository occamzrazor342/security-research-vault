# RAG Distributed Poisoning — Splitting an Attack Across Documents

An escalation past [[rag-ingestion-preview-evasion-via-blending]] for
targets whose ingestion defense might plausibly scan more than a fixed-size
preview (a full-document content scan, a per-file classifier). Any
per-document defense — preview-based or not — has a structural blind spot:
it can only ever evaluate one document's content in isolation. Splitting a
single attack into two (or more) documents, where no individual file
contains the complete instruction+target pairing, defeats that class of
defense entirely, not just a specific character-offset check. The pieces
only ever combine inside the model's own context window, at query time,
across documents that were never uploaded or reviewed together.

## Structure: a procedure fragment and a target fragment

- **Fragment 1 (the "what to do"):** genuine-sounding policy content, plus
  a pointer to a second, named document for "special case" handling —
  phrased as ordinary cross-referencing (e.g. "for X inquiries, consult
  the Y reference and follow its guidance"), not as anything resembling an
  instruction to an AI system. No sensitive target (path, URL, command)
  appears anywhere in this file.
- **Fragment 2 (the "what to do it to"):** the actual target/payload, with
  its own topical framing so it independently ranks for the same trigger
  query rather than depending on luck to get pulled into the same
  retrieval batch as fragment 1. This is a real design requirement, not
  incidental — a target fragment written as generic, off-topic filler with
  a payload buried in it may never get retrieved alongside the procedure
  fragment for the actual trigger phrasing. Confirm both fragments land in
  the same context window for the intended query via the pipeline's own
  retrieval tracing (which chunk IDs/titles made it into context) before
  concluding the split "should" work.
- Both fragments individually pass whatever per-document defense exists —
  apply [[rag-ingestion-preview-evasion-via-blending]]'s offset/chunk-fit
  discipline to *each* file independently.

## Combine with an obfuscated target when a tool-call denylist is in play

If the pipeline has agentic tool-calling (a file-read/fetch/exec tool) with
a keyword denylist, that denylist typically checks one specific point (per
[[rag-tool-call-authorization-via-retrieval-hijacking]]: raw incoming
request text, not the model's own resolved action) — and even a check that
does inspect the resolved tool-call argument is usually still a
*contiguous substring* match. Zero-width Unicode characters (U+200B,
zero-width space) interspersed between every letter of the target string
defeat a substring match completely (`"passwd"` → `"p​a​s​s​w​o​r​d"`, i.e.
`ZWSP.join(target)`) while an LLM's own token-level reading still
reconstructs the intended string fine, especially when the fragment
explicitly names the noise and instructs stripping it before use:

```python
ZWSP = '​'
def zw(s): return ZWSP.join(s)
payload = "Canonical source: /" + zw("etc") + "/" + zw("passwd")
```

Requires a Unicode-capable font when rendering to PDF (e.g. register a
DejaVu TTF with `reportlab`) — the default base-14 PDF fonts can't encode
U+200B and will error or silently drop it. Verify the character survives
both generation and extraction intact before trusting it against a live
target (`text.count('​')` should match the expected insertion count
exactly) — a silent normalization/stripping step anywhere in that pipeline
breaks the technique with no error message.

## Verify the tool call actually fired, not just that the answer looks right

File-shaped text in the final answer is not proof a tool executed —
check the pipeline's own tracing for the actual tool-invocation record
(function name, resolved arguments, a blocked/not-blocked flag, a result
preview) before treating this as confirmed arbitrary read/write rather
than a plausible-looking hallucination. The resolved argument value is
also direct evidence of *where* a denylist check does or doesn't apply:
an argument matching the clean, de-obfuscated target with an unblocked
flag confirms the model performed the deobfuscation itself during
reasoning, ahead of whatever check exists at the tool-call layer.

## Bug-bounty relevance

Worth testing on any AI-feature scope with both an ingestion-review step
*and* agentic tool access — a program that's hardened single-document
content moderation may not have considered that authorization/target can
be split across two otherwise-unremarkable, individually-reviewed
uploads. Maps to OWASP LLM Top 10 LLM01 (indirect prompt injection,
compounded across multiple untrusted sources) and LLM08 (Excessive
Agency, once a tool-calling layer is involved).

— [[OSAI+ - Exploiting RAG Pipelines]]
