"""
Output Sanitizer & Context Manager.

Cleans and shrinks raw CLI output before it goes back to Claude as a
tool_result. This is deliberately rule-based, not another LLM call: it runs
on every tool result in the loop, so it needs to be free and instant, not
another round trip with its own latency/cost/failure modes.

Three jobs:
  1. Sanitize  - strip ANSI escape codes and other terminal control noise.
  2. Redact    - blank out anything that looks like a live credential/secret
                 so it never lands in Claude's context window or API logs.
  3. Summarize - if output is still too big after that, keep the lines most
                 likely to matter (recon hits, HTTP status codes, errors)
                 plus a head/tail sample, and say plainly what was dropped.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")

# Patterns for lines worth keeping even when we're trimming aggressively.
# Tuned for nmap / ffuf / gobuster / rustscan style output.
_HIGH_SIGNAL_RE = re.compile(
    r"(open|closed\|filtered|\d{2,3}/tcp|\d{2,3}/udp"  # nmap port lines
    r"|Status:\s*\d{3}|\[Status:\s*\d{3}"  # ffuf/gobuster status codes
    r"|error|Error|ERROR|fail|Fail|FAIL"
    r"|CVE-\d{4}-\d+"
    r"|\bvuln\b)",
    re.IGNORECASE,
)

# Secrets we never want echoed back into an LLM context, even our own.
_REDACT_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key ID
    re.compile(r"-----BEGIN (RSA|OPENSSH|EC|DSA|PGP) PRIVATE KEY-----.*?-----END \1 PRIVATE KEY-----", re.DOTALL),
    re.compile(r"(?i)(password|passwd|secret|api[_-]?key)\s*[:=]\s*\S+"),
]


@dataclass
class SanitizedOutput:
    text: str
    original_chars: int
    truncated: bool
    redacted_count: int


class OutputSanitizer:
    def __init__(self, max_output_chars: int = 6000):
        self.max_output_chars = max_output_chars

    def sanitize(self, raw: str) -> SanitizedOutput:
        original_chars = len(raw)
        cleaned = _ANSI_RE.sub("", raw)
        cleaned, redacted_count = self._redact(cleaned)
        cleaned = self._dedupe_blank_lines(cleaned)

        if len(cleaned) <= self.max_output_chars:
            return SanitizedOutput(
                text=cleaned,
                original_chars=original_chars,
                truncated=False,
                redacted_count=redacted_count,
            )

        summarized = self._summarize(cleaned)
        return SanitizedOutput(
            text=summarized,
            original_chars=original_chars,
            truncated=True,
            redacted_count=redacted_count,
        )

    def _redact(self, text: str) -> tuple[str, int]:
        count = 0
        for pattern in _REDACT_PATTERNS:
            text, n = pattern.subn("[REDACTED]", text)
            count += n
        return text, count

    def _dedupe_blank_lines(self, text: str) -> str:
        return re.sub(r"\n{3,}", "\n\n", text)

    def _summarize(self, text: str) -> str:
        lines = text.splitlines()
        high_signal = [ln for ln in lines if _HIGH_SIGNAL_RE.search(ln)]

        # Budget: high-signal lines first, then head/tail context, all
        # capped to max_output_chars so a pathological single line (e.g. a
        # giant base64 blob) can't blow the budget on its own.
        head = lines[:15]
        tail = lines[-15:] if len(lines) > 30 else []

        parts: list[str] = []
        if high_signal:
            parts.append(
                f"[{len(high_signal)} high-signal line(s) matched from "
                f"{len(lines)} total — showing them below, followed by "
                f"head/tail context]"
            )
            parts.extend(high_signal[:80])
        parts.append("--- head ---")
        parts.extend(head)
        if tail:
            parts.append("--- tail ---")
            parts.extend(tail)

        result = "\n".join(parts)
        if len(result) > self.max_output_chars:
            result = (
                result[: self.max_output_chars]
                + f"\n[... truncated to {self.max_output_chars} chars ...]"
            )
        else:
            result += (
                f"\n[output was {len(text)} chars total; summarized to "
                f"{len(result)} chars — full text discarded, not stored]"
            )
        return result
