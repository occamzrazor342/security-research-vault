"""
Pure-Python parser for the analyze_services tool.

Unlike run_recon / execute_fuzzing, this tool never touches the network or
a shell — it just structures text Claude already has (the sanitized output
of an earlier run_recon/execute_fuzzing call) into a compact summary. It
runs directly in the orchestrator, with no local-worker round trip and no
subprocess, since there's nothing here that benefits from either.
"""

from __future__ import annotations

import re

_NMAP_PORT_RE = re.compile(
    r"^(?P<port>\d+)/(?P<proto>tcp|udp)\s+(?P<state>\S+)\s+(?P<service>\S+)"
    r"(?:\s+(?P<version>.*))?$",
    re.MULTILINE,
)
_FFUF_HIT_RE = re.compile(
    r"^(?P<path>\S+)\s+\[Status:\s*(?P<status>\d+).*?\]", re.MULTILINE
)
_GOBUSTER_HIT_RE = re.compile(
    r"^(?P<path>/\S*)\s+\(Status:\s*(?P<status>\d+)\)", re.MULTILINE
)


def analyze_services(raw_output: str, source_tool: str) -> str:
    if source_tool == "run_recon":
        return _summarize_nmap(raw_output)
    if source_tool == "execute_fuzzing":
        return _summarize_fuzzing(raw_output)
    return f"Unknown source_tool '{source_tool}'; nothing parsed."


def _summarize_nmap(raw_output: str) -> str:
    hits = []
    for m in _NMAP_PORT_RE.finditer(raw_output):
        if m.group("state") != "open":
            continue
        line = f"{m.group('port')}/{m.group('proto')} {m.group('service')}"
        if m.group("version"):
            line += f" ({m.group('version').strip()})"
        hits.append(line)

    if not hits:
        return "No open ports parsed from the given output."
    return "Open services:\n" + "\n".join(f"- {h}" for h in hits)


def _summarize_fuzzing(raw_output: str) -> str:
    hits = []
    for m in _FFUF_HIT_RE.finditer(raw_output):
        hits.append(f"{m.group('path')} [{m.group('status')}]")
    for m in _GOBUSTER_HIT_RE.finditer(raw_output):
        hits.append(f"{m.group('path')} [{m.group('status')}]")

    if not hits:
        return "No hits parsed from the given fuzzing output."
    # Interesting statuses first (2xx/3xx over 4xx noise).
    hits.sort(key=lambda h: 0 if any(s in h for s in ("[200", "[301", "[302")) else 1)
    return "Fuzzing hits:\n" + "\n".join(f"- {h}" for h in hits[:50])
