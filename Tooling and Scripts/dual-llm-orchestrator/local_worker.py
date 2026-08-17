"""
Execution Worker client — talks to the local open-weights model hosted on
Runpod (vLLM/Ollama, both expose an OpenAI-compatible /v1/chat/completions
endpoint) via the `openai` Python SDK pointed at that base_url.

The local worker's only job is: given an abstract tool intent (already
resolved to a real target by config.OrchestratorConfig), produce the exact
CLI syntax to run. It does not decide *whether* to run something, and it
does not get network/filesystem access itself — executor.py runs whatever
it returns, and only after validate_command() has checked it against the
allowlist.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from openai import OpenAI

_SYSTEM_PROMPT = """\
You are a CLI command generator for authorized penetration testing tooling.
You are given a structured intent (a tool name and parameters, already
resolved to a real, in-scope target) and must produce the exact command to
run. Wrap the command in <cmd>...</cmd> tags with nothing else inside the
tags. You may write a brief sentence of reasoning before the tags if you
want, but the actual command must be inside them, exactly as it should run.

Default rules (run_recon, execute_fuzzing, execute_exploit, run_service_enum,
spray_credentials — anything the orchestrator runs as a LOCAL subprocess on
the operator's own machine):
- Exactly one command inside the tags.
- Use only the binary appropriate to the tool (see the tool-specific
  guidance below). Do not chain commands with ;, &&, |, or backticks —
  these run through a strict local allowlist that rejects shell
  metacharacters outright, so a chained command will simply be refused,
  not partially run.
- Do not invent flags you're unsure about; prefer well-known, common flags.
- Never include destructive flags (e.g. nmap --script that writes files
  outside a scan report, rm, output redirection with '>').

Different rules for escalate_privileges ONLY: the command you generate is
sent into an ALREADY-OPEN remote shell session on the target, not run as a
local subprocess — normal shell syntax (pipes, redirects like
`2>/dev/null`, `&&` between two enumeration steps) is expected and fine
there, since it's just ordinary input to a shell that's already running.
Still exactly one command inside the tags.

Tool-specific guidance:
- run_recon: use nmap. scan_type=quick -> `-T4 -F`. scan_type=full_tcp ->
  `-T4 -p-`. scan_type=udp -> `-sU --top-ports 100`. scan_type=service_version
  -> `-sV -p <ports>`.
- execute_fuzzing: use ffuf. mode=directory -> fuzz path with FUZZ against
  a wordlist path (assume /usr/share/wordlists/dirb/common.txt for 'common'
  hints, /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
  for 'medium'). mode=vhost -> fuzz the Host header. mode=parameter -> fuzz
  a GET parameter name.
- execute_exploit: this is the DELIVERY step only — the command that
  fires the exploit/PoC against the target from our machine. If a known
  public PoC script is the standard approach, invoke it with python3 and
  the resolved target/callback values. If reverse_shell is true, the
  payload's callback address is the literal string LISTENER_HOST and its
  port is the literal listener_port value given — do not invent an IP.
- escalate_privileges: this is a single enumeration or exploitation
  command to run INSIDE the existing session for the given technique —
  e.g. `find / -perm -4000 -type f 2>/dev/null` for SUID abuse, or the
  specific GTFOBins command for a named sudo/binary technique.
- run_service_enum: protocol=smb -> prefer `nxc smb <target> -u '<username
  or empty string>' -p '<password or empty string>' --shares` for share
  enumeration, or `enum4linux-ng -A <target>` for a broad unauthenticated
  sweep. protocol=ldap -> `ldapsearch -x -H ldap://<target> -b "" -s base`
  for an anonymous naming-context pull, or with creds
  `ldapsearch -x -H ldap://<target> -D '<username>' -w '<password>' -b
  '<base DN inferred from the domain, e.g. dc=corp,dc=local>'`.
  protocol=rpc -> `rpcclient -U '<username>%<password or empty>' <target>
  -c 'enumdomusers'` (or another single rpcclient -c command matching
  goal_hint). Use the literal username/password given, or empty strings
  for an anonymous/null-session attempt if none were given.
- spray_credentials: use nxc. `nxc <service> <target> -u <user1> <user2>
  ... -p <pass1> <pass2> ...` — list every given username after -u and
  every given password after -p, space-separated, no wordlist files.
"""

_CMD_TAG_RE = re.compile(r"<cmd>(.*?)</cmd>", re.DOTALL)


def _extract_command(raw: str) -> str:
    """Pull the command out of the local worker's raw response.

    Prefers the last <cmd>...</cmd> tag (see _SYSTEM_PROMPT) over a naive
    "take the first line" parse — local models reliably prefix answers
    with a sentence of reasoning even when told to respond with only the
    command, and a naive first-line strip silently mis-extracts that prose
    as the command instead of rejecting it or finding the real one. This
    is the same class of bug LLM Training/orchestration/recon_loop.py's
    extract_tool_call() was written to fix (see that function's docstring
    for the real dry-run failure that motivated it) — this module's
    contract is a bare command string rather than a JSON tool-call object,
    so the fix here is a tag scan rather than brace-matching, but the
    underlying lesson (scan the full content, don't assume clean output)
    is the same one.

    Falls back to the first non-empty, backtick-stripped line if no tag is
    present, for local models that don't reliably follow the tag
    instruction — better than returning nothing, but strictly worse than
    the tagged path, so treat a run that's consistently hitting this
    fallback as a sign to tune the local model's prompt/temperature, not
    as normal operation.
    """
    matches = _CMD_TAG_RE.findall(raw)
    if matches:
        return matches[-1].strip()
    for line in raw.strip().splitlines():
        line = line.strip().strip("`")
        if line:
            return line
    return ""


@dataclass
class LocalWorkerResult:
    command: str
    raw_response: str
    used_fallback_extraction: bool


class LocalExecutionWorker:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        model: str,
        timeout_s: float = 60,
    ):
        self.client = OpenAI(base_url=base_url, api_key=api_key, timeout=timeout_s)
        self.model = model

    def generate_command(self, tool_name: str, parameters: dict) -> LocalWorkerResult:
        """Ask the local model to translate a resolved tool intent into a
        precise CLI command. Returns the extracted single-line command
        string; executor.validate_command() is responsible for checking
        it's safe to run before anything touches subprocess/Docker."""
        user_prompt = (
            f"Tool: {tool_name}\n"
            f"Parameters: {parameters}\n\n"
            "Respond with the command wrapped in <cmd></cmd> tags."
        )
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0,
            max_tokens=256,
        )
        raw = response.choices[0].message.content or ""
        used_fallback = not _CMD_TAG_RE.search(raw)
        command = _extract_command(raw)
        return LocalWorkerResult(
            command=command, raw_response=raw, used_fallback_extraction=used_fallback
        )
