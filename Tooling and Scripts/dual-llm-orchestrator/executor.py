"""
Command execution wrapper.

Runs the CLI command the local worker generated, either as a bare subprocess
or (recommended for anything beyond a disposable lab VM) inside a Docker
container. Two safety layers sit in front of every execution:

  1. ALLOWED_BINARIES — each tool_schemas.py tool may only ever invoke a
     fixed, small set of known-safe binaries. A local-model hallucination
     that tries to run `rm`, `curl | sh`, or anything else off-list is
     rejected before it reaches subprocess/Docker.
  2. Shell metacharacter rejection — commands run with shell=False and
     shlex.split, never a shell string. If the local worker's output still
     contains shell operators (;, |, &, `, $(...), >, <) after that split,
     it's rejected rather than guessed at, since those are the primary
     vector for a hallucinated or injected command doing something the
     tool schema never asked for.

This is deliberately conservative — it will refuse commands a human
pentester would consider obviously fine (e.g. piping nmap into grep) because
distinguishing "fine" from "not fine" automatically is exactly the kind of
judgment call this vault's operating principles reserve for a human. Do the
piping/chaining yourself afterward, or extend ALLOWED_BINARIES deliberately.
"""

from __future__ import annotations

import shlex
import subprocess
from dataclasses import dataclass

# Per-tool allowlist of binaries the local worker is permitted to invoke as
# a *local* subprocess. Keep this in sync with tool_schemas.py — every new
# tool that runs a local command needs an entry.
#
# escalate_privileges and send_to_session are NOT here on purpose: they
# send their command into an already-open remote shell session
# (session_manager.SessionManager.send_and_wait), not through this local
# subprocess path — see orchestrator.py's handlers for why the same
# allowlist/no-shell-metachars rule would be actively wrong there (a
# privesc enumeration command like `find / -perm -4000 2>/dev/null`
# legitimately needs shell redirection once it's running inside the
# target's own shell).
ALLOWED_BINARIES: dict[str, set[str]] = {
    "run_recon": {"nmap", "rustscan"},
    "execute_fuzzing": {"ffuf", "gobuster", "wfuzz"},
    # execute_exploit's *delivery* command only — e.g. running a PoC script
    # or curl-ing a payload in. This still runs locally via executor.py, so
    # it's still allowlisted and still rejects shell metacharacters.
    "execute_exploit": {"python3", "python", "curl", "searchsploit", "msfconsole", "nc"},
    # SMB/LDAP/RPC enumeration. `crackmapexec` accepted alongside `nxc`
    # since the binary name varies by Kali release (nxc is the current
    # netexec name; crackmapexec is the predecessor some images still ship).
    "run_service_enum": {
        "nxc",
        "crackmapexec",
        "enum4linux",
        "enum4linux-ng",
        "smbclient",
        "ldapsearch",
        "rpcclient",
    },
    # Credential count cap is enforced separately in
    # orchestrator._run_spray_credentials BEFORE this is ever reached —
    # this allowlist only constrains which binary can run, not how many
    # combinations it's given.
    "spray_credentials": {"nxc", "crackmapexec"},
}

_SHELL_METACHARS = set(";&|`$<>\n")


class CommandRejected(Exception):
    """Raised when a generated command fails the allowlist/metacharacter check."""


@dataclass
class ExecutionResult:
    argv: list[str]
    stdout: str
    stderr: str
    returncode: int
    timed_out: bool


def validate_command(tool_name: str, command: str) -> list[str]:
    """Validate a raw command string against the allowlist for `tool_name`
    and return it as an argv list. Raises CommandRejected if the command
    isn't safe to run as-is."""
    if any(ch in command for ch in _SHELL_METACHARS):
        raise CommandRejected(
            f"Generated command for '{tool_name}' contains shell metacharacters "
            f"and was rejected: {command!r}"
        )

    argv = shlex.split(command)
    if not argv:
        raise CommandRejected(f"Generated command for '{tool_name}' was empty.")

    binary = argv[0].rsplit("/", 1)[-1]  # tolerate an absolute path
    allowed = ALLOWED_BINARIES.get(tool_name, set())
    if binary not in allowed:
        raise CommandRejected(
            f"Generated command for '{tool_name}' uses binary '{binary}', "
            f"which is not in the allowlist {sorted(allowed)}: {command!r}"
        )
    return argv


class CommandExecutor:
    def __init__(
        self,
        timeout_s: float = 300,
        use_docker: bool = False,
        docker_image: str = "kalilinux/kali-rolling",
        docker_network: str = "host",
    ):
        self.timeout_s = timeout_s
        self.use_docker = use_docker
        self.docker_image = docker_image
        self.docker_network = docker_network

    def run(self, argv: list[str]) -> ExecutionResult:
        final_argv = self._wrap_for_docker(argv) if self.use_docker else argv
        try:
            # Captured as bytes, not text=True -- a command can legitimately
            # return binary content (e.g. execute_exploit/curl fetching an
            # image while probing an LFI path), and text=True's default
            # strict UTF-8 decoding raises UnicodeDecodeError on the first
            # non-UTF8 byte, crashing the tool call instead of just
            # returning the (mostly useless, but not fatal) binary blob.
            # errors="replace" matches the TimeoutExpired handler below,
            # which already had to solve this same problem.
            proc = subprocess.run(
                final_argv,
                shell=False,
                capture_output=True,
                timeout=self.timeout_s,
            )
            return ExecutionResult(
                argv=argv,
                stdout=proc.stdout.decode(errors="replace"),
                stderr=proc.stderr.decode(errors="replace"),
                returncode=proc.returncode,
                timed_out=False,
            )
        except subprocess.TimeoutExpired as exc:
            return ExecutionResult(
                argv=argv,
                stdout=(exc.stdout or b"").decode(errors="replace")
                if isinstance(exc.stdout, bytes)
                else (exc.stdout or ""),
                stderr=f"Command timed out after {self.timeout_s}s",
                returncode=-1,
                timed_out=True,
            )
        except FileNotFoundError as exc:
            return ExecutionResult(
                argv=argv,
                stdout="",
                stderr=f"Binary not found: {exc}",
                returncode=127,
                timed_out=False,
            )

    def _wrap_for_docker(self, argv: list[str]) -> list[str]:
        return [
            "docker",
            "run",
            "--rm",
            "--network",
            self.docker_network,
            self.docker_image,
            *argv,
        ]
