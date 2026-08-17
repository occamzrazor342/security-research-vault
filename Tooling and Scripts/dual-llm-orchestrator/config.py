"""
Session/runtime configuration for the dual-LLM orchestrator.

Everything target- and credential-related lives here, resolved once at
startup from environment variables plus whatever the caller passes in for
the current engagement. Nothing in this file is sent to Claude — the
Planner only ever sees the abstract placeholders defined in tool_schemas.py;
OrchestratorConfig is where those placeholders get resolved to real values,
strictly on this side of the fence.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _load_dotenv(path: Path = Path(__file__).parent / ".env") -> None:
    """Minimal stdlib-only .env loader — sets os.environ from a local .env
    file if present, without overriding anything already set. Exists so a
    secret like ANTHROPIC_API_KEY can be written ONCE into a gitignored
    local file (create/edit it directly, in a text editor — never via a
    `!`/shell `export` command, which echoes the full command *including
    the value* into the session transcript) instead of re-exporting it
    before every invocation, which doesn't even work across separate
    subprocess calls anyway (shell state/env vars don't persist between
    them). See .env.example for the format."""
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


_load_dotenv()


@dataclass
class OrchestratorConfig:
    # --- Target context (never sent to Claude; substituted into tool calls
    # right before they reach the local worker / executor) ---
    target_host: str
    target_url: str | None = None  # e.g. "http://TARGET_HOST:8080" resolved

    # --- Anthropic (Planner) ---
    anthropic_api_key: str | None = field(
        default_factory=lambda: os.environ.get("ANTHROPIC_API_KEY")
    )
    # Per vault convention (see .claude/skills' claude-api guidance): default
    # to the current flagship unless the user overrides it explicitly.
    anthropic_model: str = field(
        default_factory=lambda: os.environ.get("ANTHROPIC_MODEL", "claude-opus-5")
    )
    # A full recon -> enum -> foothold -> privesc chain against a real
    # HTB/lab box realistically needs well more turns than recon/fuzzing
    # alone -- each tool call is one turn, and getting from nothing to
    # root often means a dozen-plus recon/enum calls before a foothold is
    # even attempted. This is a budget ceiling (see this vault's own
    # exploit-agent iteration-budget discipline), not a target to hit.
    max_planner_iterations: int = field(
        default_factory=lambda: int(os.environ.get("MAX_PLANNER_ITERATIONS", "40"))
    )
    # Hard, code-enforced spend ceiling for one run() call -- checked
    # after every Claude API turn (orchestrator._track_usage), the run
    # aborts the moment cumulative estimated cost crosses this, regardless
    # of how many planner iterations are left in the budget above. This
    # exists because iteration count alone doesn't bound cost: without
    # prompt caching a growing agentic-loop conversation is worst-case for
    # token spend, and turn count says nothing about how large each turn's
    # resent context has grown. See this vault's 2026-08-16 session
    # history for the concrete case that motivated this (a $20 balance
    # consumed across two runs with no cost visibility or ceiling at all).
    # Deliberately conservative default -- raise it explicitly per run via
    # MAX_RUN_COST_USD, not by editing this file, same posture as
    # max_credential_combinations below.
    max_run_cost_usd: float = field(
        default_factory=lambda: float(os.environ.get("MAX_RUN_COST_USD", "5.00"))
    )
    # Nested under output_config.effort on the Claude API call if set --
    # None (default) means the API's own default applies ("high"). Lower
    # effort is a legitimate, direct cost lever for less
    # intelligence-sensitive turns (the claude-api skill: "medium is often
    # the sweet spot balancing quality and token efficiency"); left unset
    # by default since this is a real quality/cost tradeoff the operator
    # should choose deliberately, not something to silently downgrade.
    anthropic_effort: str | None = field(
        default_factory=lambda: os.environ.get("ANTHROPIC_EFFORT") or None
    )

    # --- Local execution worker (Runpod vLLM/Ollama, OpenAI-compatible) ---
    local_worker_base_url: str = field(
        default_factory=lambda: os.environ.get(
            "LOCAL_WORKER_BASE_URL", "http://localhost:8000/v1"
        )
    )
    local_worker_api_key: str = field(
        # vLLM/Ollama servers usually don't check this, but the OpenAI SDK
        # requires a non-empty string to construct the client.
        default_factory=lambda: os.environ.get("LOCAL_WORKER_API_KEY", "not-needed")
    )
    local_worker_model: str = field(
        default_factory=lambda: os.environ.get("LOCAL_WORKER_MODEL", "local-model")
    )
    local_worker_timeout_s: float = field(
        default_factory=lambda: float(os.environ.get("LOCAL_WORKER_TIMEOUT_S", "60"))
    )

    # --- Execution safety ---
    # Require an interactive y/N confirmation before every subprocess/docker
    # exec. Defaults on: this middleware runs commands from a chain of two
    # LLMs (Claude's intent -> local model's CLI syntax), and neither step
    # is guaranteed correct. Only disable for fully unattended runs you've
    # already scoped and trust (see README "Autonomy" section).
    require_confirmation: bool = field(
        default_factory=lambda: os.environ.get("REQUIRE_CONFIRMATION", "1") == "1"
    )
    # Run the generated command inside a Docker container instead of a bare
    # subprocess. Recommended for anything beyond a disposable lab VM.
    use_docker_isolation: bool = field(
        default_factory=lambda: os.environ.get("USE_DOCKER_ISOLATION", "0") == "1"
    )
    docker_image: str = field(
        default_factory=lambda: os.environ.get(
            "DOCKER_ISOLATION_IMAGE", "kalilinux/kali-rolling"
        )
    )
    # Passed as --network to `docker run` when use_docker_isolation is set.
    # "host" is usually required for HTB/lab targets reachable only via a
    # VPN interface already up on the host.
    docker_network: str = field(
        default_factory=lambda: os.environ.get("DOCKER_NETWORK", "host")
    )
    command_timeout_s: float = field(
        default_factory=lambda: float(os.environ.get("COMMAND_TIMEOUT_S", "300"))
    )

    # --- Output sanitization ---
    max_output_chars: int = field(
        default_factory=lambda: int(os.environ.get("MAX_OUTPUT_CHARS", "6000"))
    )

    # --- Reverse-shell sessions (execute_exploit / escalate_privileges /
    # send_to_session) ---
    # The address a reverse-shell payload should call back to — normally
    # your VPN interface IP (tun0 for HTB/lab targets). Required only when
    # execute_exploit is actually invoked with reverse_shell=true;
    # recon/fuzz-only runs don't need it, so this stays optional here and
    # is validated lazily in orchestrator.py.
    attacker_ip: str | None = field(
        default_factory=lambda: os.environ.get("ATTACKER_IP")
    )
    nc_binary: str = field(default_factory=lambda: os.environ.get("NC_BINARY", "nc"))
    max_concurrent_sessions: int = field(
        default_factory=lambda: int(os.environ.get("MAX_CONCURRENT_SESSIONS", "5"))
    )
    # How long to wait, after starting a listener and firing the exploit
    # delivery command, before checking whether anything connected back.
    exploit_connect_wait_s: float = field(
        default_factory=lambda: float(os.environ.get("EXPLOIT_CONNECT_WAIT_S", "8"))
    )
    default_session_wait_s: float = field(
        default_factory=lambda: float(os.environ.get("DEFAULT_SESSION_WAIT_S", "5"))
    )

    # Directory serve_payloads hosts over HTTP. Populate it yourself with
    # whatever enumeration/exploit scripts you want available to a caught
    # session (linpeas.sh, winPEAS.exe, pspy64, ...) — nothing is bundled
    # here on purpose, both to avoid redistributing third-party GPL/
    # PEASS-ng scripts inside this vault and because those tools update
    # independently of this harness.
    payloads_dir: str = field(
        default_factory=lambda: os.environ.get("PAYLOADS_DIR", "./payloads")
    )

    # Hard cap on username x password combinations per spray_credentials
    # call, enforced in code (orchestrator._run_spray_credentials), not
    # just prompted — matches this vault's standing credential-spray
    # policy (small, evidence-based guess sets only, never a wordlist
    # brute-force). Raise only with a deliberate, explicit reason; this
    # isn't a knob to bump for convenience.
    max_credential_combinations: int = field(
        default_factory=lambda: int(os.environ.get("MAX_CREDENTIAL_COMBINATIONS", "30"))
    )

    def __post_init__(self) -> None:
        if not self.anthropic_api_key:
            raise ValueError(
                "ANTHROPIC_API_KEY is not set. Export it or pass "
                "anthropic_api_key= explicitly."
            )
        if self.target_url is None:
            self.target_url = f"http://{self.target_host}"

    @property
    def placeholder_map(self) -> dict[str, str]:
        """Maps the abstract placeholders Claude is allowed to use to real
        values. Walked recursively over every tool_use.input by
        orchestrator._substitute_placeholders() before the intent leaves
        this process. LISTENER_HOST is only present when attacker_ip is
        configured — orchestrator.py raises a clear error instead of
        silently leaving the literal string in a live payload if
        reverse_shell=true is requested without it set."""
        placeholders = {
            "TARGET_HOST": self.target_host,
            "TARGET_URL": self.target_url or f"http://{self.target_host}",
        }
        if self.attacker_ip:
            placeholders["LISTENER_HOST"] = self.attacker_ip
        return placeholders
