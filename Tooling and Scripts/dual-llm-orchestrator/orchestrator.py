"""
Python Orchestrator Middleware — the piece that ties Planner (Claude),
Execution Worker (local model), and the local terminal/container together.

Loop, per turn:
  1. Send the conversation + TOOLS to Claude (`anthropic` SDK).
  2. For each tool_use block Claude returns:
       a. Substitute abstract placeholders (TARGET_HOST/TARGET_URL/
          LISTENER_HOST) with the real values from OrchestratorConfig —
          Claude's own prompt/response never contains the real target.
       b. Route the resolved intent (see _handle_tool_call's dispatch
          table):
            - analyze_services -> plain Python parser (service_parser.py),
              no shell, no local worker.
            - run_recon / execute_fuzzing / execute_exploit's delivery
              step / run_service_enum / spray_credentials -> local worker
              generates exact CLI syntax (local_worker.py) -> validated
              against an allowlist and run as a LOCAL subprocess
              (executor.py) -> sanitized (sanitizer.py).
            - escalate_privileges / send_to_session -> a command (worker-
              generated or given directly by Claude) sent into an
              already-open REMOTE shell session (session_manager.py) —
              no local subprocess, no allowlist check; see
              executor.py's ALLOWED_BINARIES docstring for why that
              check doesn't apply once you're inside a caught shell.
            - serve_payloads -> deterministic Python (start/stop a local
              `python3 -m http.server`), never touches the local worker.
            - report_finding -> records a flag/outcome; a terminal
              finding_type (user_flag/root_flag/objective_complete) ends
              the run on this turn instead of looping back to Claude.
       c. Optionally confirm with the human operator before executing or
          sending anything (config.require_confirmation).
  3. Feed all tool_results back to Claude as a single user turn and repeat
     until Claude stops requesting tools, reports a terminal finding, or
     the iteration budget is exhausted. However the run ends, any open
     reverse-shell sessions and the payload server are closed, and a
     transcript is written to disk (notes.py) — see run()'s `finally`.

This is a manual agentic loop, not the Anthropic SDK's beta tool_runner —
deliberate, because the tool_runner executes tools directly and this
pipeline needs to intercept every tool_use block to route it through the
local worker + executor first, not just call a plain Python function.
"""

from __future__ import annotations

import copy
import subprocess
import threading
from pathlib import Path

import anthropic

from config import OrchestratorConfig
from executor import CommandExecutor, CommandRejected, validate_command
from local_worker import LocalExecutionWorker
from notes import write_run_transcript
from sanitizer import OutputSanitizer
from service_parser import analyze_services
from session_manager import SessionManager
from tool_schemas import TOOLS

_SYSTEM_PROMPT = """\
You are the planning strategist for an authorized penetration-testing /
security-lab engagement — a HackTheBox machine or similar deliberately
vulnerable lab target, run under the operator's own account with explicit
permission to attack it, not a real unauthorized system. Work toward the
operator's stated goal (e.g. "get root", "confirm the web foothold"). You
never see or need the real target address, callback address, or
credentials — always pass the literal placeholders TARGET_HOST /
TARGET_URL / LISTENER_HOST exactly as each tool schema requires; the
orchestrator resolves them.

Work in phases, in order, and don't skip ahead without reason:
1. Recon (run_recon) - learn what's actually listening before acting on it.
2. Service enumeration - execute_fuzzing if a web service is present
   (content/vhosts/parameters); run_service_enum if SMB/LDAP/RPC ports are
   open (shares, users, anonymous/null-session access) — don't assume web
   is the only path in, especially on Windows/AD-flavored targets.
3. Analysis (analyze_services) - call this on raw recon/fuzzing output
   before deciding next steps, so your plan is grounded in what was found,
   not assumed.
4. Foothold (execute_exploit, or spray_credentials if you have a small,
   evidence-based set of candidate creds — never invent a guess list, it's
   hard-capped at 30 combinations regardless). If execute_exploit's
   technique is expected to call back to us, set reverse_shell=true;
   you'll get a session_id back for everything after.
5. IMMEDIATELY after a session_id is returned as connected, upgrade it to
   a real PTY before anything else — send `python3 -c 'import pty;
   pty.spawn("/bin/bash")'` via send_to_session (or the `python` binary if
   python3 isn't present on the target). Skipping this makes sudo/su and
   any interactive tool unreliable or hanging later, so do it first, not
   if something breaks.
6. Privesc - escalate_privileges for a named technique; send_to_session
   for plain enumeration or commands you already know verbatim; serve_
   payloads if a technique needs a script on the target (linpeas.sh,
   pspy, etc. — start the server, then curl/wget it from the session at
   http://LISTENER_HOST:<port>/<filename>). Work from enumeration to a
   specific technique, the same way a human operator would: check obvious
   things first (sudo -l, SUID binaries, cron jobs) before reaching for a
   kernel exploit.
7. Report (report_finding) - call this the moment you have PROOF (actual
   command output showing it), not a plan to get it. user_flag/root_flag/
   objective_complete END THE RUN — only report one once you've actually
   run the command that reads it via send_to_session. Use 'blocked' to
   leave a clear record if you've run out of ideas without ending the run.

Don't call tools speculatively with no plan for the result, and don't
declare a flag/objective via plain text — report_finding is the only way
the operator gets a clean, structured signal that you're actually done.
"""


class DualLLMOrchestrator:
    def __init__(self, config: OrchestratorConfig, on_event=None):
        """on_event, if given, is called with a dict for every significant
        moment in the run (planner text, tool calls, findings, completion,
        errors) — in addition to, not instead of, the existing print()
        calls. This is what lets a different front end (webui.py) drive
        the exact same engine as main.py without duplicating any
        orchestration logic: it just registers a callback and renders
        whatever comes through it. Exceptions raised inside on_event are
        swallowed (see _emit) so a broken GUI callback can never take down
        a run."""
        self.config = config
        self.on_event = on_event
        self.claude = anthropic.Anthropic(api_key=config.anthropic_api_key)
        self.local_worker = LocalExecutionWorker(
            base_url=config.local_worker_base_url,
            api_key=config.local_worker_api_key,
            model=config.local_worker_model,
            timeout_s=config.local_worker_timeout_s,
        )
        self.executor = CommandExecutor(
            timeout_s=config.command_timeout_s,
            use_docker=config.use_docker_isolation,
            docker_image=config.docker_image,
            docker_network=config.docker_network,
        )
        self.sanitizer = OutputSanitizer(max_output_chars=config.max_output_chars)
        self.session_manager = SessionManager(
            nc_binary=config.nc_binary, max_sessions=config.max_concurrent_sessions
        )

        # Run-scoped state — reset per run() call via _reset_run_state().
        self.transcript: list[dict] = []
        self.findings: list[dict] = []
        self._terminal_finding: dict | None = None
        self._payload_server_proc: subprocess.Popen | None = None
        self._payload_server_port: int | None = None
        self.cumulative_cost_usd: float = 0.0

        # Mid-run interjection: push_interjection() is called from a
        # different thread (webui.py's Flask request handler) than the
        # one running _run_loop, hence the lock. Not reset in
        # _reset_run_state() -- an interjection pushed in the brief window
        # between one run finishing and the next starting should still
        # reach the new run rather than being silently dropped.
        self._interjection_lock = threading.Lock()
        self._pending_interjections: list[str] = []

    def push_interjection(self, text: str) -> None:
        """Queue an operator message to be woven into the NEXT Claude
        turn -- call this any time from another thread while run() is in
        progress (e.g. webui.py's /interject endpoint). Delivered as a
        mid-conversation `role: "system"` message (see _run_loop), which
        the claude-api skill documents as the correct operator-authority
        channel for exactly this: it doesn't invalidate the cached prefix
        the way editing the top-level system prompt would, and unlike
        stuffing it into a user turn it can't be spoofed by anything the
        target/local-worker output contains. Does nothing if no run is
        active -- it's just queued for whenever _run_loop next checks."""
        with self._interjection_lock:
            self._pending_interjections.append(text)

    def run(self, goal: str, target_name: str | None = None) -> str:
        """Drive the planner loop for one operator-supplied goal. Returns
        Claude's final text response (or the terminal report_finding, if
        one was made). Whatever happened along the way — reverse-shell
        sessions, a running payload server — is torn down on the way out,
        and a transcript is written to disk, whether the run finished
        cleanly, hit the iteration cap, or raised."""
        self._reset_run_state()
        result: str | None = None
        error: Exception | None = None
        try:
            result = self._run_loop(goal)
            return result
        except Exception as exc:
            error = exc
            raise
        finally:
            # Cleanup (and its own notes_written event) happens BEFORE the
            # final done/error emit below, on purpose -- a consumer of
            # on_event (webui.py) should be able to treat "done"/"error"
            # as "the stream is actually finished now", not just "the
            # planner loop returned, more cleanup events may still follow".
            self.session_manager.close_all()
            self._stop_payload_server()
            self._write_transcript(goal, target_name)
            if error is not None:
                self._emit({"kind": "error", "error": str(error)})
            else:
                self._emit({"kind": "done", "result": result})

    def _reset_run_state(self) -> None:
        self.transcript = []
        self.findings = []
        self._terminal_finding = None
        self.cumulative_cost_usd = 0.0

    # Claude Opus 5 and its refusal-fallback target (Opus 4.8) share the
    # same list price -- see the claude-api skill's pricing table. This is
    # a rough running estimate for operator visibility, not a billing
    # source of truth: it doesn't know your actual negotiated rate, and
    # cache-write TTL (5m vs 1h) isn't distinguished. Good enough to catch
    # "this run is burning fast" in real time, which is the actual gap
    # that let a run consume a $20 balance with zero visibility.
    _PRICE_PER_MTOK = {
        "input": 5.00,
        "output": 25.00,
        "cache_write": 6.25,  # ephemeral default (5m TTL) is 1.25x input
        "cache_read": 0.50,  # 0.1x input
    }

    def _track_usage(self, response) -> None:
        usage = getattr(response, "usage", None)
        if usage is None:
            return
        input_tokens = getattr(usage, "input_tokens", 0) or 0
        output_tokens = getattr(usage, "output_tokens", 0) or 0
        cache_write = getattr(usage, "cache_creation_input_tokens", 0) or 0
        cache_read = getattr(usage, "cache_read_input_tokens", 0) or 0

        turn_cost = (
            input_tokens * self._PRICE_PER_MTOK["input"]
            + output_tokens * self._PRICE_PER_MTOK["output"]
            + cache_write * self._PRICE_PER_MTOK["cache_write"]
            + cache_read * self._PRICE_PER_MTOK["cache_read"]
        ) / 1_000_000
        self.cumulative_cost_usd += turn_cost

        print(
            f"[usage] model={response.model} in={input_tokens} out={output_tokens} "
            f"cache_write={cache_write} cache_read={cache_read} "
            f"turn=${turn_cost:.4f} cumulative=${self.cumulative_cost_usd:.4f}"
        )
        self._emit({
            "kind": "usage",
            "model": response.model,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cache_creation_input_tokens": cache_write,
            "cache_read_input_tokens": cache_read,
            "turn_cost_usd": round(turn_cost, 4),
            "cumulative_cost_usd": round(self.cumulative_cost_usd, 4),
        })

    def _emit(self, event: dict) -> None:
        if self.on_event is None:
            return
        try:
            self.on_event(event)
        except Exception:  # noqa: BLE001 - a broken GUI callback must never break a run
            pass

    def _write_transcript(self, goal: str, target_name: str | None) -> None:
        try:
            notes_path = write_run_transcript(
                target_host=self.config.target_host,
                target_name=target_name,
                goal=goal,
                transcript=self.transcript,
                findings=self.findings,
                cumulative_cost_usd=self.cumulative_cost_usd,
            )
            print(f"\n[notes] wrote run transcript to {notes_path}")
            self._emit({"kind": "notes_written", "path": str(notes_path)})
        except Exception as exc:  # noqa: BLE001 - never let notes-writing hide the real result
            print(f"\n[notes] failed to write run transcript: {exc}")

    def _run_loop(self, goal: str) -> str:
        messages: list[dict] = [{"role": "user", "content": goal}]

        for iteration in range(1, self.config.max_planner_iterations + 1):
            # Fold in any operator interjections queued since the last
            # turn. `messages` always ends in a "user" role entry at this
            # point (the initial goal on iteration 1, tool_results on
            # every iteration after) -- required for a mid-conversation
            # system message per the claude-api skill: it must follow a
            # user turn and be the last entry before the next assistant
            # turn, never messages[0].
            with self._interjection_lock:
                pending, self._pending_interjections = self._pending_interjections, []
            if pending:
                note = "\n".join(pending)
                messages.append({"role": "system", "content": f"[Operator note] {note}"})
                self.transcript.append({"kind": "interjection", "text": note})
                self._emit({"kind": "interjection", "text": note})

            # Claude Opus 5 ships elevated cybersecurity safety classifiers
            # that can decline a request outright (HTTP 200,
            # stop_reason="refusal", empty content) even for fully
            # authorized work -- a bare "get root" against a raw IP with
            # exploit/privesc tools in play is exactly the shape that can
            # trip it. fallbacks="default" (beta) re-serves a declined
            # request on Anthropic's recommended fallback model within the
            # same call, which is the documented fix rather than a
            # workaround. See shared/model-migration.md's Claude Opus 5
            # refusal section in the claude-api skill for the full
            # semantics (billing, sticky routing).
            create_kwargs = dict(
                model=self.config.anthropic_model,
                # 8192, not 4096 -- Claude Opus 5 runs adaptive thinking on
                # by default (we never disable it) and thinking + the
                # visible response share this same budget. At 4096 a turn
                # with a lot of internal reasoning risks silent truncation
                # mid tool-call. Not raised further than this without also
                # switching to streaming -- the SDK's own non-streaming
                # timeout guard trips around the ~16000 mark.
                max_tokens=8192,
                system=_SYSTEM_PROMPT,
                tools=TOOLS,
                # Auto-caches the last cacheable block (system+tools on
                # turn 1, then the growing messages history each turn
                # after). Without this, every turn re-sends the entire
                # accumulated transcript at full input price instead of
                # ~1/10th for the cached portion -- on a 90-turn run that
                # is the difference between "expensive" and "burns a $20
                # balance in one session" (see 2026-08-16 in this vault's
                # session history for the concrete cost of skipping this).
                cache_control={"type": "ephemeral"},
                messages=messages,
                betas=["server-side-fallback-2026-07-01"],
                fallbacks="default",
            )
            if self.config.anthropic_effort:
                create_kwargs["output_config"] = {"effort": self.config.anthropic_effort}

            # Claude Opus 5 ships elevated cybersecurity safety classifiers
            # that can decline a request outright (HTTP 200,
            # stop_reason="refusal", empty content) even for fully
            # authorized work -- a bare "get root" against a raw IP with
            # exploit/privesc tools in play is exactly the shape that can
            # trip it. fallbacks="default" (beta) re-serves a declined
            # request on Anthropic's recommended fallback model within the
            # same call, which is the documented fix rather than a
            # workaround. See shared/model-migration.md's Claude Opus 5
            # refusal section in the claude-api skill for the full
            # semantics (billing, sticky routing).
            response = self.claude.beta.messages.create(**create_kwargs)
            self._track_usage(response)

            if self.cumulative_cost_usd >= self.config.max_run_cost_usd:
                # Code-enforced, not just logged -- see config.py's
                # max_run_cost_usd docstring for why this exists. Checked
                # AFTER the turn that crossed it completes (can't cancel a
                # request already billed), so the actual spend can exceed
                # this by at most one turn's cost -- same "bound on new
                # work, not an exact stop" shape as the Messages-API
                # session-budget pattern this mirrors.
                raise RuntimeError(
                    f"Run aborted: cumulative estimated cost "
                    f"${self.cumulative_cost_usd:.2f} reached the "
                    f"${self.config.max_run_cost_usd:.2f} ceiling "
                    f"(MAX_RUN_COST_USD). Raise it explicitly in .env if "
                    f"this run genuinely needs more budget."
                )

            if response.stop_reason == "refusal":
                # Fallback still declined, or fallback wasn't available for
                # this refusal category -- surface it as a real error
                # rather than silently returning empty text, which is what
                # a bare stop_reason != "tool_use" check would do.
                category = getattr(response.stop_details, "category", None)
                raise RuntimeError(
                    f"Claude declined this request (refusal, category="
                    f"{category!r}) even after the fallback model was "
                    f"tried. Rephrase the goal with more explicit "
                    f"authorization context, or check "
                    f"response.stop_details for details."
                )

            for block in response.content:
                if block.type == "text" and block.text.strip():
                    text = block.text.strip()
                    print(f"\n[planner] {text}\n")
                    self.transcript.append({"kind": "text", "text": text})
                    self._emit({"kind": "text", "text": text})

            messages.append({"role": "assistant", "content": response.content})

            if response.stop_reason != "tool_use":
                final_text = next(
                    (b.text for b in response.content if b.type == "text"), ""
                )
                return final_text

            tool_results = []
            for block in response.content:
                if block.type != "tool_use":
                    continue
                tool_results.append(self._handle_tool_call(block))
            messages.append({"role": "user", "content": tool_results})

            if self._terminal_finding:
                return self._build_final_report()

        return (
            f"[stopped: hit max_planner_iterations="
            f"{self.config.max_planner_iterations} without Claude reaching "
            f"end_turn or a terminal report_finding]"
        )

    def _build_final_report(self) -> str:
        f = self._terminal_finding
        assert f is not None
        return f"[{f['finding_type']}] {f['content']}\nEvidence: {f['evidence']}"

    # -- tool dispatch -----------------------------------------------------

    def _handle_tool_call(self, block) -> dict:
        name = block.name
        params = self._substitute_placeholders(block.input)
        print(f"[tool_use] {name}({params})")

        dispatch = {
            "analyze_services": self._run_analyze_services,
            "run_recon": lambda p: self._run_via_local_worker(name, p),
            "execute_fuzzing": lambda p: self._run_via_local_worker(name, p),
            "run_service_enum": lambda p: self._run_via_local_worker(name, p),
            "execute_exploit": self._run_execute_exploit,
            "escalate_privileges": self._run_escalate_privileges,
            "send_to_session": self._run_send_to_session,
            "serve_payloads": self._run_serve_payloads,
            "spray_credentials": self._run_spray_credentials,
            "report_finding": self._run_report_finding,
        }

        try:
            handler = dispatch.get(name)
            if handler is None:
                raise ValueError(f"No handler registered for tool '{name}'")
            result_text = handler(params)
            tool_result = {
                "type": "tool_result",
                "tool_use_id": block.id,
                "content": result_text,
            }
        except CommandRejected as exc:
            print(f"[REJECTED] {exc}")
            tool_result = {
                "type": "tool_result",
                "tool_use_id": block.id,
                "content": f"Command rejected by safety check: {exc}",
                "is_error": True,
            }
        except Exception as exc:  # noqa: BLE001 - surface any failure to Claude, not just known ones
            print(f"[ERROR] {name} failed: {exc}")
            tool_result = {
                "type": "tool_result",
                "tool_use_id": block.id,
                "content": f"Tool '{name}' failed: {exc}",
                "is_error": True,
            }

        self.transcript.append(
            {"kind": "tool_call", "tool": name, "params": params, "result": tool_result["content"]}
        )
        self._emit({
            "kind": "tool_call",
            "tool": name,
            "params": params,
            "result": tool_result["content"],
            "is_error": tool_result.get("is_error", False),
        })
        return tool_result

    # -- recon / fuzzing / enum (local worker -> local subprocess) ----------

    def _run_analyze_services(self, params: dict) -> str:
        return analyze_services(
            raw_output=params.get("raw_output", ""),
            source_tool=params.get("source_tool", ""),
        )

    def _run_via_local_worker(self, name: str, params: dict) -> str:
        """run_recon / execute_fuzzing / run_service_enum: local worker
        generates the exact CLI syntax, validated against the allowlist
        and run as a local subprocess."""
        worker_result = self.local_worker.generate_command(name, params)
        print(f"[local worker] {worker_result.command}")

        argv = validate_command(name, worker_result.command)

        if not self._confirm(f"Run locally: {' '.join(argv)}"):
            return "Operator declined to run this command."

        exec_result = self.executor.run(argv)
        return self._format_exec_result(exec_result)

    def _run_spray_credentials(self, params: dict) -> str:
        """Same local-subprocess path as _run_via_local_worker, but with a
        hard cap on username x password combinations enforced HERE, in
        code, before the local worker or executor ever sees the request —
        matches this vault's standing credential-spray policy. See
        config.OrchestratorConfig.max_credential_combinations."""
        usernames = params.get("usernames") or []
        passwords = params.get("passwords") or []
        if not usernames or not passwords:
            raise ValueError("spray_credentials requires at least one username and one password")

        combos = len(usernames) * len(passwords)
        if combos > self.config.max_credential_combinations:
            raise ValueError(
                f"spray_credentials refused: {len(usernames)} usernames x "
                f"{len(passwords)} passwords = {combos} combinations, over "
                f"the {self.config.max_credential_combinations}-combination "
                f"cap. Narrow to your best-evidenced guesses, not a wordlist."
            )

        return self._run_via_local_worker("spray_credentials", params)

    # -- foothold / privesc (local worker or Claude -> remote session) ------

    def _run_execute_exploit(self, params: dict) -> str:
        reverse_shell = bool(params.get("reverse_shell"))
        session = None

        if reverse_shell:
            if not self.config.attacker_ip:
                raise RuntimeError(
                    "execute_exploit was called with reverse_shell=true but "
                    "ATTACKER_IP is not configured — set it to your "
                    "VPN/attacking interface IP before retrying (see "
                    "README.md)."
                )
            port = params.get("listener_port")
            if not isinstance(port, int) or not (1025 <= port <= 65000):
                raise ValueError(
                    f"listener_port must be an integer in 1025-65000, got {port!r}"
                )
            session = self.session_manager.start_listener(port)
            print(f"[session {session.session_id}] listening on :{port}")

        worker_result = self.local_worker.generate_command("execute_exploit", params)
        print(f"[local worker] {worker_result.command}")
        argv = validate_command("execute_exploit", worker_result.command)

        if not self._confirm(f"Run locally (exploit delivery): {' '.join(argv)}"):
            if session:
                self.session_manager.close(session.session_id)
            return "Operator declined to run this command."

        exec_result = self.executor.run(argv)
        result = f"[delivery] {self._format_exec_result(exec_result)}"

        if session:
            # send_and_wait itself blocks for wait_s waiting on the
            # listener's output queue -- no separate time.sleep() needed,
            # that would just double the delay.
            catch = self.session_manager.send_and_wait(
                session.session_id, "", wait_s=self.config.exploit_connect_wait_s
            )
            status = self.session_manager.status(session.session_id)
            sanitized = self.sanitizer.sanitize(catch)
            result += (
                f"\n[session {session.session_id} status={status}]\n"
                f"{sanitized.text}"
            )

        return result

    def _run_escalate_privileges(self, params: dict) -> str:
        """Local worker generates the technique's exact command; it's sent
        into the existing session, not run as a local subprocess, so it
        does NOT go through validate_command()'s allowlist/no-metachars
        check -- see executor.py's ALLOWED_BINARIES docstring for why."""
        session_id = params.get("session_id", "")
        worker_result = self.local_worker.generate_command("escalate_privileges", params)
        command = worker_result.command
        print(f"[local worker] {command}")
        if not command:
            raise ValueError("Local worker returned an empty command for escalate_privileges")

        if not self._confirm(f"Send into session {session_id}: {command}"):
            return "Operator declined to run this command."

        output = self.session_manager.send_and_wait(
            session_id, command, wait_s=self.config.default_session_wait_s
        )
        return self.sanitizer.sanitize(output).text

    def _run_send_to_session(self, params: dict) -> str:
        session_id = params.get("session_id", "")
        command = params.get("command", "")
        wait_s = float(params.get("wait_seconds") or self.config.default_session_wait_s)

        if not self._confirm(f"Send into session {session_id}: {command}"):
            return "Operator declined to run this command."

        output = self.session_manager.send_and_wait(session_id, command, wait_s=wait_s)
        return self.sanitizer.sanitize(output).text

    # -- payload hosting (deterministic, no local worker) --------------------

    def _run_serve_payloads(self, params: dict) -> str:
        action = params.get("action")

        if action == "stop":
            return self._stop_payload_server()

        if self._payload_server_proc is not None:
            return (
                f"A payload server is already running on :{self._payload_server_port}. "
                f"Stop it first if you need a different port."
            )

        port = params.get("port")
        if not isinstance(port, int) or not (1025 <= port <= 65000):
            raise ValueError(f"port must be an integer in 1025-65000, got {port!r}")

        payloads_dir = Path(self.config.payloads_dir)
        payloads_dir.mkdir(parents=True, exist_ok=True)
        files = sorted(p.name for p in payloads_dir.iterdir() if p.is_file())

        if not self._confirm(f"Start HTTP file server on :{port} serving {payloads_dir}"):
            return "Operator declined to start the payload server."

        self._payload_server_proc = subprocess.Popen(
            ["python3", "-m", "http.server", str(port), "--directory", str(payloads_dir)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self._payload_server_port = port
        listing = ", ".join(files) if files else "(directory is empty -- nothing to serve yet)"
        return f"Serving {payloads_dir} on :{port}. Files available: {listing}"

    def _stop_payload_server(self) -> str:
        if self._payload_server_proc is None:
            return "No payload server is running."
        self._payload_server_proc.terminate()
        port = self._payload_server_port
        self._payload_server_proc = None
        self._payload_server_port = None
        return f"Stopped payload server on :{port}."

    # -- findings ------------------------------------------------------------

    _TERMINAL_FINDING_TYPES = {"user_flag", "root_flag", "objective_complete"}

    def _run_report_finding(self, params: dict) -> str:
        finding = {
            "finding_type": params.get("finding_type", ""),
            "content": params.get("content", ""),
            "evidence": params.get("evidence", ""),
            "session_id": params.get("session_id"),
        }
        self.findings.append(finding)
        print(f"[finding] {finding['finding_type']}: {finding['content']}")
        self._emit({"kind": "finding", **finding})

        if finding["finding_type"] in self._TERMINAL_FINDING_TYPES:
            self._terminal_finding = finding
            return (
                f"Recorded as {finding['finding_type']} — the run is ending "
                f"now, no further tool calls will be processed."
            )
        return f"Recorded as {finding['finding_type']}. Continue if you have another lead."

    # -- shared helpers -----------------------------------------------------

    def _confirm(self, description: str) -> bool:
        if not self.config.require_confirmation:
            return True
        return input(f"{description}\n  proceed? [y/N] ").strip().lower() == "y"

    def _format_exec_result(self, exec_result) -> str:
        combined = exec_result.stdout
        if exec_result.stderr:
            combined += f"\n[stderr]\n{exec_result.stderr}"
        if exec_result.timed_out:
            combined += "\n[command timed out]"

        sanitized = self.sanitizer.sanitize(combined)
        note = (
            f" (summarized from {sanitized.original_chars} chars)"
            if sanitized.truncated
            else ""
        )
        return f"[exit={exec_result.returncode}]{note}\n{sanitized.text}"

    # -- placeholder substitution -------------------------------------------

    def _substitute_placeholders(self, value):
        """Recursively walk a tool_use.input value, replacing any string
        that exactly matches a known placeholder with its real value from
        config.placeholder_map. Nested dicts/lists are handled so a future
        tool schema can nest the placeholder without extra plumbing here."""
        placeholder_map = self.config.placeholder_map
        if isinstance(value, str):
            return placeholder_map.get(value, value)
        if isinstance(value, dict):
            return {k: self._substitute_placeholders(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self._substitute_placeholders(v) for v in value]
        return copy.copy(value)
