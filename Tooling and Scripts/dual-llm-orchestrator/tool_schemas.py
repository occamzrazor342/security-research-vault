"""
Claude tool-call schemas for the dual-LLM orchestrator.

These are the tools exposed to the Planner (Claude) via the Messages API
`tools` parameter. Claude never sees a real target — every schema takes an
abstract placeholder (TARGET_HOST / TARGET_URL / LISTENER_HOST) that
orchestrator.py substitutes with the real value from OrchestratorConfig at
dispatch time, right before the intent is handed to the local execution
worker. This keeps the target out of the prompt that gets sent to
Anthropic's API and out of prompt-cache-visible history — it only ever
exists in this process's memory and in the local worker / subprocess calls.

Two tool families, matching pwn-box's recon -> exploit -> privesc shape:
  - run_recon, execute_fuzzing, analyze_services: the original recon/fuzz
    pipeline (local worker generates CLI syntax -> subprocess, or, for
    analyze_services, a pure-Python parser — see service_parser.py).
  - execute_exploit, escalate_privileges, send_to_session: foothold and
    privesc, built around session_manager.SessionManager. execute_exploit
    can start a reverse-shell listener and return a session_id;
    escalate_privileges and send_to_session both send commands into an
    already-open session rather than running a local subprocess — see
    session_manager.py's module docstring for what that channel does and
    doesn't guarantee.

Add a new tool by:
  1. Adding its schema to TOOLS below.
  2. Adding an entry to ALLOWED_BINARIES in executor.py (the allowlist of
     binaries that tool is permitted to invoke) — only needed if the tool
     runs a *local* subprocess (like run_recon/execute_fuzzing/
     execute_exploit's delivery step), not if it sends into an existing
     session (escalate_privileges/send_to_session skip this check — see
     their handlers in orchestrator.py for why).
  3. Handling it in DualLLMOrchestrator._handle_tool_call (orchestrator.py).
"""

TOOLS = [
    {
        "name": "run_recon",
        "description": (
            "Run network/service reconnaissance against a target (port scan, "
            "service/version detection). Use this first, before fuzzing or "
            "deeper analysis, to learn what's actually listening. The target "
            "is always the literal string TARGET_HOST — never invent or "
            "guess a real IP/hostname; the orchestrator substitutes it."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "const": "TARGET_HOST",
                    "description": "Always the literal placeholder TARGET_HOST.",
                },
                "scan_type": {
                    "type": "string",
                    "enum": ["quick", "full_tcp", "udp", "service_version"],
                    "description": (
                        "quick: top ~1000 TCP ports, fast. full_tcp: all 65535 "
                        "TCP ports. udp: top UDP ports. service_version: "
                        "version/banner detection on already-known open ports "
                        "(pass them via 'ports')."
                    ),
                },
                "ports": {
                    "type": "string",
                    "description": (
                        "Optional comma-separated port list or range (e.g. "
                        "'22,80,443' or '1-1024'). Omit to let the local "
                        "worker pick sane defaults for scan_type."
                    ),
                },
            },
            "required": ["target", "scan_type"],
        },
    },
    {
        "name": "execute_fuzzing",
        "description": (
            "Fuzz a web target for content, virtual hosts, or parameters "
            "(directories/files, vhosts, or GET/POST parameters). Use after "
            "run_recon has confirmed an HTTP(S) service. The target is "
            "always the literal string TARGET_URL — never invent a real URL; "
            "the orchestrator substitutes it."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target_url": {
                    "type": "string",
                    "const": "TARGET_URL",
                    "description": "Always the literal placeholder TARGET_URL.",
                },
                "mode": {
                    "type": "string",
                    "enum": ["directory", "vhost", "parameter"],
                    "description": (
                        "directory: content/path discovery. vhost: virtual-"
                        "host / Host-header discovery. parameter: GET/POST "
                        "parameter discovery."
                    ),
                },
                "wordlist_hint": {
                    "type": "string",
                    "description": (
                        "Optional hint for wordlist size/type, e.g. "
                        "'common', 'medium', 'api-endpoints'. The local "
                        "worker resolves this to an actual wordlist path."
                    ),
                },
            },
            "required": ["target_url", "mode"],
        },
    },
    {
        "name": "analyze_services",
        "description": (
            "Parse and structure raw recon/fuzzing output already collected "
            "in this session (e.g. the last run_recon or execute_fuzzing "
            "result) into a normalized summary: open ports, service names/ "
            "versions, and interesting web paths/status codes. This does "
            "NOT run any command or touch the network — pass it the output "
            "text you already have."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "raw_output": {
                    "type": "string",
                    "description": "Raw tool output text to parse (nmap/ffuf/gobuster style).",
                },
                "source_tool": {
                    "type": "string",
                    "enum": ["run_recon", "execute_fuzzing"],
                    "description": "Which tool produced raw_output, so the parser picks the right format.",
                },
            },
            "required": ["raw_output", "source_tool"],
        },
    },
    {
        "name": "execute_exploit",
        "description": (
            "Attempt to gain a foothold by exploiting a specific, already-"
            "identified service/vulnerability (from analyze_services, or a "
            "CVE you already know applies). If the technique triggers a "
            "connection back to us, set reverse_shell=true and pick an "
            "unused listener_port — the orchestrator starts the listener "
            "BEFORE running the exploit so the callback isn't missed, then "
            "reports a session_id you use with send_to_session and "
            "escalate_privileges for everything after. The target is "
            "always the literal string TARGET_HOST, and any callback "
            "address in the payload is always the literal string "
            "LISTENER_HOST — never invent real values; the orchestrator "
            "substitutes both."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "const": "TARGET_HOST",
                    "description": "Always the literal placeholder TARGET_HOST.",
                },
                "service": {
                    "type": "string",
                    "description": "The vulnerable service/version, e.g. 'vsftpd 2.3.4 on port 21'.",
                },
                "technique": {
                    "type": "string",
                    "description": (
                        "What to exploit and how, e.g. 'vsftpd 2.3.4 "
                        "backdoor command execution (CVE-2011-2523)'."
                    ),
                },
                "reverse_shell": {
                    "type": "boolean",
                    "description": "Whether this technique triggers a callback connection to us.",
                },
                "listener_port": {
                    "type": "integer",
                    "description": (
                        "Local port to listen on, 1025-65000. Required if "
                        "reverse_shell is true; omit otherwise."
                    ),
                },
            },
            "required": ["target", "service", "technique", "reverse_shell"],
        },
    },
    {
        "name": "escalate_privileges",
        "description": (
            "Generate and run a specific privilege-escalation technique "
            "inside an already-established session (from execute_exploit). "
            "Use this when you have a concrete technique in mind (a "
            "specific SUID binary, a sudo misconfiguration, a named kernel "
            "exploit) and want the local worker to produce the exact "
            "command for it. For plain enumeration or a one-off command "
            "you already know verbatim, use send_to_session instead — "
            "it's cheaper and skips the translation step."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Session ID returned by a prior execute_exploit call.",
                },
                "technique": {
                    "type": "string",
                    "description": (
                        "The specific privesc technique to attempt, e.g. "
                        "'abuse SUID find binary' or 'sudo NOPASSWD entry "
                        "for /usr/bin/vim (GTFOBins)'."
                    ),
                },
            },
            "required": ["session_id", "technique"],
        },
    },
    {
        "name": "send_to_session",
        "description": (
            "Send a literal command directly into an already-established "
            "session (from execute_exploit) and return whatever output "
            "arrives within the wait window. Use this for enumeration and "
            "one-off commands you already know the exact syntax for "
            "(whoami, id, cat /etc/passwd, find / -perm -4000 ...) — no "
            "local-worker translation happens here, so it's the default "
            "choice for anything you can already write yourself."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Session ID returned by a prior execute_exploit call.",
                },
                "command": {
                    "type": "string",
                    "description": "The exact command to run in the session.",
                },
                "wait_seconds": {
                    "type": "number",
                    "description": "How long to wait for output, default 5. Increase for slow commands.",
                },
            },
            "required": ["session_id", "command"],
        },
    },
    {
        "name": "run_service_enum",
        "description": (
            "Run deeper protocol-specific enumeration against a discovered "
            "service beyond run_recon's port/version scan — SMB shares/"
            "users/sessions, LDAP/AD naming context and objects, or RPC "
            "endpoint queries, optionally with a found username/password. "
            "Use after run_recon shows the relevant port open (445/139 for "
            "SMB, 389/636 for LDAP, 135 for RPC)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "const": "TARGET_HOST",
                    "description": "Always the literal placeholder TARGET_HOST.",
                },
                "protocol": {"type": "string", "enum": ["smb", "ldap", "rpc"]},
                "username": {
                    "type": "string",
                    "description": "Optional — omit for an anonymous/null-session attempt.",
                },
                "password": {
                    "type": "string",
                    "description": "Optional, only meaningful alongside username.",
                },
                "goal_hint": {
                    "type": "string",
                    "description": (
                        "What you're looking for, e.g. 'list shares and "
                        "readable files' or 'enumerate domain users'."
                    ),
                },
            },
            "required": ["target", "protocol", "goal_hint"],
        },
    },
    {
        "name": "serve_payloads",
        "description": (
            "Start or stop a local HTTP file server so an already-caught "
            "session can pull enumeration/exploit scripts onto the target "
            "via curl/wget (e.g. linpeas.sh, winPEAS.exe, pspy64 — drop "
            "your own copies into the configured payloads directory "
            "first; none are bundled). Once started, fetch from the "
            "session with an ordinary send_to_session command pointed at "
            "http://LISTENER_HOST:<port>/<filename> — never invent the "
            "callback address, use the literal placeholder LISTENER_HOST."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": ["start", "stop"]},
                "port": {
                    "type": "integer",
                    "description": "Port to serve on, 1025-65000. Only used for action=start.",
                },
            },
            "required": ["action"],
        },
    },
    {
        "name": "spray_credentials",
        "description": (
            "Try a SMALL set of already-discovered or well-known default "
            "credentials against a service. This is NOT a wordlist "
            "brute-forcer — capped at 30 total username x password "
            "combinations per call, enforced by the orchestrator "
            "regardless of what you pass. Use only credentials you've "
            "actually found (recon, config files, default creds for the "
            "identified software) or well-known service defaults — never "
            "invent a guess list."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "const": "TARGET_HOST",
                    "description": "Always the literal placeholder TARGET_HOST.",
                },
                "service": {"type": "string", "enum": ["ssh", "smb", "winrm"]},
                "usernames": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Up to 10 usernames.",
                },
                "passwords": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Up to 10 passwords.",
                },
            },
            "required": ["target", "service", "usernames", "passwords"],
        },
    },
    {
        "name": "report_finding",
        "description": (
            "Formally record a flag or the engagement's outcome. Call this "
            "the moment you have PROOF (actual command output showing it), "
            "not a plan to get it. finding_type='user_flag' or 'root_flag' "
            "END THE RUN immediately once reported, so only report one "
            "once you've actually run the command that reads it via "
            "send_to_session. 'objective_complete' also ends the run — "
            "use it for goals that aren't literally a flag file (e.g. "
            "'confirm the web foothold'). 'blocked' records that you've "
            "exhausted your current ideas WITHOUT ending the run — use it "
            "to leave a clear record instead of trailing off in plain "
            "text; you may still continue afterward if you think of "
            "something else."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "finding_type": {
                    "type": "string",
                    "enum": ["user_flag", "root_flag", "objective_complete", "blocked"],
                },
                "content": {
                    "type": "string",
                    "description": "The flag value, or a description of what was accomplished/blocked on.",
                },
                "evidence": {
                    "type": "string",
                    "description": (
                        "The exact command and output that proves this, "
                        "e.g. \"cat /root/root.txt -> <hash>\"."
                    ),
                },
                "session_id": {
                    "type": "string",
                    "description": "The session this was captured from, if applicable.",
                },
            },
            "required": ["finding_type", "content", "evidence"],
        },
    },
]
