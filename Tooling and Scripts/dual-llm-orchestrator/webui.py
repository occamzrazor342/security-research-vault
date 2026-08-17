#!/usr/bin/env python3
"""
Minimal local web GUI for the dual-LLM orchestrator.

    python webui.py
    # then open http://127.0.0.1:5000

Fill in the target (and optionally its HTB/lab name, for where the run
transcript lands — see notes.py), give it a goal, hit Start, and watch it
work. This drives the exact same DualLLMOrchestrator engine as main.py —
no separate orchestration logic here, just a GUI wired to
orchestrator.py's on_event callback (see orchestrator.py's __init__
docstring) instead of main.py's print()-only output.

Single-operator local tool, not a multi-user service: binds to
127.0.0.1 only, one run at a time (a second /start while one is running
is refused), no authentication of its own. Same env/.env setup as
main.py — see README.md and .env.example.
"""

from __future__ import annotations

import threading

from flask import Flask, jsonify, render_template_string, request

from config import OrchestratorConfig
from orchestrator import DualLLMOrchestrator

app = Flask(__name__)

_state_lock = threading.Lock()
_state: dict = {
    "status": "idle",  # idle | running | done | error
    "events": [],
    "target": None,
    "target_name": None,
    "goal": None,
}
# The DualLLMOrchestrator instance actually running _run_loop right now,
# if any -- /interject needs this to reach push_interjection() on the
# live instance, not the module-level _state dict (which only mirrors
# events, it isn't the orchestrator itself).
_current_orchestrator: DualLLMOrchestrator | None = None


def _on_event(event: dict) -> None:
    with _state_lock:
        _state["events"].append(event)
        if event["kind"] == "done":
            _state["status"] = "done"
        elif event["kind"] == "error":
            _state["status"] = "error"


def _run_in_background(config: OrchestratorConfig, goal: str, target_name: str | None) -> None:
    global _current_orchestrator
    orchestrator = DualLLMOrchestrator(config, on_event=_on_event)
    with _state_lock:
        _current_orchestrator = orchestrator
    try:
        orchestrator.run(goal, target_name=target_name)
    except Exception as exc:  # noqa: BLE001 - surface to the GUI, don't just die silently in the thread
        _on_event({"kind": "error", "error": str(exc)})
    finally:
        with _state_lock:
            _current_orchestrator = None


@app.route("/")
def index():
    return render_template_string(_PAGE)


@app.route("/start", methods=["POST"])
def start():
    with _state_lock:
        if _state["status"] == "running":
            return jsonify({"error": "A run is already in progress."}), 409

    target = (request.form.get("target") or "").strip()
    target_name = (request.form.get("target_name") or "").strip() or None
    goal = (request.form.get("goal") or "").strip()
    if not target or not goal:
        return jsonify({"error": "Target and goal are both required."}), 400

    try:
        config = OrchestratorConfig(target_host=target)
    except ValueError as exc:
        # e.g. ANTHROPIC_API_KEY not set -- surface it in the GUI instead
        # of a bare 500 with no explanation.
        return jsonify({"error": str(exc)}), 400

    with _state_lock:
        _state["status"] = "running"
        _state["events"] = []
        _state["target"] = target
        _state["target_name"] = target_name
        _state["goal"] = goal

    thread = threading.Thread(
        target=_run_in_background, args=(config, goal, target_name), daemon=True
    )
    thread.start()
    return jsonify({"ok": True})


@app.route("/status")
def status():
    with _state_lock:
        # Shallow copy is enough -- events/target/goal are replaced
        # wholesale on the next /start, never mutated in place.
        return jsonify(dict(_state))


@app.route("/interject", methods=["POST"])
def interject():
    message = (request.form.get("message") or "").strip()
    if not message:
        return jsonify({"error": "message is required"}), 400

    with _state_lock:
        orchestrator = _current_orchestrator

    if orchestrator is None:
        return jsonify({"error": "No run is currently active."}), 409

    orchestrator.push_interjection(message)
    return jsonify({"ok": True})


_PAGE = """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Dual-LLM Orchestrator</title>
<style>
  :root {
    --bg: #0d1117; --panel: #161b22; --border: #30363d;
    --text: #c9d1d9; --dim: #8b949e; --accent: #58a6ff;
    --green: #3fb950; --red: #f85149; --yellow: #d29922;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--bg); color: var(--text);
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 14px;
  }
  header {
    padding: 16px 24px; border-bottom: 1px solid var(--border);
    display: flex; align-items: baseline; gap: 12px;
  }
  header h1 { font-size: 16px; margin: 0; color: var(--accent); }
  header .status { font-size: 12px; padding: 2px 8px; border-radius: 4px; }
  .status-idle { background: #21262d; color: var(--dim); }
  .status-running { background: #1c2b1f; color: var(--green); }
  .status-done { background: #1c2b1f; color: var(--green); }
  .status-error { background: #2b1c1c; color: var(--red); }
  main { display: flex; gap: 16px; padding: 16px 24px; }
  #form-panel { width: 320px; flex-shrink: 0; }
  #log-panel { flex: 1; min-width: 0; }
  .panel {
    background: var(--panel); border: 1px solid var(--border);
    border-radius: 6px; padding: 16px;
  }
  label { display: block; margin-top: 12px; margin-bottom: 4px; color: var(--dim); font-size: 12px; }
  input, textarea {
    width: 100%; background: #0d1117; border: 1px solid var(--border);
    color: var(--text); padding: 6px 8px; border-radius: 4px;
    font-family: inherit; font-size: 13px;
  }
  textarea { resize: vertical; min-height: 60px; }
  button {
    margin-top: 16px; width: 100%; padding: 8px; border-radius: 4px;
    border: 1px solid var(--accent); background: #1f2937; color: var(--accent);
    font-family: inherit; font-size: 13px; cursor: pointer;
  }
  button:disabled { opacity: 0.5; cursor: not-allowed; }
  button:hover:not(:disabled) { background: var(--accent); color: #0d1117; }
  #error-banner {
    display: none; margin-top: 12px; padding: 8px; border-radius: 4px;
    background: #2b1c1c; color: var(--red); font-size: 12px;
  }
  #log { height: calc(100vh - 140px); overflow-y: auto; }
  .event { margin-bottom: 10px; padding-bottom: 10px; border-bottom: 1px solid var(--border); }
  .event:last-child { border-bottom: none; }
  .kind-text { color: var(--text); }
  .kind-text .tag { color: var(--accent); }
  .kind-tool_call .tag { color: var(--yellow); }
  .kind-tool_call.error .tag { color: var(--red); }
  .kind-finding .tag { color: var(--green); font-weight: bold; }
  .kind-finding.terminal { background: #1c2b1f; padding: 8px; border-radius: 4px; }
  .kind-error .tag { color: var(--red); font-weight: bold; }
  .kind-notes_written .tag { color: var(--dim); }
  .kind-done .tag { color: var(--green); font-weight: bold; }
  .kind-usage { color: var(--dim); font-size: 12px; }
  .kind-usage .tag { color: var(--dim); }
  .kind-interjection { background: #142433; padding: 8px; border-radius: 4px; }
  .kind-interjection .tag { color: var(--accent); font-weight: bold; }
  .tag { font-size: 11px; text-transform: uppercase; margin-right: 8px; }
  #interject-row { display: flex; gap: 8px; margin-top: 8px; }
  #interject-row input { flex: 1; }
  #interject-row button {
    width: auto; margin-top: 0; padding: 6px 14px;
  }
  pre {
    margin: 4px 0 0; white-space: pre-wrap; word-break: break-word;
    color: var(--dim); font-size: 12.5px; max-height: 240px; overflow-y: auto;
  }
  .empty { color: var(--dim); font-style: italic; }
  #cost-badge {
    font-size: 12px; padding: 2px 8px; border-radius: 4px;
    background: #21262d; color: var(--yellow);
  }
</style>
</head>
<body>
<header>
  <h1>Dual-LLM Orchestrator</h1>
  <span id="status-badge" class="status status-idle">idle</span>
  <span id="cost-badge">$0.0000</span>
</header>
<main>
  <div id="form-panel" class="panel">
    <label for="target">Target host/IP</label>
    <input id="target" placeholder="10.10.10.5">

    <label for="target_name">Target name (optional)</label>
    <input id="target_name" placeholder="cobblestone">

    <label for="goal">Goal</label>
    <textarea id="goal" placeholder="Get root">Get root</textarea>

    <button id="start-btn" onclick="startRun()">Start</button>
    <div id="error-banner"></div>

    <label for="interject-input">Say something mid-run</label>
    <div id="interject-row">
      <input id="interject-input" placeholder="e.g. stop that lead, try X instead" disabled
             onkeydown="if(event.key==='Enter') sendInterjection()">
      <button id="interject-btn" onclick="sendInterjection()" disabled>Send</button>
    </div>
  </div>
  <div id="log-panel" class="panel">
    <div id="log"><div class="empty">No run started yet.</div></div>
  </div>
</main>
<script>
let lastEventCount = 0;

function escapeHtml(s) {
  const d = document.createElement('div');
  d.textContent = String(s);
  return d.innerHTML;
}

function renderEvent(ev) {
  const div = document.createElement('div');
  const isError = ev.is_error || ev.kind === 'error';
  const isTerminal = ev.kind === 'finding' && ['user_flag', 'root_flag', 'objective_complete'].includes(ev.finding_type);
  div.className = 'event kind-' + ev.kind + (isError ? ' error' : '') + (isTerminal ? ' terminal' : '');

  if (ev.kind === 'text') {
    div.innerHTML = '<span class="tag">planner</span>' + escapeHtml(ev.text);
  } else if (ev.kind === 'tool_call') {
    div.innerHTML = '<span class="tag">' + escapeHtml(ev.tool) + '</span>'
      + '<pre>' + escapeHtml(JSON.stringify(ev.params)) + '</pre>'
      + '<pre>' + escapeHtml(ev.result) + '</pre>';
  } else if (ev.kind === 'finding') {
    div.innerHTML = '<span class="tag">' + escapeHtml(ev.finding_type) + '</span>' + escapeHtml(ev.content)
      + '<pre>' + escapeHtml(ev.evidence || '') + '</pre>';
  } else if (ev.kind === 'notes_written') {
    div.innerHTML = '<span class="tag">notes</span>wrote transcript to ' + escapeHtml(ev.path);
  } else if (ev.kind === 'error') {
    div.innerHTML = '<span class="tag">error</span>' + escapeHtml(ev.error);
  } else if (ev.kind === 'done') {
    div.innerHTML = '<span class="tag">done</span><pre>' + escapeHtml(ev.result) + '</pre>';
  } else if (ev.kind === 'usage') {
    div.innerHTML = '<span class="tag">usage</span>'
      + `${ev.model} in=${ev.input_tokens} out=${ev.output_tokens} `
      + `cache_read=${ev.cache_read_input_tokens} turn=$${ev.turn_cost_usd.toFixed(4)} `
      + `cumulative=$${ev.cumulative_cost_usd.toFixed(4)}`;
  } else if (ev.kind === 'interjection') {
    div.innerHTML = '<span class="tag">you</span>' + escapeHtml(ev.text);
  }
  return div;
}

async function poll() {
  const res = await fetch('/status');
  const state = await res.json();

  const badge = document.getElementById('status-badge');
  badge.textContent = state.status;
  badge.className = 'status status-' + state.status;
  document.getElementById('start-btn').disabled = (state.status === 'running');
  document.getElementById('interject-input').disabled = (state.status !== 'running');
  document.getElementById('interject-btn').disabled = (state.status !== 'running');

  const log = document.getElementById('log');
  if (state.events.length > 0 && lastEventCount === 0) log.innerHTML = '';
  for (let i = lastEventCount; i < state.events.length; i++) {
    log.appendChild(renderEvent(state.events[i]));
  }
  if (state.events.length > lastEventCount) log.scrollTop = log.scrollHeight;
  lastEventCount = state.events.length;

  // Cost badge tracks the latest usage event regardless of scroll position
  // -- always visible in the header, not something you have to scroll the
  // log to find.
  const usageEvents = state.events.filter(e => e.kind === 'usage');
  if (usageEvents.length > 0) {
    const latest = usageEvents[usageEvents.length - 1];
    document.getElementById('cost-badge').textContent = `$${latest.cumulative_cost_usd.toFixed(4)}`;
  }

  setTimeout(poll, 1000);
}

async function startRun() {
  const errBanner = document.getElementById('error-banner');
  errBanner.style.display = 'none';
  lastEventCount = 0;
  document.getElementById('log').innerHTML = '<div class="empty">Starting...</div>';
  document.getElementById('cost-badge').textContent = '$0.0000';

  const body = new URLSearchParams({
    target: document.getElementById('target').value,
    target_name: document.getElementById('target_name').value,
    goal: document.getElementById('goal').value,
  });
  const res = await fetch('/start', { method: 'POST', body });
  const data = await res.json();
  if (!res.ok) {
    errBanner.textContent = data.error;
    errBanner.style.display = 'block';
    document.getElementById('log').innerHTML = '<div class="empty">No run started yet.</div>';
    return;
  }
  document.getElementById('start-btn').disabled = true;
}

async function sendInterjection() {
  const input = document.getElementById('interject-input');
  const message = input.value.trim();
  if (!message) return;
  const res = await fetch('/interject', {
    method: 'POST',
    body: new URLSearchParams({ message }),
  });
  if (res.ok) {
    input.value = '';
    // Optimistic local echo -- the real interjection event only lands in
    // /status once the orchestrator actually folds it into the next
    // turn, which can be a while if a tool call is mid-flight. This
    // gives immediate feedback that it was received rather than looking
    // like nothing happened.
    const log = document.getElementById('log');
    const div = document.createElement('div');
    div.className = 'event kind-interjection';
    div.innerHTML = '<span class="tag">you (sending...)</span>' + escapeHtml(message);
    log.appendChild(div);
    log.scrollTop = log.scrollHeight;
  } else {
    const data = await res.json();
    alert(data.error || 'Failed to send.');
  }
}

poll();
</script>
</body>
</html>
"""

if __name__ == "__main__":
    print("Dual-LLM orchestrator GUI: http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
