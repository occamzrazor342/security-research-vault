#!/usr/bin/env python3
"""
Runpod pod cost safety net -- closes the gap flagged in README.md's Cost
controls section: nothing in this harness bounds Runpod spend. The
Cobblestone session's pod ran ~2h16m (~$3.60) purely because a human
remembered to stop it by hand at the end; nothing would have stopped it
otherwise. This is a standalone watchdog for that.

`runpodctl pod update` has no auto-stop-at-time flag for an EXISTING pod
(only `pod create --stop-after` does, at creation time, which doesn't
help a pod you resumed rather than freshly created) -- so this has to be
a real polling watchdog, not a one-shot flag.

Two independent triggers, whichever fires first:
  - --max-hours: hard wall-clock ceiling since the pod's own `createdAt`
    (not since the watchdog started -- so this is correct even if you
    start the guard partway through a session).
  - --idle-minutes: GPU utilization (`nvidia-smi`, queried over SSH)
    below --idle-threshold-percent for this many consecutive minutes.
    Requires --ssh-host/--ssh-port/--ssh-key (the same values
    `runpodctl pod get <id>` prints under .ssh.ssh_command). Omit these
    to run max-hours-only (no SSH access needed).

Usage:
    python runpod_guard.py --pod-id 6ctt3721nf8n1f --max-hours 4
    python runpod_guard.py --pod-id 6ctt3721nf8n1f --max-hours 6 \\
        --idle-minutes 20 --ssh-host 154.54.102.22 --ssh-port 14972 \\
        --ssh-key ~/.runpod/ssh/runpodctl-ssh-key

Run it detached (tmux/nohup) alongside the pod, same as vLLM itself needs
to be -- this process dying doesn't stop the pod, it just stops watching
it. It only ever calls `runpodctl pod stop`, never `terminate`/`delete` --
stopping preserves the container disk exactly like a manual stop does.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import subprocess
import sys
import time


def _run(argv: list[str]) -> tuple[int, str]:
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    return proc.returncode, (proc.stdout or proc.stderr)


def get_pod(pod_id: str) -> dict:
    code, out = _run(["runpodctl", "pod", "get", pod_id])
    if code != 0:
        raise RuntimeError(f"runpodctl pod get failed: {out}")
    return json.loads(out)


def pod_age_hours(pod: dict) -> float:
    created = _dt.datetime.strptime(
        pod["createdAt"].split(".")[0], "%Y-%m-%d %H:%M:%S"
    ).replace(tzinfo=_dt.timezone.utc)
    return (_dt.datetime.now(_dt.timezone.utc) - created).total_seconds() / 3600


def gpu_utilization_percent(ssh_host: str, ssh_port: int, ssh_key: str) -> float | None:
    """Returns None (treated as "not idle" -- fail safe, don't stop a pod
    you can't actually observe) if the SSH query itself fails, so a
    network blip never triggers a stop on a pod that might be mid-task."""
    code, out = _run([
        "ssh", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=accept-new",
        "-i", ssh_key, "-p", str(ssh_port), f"root@{ssh_host}",
        "nvidia-smi --query-gpu=utilization.gpu --format=csv,noheader,nounits",
    ])
    if code != 0:
        print(f"[runpod_guard] WARNING: couldn't query GPU utilization ({out.strip()!r}) "
              f"-- treating as not-idle rather than risk stopping a pod mid-task", file=sys.stderr)
        return None
    try:
        return float(out.strip().splitlines()[0])
    except (ValueError, IndexError):
        return None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pod-id", required=True)
    parser.add_argument("--max-hours", type=float, default=4.0,
                         help="Hard ceiling since the pod's own createdAt. Default 4.")
    parser.add_argument("--idle-minutes", type=float, default=None,
                         help="Stop after this many consecutive minutes below --idle-threshold-percent GPU util. Needs --ssh-host.")
    parser.add_argument("--idle-threshold-percent", type=float, default=2.0)
    parser.add_argument("--ssh-host")
    parser.add_argument("--ssh-port", type=int, default=22)
    parser.add_argument("--ssh-key", default="~/.runpod/ssh/runpodctl-ssh-key")
    parser.add_argument("--poll-seconds", type=int, default=60)
    parser.add_argument("--dry-run", action="store_true",
                         help="Log what would happen without actually calling `runpodctl pod stop`.")
    args = parser.parse_args()

    if args.idle_minutes and not args.ssh_host:
        parser.error("--idle-minutes requires --ssh-host (idle detection needs to SSH in and check nvidia-smi)")

    consecutive_idle_polls = 0
    idle_polls_needed = (
        int(args.idle_minutes * 60 / args.poll_seconds) if args.idle_minutes else None
    )

    print(f"[runpod_guard] watching pod {args.pod_id} -- max_hours={args.max_hours}, "
          f"idle_minutes={args.idle_minutes}, poll_seconds={args.poll_seconds}, dry_run={args.dry_run}")

    while True:
        try:
            pod = get_pod(args.pod_id)
        except RuntimeError as exc:
            print(f"[runpod_guard] ERROR checking pod state: {exc}", file=sys.stderr)
            time.sleep(args.poll_seconds)
            continue

        if pod.get("runtimeStatus") != "running":
            print(f"[runpod_guard] pod status is {pod.get('runtimeStatus')!r}, not 'running' -- nothing to guard, exiting")
            return

        age = pod_age_hours(pod)
        reason = None

        if age >= args.max_hours:
            reason = f"max_hours ceiling reached ({age:.2f}h >= {args.max_hours}h)"
        elif args.idle_minutes:
            util = gpu_utilization_percent(args.ssh_host, args.ssh_port, args.ssh_key)
            if util is not None and util < args.idle_threshold_percent:
                consecutive_idle_polls += 1
                print(f"[runpod_guard] age={age:.2f}h util={util:.1f}% "
                      f"(idle poll {consecutive_idle_polls}/{idle_polls_needed})")
                if consecutive_idle_polls >= idle_polls_needed:
                    reason = f"idle for {args.idle_minutes} consecutive minutes (util < {args.idle_threshold_percent}%)"
            else:
                if consecutive_idle_polls > 0:
                    print(f"[runpod_guard] activity resumed (util={util}%) -- idle counter reset")
                consecutive_idle_polls = 0
                print(f"[runpod_guard] age={age:.2f}h util={util}%")
        else:
            print(f"[runpod_guard] age={age:.2f}h (max_hours-only mode)")

        if reason:
            print(f"[runpod_guard] STOPPING pod {args.pod_id}: {reason}")
            if args.dry_run:
                print("[runpod_guard] --dry-run set, not actually calling runpodctl pod stop")
            else:
                code, out = _run(["runpodctl", "pod", "stop", args.pod_id])
                print(f"[runpod_guard] runpodctl pod stop exit={code}: {out.strip()}")
            return

        time.sleep(args.poll_seconds)


if __name__ == "__main__":
    main()
