#!/usr/bin/env python3
"""
Example CLI driver for the dual-LLM orchestrator.

    python main.py --target 10.10.10.5 --goal "Get root"
    python main.py --target 10.10.10.5 --target-name ghostlink --goal "Get root"

--target-name is optional and only affects where the run transcript is
written: given, it goes to this vault's Recon Output/Machines/ next to
recon-agent's own notes for that box; omitted, it goes to this folder's own
./runs/ directory instead. See notes.py for the full logic.

Requires ANTHROPIC_API_KEY, LOCAL_WORKER_BASE_URL (your Runpod vLLM/Ollama
endpoint), and optionally LOCAL_WORKER_MODEL / ATTACKER_IP set in the
environment — see README.md for the full list and setup steps.
"""

from __future__ import annotations

import argparse

from config import OrchestratorConfig
from orchestrator import DualLLMOrchestrator


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", required=True, help="Real target host/IP (authorized scope only)")
    parser.add_argument("--target-url", help="Override the derived http://<target> base URL")
    parser.add_argument(
        "--target-name",
        help="HTB/lab box name, if known -- controls where the run transcript is saved (see notes.py)",
    )
    parser.add_argument("--goal", required=True, help="What to accomplish this run, e.g. 'Get root'")
    args = parser.parse_args()

    config = OrchestratorConfig(target_host=args.target, target_url=args.target_url)
    orchestrator = DualLLMOrchestrator(config)

    print(f"=== Goal: {args.goal} (target={args.target}) ===")
    try:
        final = orchestrator.run(args.goal, target_name=args.target_name)
        print("\n=== Final planner response ===")
        print(final)
    except Exception as exc:  # noqa: BLE001 - e.g. the cost ceiling or a fallback-exhausted refusal
        print(f"\n=== Run aborted: {exc} ===")
    finally:
        # Printed either way -- this is what actually happened to spend,
        # whether the run finished cleanly or was aborted by the cost
        # ceiling. See orchestrator._track_usage's docstring for what this
        # estimate does and doesn't account for.
        print(f"\n=== Estimated Claude API cost this run: ${orchestrator.cumulative_cost_usd:.4f} ===")

    if orchestrator.findings:
        print("\n=== Findings recorded this run ===")
        for f in orchestrator.findings:
            print(f"- [{f['finding_type']}] {f['content']}")


if __name__ == "__main__":
    main()
