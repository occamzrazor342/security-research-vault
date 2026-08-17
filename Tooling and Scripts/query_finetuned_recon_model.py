#!/usr/bin/env python3
"""
Calls our own fine-tuned Qwen2.5-Coder-32B-Instruct model (QLoRA adapter
trained in LLM Training/, see that folder's README) to do recon-agent's
analysis step: raw tool output in, a structured findings narrative out.

This is the "one narrow task first" integration decided on 2026-08-14 --
NOT a replacement for recon-agent or Claude Code's own orchestration, just
a standalone script that routes this one specific, well-matched task
through our own model instead of Claude, so its output quality can be
directly compared against what recon-agent/Sonnet actually produced for
the same target.

Usage:
    python3 query_finetuned_recon_model.py --file raw_output.txt --heading "NMAP Scan" --target ghostlink
    echo "..." | python3 query_finetuned_recon_model.py --heading "NMAP Scan" --target ghostlink

Requires the vLLM server to be reachable -- edit BASE_URL below (or pass
--base-url) to point at wherever it's currently running. As of 2026-08-14
that's an SSH-tunneled/direct connection to the RunPod pod's port 8000;
this has no fixed public URL yet (see LLM Training/README.md's serverless
deployment discussion for the planned stable-endpoint follow-up).
"""
import argparse
import sys

from openai import OpenAI

BASE_URL = "http://localhost:8000/v1"  # override with --base-url if serving elsewhere
MODEL_NAME = "security-adapter"  # the --lora-modules name registered when vLLM was started

# Mirrors ANALYSIS_TEMPLATES in LLM Training/scripts/build_dataset.py so the
# model sees the same prompt shape it was actually trained on.
SYSTEM_PROMPT = (
    "You are a penetration tester's assistant. You are given raw output from "
    "a security tool used during an authorized engagement. Analyze it and "
    "produce a clear, structured findings narrative."
)
USER_TEMPLATE = (
    "Here is raw output captured during the {heading} phase of an authorized "
    "HTB lab engagement against `{target}`. Analyze it and summarize the "
    "notable findings:\n\n```\n{code}\n```"
)


def analyze(raw_output, heading, target, base_url=BASE_URL, max_tokens=1024, temperature=0.3):
    client = OpenAI(base_url=base_url, api_key="not-needed")  # vLLM doesn't check the key locally
    user_msg = USER_TEMPLATE.format(heading=heading, target=target, code=raw_output.strip())
    resp = client.chat.completions.create(
        model=MODEL_NAME,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_msg},
        ],
        max_tokens=max_tokens,
        temperature=temperature,
    )
    return resp.choices[0].message.content


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--file", help="File containing raw tool output. Reads stdin if omitted.")
    ap.add_argument("--heading", required=True, help='e.g. "NMAP Top-1000 Ports Scan"')
    ap.add_argument("--target", required=True, help="Target/box name, e.g. ghostlink")
    ap.add_argument("--base-url", default=BASE_URL)
    ap.add_argument("--max-tokens", type=int, default=1024)
    ap.add_argument("--temperature", type=float, default=0.3)
    args = ap.parse_args()

    raw = open(args.file).read() if args.file else sys.stdin.read()
    if not raw.strip():
        print("No input provided (empty file/stdin).", file=sys.stderr)
        sys.exit(1)

    result = analyze(raw, args.heading, args.target, args.base_url, args.max_tokens, args.temperature)
    print(result)
