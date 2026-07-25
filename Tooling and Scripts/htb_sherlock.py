#!/usr/bin/env python3
"""HTB API CLI wrapper for Sherlocks (DFIR/forensics challenges), for the
sherlock-agent. Sibling to htb_connect.py but deliberately separate --
Sherlocks have no VPN/spawn lifecycle at all, just an evidence archive and
a set of text-answer tasks, so this script's shape doesn't overlap with
htb_connect.py's machine-lifecycle commands.

Run with the venv interpreter installed alongside this script:
    Tooling and Scripts/.venv/bin/python3 "Tooling and Scripts/htb_sherlock.py" <command> ...

Auth: reads HTB_API_TOKEN from the environment, same as htb_connect.py.

Every subcommand prints a single JSON object to stdout on success, or to
stderr with a non-zero exit code on failure.

pyhackthebox (the library htb_connect.py wraps) has zero Sherlock support
-- no Sherlock class, no endpoints for it anywhere in the package. Every
call here goes through HTBClient.do_request() directly against real but
undocumented endpoints, found by live-probing this vault owner's own
authenticated account with read-only GET requests (2026-07-24) -- no
public API docs for Sherlocks exist (checked: the community Postman
collection and the GitHub doc repos covering HTB's v4 API document
machines/challenges/labs, not Sherlocks).

Confirmed working (read-only GET):
  sherlocks                    -> paginated list (id, name, difficulty,
                                   state, category_name, progress,
                                   play_methods)
  sherlocks/<id>                -> full detail + tags
  sherlocks/<id>/info             -> description, related academy modules
  sherlocks/<id>/play               -> scenario text, creators, evidence
                                       file_name/file_size, play_info
  sherlocks/<id>/tasks                -> the actual question set (title,
                                          description, hint, masked_flag,
                                          completed)
  sherlocks/<id>/progress               -> is_owned, progress,
                                            total_tasks, tasks_answered
  sherlocks/<id>/writeup                  -> official writeup pointer
                                              (pdf/video), 404s if none
                                              released yet

KNOWN GAP (2026-07-24) -- evidence download: GET sherlocks/<id>/download
is a real, routed endpoint (POST/PUT/DELETE all 405 off it with
`Allow: GET, HEAD`, confirming GET is the right verb) but it returns
"500 Server Error" with no further detail even against a valid App Token
and a real, ownable Sherlock (id 631, "Brutus", state retired_free) --
reproduced twice, not a fluke of one bad id. Also checked for a "start
play" step some other HTB content types need before their
download/instance unlocks (machines need `spawn`; this seemed plausible
given sherlocks/<id>/play's `play_info.status` reads null pre-download):
both `sherlocks/<id>/play/start` and `sherlocks/<id>/start` 404 --
no such step exists for Sherlocks. Leading theory: like cmd_submit's gap
in htb_connect.py, this is an App-Token-scope restriction rather than a
bug -- HTB's own web app likely fetches the archive via a
session-cookie-authenticated browser request, possibly a signed URL
against cdn.services-k8s.prod.aws.htb.systems (the same host serving
avatar/asset URLs elsewhere in these responses). This endpoint also
carries its own tight rate limit (`x-ratelimit-limit: 15`) separate from
the rest of the API, so it isn't worth spending calls re-probing casually.
Until a working App-Token route is found, evidence archives must be
downloaded manually from the Sherlock's page in a logged-in browser
(https://app.hackthebox.com/sherlocks/<id>) and extracted (HTB's
standard zip password is "hacktheblue") before sherlock-agent can start
analysis -- see that agent's "Evidence acquisition" section.

Deliberately not implemented: answer submission. No endpoint for it was
probed (probing a real answer-submission endpoint has account-visible
side effects -- recorded attempts, progress state -- unlike the
read-only GETs above, so it wasn't tested blind). Even if a working route
existed, this mirrors the vault's existing flag-submission boundary
(cmd_submit in htb_connect.py, never auto-invoked by connect-agent):
Sherlock task answers are a manual, opt-in, human action, not something
an agent fires automatically.
"""
import argparse
import json
import os
import sys

from hackthebox import HTBClient, HtbException

API_BASE = "https://labs.hackthebox.com/api/v4/"


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}), file=sys.stderr)
    sys.exit(1)


def emit(payload):
    print(json.dumps(payload, indent=2, default=str))


def get_client():
    token = os.environ.get("HTB_API_TOKEN")
    if not token:
        fail(
            "HTB_API_TOKEN is not set. Generate an App Token at "
            "https://app.hackthebox.com/profile/settings and export it "
            "(e.g. in ~/.zshrc: export HTB_API_TOKEN=\"...\"), then open a "
            "new shell."
        )
    return HTBClient(app_token=token, api_base=API_BASE)


def fetch_all_sherlocks(client):
    rows = []
    page = 1
    while True:
        resp = client.do_request(f"sherlocks?page={page}")
        batch = resp.get("data", [])
        rows.extend(batch)
        meta = resp.get("meta", {})
        if not batch or page >= meta.get("last_page", page):
            break
        page += 1
    return rows


def resolve_id(client, target):
    """Sherlocks have no name-based lookup endpoint (unlike machines) --
    resolve a name to its id by paging the list."""
    if str(target).isdigit():
        return int(target)
    for row in fetch_all_sherlocks(client):
        if row["name"].lower() == str(target).lower():
            return row["id"]
    fail(f"No Sherlock found matching '{target}'")


def cmd_list(args):
    client = get_client()
    rows = fetch_all_sherlocks(client)
    if args.state:
        rows = [r for r in rows if r.get("state") == args.state]
    emit(
        [
            {
                "id": r["id"],
                "name": r["name"],
                "difficulty": r["difficulty"],
                "state": r["state"],
                "category": r.get("category_name"),
                "progress": r.get("progress"),
                "play_methods": r.get("play_methods"),
            }
            for r in rows
        ]
    )


def cmd_info(args):
    client = get_client()
    sid = resolve_id(client, args.target)
    detail = client.do_request(f"sherlocks/{sid}").get("data", {})
    play = client.do_request(f"sherlocks/{sid}/play").get("data", {})
    progress = client.do_request(f"sherlocks/{sid}/progress").get("data", {})
    try:
        writeup = client.do_request(f"sherlocks/{sid}/writeup").get("data", {})
    except Exception:
        # Not just HtbException: a non-retired/non-writeup-eligible Sherlock
        # (e.g. still active, or writeup gated some other way) can 403 with
        # an HTML page rather than a clean 404 JSON body, which raises a
        # requests JSONDecodeError inside do_request() instead of
        # NotFoundException. Writeup availability is optional metadata
        # either way, so any failure here just means "none available".
        writeup = None
    emit(
        {
            "id": sid,
            "name": detail.get("name"),
            "difficulty": detail.get("difficulty"),
            "state": detail.get("state"),
            "category": detail.get("category_name"),
            "tags": [t["name"] for t in detail.get("tags", [])],
            "scenario": play.get("scenario"),
            "file_name": play.get("file_name"),
            "file_size": play.get("file_size"),
            "progress": progress,
            "writeup": writeup,
        }
    )


def cmd_tasks(args):
    client = get_client()
    sid = resolve_id(client, args.target)
    tasks = client.do_request(f"sherlocks/{sid}/tasks").get("data", [])
    emit(
        [
            {
                "id": t["id"],
                "title": t["title"],
                "description": t["description"],
                "hint": t.get("hint"),
                "masked_flag": t.get("masked_flag"),
                "completed": t.get("completed"),
            }
            for t in tasks
        ]
    )


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("list", help="List Sherlocks (id, name, difficulty, state, category, progress)")
    p.add_argument("--state", help="Filter by state, e.g. active, retired_free, retired_vip")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser(
        "info", help="Full detail for one Sherlock (scenario, evidence file name/size, progress, writeup)"
    )
    p.add_argument("target", help="Sherlock name or id")
    p.set_defaults(func=cmd_info)

    p = sub.add_parser(
        "tasks", help="The question set for one Sherlock (title, description, hint, masked_flag, completed)"
    )
    p.add_argument("target", help="Sherlock name or id")
    p.set_defaults(func=cmd_tasks)

    return parser


def main():
    args = build_parser().parse_args()
    try:
        args.func(args)
    except HtbException as e:
        fail(str(e))


if __name__ == "__main__":
    main()
