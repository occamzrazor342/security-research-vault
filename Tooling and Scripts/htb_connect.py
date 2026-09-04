#!/usr/bin/env python3
"""HTB API CLI wrapper around pyhackthebox, for the connect-agent stage of
the pwn-box pipeline (and for manual use).

Run with the venv interpreter installed alongside this script:
    Tooling and Scripts/.venv/bin/python3 "Tooling and Scripts/htb_connect.py" <command> ...

Auth: reads HTB_API_TOKEN from the environment (an HTB "App Token",
generated at https://app.hackthebox.com/profile/settings). Never pass the
token on the command line or hardcode it here.

Every subcommand prints a single JSON object to stdout on success, or to
stderr with a non-zero exit code on failure.

Note: this only talks to the HTB API (spawn/stop/reset/status/vpn/submit).
It does not start the OpenVPN tunnel itself -- that needs `sudo`, which
can't run non-interactively here. `vpn-download` prints the exact
`sudo openvpn --config ...` command to run by hand.

KNOWN GAP (historical, 2026-07-16/17) -- non-"labs" VPN products:
pyhackthebox's get_active_machine() calls get_current_vpn_server()
internally to build the MachineInstance, which only queried the default
paid "labs" product's `connections` response
(`data['lab']['assigned_server']`); for any other product (free_lab,
sp_lab, ra_lab, ...) that lookup 404s/KeyErrors, and
get_active_machine_or_none() normalized that into "nothing active" --
wrong whenever the real session lived on one of those other products.
Confirmed on THREE separate products:
  - "sp_lab" (Starting Point) -- 2026-07-16, spawning "Meow" (id 394).
  - "free_lab" (free-tier regular machines) -- 2026-07-16/17, "kobold"
    (id 856).
  - "ra_lab" (Release Arena) -- 2026-08-08/09, "DanglingTree" (id 936).

RESOLVED (2026-08-09) -- superseded by a newer, unified API surface found
by inspecting the current web app's JS bundles (app.hackthebox.com's
`/assets/*.js`, specifically `common-api-*.js` and
`useCurrentActiveContent-*.js`) after the old per-product raw-endpoint
workarounds below stopped working for Release Arena (`release_arena/active`
and `release_arena/spawn` now both 404 outright -- HTB retired that whole
`release_arena/*` v4 namespace):
  - There is now a **v5 API** (`https://labs.hackthebox.com/api/v5/`,
    distinct from the v4 base this script otherwise uses) with
    `GET virtual_machine/active`, which returns the currently active
    instance -- of ANY type/product (regular machine, free machine,
    Starting Point, Release Arena, even Sherlocks) -- uniformly, with no
    release_arena flag needed at all. This is what the web app's own
    "currently playing" indicator calls. `get_active_machine_v5()` below
    wraps it with a raw `requests` call (pyhackthebox's HTBClient has no
    v5 support and is hardcoded to one `_api_base`). This fully supersedes
    the old `machine/active` / `release_arena/active` v4 raw fallbacks --
    confirmed 2026-08-09 that v4 `machine/active` returned a stale/wrong
    `{"info": null}` for a release arena machine that v5
    `virtual_machine/active` correctly showed as active.
  - Spawning is now **fully unified**: `POST /vm/spawn` (v4, same endpoint
    used for regular machines) with body `{"machine_id": <id>}` spawns
    ANY machine type, Release Arena included -- the server infers the
    right pool from the machine itself. Confirmed live 2026-08-09
    (`{"message":"Machine deployed to lab. Playing on the release arena
    server!","success":true}` for DanglingTree, id 936). The old
    `machine.spawn(release_arena=True)` code path in pyhackthebox
    (`release_arena/spawn`, gated behind an `is_release` check that itself
    calls the now-404ing bare `connections` endpoint) is dead code against
    the current API -- do not call it. Same story for stop/reset:
    `POST /vm/terminate` and `POST /vm/reset`, each with an explicit
    `{"machine_id": <id>}` body, work for every product; the
    `release_arena/terminate` / `release_arena/reset` endpoints this
    script used to call for the release-arena case now 404.
  - **Hazard confirmed the hard way, 2026-08-09**: `POST vm/terminate`
    with an EMPTY body (`{}`, sent as a "does this route exist" probe, not
    intended to do anything) did not error -- it silently terminated the
    real active instance (DanglingTree) immediately, HTTP 200
    `{"message":"Machine terminated.","success":true}`. The endpoint
    apparently defaults to acting on the caller's current active instance
    when no `machine_id` is given, rather than requiring/validating it.
    **Never call `vm/terminate` or `vm/reset` without an explicit,
    confirmed `machine_id` bound to a real raw active-machine lookup** --
    every call site in this file now does this. (Recovered same-session by
    immediately re-spawning via `vm/spawn`; no lasting harm, but this is a
    real footgun worth flagging for anyone else probing this API by hand.)
  - The bare `connections` endpoint (used internally by pyhackthebox's
    `get_current_vpn_server(release_arena=False)` AND `Machine.is_release`)
    is ALSO now 404, independent of the release-arena-specific gap above --
    this breaks even the plain default "labs" product's "current server"
    lookup. `connections/servers?product=<name>` (which
    `get_all_vpn_servers()` already used correctly) is the working
    replacement and has an `assigned` key with the same data.
    `get_vpn_server_info()` below wraps this directly. Confirmed working
    product values: `labs` (regular + free machines), `release_arena`,
    `starting_point` (note: this is NOT the same string as the `lab_server`
    field on a machine/instance, which uses `sp_lab`/`ra_lab`/`free_lab`/
    `labs` -- see `LAB_SERVER_TO_PRODUCT` below for the mapping between the
    two).
  - Net effect: `status`/`spawn`/`stop`/`reset` no longer need the
    `--release-arena` flag at all (they detect the active machine's real
    type via v5 and act generically) -- the flag is kept only for the
    VPN-server-listing commands (`vpn-servers`/`vpn-current`/`vpn-switch`/
    `vpn-download`), which still need to know which product's server list
    to show when nothing is active yet to introspect.
"""
import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import requests
from hackthebox import (
    CannotSwitchWithActive,
    HtbException,
    IncorrectFlagException,
    NotFoundException,
    RootAlreadySubmitted,
    UserAlreadySubmitted,
)
from hackthebox import HTBClient

VAULT_ROOT = Path(__file__).resolve().parent.parent
CONNECTION_FILE = VAULT_ROOT / "Lab Environment" / "htb-active-connection.json"


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}), file=sys.stderr)
    sys.exit(1)


def emit(payload):
    print(json.dumps(payload, indent=2, default=str))


# pyhackthebox's built-in default (www.hackthebox.com) 404s on every
# endpoint as of 2026-07 -- the real API lives here. Override explicitly
# rather than relying on the library's stale default.
API_BASE = "https://labs.hackthebox.com/api/v4/"
# Newer unified active-instance endpoint lives under a separate v5 base --
# see "RESOLVED (2026-08-09)" in the module docstring. pyhackthebox has no
# support for this at all, so it's queried with a plain `requests` call.
API_BASE_V5 = "https://labs.hackthebox.com/api/v5/"

# Maps a machine/instance's `lab_server` field (as returned by
# machine/active, virtual_machine/active, etc.) to the `product` query
# param `connections/servers?product=<x>` expects -- these are NOT the same
# string. Unknown/unseen lab_server values fall back to "labs".
LAB_SERVER_TO_PRODUCT = {
    "ra_lab": "release_arena",
    "sp_lab": "starting_point",
    "free_lab": "labs",
    "labs": "labs",
}


def get_token():
    token = os.environ.get("HTB_API_TOKEN")
    if not token:
        fail(
            "HTB_API_TOKEN is not set. Generate an App Token at "
            "https://app.hackthebox.com/profile/settings and export it "
            "(e.g. in ~/.zshrc: export HTB_API_TOKEN=\"...\"), then open a "
            "new shell."
        )
    return token


def get_client():
    return HTBClient(app_token=get_token(), api_base=API_BASE)


def tun_interfaces():
    """Best-effort check for an already-up tun interface (VPN tunnel)."""
    try:
        out = subprocess.run(
            ["ip", "-j", "addr"], capture_output=True, text=True, timeout=5
        )
        ifaces = json.loads(out.stdout)
        return [i["ifname"] for i in ifaces if i.get("ifname", "").startswith("tun")]
    except Exception:
        return []


def write_connection_snapshot(data):
    CONNECTION_FILE.parent.mkdir(parents=True, exist_ok=True)
    CONNECTION_FILE.write_text(json.dumps(data, indent=2, default=str))


def get_active_machine_v5(token):
    """Query the v5 unified active-machine endpoint -- see "RESOLVED
    (2026-08-09)" in the module docstring. Works uniformly across every
    VPN product (labs, free_lab, starting_point/sp_lab, release_arena/
    ra_lab). Returns the raw `info` dict (id/name/ip/lab_server/
    vpn_server_id/isSpawning/expires_at/...) or None if nothing is active
    (the real "nothing active" response is HTTP 200 with `{"info": null}`,
    not a 404).

    Gotcha found 2026-08-09: `requests`' default User-Agent
    (`python-requests/x.x`) gets a flat WAF-level 404 (nginx's own error
    page, not HTB's) on this v5 host -- an explicit User-Agent of ANY value
    (tested pyhackthebox's own "htb-api/0.5.2", curl's UA, and a generic
    browser UA) is accepted fine. Must set one explicitly here; the v4 base
    doesn't have this problem because pyhackthebox's do_request() already
    always sets USER_AGENT.
    """
    try:
        r = requests.get(
            API_BASE_V5 + "virtual_machine/active",
            headers={"Authorization": f"Bearer {token}", "User-Agent": "htb-api/0.5.2"},
            timeout=15,
        )
    except requests.RequestException as e:
        raise HtbException(f"v5 active-machine check failed: {e}")
    if r.status_code == 404:
        # A real 404 here (as opposed to the WAF/User-Agent gotcha above,
        # which is now avoided) would mean the endpoint itself moved again
        # -- surface that distinctly rather than silently treating it as
        # "nothing active" and masking a future API change.
        raise HtbException(
            "v5 active-machine check 404'd even with an explicit User-Agent "
            "set -- the endpoint may have moved again, don't trust this as "
            "'nothing active'."
        )
    try:
        data = r.json()
    except ValueError:
        raise HtbException(
            f"v5 active-machine check returned non-JSON (HTTP {r.status_code})"
        )
    return data.get("info") or None


def poll_for_active_machine(token, machine_id, attempts=10, delay=5):
    """After a spawn call reports success, the instance can take a few
    seconds to actually appear via the v5 active-machine check (and often
    another 30-60s beyond that to finish booting far enough to answer
    ICMP/TCP -- verifying that is the CLI caller's job, not this
    function's). Poll briefly for it to appear at all before giving up."""
    for _ in range(attempts):
        raw = get_active_machine_v5(token)
        if raw is not None and str(raw.get("id")) == str(machine_id):
            return raw
        time.sleep(delay)
    return None


def get_vpn_server_info(client, product):
    """Raw replacement for HTBClient.get_current_vpn_server(): its
    release_arena=False branch calls the bare `connections` endpoint, which
    404s against the real API as of 2026-08 (independent of the
    non-"labs"-product KNOWN GAP -- this breaks even the plain default
    "labs" product). `connections/servers?product=<x>` (which
    get_all_vpn_servers() already uses correctly) has an `assigned` key
    with the same data and is confirmed working for "labs", "release_arena",
    and "starting_point". Returns the raw `assigned` dict (id/friendly_name/
    location/...) or None."""
    try:
        data = client.do_request(f"connections/servers?product={product}")["data"]
    except (NotFoundException, KeyError):
        return None
    return data.get("assigned")


def get_current_vpn_server_obj(client, release_arena):
    """Returns a proper pyhackthebox VPNServer object (needed for
    .download()/.switch()) for whichever product is currently assigned.
    release_arena=True still works via pyhackthebox's own
    get_current_vpn_server() (connections/servers?product=release_arena is
    a live endpoint). release_arena=False is worked around: look up the
    assigned server id via get_vpn_server_info() (which doesn't hit the
    broken bare `connections` endpoint) and match it against
    get_all_vpn_servers(), which already uses the working
    connections/servers?product=labs endpoint internally."""
    if release_arena:
        try:
            return client.get_current_vpn_server(release_arena=True)
        except NotFoundException:
            return None
    assigned = get_vpn_server_info(client, "labs")
    if assigned is None:
        return None
    for s in client.get_all_vpn_servers(release_arena=False):
        if s.id == assigned.get("id"):
            return s
    return None


def cmd_status(args):
    client = get_client()
    token = get_token()
    result = {"tun_interfaces": tun_interfaces()}
    result["vpn_tunnel_up"] = bool(result["tun_interfaces"])

    raw = get_active_machine_v5(token)
    if raw is not None:
        result["active_machine"] = {
            "name": raw.get("name"),
            "id": raw.get("id"),
            "ip": raw.get("ip"),
            "type": raw.get("type"),
            "lab_server": raw.get("lab_server"),
            "vpn_server_id": raw.get("vpn_server_id"),
            "is_spawning": raw.get("isSpawning"),
            "expires_at": raw.get("expires_at"),
        }
        write_connection_snapshot({"target": raw.get("name"), **result["active_machine"]})
        product = LAB_SERVER_TO_PRODUCT.get(raw.get("lab_server"), "labs")
    else:
        result["active_machine"] = None
        # Nothing active to introspect -- fall back to the CLI flag as a
        # hint for which product's assigned server to report.
        product = "release_arena" if args.release_arena else "labs"

    server = get_vpn_server_info(client, product)
    result["vpn_server_assigned"] = server.get("friendly_name") if server else None

    emit(result)


def cmd_spawn(args):
    client = get_client()
    token = get_token()
    try:
        machine = client.get_machine(args.target)
    except NotFoundException:
        fail(f"No machine found matching '{args.target}'")

    # Unified spawn endpoint -- see "RESOLVED (2026-08-09)" in the module
    # docstring. No release_arena branching needed: the server infers the
    # right pool from machine_id alone.
    try:
        resp = client.do_request("vm/spawn", json_data={"machine_id": machine.id})
    except NotFoundException:
        fail("Spawn failed: vm/spawn endpoint not found (HTB API may have changed again).")
    except HtbException as e:
        fail(f"Spawn failed: {e}")

    if resp.get("success") not in (True, 1, "1"):
        fail(f"Spawn failed: {resp.get('message', resp)}", spawn_response=resp)

    raw = poll_for_active_machine(token, machine.id)
    if raw is None:
        fail(
            "Spawn call reported success but the machine never showed up "
            "as active via the v5 status check after polling -- verify "
            "manually (`status`) before retrying, since retrying a "
            "genuinely-succeeded spawn will hit either the 'already have "
            "an active instance' guard or the ~60s between-machine-actions "
            "cooldown.",
            spawn_response=resp,
        )

    result = {
        "name": machine.name,
        "id": machine.id,
        "ip": raw.get("ip"),
        "lab_server": raw.get("lab_server"),
        "vpn_server_id": raw.get("vpn_server_id"),
        "expires_at": raw.get("expires_at"),
    }
    write_connection_snapshot({"target": machine.name, **result})
    emit(result)


def cmd_stop(args):
    client = get_client()
    token = get_token()
    raw = get_active_machine_v5(token)
    if raw is None:
        fail("No active machine to stop.")
    # ALWAYS pass machine_id explicitly -- confirmed 2026-08-09 that an
    # empty-bodied POST to vm/terminate still terminates the caller's
    # current active instance rather than erroring. See docstring hazard
    # note.
    client.do_request("vm/terminate", json_data={"machine_id": raw["id"]})
    emit({"stopped": raw.get("name"), "id": raw.get("id")})


def cmd_reset(args):
    client = get_client()
    token = get_token()
    raw = get_active_machine_v5(token)
    if raw is None:
        fail("No active machine to reset.")
    try:
        client.do_request("vm/reset", json_data={"machine_id": raw["id"]})
    except HtbException as e:
        fail(f"Reset failed: {e}")
    emit({"reset_requested": raw.get("name"), "id": raw.get("id")})


def cmd_vpn_servers(args):
    client = get_client()
    servers = client.get_all_vpn_servers(release_arena=args.release_arena)
    emit(
        [
            {
                "id": s.id,
                "friendly_name": s.friendly_name,
                "location": s.location,
                "current_clients": s.current_clients,
            }
            for s in servers
        ]
    )


def cmd_vpn_current(args):
    client = get_client()
    product = "release_arena" if args.release_arena else "labs"
    server = get_vpn_server_info(client, product)
    if server is None:
        emit({"current": None})
    else:
        emit(
            {
                "id": server.get("id"),
                "friendly_name": server.get("friendly_name"),
                "location": server.get("location"),
            }
        )


def cmd_vpn_switch(args):
    client = get_client()
    servers = client.get_all_vpn_servers(release_arena=args.release_arena)
    match = next(
        (s for s in servers if str(s.id) == args.server or s.friendly_name == args.server),
        None,
    )
    if match is None:
        fail(
            f"No VPN server matching '{args.server}'",
            available=[s.friendly_name for s in servers],
        )
    try:
        ok = match.switch()
    except CannotSwitchWithActive:
        fail("Cannot switch VPN server while a machine is active -- stop it first.")
    emit({"switched_to": match.friendly_name, "success": ok})


def cmd_vpn_download(args):
    client = get_client()
    server = get_current_vpn_server_obj(client, args.release_arena)
    if server is None:
        fail("No VPN server currently assigned -- spawn a machine or switch servers first.")
    dest_dir = VAULT_ROOT / "Lab Environment" / "vpn"
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / f"{server.friendly_name.replace(' ', '_')}.ovpn"
    path = server.download(path=str(dest), tcp=args.tcp)
    emit(
        {
            "downloaded": path,
            "server": server.friendly_name,
            "start_command": f"sudo openvpn --config '{path}'",
        }
    )


def cmd_submit(args):
    # KNOWN GAP (2026-07-18): pyhackthebox's Machine.submit() posts to
    # "machine/own", which 404s ("route ... could not be found") against the
    # real v4 API when authenticated via an App Token, not a session cookie.
    # This is NOT the same class of bug as the machine/list or
    # get_active_machine gaps documented above (those are stale endpoints
    # with a working replacement) -- probing found no working App-Token
    # equivalent at all: "machine/submit" exists but is the "submit a new
    # box for review" endpoint (expects download_link/writeup_link/
    # hypervisor/accept_terms, nothing about an existing machine's flag),
    # and no other plausible route name (machine/flag, machine/{id}/own,
    # flag/own, flags, machine/submitflag, etc.) resolves. GET
    # machine/activity/own *is* reachable via App Token (returns "Machine
    # not found" without a valid id param), which rules out a blanket
    # read-only token restriction -- so the leading theory is that flag
    # submission specifically is deliberately excluded from the App Token
    # scope (an anti-automation measure on HTB's part, not a bug to work
    # around), but this isn't confirmed against HTB's own docs. Bottom
    # line: this subcommand does not currently work. Flags still need to be
    # submitted manually via the website until/unless a working endpoint is
    # found.
    client = get_client()
    try:
        machine = client.get_machine(args.target)
    except NotFoundException:
        fail(f"No machine found matching '{args.target}'")
    try:
        message = machine.submit(args.flag, args.difficulty)
    except IncorrectFlagException:
        fail("Incorrect flag.")
    except (UserAlreadySubmitted, RootAlreadySubmitted) as e:
        fail(str(e) or "Flag already submitted.")
    except HtbException as e:
        fail(f"Submit failed: {e}")
    emit({"result": message})


def _fetch_paginated_machines(token, endpoint, retired):
    """Page through one of the two live v4 listing endpoints and return raw
    machine dicts, tagged with `retired`.

    KNOWN GAP (2026-09-03): pyhackthebox's own `Client.get_machines()` posts
    to `machine/list` / `machine/list/retired`, which both 404 against the
    real API now -- same class of staleness as the other v4 workarounds in
    this file. Live-probed replacements (confirmed working against a real
    App Token, same session that found these):
      - active machines:  `machine/paginated` (only ever returns the
        current ~20-box rotating "active" pool -- its own `retired` query
        param is accepted but has no effect, always serves the active pool
        regardless of the value passed).
      - retired machines: `machine/list/retired/paginated` (529 machines
        across 6 pages at the API's max `per_page=100`, 500s above that).
    Both accept `sort_by=release-date`/`sort_type=asc|desc`, but that
    server-side sort is NOT trustworthy -- one item ("Cap") consistently
    sorted first regardless of direction, out of chronological order, in
    live testing. Don't rely on it: fetch every page and sort client-side
    on the `release` field instead (plain ISO-8601 strings, so a lexical
    sort is already a chronological sort -- no date parsing needed).
    """
    headers = {"Authorization": f"Bearer {token}", "User-Agent": "htb-api/0.5.2"}
    machines = []
    page = 1
    while True:
        r = requests.get(
            API_BASE + endpoint,
            headers=headers,
            params={"per_page": 100, "page": page},
            timeout=15,
        )
        if r.status_code != 200:
            fail(f"{endpoint} page {page} returned HTTP {r.status_code}: {r.text[:200]}")
        data = r.json()
        items = data.get("data", [])
        if not items:
            break
        for m in items:
            m["retired"] = retired
        machines.extend(items)
        if page >= (data.get("meta", {}) or {}).get("last_page", page):
            break
        page += 1
    return machines


def cmd_list_machines(args):
    token = get_token()
    machines = []
    if args.status in ("all", "active"):
        machines.extend(_fetch_paginated_machines(token, "machine/paginated", retired=False))
    if args.status in ("all", "retired"):
        machines.extend(
            _fetch_paginated_machines(token, "machine/list/retired/paginated", retired=True)
        )

    if args.owned == "unowned":
        machines = [m for m in machines if not m.get("authUserInRootOwns")]
    elif args.owned == "owned":
        machines = [m for m in machines if m.get("authUserInRootOwns")]

    machines.sort(key=lambda m: m["release"], reverse=not args.asc)
    if args.limit:
        machines = machines[: args.limit]

    emit(
        [
            {
                "id": m["id"],
                "name": m["name"],
                "os": m.get("os"),
                "difficulty": m.get("difficultyText"),
                "points": m.get("points"),
                "release_date": m["release"],
                "retired": m["retired"],
                "user_owned": bool(m.get("authUserInUserOwns")),
                "root_owned": bool(m.get("authUserInRootOwns")),
                "free": m.get("free"),
            }
            for m in machines
        ]
    )


# KNOWN GAP (2026-07-19): no working endpoint found yet for a machine's
# official synopsis/description text (the scenario blurb HTB shows on a
# machine's info page, distinct from the box's own hosted content). The
# pyhackthebox `Machine` object doesn't expose it (only `authors`, `ip`,
# `is_release`, `spawn`, `start`, `submit`), and quick raw-API guesses
# against a real App Token all 404'd: `machine/profile/<id>`,
# `machine/info/<id>`, `machine/<id>`, `machine/get/<id>`. Not deep-dived
# yet (didn't want to burn time on this mid-engagement) -- possibly the
# same class of App-Token-scope restriction as the `cmd_submit` gap above,
# or just the wrong endpoint name. If this matters later: check HTB's own
# API docs (if published) or capture the real request the web UI makes via
# browser devtools while logged in, rather than continuing to guess paths.
# Until then, synopsis/description text has to come from the user manually
# (either the HTB platform's info page, or the box's own hosted content --
# both are worth checking, they're not always the same text).


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    def add_release_flag(p):
        p.add_argument(
            "--release-arena",
            action="store_true",
            help="Operate on Release Arena instead of standard/retired machines",
        )

    p = sub.add_parser("status", help="Show active machine + VPN tunnel/server state")
    add_release_flag(p)
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("spawn", help="Spawn a machine by name or id")
    p.add_argument("target")
    add_release_flag(p)
    p.set_defaults(func=cmd_spawn)

    p = sub.add_parser("stop", help="Stop the active machine instance")
    add_release_flag(p)
    p.set_defaults(func=cmd_stop)

    p = sub.add_parser("reset", help="Reset the active machine instance")
    add_release_flag(p)
    p.set_defaults(func=cmd_reset)

    p = sub.add_parser("vpn-servers", help="List available VPN servers")
    add_release_flag(p)
    p.set_defaults(func=cmd_vpn_servers)

    p = sub.add_parser("vpn-current", help="Show currently assigned VPN server")
    add_release_flag(p)
    p.set_defaults(func=cmd_vpn_current)

    p = sub.add_parser("vpn-switch", help="Switch VPN server (fails if a machine is active)")
    p.add_argument("server", help="Server id or friendly_name")
    add_release_flag(p)
    p.set_defaults(func=cmd_vpn_switch)

    p = sub.add_parser("vpn-download", help="Download the current server's .ovpn config")
    p.add_argument("--tcp", action="store_true")
    add_release_flag(p)
    p.set_defaults(func=cmd_vpn_download)

    p = sub.add_parser(
        "list-machines",
        help="List machines sorted by release date (newest first by default)",
    )
    p.add_argument(
        "--status",
        choices=["all", "active", "retired"],
        default="all",
        help="Which machine pool to list (default: all)",
    )
    p.add_argument(
        "--owned",
        choices=["all", "unowned", "owned"],
        default="all",
        help="Filter by whether you've already rooted the machine (default: all)",
    )
    p.add_argument(
        "--asc",
        action="store_true",
        help="Sort oldest-first instead of the default newest-first",
    )
    p.add_argument("--limit", type=int, default=None, help="Cap the number of results after sorting")
    p.set_defaults(func=cmd_list_machines)

    p = sub.add_parser("submit", help="Submit a user/root flag for a machine")
    p.add_argument("target")
    p.add_argument("flag")
    p.add_argument("difficulty", type=int, help="10-100, multiple of 10")
    p.set_defaults(func=cmd_submit)

    return parser


def main():
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
