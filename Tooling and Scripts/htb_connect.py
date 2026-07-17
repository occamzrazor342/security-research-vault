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

KNOWN GAP -- non-"labs" VPN products: pyhackthebox's get_active_machine()
calls get_current_vpn_server() internally to build the MachineInstance,
which only queries the default paid "labs" product's `connections`
response (`data['lab']['assigned_server']`); for any other product
(free_lab, sp_lab, ...) that lookup 404s/KeyErrors, and
get_active_machine_or_none() below normalizes that into "nothing
active" -- wrong whenever the real session lives on one of those other
products. Confirmed on TWO separate products so far:
  - "sp_lab" (Starting Point) -- 2026-07-16, spawning "Meow" (id 394)
    worked server-side and showed up via a raw `machine/active` call,
    while `status` reported null throughout.
  - "free_lab" (free-tier regular machines) -- 2026-07-16, "kobold"
    (id 856) was already active on this product from prior manual work;
    `status` showed null and `spawn kobold` failed with "You already
    have an active instance" -- a real, in-scope target got misreported
    as spawnable when it was already up and reachable. The same gap
    also broke `stop`/`reset` (both built on
    get_active_machine_or_none()) -- 2026-07-17, `stop` refused with
    "No active machine to stop" while kobold was genuinely still up.
`status`/`stop`/`reset` now self-heal via get_active_machine_raw() below:
when the pyhackthebox object lookup comes back empty, they fall back to
the same raw `machine/active` call (which doesn't go through
get_current_vpn_server() and so isn't affected) and act on that instead
of trusting a bare "nothing active". `spawn`'s "already have an active
instance" error is a correct-but-confusing signal once you know this --
it means status/stop's fallback should be checked before assuming a
target really is free to spawn. Not fixed at the root: a proper fix
means pyhackthebox querying every VPN product rather than just the
default, which it doesn't support out of the box.
"""
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

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


def get_active_machine_or_none(client, release_arena):
    """get_active_machine raises NotFoundException (a 404 from machine/active)
    when nothing is spawned, rather than returning None -- normalize that."""
    try:
        return client.get_active_machine(release_arena=release_arena)
    except NotFoundException:
        return None


def get_active_machine_raw(client, release_arena):
    """Fallback for when get_active_machine_or_none() wrongly says "nothing
    active" (see KNOWN GAP above): hits `machine/active`/`release_arena/active`
    directly, without the get_current_vpn_server() call that 404s/KeyErrors
    for non-"labs" VPN products. Returns the raw `info` dict (id/name/ip/
    lab_server/vpn_server_id/expires_at) or None if truly nothing is active."""
    endpoint = "release_arena/active" if release_arena else "machine/active"
    try:
        resp = client.do_request(endpoint)
    except NotFoundException:
        return None
    return resp.get("info") or None


def cmd_status(args):
    client = get_client()
    result = {"tun_interfaces": tun_interfaces()}
    result["vpn_tunnel_up"] = bool(result["tun_interfaces"])

    try:
        instance = get_active_machine_or_none(client, args.release_arena)
    except HtbException as e:
        fail(f"Failed to query active machine: {e}")

    if instance is not None:
        result["active_machine"] = {
            "name": instance.machine.name,
            "id": instance.machine.id,
            "ip": instance.ip,
            "vpn_server": instance.server.friendly_name,
        }
        write_connection_snapshot({"target": instance.machine.name, **result["active_machine"]})
    else:
        raw = get_active_machine_raw(client, args.release_arena)
        if raw is None:
            result["active_machine"] = None
        else:
            result["active_machine"] = {
                "name": raw.get("name"),
                "id": raw.get("id"),
                "ip": raw.get("ip"),
                "vpn_server": None,
                "lab_server": raw.get("lab_server"),
                "note": "recovered via raw machine/active fallback -- see KNOWN GAP",
            }
            write_connection_snapshot({"target": raw.get("name"), **result["active_machine"]})

    try:
        server = client.get_current_vpn_server(release_arena=args.release_arena)
        result["vpn_server_assigned"] = server.friendly_name if server else None
    except HtbException:
        result["vpn_server_assigned"] = None

    emit(result)


def cmd_spawn(args):
    client = get_client()
    try:
        machine = client.get_machine(args.target)
    except NotFoundException:
        fail(f"No machine found matching '{args.target}'")

    try:
        instance = machine.spawn(release_arena=args.release_arena)
    except HtbException as e:
        fail(f"Spawn failed: {e}")

    result = {
        "name": machine.name,
        "id": machine.id,
        "ip": instance.ip,
        "vpn_server": instance.server.friendly_name,
    }
    write_connection_snapshot({"target": machine.name, **result})
    emit(result)


def cmd_stop(args):
    client = get_client()
    instance = get_active_machine_or_none(client, args.release_arena)
    if instance is not None:
        instance.stop()
        emit({"stopped": instance.machine.name})
        return

    raw = get_active_machine_raw(client, args.release_arena)
    if raw is None:
        fail("No active machine to stop.")
    if args.release_arena:
        client.do_request("release_arena/terminate", post=True)
    else:
        client.do_request("vm/terminate", json_data={"machine_id": raw["id"]})
    emit({"stopped": raw.get("name"), "note": "stopped via raw machine/active fallback -- see KNOWN GAP"})


def cmd_reset(args):
    client = get_client()
    instance = get_active_machine_or_none(client, args.release_arena)
    if instance is not None:
        try:
            instance.reset()
        except HtbException as e:
            fail(f"Reset failed: {e}")
        emit({"reset_requested": instance.machine.name})
        return

    raw = get_active_machine_raw(client, args.release_arena)
    if raw is None:
        fail("No active machine to reset.")
    try:
        if args.release_arena:
            client.do_request("release_arena/reset", json_data={"machine_id": raw["id"]})
        else:
            client.do_request("vm/reset", json_data={"machine_id": raw["id"]})
    except HtbException as e:
        fail(f"Reset failed: {e}")
    emit({"reset_requested": raw.get("name"), "note": "reset via raw machine/active fallback -- see KNOWN GAP"})


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
    try:
        server = client.get_current_vpn_server(release_arena=args.release_arena)
    except NotFoundException:
        server = None
    if server is None:
        emit({"current": None})
    else:
        emit({"id": server.id, "friendly_name": server.friendly_name, "location": server.location})


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
    try:
        server = client.get_current_vpn_server(release_arena=args.release_arena)
    except NotFoundException:
        server = None
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
