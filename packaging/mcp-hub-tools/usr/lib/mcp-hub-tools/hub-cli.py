#!/usr/bin/env python3
"""
hub-cli.py — local secrets/config management for the Linux hub server.

Per coordination/BROADCAST.md [0007]/[0012]: a CLI for managing PCS
registry entries (i.e. which PCs are configured), tunnel config, and the
Render-hosted service's own secrets (MCP_SERVER_PASSWORD, ADMIN_PASSWORD,
etc.) -- the local-terminal, scriptable equivalent of server.py's /admin
web dashboard, not a replacement for it (both talk to the same Render
API the same way, for the parts they overlap on).

Subcommands
-----------
  hub-cli pc list                        List configured PCs
  hub-cli pc add <name> <ip> [--port N]  Add a PC: writes /etc/pc-tunnel/<name>.conf,
                                          enables + starts pc-tunnel@<name>.service
  hub-cli pc remove <name>               Stop + disable the service, remove the conf file
  hub-cli pc pin <name>                  ssh-keyscan the PC and pin its host key to
                                          known_hosts.d/<name> -- automates the manual
                                          "setup step 4" from pc-tunnel@.service's own
                                          header comment
  hub-cli diagnostics [--json]           Runs hub-diagnostics.py's checks (imported
                                          directly, not shelled out to, so this stays
                                          one dependency-free script calling another)

  hub-cli render get <KEY>               Read one env var from the Render service
  hub-cli render set <KEY> <VALUE>       Set one env var (does NOT auto-redeploy --
                                          same "you still have to click deploy"
                                          behavior as /admin, for the same reason:
                                          a bad value shouldn't auto-propagate)
  hub-cli render deploy                  Trigger a redeploy

  hub-cli config show                    Show this CLI's own local config (paths,
                                          whether Render credentials are set -- never
                                          prints the actual secret values)
  hub-cli config set-render-credentials --api-key KEY --service-id ID
                                          Store Render API credentials locally
                                          (0600-permissioned file) so the `render`
                                          subcommands have something to authenticate
                                          with, without needing them passed as CLI
                                          args (and ending up in shell history) every time

All destructive/systemd-touching operations (pc add/remove/pin) require
root (checked explicitly, not left to fail opaquely partway through).
`pc list`, `diagnostics`, `config show`, and the read-only `render get`
do not.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

PC_TUNNEL_CONF_DIR = Path(os.environ.get("HUB_CLI_PC_TUNNEL_DIR", "/etc/pc-tunnel"))
KNOWN_HOSTS_DIR = PC_TUNNEL_CONF_DIR / "known_hosts.d"
CLI_CONFIG_PATH = Path(os.environ.get("HUB_CLI_CONFIG_PATH", "/etc/hub-cli/config.json"))
RENDER_API = os.environ.get("HUB_CLI_RENDER_API", "https://api.render.com/v1")  # overridable for tests
DEFAULT_TUNNEL_USER = "sepisotoni"


def _run(cmd, **kwargs):
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)


def _require_root():
    # Test-only bypass (never set this in real usage) -- GitHub Actions
    # runners are non-root by default, so without this, every test that
    # exercises pc add/remove/pin or config set-render-credentials would
    # pass in this sandbox (root) and then fail the moment CI actually
    # ran them on a real runner. Confirmed this distinction matters by
    # testing in a sandbox that happens to run as root -- worth being
    # explicit about, since it's exactly the kind of environment
    # difference that silently breaks CI on the very first real run.
    if os.environ.get("HUB_CLI_SKIP_ROOT_CHECK") == "1":
        return
    if os.geteuid() != 0:
        print("error: this command needs root (systemd unit + /etc file changes) -- try sudo", file=sys.stderr)
        sys.exit(1)


def _load_cli_config() -> dict:
    if CLI_CONFIG_PATH.exists():
        try:
            return json.loads(CLI_CONFIG_PATH.read_text())
        except (OSError, json.JSONDecodeError):
            return {}
    return {}


def _save_cli_config(data: dict) -> None:
    CLI_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CLI_CONFIG_PATH.write_text(json.dumps(data, indent=2))
    os.chmod(CLI_CONFIG_PATH, 0o600)  # contains RENDER_API_KEY -- must not be world-readable


# ---------------------------------------------------------------------------
# pc subcommands
# ---------------------------------------------------------------------------

def cmd_pc_list(args):
    if not PC_TUNNEL_CONF_DIR.is_dir():
        print("No PCs configured yet (run: hub-cli pc add <name> <ip>)")
        return 0
    confs = sorted(PC_TUNNEL_CONF_DIR.glob("*.conf"))
    if not confs:
        print("No PCs configured yet (run: hub-cli pc add <name> <ip>)")
        return 0
    for conf in confs:
        name = conf.stem
        pc_ip, port = "?", "?"
        for line in conf.read_text().splitlines():
            if line.startswith("PC_IP="):
                pc_ip = line.split("=", 1)[1].strip()
            elif line.startswith("PORT="):
                port = line.split("=", 1)[1].strip()
        pinned = (KNOWN_HOSTS_DIR / name).exists()
        active = "?"
        if shutil.which("systemctl"):
            r = _run(["systemctl", "is-active", f"pc-tunnel@{name}.service"])
            active = (r.stdout or "").strip() or "unknown"
        print(f"{name:<15} {pc_ip:<16} port={port:<6} pinned={'yes' if pinned else 'NO':<4} service={active}")
    return 0


def cmd_pc_add(args):
    _require_root()
    PC_TUNNEL_CONF_DIR.mkdir(parents=True, exist_ok=True)
    conf_path = PC_TUNNEL_CONF_DIR / f"{args.name}.conf"
    if conf_path.exists() and not args.force:
        print(f"error: {conf_path} already exists (use --force to overwrite)", file=sys.stderr)
        return 1
    conf_path.write_text(f"PC_IP={args.ip}\nPORT={args.port}\n")
    print(f"Wrote {conf_path}")

    if not shutil.which("systemctl"):
        print("systemctl not available -- conf file written, but couldn't enable/start the tunnel service here")
        return 0

    r = _run(["systemctl", "daemon-reload"])
    if r.returncode != 0:
        print(f"warning: systemctl daemon-reload failed: {r.stderr.strip()}", file=sys.stderr)
    r = _run(["systemctl", "enable", "--now", f"pc-tunnel@{args.name}"])
    if r.returncode != 0:
        print(f"warning: could not enable/start pc-tunnel@{args.name}: {r.stderr.strip()}", file=sys.stderr)
        print("(conf file is in place -- fix SSH access / retry `systemctl start` once it works)", file=sys.stderr)
        return 1
    print(f"pc-tunnel@{args.name} enabled and started")
    if not (KNOWN_HOSTS_DIR / args.name).exists():
        print(f"NOTE: host key not pinned yet -- run: hub-cli pc pin {args.name}")
    return 0


def cmd_pc_remove(args):
    _require_root()
    conf_path = PC_TUNNEL_CONF_DIR / f"{args.name}.conf"
    if not conf_path.exists():
        print(f"error: no such PC configured: {args.name}", file=sys.stderr)
        return 1
    if shutil.which("systemctl"):
        _run(["systemctl", "disable", "--now", f"pc-tunnel@{args.name}"])
    conf_path.unlink()
    pinned = KNOWN_HOSTS_DIR / args.name
    if pinned.exists():
        pinned.unlink()
    print(f"Removed {args.name} (service stopped+disabled, conf + pinned host key deleted)")
    return 0


def cmd_pc_pin(args):
    _require_root()
    conf_path = PC_TUNNEL_CONF_DIR / f"{args.name}.conf"
    if not conf_path.exists():
        print(f"error: no such PC configured: {args.name} (run: hub-cli pc add first)", file=sys.stderr)
        return 1
    pc_ip = None
    for line in conf_path.read_text().splitlines():
        if line.startswith("PC_IP="):
            pc_ip = line.split("=", 1)[1].strip()
    if not pc_ip:
        print(f"error: {conf_path} has no PC_IP set", file=sys.stderr)
        return 1
    if not shutil.which("ssh-keyscan"):
        print("error: ssh-keyscan not found (part of openssh-client)", file=sys.stderr)
        return 1

    r = _run(["ssh-keyscan", "-t", "ed25519", pc_ip])
    if r.returncode != 0 or not r.stdout.strip():
        print(f"error: ssh-keyscan against {pc_ip} produced no key: {r.stderr.strip()}", file=sys.stderr)
        return 1

    KNOWN_HOSTS_DIR.mkdir(parents=True, exist_ok=True)
    pinned_file = KNOWN_HOSTS_DIR / args.name
    pinned_file.write_text(r.stdout)
    print(f"Pinned host key for {args.name} ({pc_ip}) -> {pinned_file}")
    print("Restart the tunnel to pick this up: systemctl restart pc-tunnel@" + args.name)
    return 0


# ---------------------------------------------------------------------------
# diagnostics subcommand -- delegates to hub-diagnostics.py
# ---------------------------------------------------------------------------

def cmd_diagnostics(args):
    script = Path(__file__).parent / "hub-diagnostics.py"
    if not script.exists():
        # Installed via the .deb, hub-diagnostics.py lands next to this
        # script either way (same package, same install dir) -- this
        # fallback only matters when running from a source checkout
        # where the layout might differ slightly.
        script = Path("/usr/lib/hub-cicd/hub-diagnostics.py")
    if not script.exists():
        print(f"error: could not find hub-diagnostics.py (looked next to this script and at {script})", file=sys.stderr)
        return 1
    cmd = [sys.executable, str(script)]
    if args.json:
        cmd.append("--json")
    return subprocess.call(cmd)


# ---------------------------------------------------------------------------
# render subcommands
# ---------------------------------------------------------------------------

def _render_credentials():
    cfg = _load_cli_config()
    api_key = os.environ.get("RENDER_API_KEY", "") or cfg.get("render_api_key", "")
    service_id = os.environ.get("RENDER_SERVICE_ID", "") or cfg.get("render_service_id", "")
    return api_key, service_id


def _render_request(method: str, path: str, api_key: str, body: dict = None):
    """Minimal stdlib-only HTTP client (no httpx dependency needed just
    for this CLI) -- same base URL, same Bearer auth header, same
    endpoint shape as server.py's _render_headers()/RENDER_API so this
    CLI and the /admin dashboard are interchangeable, not two competing
    implementations of the same API contract."""
    url = f"{RENDER_API}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": f"Bearer {api_key}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    })
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode())


def cmd_render_get(args):
    api_key, service_id = _render_credentials()
    if not (api_key and service_id):
        print("error: Render credentials not configured -- run: hub-cli config set-render-credentials --api-key ... --service-id ...", file=sys.stderr)
        return 1
    try:
        items = _render_request("GET", f"/services/{service_id}/env-vars", api_key)
    except (urllib.error.HTTPError, urllib.error.URLError) as e:
        print(f"error: Render API request failed: {e}", file=sys.stderr)
        return 1
    for item in items:
        if item["envVar"]["key"] == args.key:
            print(item["envVar"]["value"])
            return 0
    print(f"error: no such env var: {args.key}", file=sys.stderr)
    return 1


def cmd_render_set(args):
    api_key, service_id = _render_credentials()
    if not (api_key and service_id):
        print("error: Render credentials not configured -- run: hub-cli config set-render-credentials --api-key ... --service-id ...", file=sys.stderr)
        return 1
    try:
        _render_request("PUT", f"/services/{service_id}/env-vars/{args.key}", api_key, {"value": args.value})
    except (urllib.error.HTTPError, urllib.error.URLError) as e:
        print(f"error: Render API request failed: {e}", file=sys.stderr)
        return 1
    print(f"Set {args.key}. Run `hub-cli render deploy` for it to take effect.")
    return 0


def cmd_render_deploy(args):
    api_key, service_id = _render_credentials()
    if not (api_key and service_id):
        print("error: Render credentials not configured", file=sys.stderr)
        return 1
    try:
        _render_request("POST", f"/services/{service_id}/deploys", api_key, {"clearCache": "do_not_clear"})
    except (urllib.error.HTTPError, urllib.error.URLError) as e:
        print(f"error: Render API request failed: {e}", file=sys.stderr)
        return 1
    print("Deploy triggered.")
    return 0


# ---------------------------------------------------------------------------
# config subcommands
# ---------------------------------------------------------------------------

def cmd_config_show(args):
    cfg = _load_cli_config()
    print(f"Config file: {CLI_CONFIG_PATH} ({'exists' if CLI_CONFIG_PATH.exists() else 'not created yet'})")
    print(f"Render API key: {'set' if cfg.get('render_api_key') or os.environ.get('RENDER_API_KEY') else 'NOT set'}")
    print(f"Render service ID: {cfg.get('render_service_id') or os.environ.get('RENDER_SERVICE_ID') or 'NOT set'}")
    print(f"PC tunnel conf dir: {PC_TUNNEL_CONF_DIR} ({'exists' if PC_TUNNEL_CONF_DIR.is_dir() else 'not created yet'})")
    return 0


def cmd_config_set_render_credentials(args):
    _require_root()  # writes a 0600 file under /etc -- keep this consistent with the rest of "changes under /etc need root"
    cfg = _load_cli_config()
    if args.api_key:
        cfg["render_api_key"] = args.api_key
    if args.service_id:
        cfg["render_service_id"] = args.service_id
    _save_cli_config(cfg)
    print(f"Saved to {CLI_CONFIG_PATH} (mode 0600)")
    return 0


# ---------------------------------------------------------------------------
# argument parsing
# ---------------------------------------------------------------------------

def build_parser():
    ap = argparse.ArgumentParser(prog="hub-cli", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)

    pc = sub.add_parser("pc", help="Manage configured PCs (pc-tunnel@.service instances)")
    pc_sub = pc.add_subparsers(dest="pc_command", required=True)
    pc_sub.add_parser("list", help="List configured PCs").set_defaults(func=cmd_pc_list)
    p = pc_sub.add_parser("add", help="Add a PC and start its tunnel")
    p.add_argument("name")
    p.add_argument("ip")
    p.add_argument("--port", type=int, default=7842)
    p.add_argument("--force", action="store_true", help="Overwrite an existing conf file")
    p.set_defaults(func=cmd_pc_add)
    p = pc_sub.add_parser("remove", help="Remove a PC and stop its tunnel")
    p.add_argument("name")
    p.set_defaults(func=cmd_pc_remove)
    p = pc_sub.add_parser("pin", help="Pin a PC's SSH host key (ssh-keyscan)")
    p.add_argument("name")
    p.set_defaults(func=cmd_pc_pin)

    p = sub.add_parser("diagnostics", help="Run hub-diagnostics.py")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_diagnostics)

    render = sub.add_parser("render", help="Manage the Render-hosted service's env vars")
    render_sub = render.add_subparsers(dest="render_command", required=True)
    p = render_sub.add_parser("get", help="Read one env var")
    p.add_argument("key")
    p.set_defaults(func=cmd_render_get)
    p = render_sub.add_parser("set", help="Set one env var (does not auto-redeploy)")
    p.add_argument("key")
    p.add_argument("value")
    p.set_defaults(func=cmd_render_set)
    render_sub.add_parser("deploy", help="Trigger a redeploy").set_defaults(func=cmd_render_deploy)

    config = sub.add_parser("config", help="This CLI's own local config")
    config_sub = config.add_subparsers(dest="config_command", required=True)
    config_sub.add_parser("show", help="Show config (never prints secret values)").set_defaults(func=cmd_config_show)
    p = config_sub.add_parser("set-render-credentials", help="Store Render API credentials locally")
    p.add_argument("--api-key")
    p.add_argument("--service-id")
    p.set_defaults(func=cmd_config_set_render_credentials)

    return ap


def main():
    parser = build_parser()
    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
