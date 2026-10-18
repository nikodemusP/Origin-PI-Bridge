#!/usr/bin/env python3
from flask import Flask, request, redirect, url_for, render_template_string
import subprocess
import re
import os
import threading
import time
from datetime import datetime

app = Flask(__name__)

# Everything can be overridden via environment variables so the script runs on any device:
#   GUEST_WIFI_IFACE        Wi-Fi interface (default: auto-detect, prefers wlan0)
#   GUEST_WIFI_HOST         Bind address    (default: 0.0.0.0 = all interfaces)
#   GUEST_WIFI_PORT         Port            (default: 8080)
#   GUEST_WIFI_WG_CONF      WireGuard config (default: /etc/wireguard/wg0.conf)
#   GUEST_WIFI_LEASES       dnsmasq lease file (default: /var/lib/misc/dnsmasq.leases)
#   ORIGIN_MAC_LAN         MAC of the Origin device (from default.env)
#   ORIGIN_IP              Fixed IP of the Origin device (from default.env)
#   GUEST_WIFI_ORIGIN       Extra hostname(s) of the Origin device, comma-separated
#                           (default: origin,celestron-origin)
#   GUEST_WIFI_HIDE_SSIDS   Comma-separated SSIDs that are never shown
#                           (in addition to the automatically detected own Wi-Fi)
#   GUEST_WIFI_HOSTAPD_CONF hostapd config used to detect the own SSID
#                           (default: /etc/hostapd/hostapd.conf)
WLAN_IFACE = os.environ.get("GUEST_WIFI_IFACE", "").strip() or "wlan0"
BIND_HOST = os.environ.get("GUEST_WIFI_HOST", "0.0.0.0")
PORT = int(os.environ.get("GUEST_WIFI_PORT", "8080"))

REFRESH_INTERVAL = 10  # seconds

VERSION = "8"
WIFI_PROFILE_TYPES = {"wifi", "802-11-wireless"}
LEASES_FILE = os.environ.get("GUEST_WIFI_LEASES", "/var/lib/misc/dnsmasq.leases")
ORIGIN_HOSTS = {
    x.strip().lower()
    for x in os.environ.get("GUEST_WIFI_ORIGIN", "origin,celestron-origin").split(",")
    if x.strip()
}
ORIGIN_MAC = os.environ.get("ORIGIN_MAC_LAN", "").strip().strip("'\"").lower()
ORIGIN_IP = os.environ.get("ORIGIN_IP", "").strip().strip("'\"")

# Own Wi-Fi (broadcast by this device): hidden from the lists.
HIDE_SSIDS = {
    x.strip() for x in os.environ.get("GUEST_WIFI_HIDE_SSIDS", "").split(",") if x.strip()
}
HOSTAPD_CONF = os.environ.get("GUEST_WIFI_HOSTAPD_CONF", "/etc/hostapd/hostapd.conf")
OWN_SSIDS_AUTO = set()  # filled by get_profiles() from AP/bridge profiles

# WireGuard: the interface name is derived from the file name (wg0.conf -> wg0)
WG_CONF = os.environ.get("GUEST_WIFI_WG_CONF", "/etc/wireguard/wg0.conf")
WG_IFACE = os.path.splitext(os.path.basename(WG_CONF))[0]
WG_LOCK = threading.Lock()

# Bridge slave profiles such as "br0-wlan0" must not show up as saved Wi-Fi networks.
BRIDGE_NAME_RE = re.compile(r"^br\d+-")
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def run_command(command, timeout=30):
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def nmcli_terse(fields, *args):
    result = run_command(["nmcli", "-t", "-e", "yes", "-f", fields, *args])
    if result.returncode != 0:
        return []
    return [line for line in result.stdout.splitlines() if line.strip()]


def nmcli_unescape(value):
    # nmcli terse mode escapes ':' and '\' with backslash.
    out = []
    escaped = False
    for char in value:
        if escaped:
            out.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        else:
            out.append(char)
    if escaped:
        out.append("\\")
    return "".join(out)


def split_nmcli_line(line):
    fields = []
    current = []
    escaped = False

    for char in line:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
            current.append("\\")
        elif char == ":":
            fields.append(nmcli_unescape("".join(current)))
            current = []
        else:
            current.append(char)

    if escaped:
        current.append("\\")
    fields.append(nmcli_unescape("".join(current)))
    return fields


def get_current():
    result = run_command([
        "nmcli", "-t", "-e", "yes",
        "-f", "GENERAL.CONNECTION",
        "device", "show", WLAN_IFACE
    ])

    if result.returncode != 0:
        return "Not connected"

    value = result.stdout.strip()
    if value.startswith("GENERAL.CONNECTION:"):
        value = value.split(":", 1)[1]

    value = nmcli_unescape(value)

    if not value or value == "--":
        return "Not connected"

    return value


def get_signal():
    result = run_command([
        "nmcli", "-t", "-e", "yes",
        "-f", "IN-USE,SIGNAL,DEVICE",
        "device", "wifi", "list",
        "ifname", WLAN_IFACE
    ])

    if result.returncode != 0:
        return None

    for line in result.stdout.splitlines():
        parts = split_nmcli_line(line)
        if len(parts) >= 3 and parts[0] == "*" and parts[2] == WLAN_IFACE:
            try:
                return int(parts[1])
            except ValueError:
                return None

    return None


def inspect_profile(name, uuid):
    """Inspects a Wi-Fi profile. Returns (is_client_profile, ssid).

    Not client profiles: bridge profiles (name br0-*), profiles assigned to a
    bridge/master and access point / ad-hoc profiles. Their SSID is the own
    Wi-Fi and is hidden from the lists.
    """
    bridge_name = bool(BRIDGE_NAME_RE.match(name))

    result = run_command([
        "nmcli", "-t", "-e", "yes", "-g",
        "802-11-wireless.mode,connection.master,connection.slave-type,802-11-wireless.ssid",
        "connection", "show", "uuid", uuid,
    ])
    if result.returncode != 0:
        return (not bridge_name), ""  # when in doubt, show it

    lines = [nmcli_unescape(l).strip() for l in result.stdout.split("\n")]
    lines += [""] * (4 - len(lines))
    mode, master, slave_type, ssid = (v if v != "--" else "" for v in lines[:4])

    is_client = not bridge_name
    if mode and mode != "infrastructure":
        is_client = False
    if master or slave_type:
        is_client = False
    return is_client, ssid


def get_own_ssids():
    """SSIDs of the own Wi-Fi: from AP/bridge profiles, hostapd and the environment variable."""
    own = set(OWN_SSIDS_AUTO) | HIDE_SSIDS
    try:
        with open(HOSTAPD_CONF, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line.startswith(("ssid=", "ssid2=")) and not line.startswith("ssid2=P"):
                    value = line.split("=", 1)[1].strip().strip('"')
                    if value:
                        own.add(value)
    except OSError:
        pass
    return own


def get_profiles():
    global OWN_SSIDS_AUTO

    result = run_command([
        "nmcli", "-t", "-e", "yes",
        "-f", "NAME,UUID,TYPE,DEVICE",
        "connection", "show"
    ])

    if result.returncode != 0:
        return []

    candidates = []
    own_auto = set()

    for line in result.stdout.splitlines():
        parts = split_nmcli_line(line)
        if len(parts) < 4:
            continue

        name, uuid, conn_type, device = parts[:4]

        if conn_type not in WIFI_PROFILE_TYPES:
            continue

        is_client, ssid = inspect_profile(name, uuid)
        if not is_client:
            if ssid:
                own_auto.add(ssid)
            continue

        candidates.append({
            "name": name,
            "uuid": uuid,
            "device": device,
            "active": device == WLAN_IFACE,
        })

    OWN_SSIDS_AUTO = own_auto
    own = get_own_ssids()

    # Do not offer the own Wi-Fi (unless it is actually connected right now).
    return [p for p in candidates if p["active"] or p["name"] not in own]


def find_origin_ip():
    """IP of the Origin device. Looked up in the dnsmasq leases by MAC address,
    fixed IP or hostname (format: <expiry> <mac> <ip> <hostname> <client-id>).
    With multiple matches the lease with the latest expiry wins. Falls back to
    ORIGIN_IP from the configuration. None if unknown."""
    best_ip, best_rank = None, -1
    now = time.time()
    try:
        with open(LEASES_FILE, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) < 4:
                    continue
                matches = (
                    (ORIGIN_MAC and parts[1].lower() == ORIGIN_MAC)
                    or (ORIGIN_IP and parts[2] == ORIGIN_IP)
                    or parts[3].lower() in ORIGIN_HOSTS
                )
                if not matches:
                    continue
                try:
                    expiry = int(parts[0])
                except ValueError:
                    continue
                if expiry != 0 and expiry < now:
                    continue  # expired (0 = unlimited)
                rank = float("inf") if expiry == 0 else expiry
                if rank > best_rank:
                    best_ip, best_rank = parts[2], rank
    except OSError:
        pass
    return best_ip or ORIGIN_IP or None


def is_host_present(ip):
    """True if the host answers right now: ping first, then the ARP/neighbor
    table (covers hosts that block ICMP but still answer ARP)."""
    try:
        ping = run_command(["ping", "-n", "-c", "1", "-W", "1", ip], timeout=4)
        if ping.returncode == 0:
            return True
    except (OSError, subprocess.TimeoutExpired):
        pass

    try:
        neigh = run_command(["ip", "neigh", "show", ip], timeout=4)
    except (OSError, subprocess.TimeoutExpired):
        return False
    for line in neigh.stdout.splitlines():
        words = line.split()
        if "lladdr" in words and words[-1] in {"REACHABLE", "DELAY", "PROBE", "PERMANENT"}:
            return True
    return False


def get_origin():
    """Origin status: {"ip": str|None, "connected": bool}."""
    ip = find_origin_ip()
    return {"ip": ip, "connected": bool(ip) and is_host_present(ip)}


def wg_cmd(*args):
    """Prepends sudo -n when the script is not running as root."""
    cmd = list(args)
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        cmd = ["sudo", "-n", *cmd]
    return cmd


def format_age(seconds):
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds} s ago"
    if seconds < 3600:
        return f"{seconds // 60} min ago"
    return f"{seconds // 3600} h ago"


def get_wireguard():
    """WireGuard status: configured?, active?, last handshake (best effort)."""
    info = {
        "iface": WG_IFACE,
        "conf": WG_CONF,
        "configured": True,
        "active": os.path.isdir(f"/sys/class/net/{WG_IFACE}"),
        "handshake": None,
    }

    try:
        os.stat(WG_CONF)
    except FileNotFoundError:
        info["configured"] = False
    except OSError:
        pass  # e.g. no read permission on /etc/wireguard -> unknown, so assume ok

    if info["active"]:
        try:
            result = run_command(wg_cmd("wg", "show", WG_IFACE, "latest-handshakes"), timeout=5)
            if result.returncode == 0:
                stamps = []
                for line in result.stdout.splitlines():
                    parts = line.split()
                    if len(parts) == 2 and parts[1].isdigit() and int(parts[1]) > 0:
                        stamps.append(int(parts[1]))
                if stamps:
                    info["handshake"] = format_age(max(0, time.time() - max(stamps)))
        except (OSError, subprocess.TimeoutExpired):
            pass

    return info


def get_networks(rescan=True):
    """Returns the list of access points, None on error."""
    result = run_command([
        "nmcli", "-t", "-e", "yes",
        "-f", "SSID,SIGNAL,SECURITY,DEVICE",
        "device", "wifi", "list",
        "ifname", WLAN_IFACE,
        "--rescan", "yes" if rescan else "no"
    ], timeout=20)

    if result.returncode != 0:
        return None

    best = {}
    own_ssids = get_own_ssids()

    for line in result.stdout.splitlines():
        parts = split_nmcli_line(line)
        if len(parts) < 4:
            continue

        ssid, signal, security, device = parts[:4]

        if device != WLAN_IFACE or not ssid:
            continue

        if ssid in own_ssids:
            continue

        try:
            signal_int = int(signal)
        except ValueError:
            signal_int = 0

        item = {
            "ssid": ssid,
            "signal": signal_int,
            "security": security,
        }

        # Same SSID can appear multiple times from different access points.
        # Keep only the strongest one.
        if ssid not in best or signal_int > best[ssid]["signal"]:
            best[ssid] = item

    return sorted(
        best.values(),
        key=lambda x: (-x["signal"], x["ssid"].lower())
    )


def detect_wlan_iface():
    """Uses GUEST_WIFI_IFACE, else wlan0 if present, else the first Wi-Fi device."""
    forced = os.environ.get("GUEST_WIFI_IFACE", "").strip()
    if forced:
        return forced

    wifi_devices = []
    for line in nmcli_terse("DEVICE,TYPE", "device"):
        parts = split_nmcli_line(line)
        if len(parts) >= 2 and parts[1] == "wifi":
            wifi_devices.append(parts[0])

    if not wifi_devices or "wlan0" in wifi_devices:
        return "wlan0"
    return wifi_devices[0]


# ---------------------------------------------------------------------
# State cache: refreshed at startup and then every REFRESH_INTERVAL
# seconds in the background. The web page only reads the cache and is
# therefore instant (no scan per page view).
# ---------------------------------------------------------------------
STATE_LOCK = threading.Lock()
SCAN_LOCK = threading.RLock()
STATE = {
    "current": "Not connected",
    "signal": None,
    "profiles": [],
    "networks": [],
    "origin": {"ip": None, "connected": False},
    "wireguard": {
        "iface": WG_IFACE, "conf": WG_CONF,
        "configured": True, "active": False, "handshake": None,
    },
    "updated": None,
}


def refresh_state(rescan=True):
    with SCAN_LOCK:
        current = get_current()
        signal = get_signal()
        profiles = get_profiles()
        networks = get_networks(rescan=rescan)
    wireguard = get_wireguard()
    origin = get_origin()

    with STATE_LOCK:
        STATE["current"] = current
        STATE["signal"] = signal
        STATE["profiles"] = profiles
        STATE["wireguard"] = wireguard
        STATE["origin"] = origin
        if networks is not None:  # keep the old list on scan errors
            STATE["networks"] = networks
        STATE["updated"] = datetime.now().strftime("%H:%M:%S")


def get_state():
    with STATE_LOCK:
        return dict(STATE)


def refresher_loop():
    while True:
        started = time.monotonic()
        try:
            refresh_state()
        except Exception as exc:  # Thread darf nie sterben
            print(f"[{datetime.now():%H:%M:%S}] Refresh failed: {exc}", flush=True)
        time.sleep(max(1.0, REFRESH_INTERVAL - (time.monotonic() - started)))


def initial_phase():
    started = datetime.now()
    print(f"GUEST_WIFI_app Version {VERSION}", flush=True)
    print(
        f"[{started:%H:%M:%S}] Initial phase started: reading current Wi-Fi "
        f"and scanning access points on {WLAN_IFACE} ...",
        flush=True,
    )

    # Right after boot the first scan is often empty -> up to 3 attempts.
    for attempt in range(3):
        refresh_state()
        if get_state()["networks"]:
            break
        if attempt < 2:
            time.sleep(3)

    finished = datetime.now()
    state = get_state()
    duration = (finished - started).total_seconds()

    print(f"[{finished:%H:%M:%S}] Initial phase finished (took {duration:.1f} s).", flush=True)
    print(f"  Interface:      {WLAN_IFACE}", flush=True)
    print(f"  Current Wi-Fi:  {state['current']}", flush=True)
    wg = state["wireguard"]
    origin = state["origin"]
    origin_text = origin["ip"] or "not found"
    origin_text += " (connected)" if origin["connected"] else " (not connected)"
    print(f"  Origin:         {origin_text}", flush=True)
    wg_text = "active" if wg["active"] else "inactive"
    if not wg["configured"]:
        wg_text += f" (config {wg['conf']} missing)"
    print(f"  WireGuard ({wg['iface']}): {wg_text}", flush=True)

    if state["profiles"]:
        print(f"  Saved Wi-Fi networks ({len(state['profiles'])}):", flush=True)
        for prof in state["profiles"]:
            mark = "  <- connected" if prof["active"] else ""
            print(f"    - {prof['name']}{mark}", flush=True)
    else:
        print("  Saved Wi-Fi networks: none", flush=True)

    if state["networks"]:
        print(f"  Networks found ({len(state['networks'])}):", flush=True)
        for net in state["networks"]:
            sec = net["security"].strip() or "open"
            print(f"    - {net['ssid']}  ({net['signal']} %, {sec})", flush=True)
    else:
        print("  Networks found: none", flush=True)

    print(
        f"  Next refresh every {REFRESH_INTERVAL} s. "
        f"Web-UI: http://{BIND_HOST}:{PORT}",
        flush=True,
    )


def error_redirect(message):
    return redirect(url_for("index", error=message))


def success_redirect(message):
    return redirect(url_for("index", success=message))


@app.route("/")
def index():
    state = get_state()
    return render_template_string(
        TEMPLATE,
        iface=WLAN_IFACE,
        current=state["current"],
        signal=state["signal"],
        profiles=state["profiles"],
        networks=state["networks"],
        wg=state["wireguard"],
        origin=state["origin"],
        updated=state["updated"],
        error=request.args.get("error"),
        success=request.args.get("success"),
    )


@app.post("/connect-profile")
def connect_profile():
    uuid = request.form.get("uuid", "").strip()

    if not UUID_RE.fullmatch(uuid):
        return error_redirect("Invalid Wi-Fi profile ID")

    with SCAN_LOCK:  # no background scan while connecting
        result = run_command([
            "nmcli",
            "connection",
            "up",
            "uuid",
            uuid,
            "ifname",
            WLAN_IFACE,
        ], timeout=45)

    if result.returncode != 0:
        error = result.stderr.strip() or result.stdout.strip() or "Connection failed"
        return error_redirect(error)

    refresh_state(rescan=False)
    return success_redirect("Saved Wi-Fi network activated.")


@app.post("/delete-profile")
def delete_profile():
    uuid = request.form.get("uuid", "").strip()

    if not UUID_RE.fullmatch(uuid):
        return error_redirect("Invalid Wi-Fi profile ID")

    with SCAN_LOCK:
        # Only delete profiles that are shown in the list (no bridges etc.).
        profile = next((p for p in get_profiles() if p["uuid"] == uuid), None)
        if profile is None:
            return error_redirect("Profile not found or cannot be deleted.")

        result = run_command(
            ["nmcli", "connection", "delete", "uuid", uuid], timeout=30
        )

    if result.returncode != 0:
        error = result.stderr.strip() or result.stdout.strip() or "Delete failed"
        return error_redirect(error)

    print(f"[{datetime.now():%H:%M:%S}] Profile deleted: {profile['name']} ({uuid})", flush=True)
    refresh_state(rescan=False)
    return success_redirect(f"Wi-Fi profile “{profile['name']}” deleted.")


@app.post("/wireguard")
def wireguard_toggle():
    action = request.form.get("action", "")
    if action not in ("up", "down"):
        return error_redirect("Invalid WireGuard action")

    with WG_LOCK:
        try:
            result = run_command(wg_cmd("wg-quick", action, WG_CONF), timeout=45)
        except FileNotFoundError:
            return error_redirect("wg-quick not found (install the wireguard-tools package).")
        except subprocess.TimeoutExpired:
            return error_redirect("WireGuard: timed out.")

    out = (result.stderr.strip() or result.stdout.strip()).replace("\n", " | ")
    print(
        f"[{datetime.now():%H:%M:%S}] wg-quick {action} {WG_CONF}: rc={result.returncode} {out}",
        flush=True,
    )

    if result.returncode != 0:
        lines = (result.stderr.strip() or result.stdout.strip() or "unknown error").splitlines()
        return error_redirect("WireGuard: " + " | ".join(lines[-3:])[:300])

    refresh_state(rescan=False)
    return success_redirect(
        "WireGuard activated." if action == "up" else "WireGuard deactivated."
    )


def log_nmcli(step, args, result):
    """Logs every connection step to the console (password masked)."""
    shown = []
    for i, a in enumerate(args):
        shown.append("***" if i > 0 and args[i - 1].endswith(".psk") else a)
    out = (result.stderr.strip() or result.stdout.strip()).replace("\n", " | ")
    print(
        f"[{datetime.now():%H:%M:%S}] {step}: rc={result.returncode} "
        f"cmd=\"{' '.join(shown)}\" {out}",
        flush=True,
    )


def nmcli_step(step, args, timeout=30):
    result = run_command(args, timeout=timeout)
    log_nmcli(step, args, result)
    return result


def list_wifi_profiles(ssid):
    """UUIDs of all Wi-Fi profiles named like the SSID (also 'SSID 1' etc.)."""
    uuids = []
    for line in nmcli_terse("NAME,UUID,TYPE", "connection", "show"):
        parts = split_nmcli_line(line)
        if len(parts) < 3 or parts[2] not in WIFI_PROFILE_TYPES:
            continue
        name, uuid = parts[0], parts[1]
        if UUID_RE.fullmatch(uuid) and (
            name == ssid or re.fullmatch(re.escape(ssid) + r" \d+", name)
        ):
            uuids.append(uuid)
    return uuids


def security_mode(security):
    """Derives the encryption type from the nmcli SECURITY column."""
    sec = security.upper()
    if "802.1X" in sec:
        return "enterprise"
    if "WPA" not in sec and "WEP" in sec:
        return "wep"
    if "WPA3" in sec and "WPA2" not in sec and "WPA1" not in sec:
        return "sae"
    return "wpa-psk"


def create_and_activate(ssid, sec_args):
    """Removes old/broken profiles of the same name, creates the profile from
    scratch (incl. key-mgmt) and activates it. Returns an error message or None."""
    for old_uuid in list_wifi_profiles(ssid):
        nmcli_step("Delete old profile", ["nmcli", "connection", "delete", "uuid", old_uuid])

    add_args = [
        "nmcli", "connection", "add",
        "type", "wifi",
        "ifname", WLAN_IFACE,
        "con-name", ssid,
        "ssid", ssid,
        *sec_args,
    ]
    result = nmcli_step("Create profile", add_args)
    if result.returncode != 0:
        err = result.stderr.strip() or result.stdout.strip() or "unknown error"
        return f"Creating profile failed: {err}"

    uuids = list_wifi_profiles(ssid)
    if not uuids:
        return "Profile was created but could not be found."
    uuid = uuids[0]

    result = nmcli_step(
        "Activate profile",
        ["nmcli", "connection", "up", "uuid", uuid, "ifname", WLAN_IFACE],
        timeout=45,
    )
    if result.returncode != 0:
        err = result.stderr.strip() or result.stdout.strip() or "unknown error"
        # Do not leave a non-working profile (e.g. wrong password) behind.
        nmcli_step("Discard profile", ["nmcli", "connection", "delete", "uuid", uuid])
        return f"Activation failed: {err}"

    return None


def connect_secured(ssid, password, security):
    mode = security_mode(security)

    if mode == "enterprise":
        return "Enterprise Wi-Fi networks (802.1X) are not supported here."
    if mode == "wep":
        return "WEP networks are not supported (insecure)."
    if not (8 <= len(password) <= 63 or re.fullmatch(r"[0-9a-fA-F]{64}", password)):
        return "The Wi-Fi password must be 8 to 63 characters long."

    return create_and_activate(ssid, [
        "802-11-wireless-security.key-mgmt", mode,
        "802-11-wireless-security.psk", password,
    ])


@app.post("/connect-new")
def connect_new():
    ssid = request.form.get("ssid", "").strip()
    password = request.form.get("password", "")

    if not ssid:
        return error_redirect("SSID is missing")

    if len(ssid) > 255:
        return error_redirect("SSID is too long")

    def find_network():
        return next((n for n in get_state()["networks"] if n["ssid"] == ssid), None)

    network = find_network()

    if network is None:
        refresh_state()  # may be new -> scan once more
        network = find_network()

    if network is None:
        return error_redirect(
            f"Wi-Fi network '{ssid}' was not found during the scan."
        )

    security = network["security"].strip()

    with SCAN_LOCK:  # no background scan while connecting
        if security:
            if not password:
                return error_redirect(
                    "A password is required for this network."
                )
            error = connect_secured(ssid, password, security)
        else:
            # Open network: profile without security settings.
            error = create_and_activate(ssid, [])

    if error:
        return error_redirect(error)

    refresh_state(rescan=False)
    return success_redirect(
        f"Connected to '{ssid}' and saved as a NetworkManager profile."
    )


TEMPLATE = r"""
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <title>Guest Wi-Fi Management</title>

    <style>
        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            font-family: Arial, Helvetica, sans-serif;
            background: #f4f6f8;
            color: #17202a;
        }

        .container {
            width: min(1000px, calc(100% - 32px));
            margin: 30px auto 50px;
        }

        h1 {
            margin-bottom: 8px;
        }

        h2 {
            margin-top: 0;
        }

        .subtitle {
            color: #667085;
            margin-bottom: 25px;
        }

        .card {
            background: white;
            border-radius: 16px;
            padding: 22px;
            margin-bottom: 20px;
            box-shadow: 0 3px 16px rgba(0, 0, 0, 0.07);
        }

        .current {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 20px;
            flex-wrap: wrap;
        }

        .ssid {
            font-size: 24px;
            font-weight: bold;
        }

        .signal {
            font-size: 16px;
            color: #667085;
            margin-top: 5px;
        }

        .network-list {
            display: flex;
            flex-direction: column;
            gap: 10px;
        }

        .network {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 15px;
            padding: 15px;
            border: 1px solid #e5e7eb;
            border-radius: 12px;
        }

        .network-info {
            min-width: 0;
        }

        .network-name {
            font-weight: bold;
            overflow-wrap: anywhere;
        }

        .network-meta {
            color: #667085;
            font-size: 14px;
            margin-top: 4px;
        }

        button {
            border: 0;
            border-radius: 10px;
            padding: 11px 16px;
            cursor: pointer;
            font-weight: bold;
            background: #2563eb;
            color: white;
        }

        button:hover {
            opacity: 0.9;
        }

        button.secondary {
            background: #475467;
        }

        button.danger {
            background: #b42318;
        }

        button:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }

        .wg {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 20px;
            flex-wrap: wrap;
        }

        .wg-off {
            color: #667085;
            font-weight: bold;
        }

        .profile {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 15px;
            padding: 14px 0;
            border-bottom: 1px solid #eaecf0;
        }

        .profile-actions {
            display: flex;
            gap: 8px;
        }

        .profile-actions form {
            margin: 0;
        }

        .profile:last-child {
            border-bottom: 0;
        }

        .active {
            color: #067647;
            font-weight: bold;
        }

        form.manual {
            display: grid;
            gap: 12px;
        }

        input {
            width: 100%;
            padding: 12px;
            border: 1px solid #d0d5dd;
            border-radius: 10px;
            font-size: 16px;
        }

        .alert {
            padding: 14px 16px;
            border-radius: 10px;
            margin-bottom: 20px;
        }

        .error {
            background: #fef3f2;
            color: #b42318;
        }

        .success {
            background: #ecfdf3;
            color: #067647;
        }

        .empty {
            color: #667085;
        }

        .modal-backdrop {
            display: none;
            position: fixed;
            inset: 0;
            background: rgba(0, 0, 0, 0.45);
            align-items: center;
            justify-content: center;
            padding: 20px;
            z-index: 1000;
        }

        .modal {
            background: white;
            width: min(460px, 100%);
            border-radius: 18px;
            padding: 24px;
            box-shadow: 0 15px 50px rgba(0, 0, 0, 0.25);
        }

        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 10px;
        }

        .modal-header h2 {
            margin: 0;
            overflow-wrap: anywhere;
        }

        .close {
            background: transparent;
            color: #475467;
            font-size: 24px;
            padding: 2px 8px;
        }

        .modal form {
            margin-top: 20px;
        }

        .modal-actions {
            display: flex;
            justify-content: flex-end;
            gap: 10px;
            margin-top: 18px;
        }

        .lock {
            margin-left: 5px;
        }

        @media (max-width: 600px) {
            .container {
                width: min(100% - 20px, 1000px);
                margin-top: 15px;
            }

            .card {
                padding: 16px;
            }

            .network,
            .profile {
                align-items: stretch;
                flex-direction: column;
            }

            .network button,
            .profile button,
            .wg button {
                width: 100%;
            }

            .profile-actions {
                flex-direction: column;
            }
        }
    </style>
</head>

<body>
<div class="container">

    <h1>Guest Wi-Fi Management</h1>
    <div class="subtitle">
        Manages <strong>{{ iface }}</strong> and WireGuard (<strong>{{ wg.iface }}</strong>).
        All other interfaces are left untouched.
    </div>

    {% if error %}
        <div class="alert error">
            {{ error }}
        </div>
    {% endif %}

    {% if success %}
        <div class="alert success">
            {{ success }}
        </div>
    {% endif %}

    <div class="card">
        <div class="current">
            <div>
                <div class="ssid">
                    {{ current }}
                </div>
                <div class="signal">
                    {% if signal is not none %}
                        Signal: {{ signal }} %
                    {% else %}
                        No Wi-Fi signal available
                    {% endif %}
                    {% if updated %}
                        · Updated: {{ updated }}
                    {% endif %}
                </div>
                <div class="signal">
                    Origin:
                    {% if origin.connected %}
                        <strong>{{ origin.ip }}</strong>
                        <span class="active"> · connected</span>
                    {% else %}
                        {% if origin.ip %}<strong>{{ origin.ip }}</strong> · {% endif %}
                        <span class="wg-off">not connected</span>
                    {% endif %}
                </div>
            </div>

            <button
                class="secondary"
                onclick="window.location.reload()">
                Refresh
            </button>
        </div>
    </div>

    <div class="card">
        <h2>WireGuard</h2>

        <div class="wg">
            <div>
                <div class="ssid" style="font-size:18px;">
                    {{ wg.iface }}
                    {% if not wg.configured %}
                        <span class="wg-off"> · Config missing</span>
                    {% elif wg.active %}
                        <span class="active"> · active</span>
                    {% else %}
                        <span class="wg-off"> · inactive</span>
                    {% endif %}
                </div>
                <div class="signal">
                    {% if not wg.configured %}
                        {{ wg.conf }} not found
                    {% elif wg.active and wg.handshake %}
                        Last handshake {{ wg.handshake }}
                    {% elif wg.active %}
                        Tunnel running · Config: {{ wg.conf }}
                    {% else %}
                        Config: {{ wg.conf }}
                    {% endif %}
                </div>
            </div>

            <form method="post" action="/wireguard">
                {% if wg.active %}
                    <input type="hidden" name="action" value="down">
                    <button type="submit" class="danger">
                        Deactivate WireGuard
                    </button>
                {% else %}
                    <input type="hidden" name="action" value="up">
                    <button type="submit" {% if not wg.configured %}disabled{% endif %}>
                        Activate WireGuard
                    </button>
                {% endif %}
            </form>
        </div>
    </div>

    <div class="card">
        <h2>Saved Wi-Fi networks</h2>

        {% if profiles %}
            {% for profile in profiles %}
                <div class="profile">
                    <div>
                        <strong>{{ profile.name }}</strong>

                        {% if profile.active %}
                            <span class="active"> · connected</span>
                        {% endif %}
                    </div>

                    <div class="profile-actions">
                        <form method="post" action="/connect-profile">
                            <input
                                type="hidden"
                                name="uuid"
                                value="{{ profile.uuid }}">

                            <button type="submit">
                                Connect
                            </button>
                        </form>

                        <form method="post" action="/delete-profile"
                              onsubmit='return confirm(
                                {{ ("Delete “" ~ profile.name ~ "”?" ~ (" This network is currently connected; the connection will be dropped." if profile.active else ""))|tojson }}
                              )'>
                            <input
                                type="hidden"
                                name="uuid"
                                value="{{ profile.uuid }}">

                            <button type="submit" class="danger">
                                Delete
                            </button>
                        </form>
                    </div>
                </div>
            {% endfor %}
        {% else %}
            <div class="empty">
                No saved Wi-Fi profiles found.
            </div>
        {% endif %}
    </div>

    <div class="card">
        <h2>Available Wi-Fi networks</h2>

        {% if networks %}
            <div class="network-list">
                {% for network in networks %}
                    <div class="network">
                        <div class="network-info">
                            <div class="network-name">
                                {{ network.ssid }}

                                {% if network.security %}
                                    <span class="lock">🔒</span>
                                {% endif %}
                            </div>

                            <div class="network-meta">
                                Signal: {{ network.signal }} %
                                {% if network.security %}
                                    · {{ network.security }}
                                {% else %}
                                    · Open
                                {% endif %}
                            </div>
                        </div>

                        <button
                            type="button"
                            onclick='openWifiModal(
                                {{ network.ssid|tojson }},
                                {{ (network.security|length > 0)|tojson }}
                            )'>
                            Connect
                        </button>
                    </div>
                {% endfor %}
            </div>
        {% else %}
            <div class="empty">
                No Wi-Fi networks found.
            </div>
        {% endif %}
    </div>

    <div class="card">
        <h2>Add Wi-Fi network manually</h2>

        <form class="manual" method="post" action="/connect-new">
            <input
                type="text"
                name="ssid"
                placeholder="SSID"
                maxlength="255"
                required>

            <input
                type="password"
                name="password"
                placeholder="Password (leave empty for open networks)"
                autocomplete="new-password">

            <button type="submit">
                Save &amp; connect
            </button>
        </form>
    </div>

</div>

<div id="wifiModal" class="modal-backdrop">
    <div class="modal">
        <div class="modal-header">
            <h2 id="modalTitle">Connect to Wi-Fi</h2>

            <button
                type="button"
                class="close"
                onclick="closeWifiModal()">
                ×
            </button>
        </div>

        <form method="post" action="/connect-new">
            <input
                type="hidden"
                id="modalSsid"
                name="ssid">

            <div id="passwordArea">
                <label for="modalPassword">
                    Wi-Fi password
                </label>

                <input
                    id="modalPassword"
                    name="password"
                    type="password"
                    autocomplete="new-password"
                    placeholder="Password">
            </div>

            <div id="openNetworkMessage"
                 style="display:none; margin-top:15px; color:#667085;">
                This network is open. It will be saved without a password.
            </div>

            <div class="modal-actions">
                <button
                    type="button"
                    class="secondary"
                    onclick="closeWifiModal()">
                    Cancel
                </button>

                <button type="submit">
                    Save &amp; connect
                </button>
            </div>
        </form>
    </div>
</div>

<script>
    const modal = document.getElementById("wifiModal");
    const modalTitle = document.getElementById("modalTitle");
    const modalSsid = document.getElementById("modalSsid");
    const modalPassword = document.getElementById("modalPassword");
    const passwordArea = document.getElementById("passwordArea");
    const openNetworkMessage = document.getElementById("openNetworkMessage");

    function openWifiModal(ssid, secured) {
        modalTitle.textContent = "Connect to “" + ssid + "”";
        modalSsid.value = ssid;
        modalPassword.value = "";

        if (secured) {
            passwordArea.style.display = "block";
            openNetworkMessage.style.display = "none";
            modalPassword.required = true;
        } else {
            passwordArea.style.display = "none";
            openNetworkMessage.style.display = "block";
            modalPassword.required = false;
        }

        modal.style.display = "flex";

        if (secured) {
            setTimeout(() => modalPassword.focus(), 50);
        }
    }

    function closeWifiModal() {
        modal.style.display = "none";
        modalPassword.value = "";
    }

    modal.addEventListener("click", function(event) {
        if (event.target === modal) {
            closeWifiModal();
        }
    });

    document.addEventListener("keydown", function(event) {
        if (event.key === "Escape") {
            closeWifiModal();
        }
    });

    // Remove old messages (?error=/?success=) from the URL after showing them,
    // so they do not stay forever on automatic reloads.
    if (window.location.search) {
        history.replaceState(null, "", window.location.pathname);
    }

    // Reload every 10 s - but not while the user is typing or the dialog
    // is open (otherwise the entered password would be lost).
    setInterval(function() {
        const typing =
            modal.style.display === "flex" ||
            document.activeElement instanceof HTMLInputElement ||
            Array.from(document.querySelectorAll("input"))
                .some(function(i) { return i.type !== "hidden" && i.value !== ""; });

        if (!typing && !document.hidden) {
            window.location.reload();
        }
    }, 10000);
</script>

</body>
</html>
"""


if __name__ == "__main__":
    WLAN_IFACE = detect_wlan_iface()
    initial_phase()
    threading.Thread(target=refresher_loop, daemon=True).start()

    app.run(
        host=BIND_HOST,
        port=PORT,
        debug=False,
        threaded=True,
    )
