#!/usr/bin/env python3
from flask import Flask, request, redirect, url_for, render_template_string
import subprocess
import re
import os
import threading
import time
from datetime import datetime

app = Flask(__name__)

# Alles per Umgebungsvariable überschreibbar, damit das Script auf jedem Gerät läuft:
#   GUEST_WIFI_IFACE  WLAN-Schnittstelle (Standard: automatisch, bevorzugt wlan0)
#   GUEST_WIFI_HOST   Bind-Adresse        (Standard: 0.0.0.0 = alle Schnittstellen)
#   GUEST_WIFI_PORT   Port                (Standard: 8080)
#   GUEST_WIFI_WG_CONF WireGuard-Config   (Standard: /etc/wireguard/wg0.conf)
#   GUEST_WIFI_LEASES  dnsmasq-Leasefile  (Standard: /var/lib/misc/dnsmasq.leases)
#   GUEST_WIFI_ORIGIN  Hostname des Origin-Geräts (Standard: origin)
WLAN_IFACE = os.environ.get("GUEST_WIFI_IFACE", "").strip() or "wlan0"
BIND_HOST = os.environ.get("GUEST_WIFI_HOST", "0.0.0.0")
PORT = int(os.environ.get("GUEST_WIFI_PORT", "8080"))

REFRESH_INTERVAL = 10  # Sekunden

VERSION = "6"
WIFI_PROFILE_TYPES = {"wifi", "802-11-wireless"}
LEASES_FILE = os.environ.get("GUEST_WIFI_LEASES", "/var/lib/misc/dnsmasq.leases")
ORIGIN_HOST = os.environ.get("GUEST_WIFI_ORIGIN", "origin").strip().lower()

# WireGuard: Interface-Name ergibt sich aus dem Dateinamen (wg0.conf -> wg0)
WG_CONF = os.environ.get("GUEST_WIFI_WG_CONF", "/etc/wireguard/wg0.conf")
WG_IFACE = os.path.splitext(os.path.basename(WG_CONF))[0]
WG_LOCK = threading.Lock()

# Bridge-Slave-Profile wie "br0-wlan0" sollen nicht als gespeichertes WLAN erscheinen.
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
        return "Nicht verbunden"

    value = result.stdout.strip()
    if value.startswith("GENERAL.CONNECTION:"):
        value = value.split(":", 1)[1]

    value = nmcli_unescape(value)

    if not value or value == "--":
        return "Nicht verbunden"

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


def is_client_profile(name, uuid):
    """True nur für normale WLAN-Client-Profile.

    Ausgeschlossen werden Bridge-Profile (Name br0-*), Profile die einer
    Bridge/einem Master zugeordnet sind und Access-Point-/Ad-hoc-Profile.
    """
    if BRIDGE_NAME_RE.match(name):
        return False

    result = run_command([
        "nmcli", "-t", "-e", "yes", "-g",
        "802-11-wireless.mode,connection.master,connection.slave-type",
        "connection", "show", "uuid", uuid,
    ])
    if result.returncode != 0:
        return True  # im Zweifel anzeigen (Namensfilter hat schon gegriffen)

    lines = [nmcli_unescape(l).strip() for l in result.stdout.split("\n")]
    lines += [""] * (3 - len(lines))
    mode, master, slave_type = (v if v != "--" else "" for v in lines[:3])

    if mode and mode != "infrastructure":
        return False
    if master or slave_type:
        return False
    return True


def get_profiles():
    result = run_command([
        "nmcli", "-t", "-e", "yes",
        "-f", "NAME,UUID,TYPE,DEVICE",
        "connection", "show"
    ])

    if result.returncode != 0:
        return []

    profiles = []

    for line in result.stdout.splitlines():
        parts = split_nmcli_line(line)
        if len(parts) < 4:
            continue

        name, uuid, conn_type, device = parts[:4]

        if conn_type not in WIFI_PROFILE_TYPES:
            continue

        if not is_client_profile(name, uuid):
            continue

        profiles.append({
            "name": name,
            "uuid": uuid,
            "device": device,
            "active": device == WLAN_IFACE,
        })

    return profiles


def get_origin_ip():
    """IP des Origin-Geräts aus den dnsmasq-Leases (Format:
    <ablauf> <mac> <ip> <hostname> <client-id>). Bei Mehrfachtreffern gewinnt
    der Lease mit der spätesten Ablaufzeit. None, wenn nicht gefunden."""
    best_ip, best_expiry = None, -1
    now = time.time()
    try:
        with open(LEASES_FILE, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) < 4 or parts[3].lower() != ORIGIN_HOST:
                    continue
                try:
                    expiry = int(parts[0])
                except ValueError:
                    continue
                if expiry != 0 and expiry < now:
                    continue  # abgelaufen (0 = unbegrenzt)
                rank = float("inf") if expiry == 0 else expiry
                if rank > best_expiry:
                    best_ip, best_expiry = parts[2], rank
    except OSError:
        return None
    return best_ip


def wg_cmd(*args):
    """Stellt sudo -n voran, wenn das Script nicht als root läuft."""
    cmd = list(args)
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        cmd = ["sudo", "-n", *cmd]
    return cmd


def format_age(seconds):
    seconds = int(seconds)
    if seconds < 60:
        return f"vor {seconds} s"
    if seconds < 3600:
        return f"vor {seconds // 60} min"
    return f"vor {seconds // 3600} h"


def get_wireguard():
    """Status von WireGuard: konfiguriert?, aktiv?, letzter Handshake (best effort)."""
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
        pass  # z. B. keine Leserechte auf /etc/wireguard -> unbekannt, also ok

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
    """Liefert Liste der Access Points, bei Fehler None."""
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

    for line in result.stdout.splitlines():
        parts = split_nmcli_line(line)
        if len(parts) < 4:
            continue

        ssid, signal, security, device = parts[:4]

        if device != WLAN_IFACE or not ssid:
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
    """Nimmt GUEST_WIFI_IFACE, sonst wlan0 falls vorhanden, sonst das erste WLAN-Device."""
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
# Zustands-Cache: wird beim Start und danach alle REFRESH_INTERVAL
# Sekunden im Hintergrund aktualisiert. Die Webseite liest nur den Cache
# und ist dadurch sofort da (kein Scan pro Seitenaufruf).
# ---------------------------------------------------------------------
STATE_LOCK = threading.Lock()
SCAN_LOCK = threading.RLock()
STATE = {
    "current": "Nicht verbunden",
    "signal": None,
    "profiles": [],
    "networks": [],
    "origin_ip": None,
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
    origin_ip = get_origin_ip()

    with STATE_LOCK:
        STATE["current"] = current
        STATE["signal"] = signal
        STATE["profiles"] = profiles
        STATE["wireguard"] = wireguard
        STATE["origin_ip"] = origin_ip
        if networks is not None:  # bei Scan-Fehler alte Liste behalten
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
            print(f"[{datetime.now():%H:%M:%S}] Aktualisierung fehlgeschlagen: {exc}", flush=True)
        time.sleep(max(1.0, REFRESH_INTERVAL - (time.monotonic() - started)))


def initial_phase():
    started = datetime.now()
    print(f"GUEST_WIFI_app Version {VERSION}", flush=True)
    print(
        f"[{started:%H:%M:%S}] Initialphase gestartet: lese aktuelles WLAN "
        f"und scanne Access Points auf {WLAN_IFACE} ...",
        flush=True,
    )

    # Direkt nach dem Boot ist der erste Scan oft leer -> bis zu 3 Versuche.
    for attempt in range(3):
        refresh_state()
        if get_state()["networks"]:
            break
        if attempt < 2:
            time.sleep(3)

    finished = datetime.now()
    state = get_state()
    duration = (finished - started).total_seconds()

    print(f"[{finished:%H:%M:%S}] Initialphase beendet (Dauer: {duration:.1f} s).", flush=True)
    print(f"  Schnittstelle:  {WLAN_IFACE}", flush=True)
    print(f"  Aktuelles WLAN: {state['current']}", flush=True)
    wg = state["wireguard"]
    print(f"  Origin-IP:      {state['origin_ip'] or 'nicht gefunden'}", flush=True)
    wg_text = "aktiv" if wg["active"] else "inaktiv"
    if not wg["configured"]:
        wg_text += f" (Config {wg['conf']} fehlt)"
    print(f"  WireGuard ({wg['iface']}): {wg_text}", flush=True)

    if state["profiles"]:
        print(f"  Gespeicherte WLANs ({len(state['profiles'])}):", flush=True)
        for prof in state["profiles"]:
            mark = "  <- verbunden" if prof["active"] else ""
            print(f"    - {prof['name']}{mark}", flush=True)
    else:
        print("  Gespeicherte WLANs: keine", flush=True)

    if state["networks"]:
        print(f"  Gefundene WLANs ({len(state['networks'])}):", flush=True)
        for net in state["networks"]:
            sec = net["security"].strip() or "offen"
            print(f"    - {net['ssid']}  ({net['signal']} %, {sec})", flush=True)
    else:
        print("  Gefundene WLANs: keine", flush=True)

    print(
        f"  Weitere Aktualisierung alle {REFRESH_INTERVAL} s. "
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
        origin_ip=state["origin_ip"],
        updated=state["updated"],
        error=request.args.get("error"),
        success=request.args.get("success"),
    )


@app.post("/connect-profile")
def connect_profile():
    uuid = request.form.get("uuid", "").strip()

    if not UUID_RE.fullmatch(uuid):
        return error_redirect("Ungültige WLAN-Profil-ID")

    with SCAN_LOCK:  # kein Hintergrund-Scan während des Verbindens
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
        error = result.stderr.strip() or result.stdout.strip() or "Verbindung fehlgeschlagen"
        return error_redirect(error)

    refresh_state(rescan=False)
    return success_redirect("Gespeichertes WLAN wurde aktiviert.")


@app.post("/wireguard")
def wireguard_toggle():
    action = request.form.get("action", "")
    if action not in ("up", "down"):
        return error_redirect("Ungültige WireGuard-Aktion")

    with WG_LOCK:
        try:
            result = run_command(wg_cmd("wg-quick", action, WG_CONF), timeout=45)
        except FileNotFoundError:
            return error_redirect("wg-quick nicht gefunden (Paket wireguard-tools installieren).")
        except subprocess.TimeoutExpired:
            return error_redirect("WireGuard: Zeitüberschreitung.")

    out = (result.stderr.strip() or result.stdout.strip()).replace("\n", " | ")
    print(
        f"[{datetime.now():%H:%M:%S}] wg-quick {action} {WG_CONF}: rc={result.returncode} {out}",
        flush=True,
    )

    if result.returncode != 0:
        lines = (result.stderr.strip() or result.stdout.strip() or "unbekannter Fehler").splitlines()
        return error_redirect("WireGuard: " + " | ".join(lines[-3:])[:300])

    refresh_state(rescan=False)
    return success_redirect(
        "WireGuard wurde aktiviert." if action == "up" else "WireGuard wurde deaktiviert."
    )


def log_nmcli(step, args, result):
    """Protokolliert jeden Verbindungsschritt auf der Konsole (Passwort maskiert)."""
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
    """UUIDs aller WLAN-Profile, die so heißen wie die SSID (auch 'SSID 1' usw.)."""
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
    """Leitet aus der nmcli-SECURITY-Spalte die Verschlüsselungsart ab."""
    sec = security.upper()
    if "802.1X" in sec:
        return "enterprise"
    if "WPA" not in sec and "WEP" in sec:
        return "wep"
    if "WPA3" in sec and "WPA2" not in sec and "WPA1" not in sec:
        return "sae"
    return "wpa-psk"


def create_and_activate(ssid, sec_args):
    """Entfernt alte/kaputte Profile gleichen Namens, legt das Profil komplett
    neu an (inkl. key-mgmt) und aktiviert es. Gibt Fehlermeldung oder None zurück."""
    for old_uuid in list_wifi_profiles(ssid):
        nmcli_step("Altes Profil löschen", ["nmcli", "connection", "delete", "uuid", old_uuid])

    add_args = [
        "nmcli", "connection", "add",
        "type", "wifi",
        "ifname", WLAN_IFACE,
        "con-name", ssid,
        "ssid", ssid,
        *sec_args,
    ]
    result = nmcli_step("Profil anlegen", add_args)
    if result.returncode != 0:
        err = result.stderr.strip() or result.stdout.strip() or "unbekannter Fehler"
        return f"Profil anlegen fehlgeschlagen: {err}"

    uuids = list_wifi_profiles(ssid)
    if not uuids:
        return "Profil wurde angelegt, aber nicht gefunden."
    uuid = uuids[0]

    result = nmcli_step(
        "Profil aktivieren",
        ["nmcli", "connection", "up", "uuid", uuid, "ifname", WLAN_IFACE],
        timeout=45,
    )
    if result.returncode != 0:
        err = result.stderr.strip() or result.stdout.strip() or "unbekannter Fehler"
        # Nicht funktionierendes Profil (z. B. falsches Passwort) nicht liegen lassen.
        nmcli_step("Profil verwerfen", ["nmcli", "connection", "delete", "uuid", uuid])
        return f"Aktivieren fehlgeschlagen: {err}"

    return None


def connect_secured(ssid, password, security):
    mode = security_mode(security)

    if mode == "enterprise":
        return "Enterprise-WLANs (802.1X) werden hier nicht unterstützt."
    if mode == "wep":
        return "WEP-WLANs werden nicht unterstützt (unsicher)."
    if not (8 <= len(password) <= 63 or re.fullmatch(r"[0-9a-fA-F]{64}", password)):
        return "Das WLAN-Passwort muss 8 bis 63 Zeichen lang sein."

    return create_and_activate(ssid, [
        "802-11-wireless-security.key-mgmt", mode,
        "802-11-wireless-security.psk", password,
    ])


@app.post("/connect-new")
def connect_new():
    ssid = request.form.get("ssid", "").strip()
    password = request.form.get("password", "")

    if not ssid:
        return error_redirect("SSID fehlt")

    if len(ssid) > 255:
        return error_redirect("SSID ist zu lang")

    def find_network():
        return next((n for n in get_state()["networks"] if n["ssid"] == ssid), None)

    network = find_network()

    if network is None:
        refresh_state()  # evtl. neu hinzugekommen -> einmal frisch scannen
        network = find_network()

    if network is None:
        return error_redirect(
            f"WLAN '{ssid}' wurde beim Scan nicht gefunden."
        )

    security = network["security"].strip()

    with SCAN_LOCK:  # kein Hintergrund-Scan während des Verbindens
        if security:
            if not password:
                return error_redirect(
                    "Für dieses WLAN wird ein Passwort benötigt."
                )
            error = connect_secured(ssid, password, security)
        else:
            # Offenes WLAN: Profil ohne Security-Einstellungen.
            error = create_and_activate(ssid, [])

    if error:
        return error_redirect(error)

    refresh_state(rescan=False)
    return success_redirect(
        f"Mit '{ssid}' verbunden und als NetworkManager-Profil gespeichert."
    )


TEMPLATE = r"""
<!doctype html>
<html lang="de">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <title>Gast-WLAN Verwaltung</title>

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
        }
    </style>
</head>

<body>
<div class="container">

    <h1>Gast-WLAN Verwaltung</h1>
    <div class="subtitle">
        Verwaltet <strong>{{ iface }}</strong> und WireGuard (<strong>{{ wg.iface }}</strong>).
        Alle anderen Schnittstellen bleiben unangetastet.
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
                        Kein WLAN-Signal verfügbar
                    {% endif %}
                    {% if updated %}
                        · Stand: {{ updated }}
                    {% endif %}
                </div>
                <div class="signal">
                    Origin:
                    {% if origin_ip %}
                        <strong>{{ origin_ip }}</strong>
                    {% else %}
                        nicht gefunden
                    {% endif %}
                </div>
            </div>

            <button
                class="secondary"
                onclick="window.location.reload()">
                Aktualisieren
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
                        <span class="wg-off"> · Config fehlt</span>
                    {% elif wg.active %}
                        <span class="active"> · aktiv</span>
                    {% else %}
                        <span class="wg-off"> · inaktiv</span>
                    {% endif %}
                </div>
                <div class="signal">
                    {% if not wg.configured %}
                        {{ wg.conf }} nicht gefunden
                    {% elif wg.active and wg.handshake %}
                        Letzter Handshake {{ wg.handshake }}
                    {% elif wg.active %}
                        Tunnel läuft · Config: {{ wg.conf }}
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
        <h2>Gespeicherte WLANs</h2>

        {% if profiles %}
            {% for profile in profiles %}
                <div class="profile">
                    <div>
                        <strong>{{ profile.name }}</strong>

                        {% if profile.active %}
                            <span class="active"> · verbunden</span>
                        {% endif %}
                    </div>

                    <form method="post" action="/connect-profile">
                        <input
                            type="hidden"
                            name="uuid"
                            value="{{ profile.uuid }}">

                        <button type="submit">
                            Verbinden
                        </button>
                    </form>
                </div>
            {% endfor %}
        {% else %}
            <div class="empty">
                Noch keine gespeicherten WLAN-Profile gefunden.
            </div>
        {% endif %}
    </div>

    <div class="card">
        <h2>Verfügbare WLANs</h2>

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
                                    · Offen
                                {% endif %}
                            </div>
                        </div>

                        <button
                            type="button"
                            onclick='openWifiModal(
                                {{ network.ssid|tojson }},
                                {{ (network.security|length > 0)|tojson }}
                            )'>
                            Verbinden
                        </button>
                    </div>
                {% endfor %}
            </div>
        {% else %}
            <div class="empty">
                Keine WLANs gefunden.
            </div>
        {% endif %}
    </div>

    <div class="card">
        <h2>WLAN manuell hinzufügen</h2>

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
                placeholder="Passwort (bei offenem WLAN leer lassen)"
                autocomplete="new-password">

            <button type="submit">
                Speichern &amp; verbinden
            </button>
        </form>
    </div>

</div>

<div id="wifiModal" class="modal-backdrop">
    <div class="modal">
        <div class="modal-header">
            <h2 id="modalTitle">WLAN verbinden</h2>

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
                    WLAN-Passwort
                </label>

                <input
                    id="modalPassword"
                    name="password"
                    type="password"
                    autocomplete="new-password"
                    placeholder="Passwort">
            </div>

            <div id="openNetworkMessage"
                 style="display:none; margin-top:15px; color:#667085;">
                Dieses WLAN ist offen. Es wird ohne Passwort gespeichert.
            </div>

            <div class="modal-actions">
                <button
                    type="button"
                    class="secondary"
                    onclick="closeWifiModal()">
                    Abbrechen
                </button>

                <button type="submit">
                    Speichern &amp; verbinden
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
        modalTitle.textContent = "Mit „" + ssid + "“ verbinden";
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

    // Alte Meldungen (?error=/?success=) nach dem Anzeigen aus der URL entfernen,
    // damit sie beim automatischen Neuladen nicht ewig stehen bleiben.
    if (window.location.search) {
        history.replaceState(null, "", window.location.pathname);
    }

    // Alle 10 s neu laden - aber nicht, wenn der Nutzer gerade tippt
    // oder der Dialog offen ist (sonst ginge das eingegebene Passwort verloren).
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
