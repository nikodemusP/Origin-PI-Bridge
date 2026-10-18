#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECRETS_FILE="${PROJECT_DIR}/config/astroBridge/default.env"

die() { echo "FEHLER: $*" >&2; exit 1; }

echo "========================================"
echo " Astro Bridge Installer"
echo "========================================"
echo

if [[ "${EUID}" -ne 0 ]]; then
    echo "Bitte ausführen mit:"
    echo "  sudo ${PROJECT_DIR}/install.sh"
    exit 1
fi

if [[ ! -f "${SECRETS_FILE}" ]]; then
    echo "FEHLER: ${SECRETS_FILE} fehlt."
    echo
    echo "Bitte zuerst:"
    echo "  cp ${PROJECT_DIR}/secrets/default.env.example ${SECRETS_FILE}"
    echo "und die echten Secrets eintragen."
    exit 1
fi


chmod 600 "${SECRETS_FILE}"
# shellcheck disable=SC1090
source "${SECRETS_FILE}"

required=(
    ORIGIN_NETWORK_CLASS_C ORIGIN_MAC_LAN ORIGIN_IP
    HOTSPOT_IFACE HOTSPOT_WIFI_SSID HOTSPOT_WIFI_PASSWORD
    GUEST_WIFI_IFACE GUEST_WIFI_PORT
)
#    HOME_NETWORK_CLASS_C WG_NETWORK_CLASS_C WG_IFACE

for v in "${required[@]}"; do
    [[ -n "${!v:-}" ]] || die "${v} fehlt in ${SECRETS_FILE}"
done

install -d -m 0755 /etc/astroBridge
install -m 0640 "${SECRETS_FILE}" /etc/astroBridge/default.env

render() {
    local src="$1" dst="$2" content v
    content="$(<"${src}")"
    for v in "${required[@]}"; do
        content="${content//@${v}@/${!v}}"
    done
    if grep -qE '@[A-Z_]+@' <<<"${content}"; then
        echo "FEHLER: Nicht ersetzte Platzhalter in ${src}:"
        grep -noE '@[A-Z_]+@' <<<"${content}"
        exit 1
    fi
    printf '%s\n' "${content}" > "${dst}"
}

#
echo "[1/11] Systempakete installieren"
apt-get update
apt-get install -y \
    network-manager \
    dnsmasq \
    nftables \
    wireguard \
    wireguard-tools \
    python3-full \
    python3-venv \
    iptables-persistent \
    iptables \
    netfilter-persistent \
    openresolv


# --- Ip Forwarding --------------------------------------
echo "[2/11] IPv4 Forwarding + Konfiguration"
cat > /etc/sysctl.d/99-astro-bridge.conf <<'SYSCTL'
net.ipv4.ip_forward=1
SYSCTL
sysctl --system >/dev/null

CON="${HOTSPOT_WIFI_SSID}"
ETH0="Wired connection 1"
# --- Clean up existing connections --------------------------------------
echo "[3/11] Cleanup"
nmcli connection delete "${CON}" 2>/dev/null || true
nmcli connection delete "${ETH0}" 2>/dev/null || true
nmcli connection delete br0-eth0 2>/dev/null || true
nmcli connection delete br0-wlan0 2>/dev/null || true
nmcli connection delete br0 2>/dev/null || true

# --- Create the bridge --------------------------------------
echo "[4/11] Bridge br0 erstellen"
nmcli connection add type bridge con-name br0 ifname br0
nmcli connection modify br0 ipv4.addresses "${ORIGIN_NETWORK_CLASS_C}.1/24" ipv4.method manual

# --- ETH0 --------------------------------------
echo "[5/11] ETH0 konfigurieren"
nmcli connection add type ethernet con-name br0-eth0 ifname eth0 master br0
nmcli connection add type ethernet con-name br0-eth0 ifname eth0 master br0 connection.slave-type bridge
nmcli connection modify br0-eth0 ipv4.method disabled ipv6.method ignore

# --- Create the Hotspot WiFi network --------------------------------------
echo "[6/11] Hotspot WiFi konfigurieren"
nmcli connection add type wifi ifname "${HOTSPOT_IFACE}" \
  con-name br0-wlan0 \
  master br0 \
  connection.slave-type bridge \
  autoconnect yes \
  connection.autoconnect-priority 100 \
  ssid "${HOTSPOT_WIFI_SSID}" \
  802-11-wireless.mode ap \
  802-11-wireless.band bg \
  802-11-wireless.channel 6 \
  wifi-sec.key-mgmt wpa-psk \
  wifi-sec.psk "${HOTSPOT_WIFI_PASSWORD}" \
  wifi-sec.proto rsn \
  wifi-sec.pairwise ccmp \
  wifi-sec.group ccmp \
  wifi-sec.pmf optional

echo "[7/11] Bridge und WiFi-Verbindungen aktivieren"
sudo nmcli connection up br0
sudo nmcli connection up br0-eth0
sudo nmcli connection up br0-wlan0

echo "[8/11] Aktive Verbindungen anzeigen"
nmcli connection show --active
nmcli device status

# --- Start the DNSMasq service --------------------------------------------
echo "[9/11] dnsmasq (Hotspot + Origin)"
render "${PROJECT_DIR}/config/dnsmasq/astrobridge.temp" /etc/dnsmasq.d/astrobridge.conf
chmod 0644 /etc/dnsmasq.d/astrobridge.conf
dnsmasq --test
systemctl enable dnsmasq
systemctl restart dnsmasq


# --- Install the Hotspot Webserver (Flask) --------------------------------------
echo "[10/11] GUEST_WIFI-Webseite installieren"
install -d -m 0755 /opt/astrobridge/app
install -m 0755 \
    "${PROJECT_DIR}/scripts/guest-wifi.py" \
    /opt/astrobridge/app/guest-wifi.py

if [[ ! -d /opt/astrobridge/venv ]]; then
    python3 -m venv /opt/astrobridge/venv
fi
/opt/astrobridge/venv/bin/pip install --upgrade pip
/opt/astrobridge/venv/bin/pip install -r "${PROJECT_DIR}/python/requirements.txt"

install -m 0644 \
    "${PROJECT_DIR}/config/systemd/guestwifi.service" \
    /etc/systemd/system/guestwifi.service

systemctl daemon-reload
systemctl enable guestwifi
systemctl restart guestwifi

# --- Post-Installation: Firewall-Regeln setzen --------------------------------------
echo "[11/11] Post-Installation: Firewall-Regeln setzen"
# Forward traffic to wlan1 (Internet Uplink)
iptables -t nat -A POSTROUTING -o wlan1 -j MASQUERADE
# WICHTIG: Traffic zwischen WireGuard (wg0) und der Brücke (br0) erlauben
iptables -A FORWARD -i wg0 -o br0 -j ACCEPT
iptables -A FORWARD -i br0 -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT
# Regeln dauerhaft speichern
netfilter-persistent save

