# Astro Bridge for Raspberry Pi

Astro Bridge turns a Raspberry Pi running Raspberry Pi OS (Debian) into a
network bridge for a Celestron Origin telescope and provides a lightwight web interface
for managing the device's guest Wi-Fi connection. The interface also reports
the telescope's reachability and can control an optional WireGuard tunnel.

## Features

- Creates a `br0` bridge between the Ethernet connection (`eth0`) and a
  dedicated Wi-Fi hotspot (normally `wlan0`).
- Runs `dnsmasq` to provide DHCP on the bridge network and a fixed lease for
  the Origin telescope.
- Uses a second Wi-Fi interface (normally `wlan1`) as the Internet uplink.
- Provides a web page to scan for Wi-Fi networks, connect to them, and manage
  saved NetworkManager profiles.
- Displays Wi-Fi signal, Origin reachability, and WireGuard status.
- Allows WireGuard to be activated or deactivated from the web page when a
  tunnel configuration is installed.

## Requirements

- Three network interfaces for the configured setup:

  | Interface | Role |
  | --- | --- |
  | `eth0` | Ethernet connection to the Origin telescope (directly or through a switch). |
  | `wlan0` | Wi-Fi hotspot for devices connecting to Astro Bridge. |
  | `wlan1` | Separate Wi-Fi uplink to the guest network and Internet. On a typical Raspberry Pi, this means adding a compatible USB Wi-Fi adapter. |

  The installer currently uses `eth0` and `wlan1` directly. The hotspot and
  web-app interfaces are set in `config/astroBridge/default.env`. Confirm your
  actual interface names and adapter capabilities before installation; they
  can vary with Raspberry Pi model, OS image, and attached adapters.

## Configuration

Edit `config/astroBridge/default.env` before installation. It is a shell-style
environment file that the installer sources, so use valid shell quoting for
values containing spaces or special characters. Replace the example/default
values, especially the hotspot password, with values for your setup.

| Variable | Purpose |
| --- | --- |
| `ORIGIN_NETWORK_CLASS_C` | First three octets of the bridge subnet, for example `10.10.0`. The bridge address is set to `.1`. |
| `ORIGIN_IP` | Fixed IP address reserved for the Origin telescope. |
| `ORIGIN_MAC_LAN` | Origin telescope's MAC address, used for its DHCP reservation. |
| `HOTSPOT_IFACE` | Wi-Fi interface used to broadcast the hotspot. |
| `HOTSPOT_WIFI_SSID` | Hotspot network name. |
| `HOTSPOT_WIFI_PASSWORD` | WPA-PSK password for the hotspot. |
| `GUEST_WIFI_IFACE` | Wi-Fi interface managed by the web app, normally the uplink interface. |
| `GUEST_WIFI_HOST` | Web-app bind address; the default configuration uses `0.0.0.0`. |
| `GUEST_WIFI_PORT` | Web-app port; the default configuration uses port `80`. |

The DHCP range is `.50`–`.100`, and the bridge gateway is `.1` within the
configured subnet. The current dnsmasq configuration advertises public DNS
resolvers (`8.8.8.8` and `1.1.1.1`).

## Installation

1. Install Raspberry Pi OS on the Raspberry Pi, connect it to the Internet,
   and copy or clone this project onto the Pi.
2. Identify the Pi's network interfaces:

   ```bash
   ip -brief link
   ```

   Confirm that the interface intended for the Origin connection is `eth0`,
   that the hotspot adapter is configured as `wlan0`, and that the separate
   Wi-Fi uplink is `wlan1`. The installer installs NetworkManager, which it
   uses to manage these connections. Check that the Wi-Fi adapter used for the
   hotspot supports access-point mode.
3. Review and edit the configuration:

   ```bash
   nano config/astroBridge/default.env
   ```

4. Set the Origin network, hotspot name and password, and interface names to
   match your setup. The installer currently uses `eth0` for its Ethernet
   bridge port and `wlan1` for Internet NAT; changing only the environment
   file does not change those hard-coded installer references.
5. Run the installer from the project directory:

   ```bash
   sudo ./install.sh
   ```

The installer installs system packages, configures the bridge and DHCP,
installs the Flask application and its Python dependencies in a virtual
environment, and enables the `dnsmasq` and `guestwifi` systemd services.

## Using the web interface

Connect a device to the configured hotspot and open the bridge gateway in a
browser. With the default subnet, the address is:

```text
http://10.10.0.1/
```

If you changed `ORIGIN_NETWORK_CLASS_C`, use `http://<subnet>.1/` instead.
The page can show nearby access points, connect to supported networks, reconnect
to or delete saved Wi-Fi profiles, and display the Origin and WireGuard status.
It refreshes its status periodically.

The web application binds to all interfaces by default and does not provide
authentication. Keep it on a trusted network and do not expose it to the
Internet or an untrusted LAN.

## Optional WireGuard tunnel

The installer installs WireGuard tools but does **not** install the sample
`config/wireguard/wg0.conf`. To use the web interface's WireGuard controls,
create a valid configuration with your own keys and endpoint, then install it
on the target device:

```bash
sudo install -D -m 600 /path/to/wg0.conf /etc/wireguard/wg0.conf
```

Never commit private or preshared keys to the repository. The web app derives
the tunnel interface name from the configuration filename, so `wg0.conf`
corresponds to interface `wg0`.

## Service management

```bash
sudo systemctl status guestwifi
sudo systemctl status dnsmasq
sudo journalctl -u guestwifi -f
sudo journalctl -u dnsmasq -f
```

To restart the web application after changing its installed configuration:

```bash
sudo systemctl restart guestwifi
```


