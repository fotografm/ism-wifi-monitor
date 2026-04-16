# ism-wifi-monitor

Passive WiFi, GPS and ISM radio monitoring platform for Raspberry Pi.
Runs headless with a browser-based UI served from the Pi itself.

## Hardware

| Component | Role |
|---|---|
| Raspberry Pi 4B or Pi Zero 2W | Host |
| Onboard WiFi (wlan0) | Hotspot — serves the web UI to connected clients |
| MT7612U USB dongle (wlan1) | Passive 802.11 monitor — scans all channels |
| RTL-SDR dongle | ISM radio monitor — 433/868/315 MHz (optional) |
| G72 GPS dongle | Location tagging, satellite display |
| Powered USB hub | Required on Pi Zero 2W (three USB devices, one port) |

## Installation

### Pi 4B (raspi81 or similar)

```bash
git clone https://github.com/fotografm/ism-wifi-monitor.git
cd ism-wifi-monitor
sudo bash install.sh
```

### Pi Zero 2W (raspi82 or similar)

The Pi Zero 2W has a single USB port so a **powered USB hub is required**.
The install script auto-detects the MT7612U interface name (may differ from wlan1)
and sets the hotspot SSID to match the Pi's hostname.

Prerequisites before running:
- Pi is running Raspberry Pi OS Bookworm Lite 32-bit headless
- Hotspot is already configured on wlan0 via NetworkManager
- MT7612U and GPS dongles are plugged into the USB hub
- Pi is reachable by SSH

```bash
git clone https://github.com/fotografm/ism-wifi-monitor.git
cd ism-wifi-monitor
sudo bash install_pizero.sh
```

After install, reboot to verify all services start cleanly:

```bash
sudo reboot
```

## Services

All services are managed by systemd and can be controlled via the **Services page**
at `http://<pi-ip>:8098`.

| Service | Port | Notes |
|---|---|---|
| ism-wifi-landing | 80 | Main landing page |
| ism-wifi-wifi-web | 8091 | WiFi APs, channel usage |
| ism-wifi-ism | 8092 | ISM live feed (RTL-SDR required) |
| ism-wifi-gps | 8093 | GPS dashboard |
| ism-wifi-skymap3d | 8094 | 3D satellite skymap (RTL-SDR required) |
| ism-wifi-history-web | 8095 | WiFi probe history |
| ism-wifi-terminal | 8096 | Browser terminal |
| ism-wifi-notes | 8097 | Persistent notes |
| ism-wifi-services | 8098 | Service control + DB management |
| ism-wifi-wifi-scan | — | WiFi frame capture (root) |
| ism-wifi-history-monitor | — | Probe request recorder (root) |

## RTL-SDR on Pi Zero 2W

The MT7612U and RTL-SDR **cannot be used simultaneously** on Pi Zero 2W — they
share a single USB bus and the combined bandwidth causes USB resets.

To switch between them:
1. Stop the relevant service on the Services page
2. Unplug one dongle, plug in the other
3. Start the relevant service

If RTL-SDR is not connected, stop its services to avoid error spam:

```bash
sudo systemctl stop ism-wifi-ism ism-wifi-skymap3d
```

## Network

- `wlan0` — hotspot, managed by NetworkManager, SSID = hostname
- `wlan1` — MT7612U in monitor mode, unmanaged by NetworkManager

The monitor interface is automatically set to unmanaged so NetworkManager
never interferes with monitor mode or channel hopping.

## Databases

All data is stored in SQLite under `~/ism-wifi-monitor/db/`:

| File | Contents |
|---|---|
| wifi_logger.db | Access points, sightings, client associations |
| wifi_history.db | Probe requests, device fingerprints |
| ism_monitor.db | ISM signals, transmitters |
| gps_history.db | Satellite position history |

Databases can be cleared individually from the Services page without stopping services.

## Updating

To deploy updated files from h510 to a running Pi:

```bash
# From h510, inside the repo directory:
scp <files> user@<pi-ip>:/home/user/ism-wifi-monitor/
ssh -t user@<pi-ip> "sudo systemctl restart <service>"
```
