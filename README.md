# ism-wifi-monitor

> **Legal and ethical notice**
>
> This project was built for personal research — specifically to monitor and
> understand the radio behaviour of my own fixed and mobile devices, learn how
> 802.11 and ISM radio protocols work in practice, and identify what information
> my own equipment broadcasts passively.
>
> I do not advocate using this software to monitor devices you do not own or
> for which you do not have explicit permission from the owner. Passive radio
> monitoring laws vary significantly by country and jurisdiction. In many places
> capturing and storing radio transmissions from third-party devices — even
> passively — may be restricted or prohibited without consent.
>
> **Check the laws in your jurisdiction before deploying this software.**
>
> The author accepts no responsibility for the actions of anyone who uses this
> software. By using it you accept full responsibility for ensuring your use is
> lawful and ethical.

---

A passive radio monitoring platform for Raspberry Pi. Captures and analyses
802.11 WiFi frames, ISM band radio signals (433/868/315 MHz), and GPS data.
Runs completely headless — the Pi serves its own browser-based UI over a WiFi
hotspot. No cloud, no external services, no display required.

---

## What it does

### WiFi monitoring
The system places a USB WiFi adapter (MT7612U AC1300) in monitor mode and
captures all 802.11 frames in range across all channels. It passively
collects:

- **Access points** — every AP detected, with SSID, BSSID, encryption type,
  channel, signal strength, GPS coordinates, first/last seen timestamps
- **Client associations** — which devices are connecting to which APs, using
  DS bit analysis of data frames to determine direction
- **Probe requests** — directed probes reveal which networks a device has
  previously joined, even when the device uses MAC address randomisation
- **Device fingerprints** — a SHA-256 hash of the 802.11 Information Elements
  in each probe request (IE IDs, HT/VHT capability bytes, vendor OUIs) creates
  a stable fingerprint that identifies the same physical device across MAC
  rotation

### ISM radio monitoring
An RTL-SDR dongle feeds raw IQ samples into rtl_433, which decodes hundreds of
device types broadcasting on 433 MHz, 868 MHz and 315 MHz. This includes
weather stations, TPMS tyre pressure sensors, remote controls, smart meters,
door bells and many other devices. Decoded signals are displayed in a live feed
with GPS tagging and plotted on a map.

### GPS
A u-blox USB GPS receiver provides real-time position for geotagging all WiFi
sightings and ISM signals. A 3D satellite skymap shows satellite positions and
signal strengths. All sightings stored with GPS coordinates are displayed on
interactive Leaflet maps with tile caching for offline use.

### WiFi history
A separate passive sniffer records probe requests into a history database with
device fingerprinting. The history section shows directed SSIDs (networks
devices are searching for), device fingerprint profiles, association frames,
and per-device probe history — all useful for understanding which devices have
been in range and which networks they have previously connected to.

---

## Hardware

### Tested configurations

| Component | Pi 4B (raspi81) | Pi Zero 2W (raspi82) |
|---|---|---|
| Host | Raspberry Pi 4B 4GB | Raspberry Pi Zero 2W 1GB |
| Hotspot | Onboard BCM43455 (wlan0) | Onboard BCM43438 (wlan0) |
| WiFi monitor | MT7612U USB dongle (wlan1) | MT7612U USB dongle (wlan1) |
| ISM radio | RTL-SDR Blog V3 dongle | RTL-SDR Blog V3 dongle (optional) |
| GPS | Geekstory G72 u-blox M8130 | Geekstory G72 u-blox M8130 |
| USB hub | Not required | Powered USB hub (essential) |
| Ethernet | Optional | USB ethernet dongle (for setup) |

### Why a powered USB hub on Pi Zero 2W?

The Pi Zero 2W has a single USB 2.0 OTG port. With GPS, WiFi dongle and
optionally RTL-SDR all connected simultaneously, a passive hub cannot supply
enough current. A powered hub is mandatory — without it you will see USB
device resets and GPS signal loss under load.

### MT7612U WiFi adapter

The Mediatek MT7612U is a dual-band AC1300 USB adapter. It is well supported
in mainline Linux via the `mt76x2u` driver with no firmware files needed. It
supports monitor mode natively. The adapter must be set unmanaged in
NetworkManager so that NetworkManager never takes it out of monitor mode or
changes its channel.

### RTL-SDR dongle

Any RTL2832U based SDR dongle will work. The RTL-SDR Blog V3 has better
sensitivity and an improved oscillator. On Pi Zero 2W the RTL-SDR and MT7612U
**cannot run simultaneously** due to USB bandwidth constraints — use the
Services page to stop one before starting the other.

### GPS receiver

The Geekstory G72 uses a u-blox UBX-M8130 chip with 72 channels supporting
GPS, GLONASS, BeiDou and QZSS. It communicates at 9600 baud over USB CDC-ACM
(`/dev/ttyACM0`). The device has no backup battery — it does a full cold start
whenever power is removed, which takes 30-60 seconds to acquire a fix in good
conditions.

**Important:** The ceramic patch antenna on the G72 must face skyward. The
flat side of the dongle must point up. Installing it upside down results in
severely degraded GPS performance with weak or no satellite reception.

---

## Architecture

### 5 GHz hotspot — outdoor legal compliance (Germany / EU)

The hotspot is configured on **channel 100 (5500 MHz)** in the 5470–5725 MHz band
with `ieee80211h=1` (DFS + TPC enabled).

**Why this matters:**
The lower 5 GHz band (5150–5350 MHz, channels 36–64) is restricted to **indoor
use only** across the entire EU. The 5470–5725 MHz band (channels 100–140) is
permitted both indoors and outdoors in Germany and the EU, provided that
Dynamic Frequency Selection (DFS) and Transmit Power Control (TPC) are active.

**Applicable regulation:**
- **ETSI EN 301 893 V2.1.1** — Harmonised EU standard for 5 GHz RLAN, mandating
  DFS per ITU-R M.1652 and TPC for the 5470–5725 MHz band.
- **Commission Implementing Decision (EU) 2021/1067** — amends Decision
  2005/513/EC harmonising the 5 GHz band across EU member states, permitting
  outdoor use of 5470–5725 MHz subject to DFS and TPC.
- **Bundesnetzagentur Allgemeinzuteilung Vfg. 17/2021** — German national
  implementation; permits outdoor 5470–5725 MHz RLAN use under the same
  DFS/TPC conditions.

**What DFS means in practice:**
On first boot (or after any restart of hostapd), the radio performs a **radar
detection scan of up to 60 seconds** before the channel becomes active. This is
mandatory — the 5470–5725 MHz band is shared with weather and military radar,
and DFS ensures the WLAN vacates the channel immediately if radar pulses are
detected. The hotspot will appear unavailable during this scan.

The configuration file is in `config/hostapd.conf`.

---

### Hotspot-first design

The Pi serves its UI over a WiFi hotspot (wlan0) rather than relying on an
existing network. This makes the system completely self-contained and portable
— you connect your laptop or phone directly to the Pi's hotspot and access
the UI at `http://10.42.0.1`. The Pi also works on an existing Ethernet
network (accessible by its Ethernet IP) but the hotspot is always available
regardless of network infrastructure.

### Port layout

| Port | Service | Technology |
|---|---|---|
| 80 | Landing page | aiohttp |
| 8091 | WiFi web (APs, channels, map) | Flask |
| 8092 | ISM monitor (live feed, map) | aiohttp + WebSocket |
| 8093 | GPS dashboard | Flask |
| 8094 | 3D satellite skymap | Flask |
| 8095 | WiFi history | aiohttp |
| 8096 | Browser terminal | aiohttp + PTY WebSocket |
| 8097 | Notes | aiohttp |
| 8098 | Services control | aiohttp |

### Database design

Four SQLite databases store data independently:

**wifi_logger.db** — Core WiFi scanner data
- `access_points` — one row per BSSID, updated on every beacon
- `sightings` — GPS-tagged sightings of each AP, throttled to avoid redundant writes
- `associations` — 802.11 association and authentication frames
- `client_sightings` — data-frame derived client↔AP relationships

**wifi_history.db** — Probe request history
- `probe_requests` — every directed probe request with source MAC and SSID
- `ie_fingerprints` — one fingerprint per unique IE profile
- `mac_fp_map` — maps each MAC to its fingerprint (handles MAC rotation)
- `beacons` — beacon frame records from the history monitor
- `associations` — association frames from the history monitor

**ism_monitor.db** — ISM signal data
- `signals` — every decoded rtl_433 signal with model, device ID, data, GPS
- `transmitters` — aggregated per-device statistics

**gps_history.db** — GPS satellite history
- `sat_history` — per-satellite azimuth, elevation and signal strength over time

All databases use WAL journal mode for concurrent read performance. They can
be cleared individually from the Services page — each is reinitialised with
empty tables immediately after clearing so services continue without errors.

### WiFi frame capture

`wifi_scanner.py` uses Scapy to capture raw 802.11 frames on the monitor
interface. It handles three frame classes:

**Beacon frames (management subtype 8) and Probe responses (subtype 5):**
These are the primary source of AP data. Each frame is parsed for SSID, BSSID,
encryption (WEP/WPA/WPA2/WPA3 via RSN IE and WPA vendor IE parsing), channel
(from the DS Parameter Set IE), frequency, and 802.11 capability flags.
Signal strength comes from the RadioTap header. GPS position is sampled at
capture time and written with each sighting.

**Association frames (management subtypes 0, 1, 2, 3, 11):**
Association request, response, reassociation request/response and
authentication frames explicitly reveal client MAC to AP BSSID relationships.
These are rate-limited to one write per (client, bssid, subtype) combination
per 5 seconds to avoid database flooding during repeated auth attempts.

**Data frames (type 2):**
Every data frame passing between a client and its AP contains both MACs. The
DS bits in the Frame Control field reveal direction: ToDS=1/FromDS=0 means
client→AP (addr2=client, addr1=BSSID), ToDS=0/FromDS=1 means AP→client
(addr1=client, addr2=BSSID). This is the most reliable method for building a
continuous picture of which clients are actively associated with which APs.
Channel is read from the RadioTap header rather than walking the IE chain
(data frames have no IEs). Rate limited to one write per (client, bssid) per
30 seconds.

A channel hopper runs in a separate thread, stepping through all 2.4 GHz
and 5 GHz channels with configurable dwell time. The scanner uses thread-local
SQLite connections to avoid locking issues.

### Device fingerprinting

The `ie_parser.py` module extracts 802.11 Information Elements from probe
request frames and computes a SHA-256 fingerprint from:

1. The sorted set of IE IDs present in the frame (identifies which
   capabilities the device advertises)
2. The raw bytes of the HT Capabilities IE (ID 45) — 26 bytes encoding
   802.11n radio capabilities specific to the chipset
3. The raw bytes of the VHT Capabilities IE (ID 191) — 12 bytes encoding
   802.11ac capabilities, only present on 5 GHz capable devices
4. The sorted list of vendor OUIs from Vendor Specific IEs (ID 221) —
   identifies proprietary extensions like Apple AWDL, Microsoft WMM, Wi-Fi
   Alliance P2P

This combination produces a hash that is stable across MAC address rotation
because none of these elements contain the MAC address. Two probe requests
from the same physical device with different randomised MACs produce identical
hashes as long as the driver version has not changed. The fingerprint changes
only when firmware is updated.

### ISM monitor watchdog

`ism_monitor.py` includes a watchdog coroutine that monitors rtl_433 output.
If no signal is received for 5 minutes (with a 2 minute grace period at
startup) the watchdog kills and restarts the rtl_433 process. This handles
the case where the RTL-SDR USB device hangs with the device claimed but
producing no data — a condition that occurs occasionally with RTL-SDR dongles
under sustained use.

---

## Initial setup

### Flash and configure the Pi

Use **Raspberry Pi Imager** to flash Raspberry Pi OS Bookworm Lite (32-bit
recommended for Pi Zero 2W, 64-bit fine for Pi 4B). In the Imager settings:

- Set hostname (e.g. `raspi81` or `raspi82`)
- Enable SSH with a password or public key
- Set your WiFi credentials for initial internet access
- Set WiFi country to your country code (e.g. `DE` for Germany)

Do not create a manual `wpa_supplicant.conf` or empty `ssh` file — these are
obsolete in Bookworm. Use the Imager settings form only.

### SSH in and update

```bash
ssh user@<ip-address>
sudo apt update && sudo apt upgrade -y
```

### Clone and install

**Pi 4B:**
```bash
git clone https://github.com/fotografm/ism-wifi-monitor.git
cd ism-wifi-monitor
sudo bash install.sh
```

**Pi Zero 2W:**
```bash
sudo apt install -y git
git clone https://github.com/fotografm/ism-wifi-monitor.git
cd ism-wifi-monitor
sudo bash install_pizero.sh
```

The install script will:
1. Install system packages (`gpsd`, `rtl-433`, `iw`, `rfkill`, `sqlite3`)
2. Detect the MT7612U interface name and patch `config.py` if not `wlan1`
3. Create the deployment directory and copy all files
4. Create a Python venv and install dependencies
5. Download the IEEE OUI database for vendor lookup
6. Initialise all SQLite databases
7. Configure gpsd to use `/dev/ttyACM0`
8. Enable WiFi, bring up wlan0, set the hotspot SSID to the hostname
9. Create the hotspot if it does not exist (password: `password`)
10. Mark the monitor interface as unmanaged in NetworkManager
11. Install and enable all systemd services

After install:
```bash
sudo systemctl start rfkill-unblock ism-wifi-landing ism-wifi-gps \
  ism-wifi-wifi-scan ism-wifi-wifi-web ism-wifi-history-monitor \
  ism-wifi-history-web ism-wifi-terminal ism-wifi-notes ism-wifi-services
sudo reboot
```

### Access the UI

Connect your device to the `raspi81` (or `raspi82`) WiFi hotspot.
Password: `password`

Open `http://10.42.0.1` in your browser.

If accessing over Ethernet, use the Pi's Ethernet IP address instead.

---

## GPS notes

The G72 receiver has no backup battery. Every time USB power is removed it
loses its almanac and ephemeris data and must do a full cold start. Cold start
time is typically 30-60 seconds outdoors with clear sky view. After a cold
start it may take 5-15 minutes for the full almanac to download, during which
satellite count will be low.

If the receiver is not getting a fix:

1. **Check antenna orientation** — the flat ceramic patch must face skyward
2. **Check gpsd config** — `/etc/default/gpsd` must have `DEVICES="/dev/ttyACM0"`
3. **Force a cold start** — `sudo ubxtool -p COLDSTART`
4. **Check raw output** — `sudo systemctl stop gpsd && sudo timeout 10 cat /dev/ttyACM0`
   should show NMEA sentences. `ANTSTATUS=OK` confirms the antenna is connected.

The GPS dashboard is at `http://<ip>:8093`. The 3D skymap is at port 8094.

---

## RTL-SDR notes

The ISM monitor uses `rtl_433` with a 5-minute watchdog. Signals are decoded
from 433 MHz, 868 MHz and 315 MHz and displayed in a live WebSocket feed.
Decoded device types include weather stations, TPMS sensors, remote controls
and many others — see the rtl_433 documentation for the full device list.

If the RTL-SDR is not connected the ISM services will fail silently. Stop them
from the Services page at port 8098 to avoid log spam.

**Pi Zero 2W:** The MT7612U and RTL-SDR cannot run simultaneously. The MT7612U
uses too much USB bandwidth when combined with the RTL-SDR's IQ stream. Use
the Services page to stop one before starting the other, then physically swap
the dongles.

---

## Services page

The Services page at `http://<ip>:8098` provides:

- **Real-time service status** — live systemd status with green/red indicators
  polling every 5 seconds. A crashed service shows red immediately.
- **Start/Stop buttons** — start or stop individual services without SSH
- **Database management** — shows current row counts and file sizes for all
  four databases. Each database has a Clear button with a confirmation step.
  Clearing a database reinitialises it with empty tables immediately so
  services continue without errors.

---

## Customisation

### Changing the hotspot SSID and password

```bash
sudo nmcli con modify <connection-name> 802-11-wireless.ssid "new-ssid"
sudo nmcli con modify <connection-name> wifi-sec.psk "new-password"
sudo nmcli con up <connection-name>
```

### Changing the monitor interface

If the MT7612U enumerates as something other than `wlan1`, update
`/home/user/ism-wifi-monitor/config.py`:

```python
WIFI_IFACE = 'wlan2'  # or whatever iw dev shows
```

Then update the NM unmanaged config:
```bash
sudo bash -c 'echo "[keyfile]
unmanaged-devices=interface-name:wlan2" > /etc/NetworkManager/conf.d/99-ism-wifi-unmanaged.conf'
sudo systemctl reload NetworkManager
sudo systemctl restart ism-wifi-wifi-scan ism-wifi-history-monitor
```

### Adjusting channel dwell time

In `config.py`, `CHANNEL_DWELL` controls how long the scanner stays on each
channel before hopping. The default is 0.3 seconds. Increase this to capture
more frames per channel at the cost of slower full-spectrum coverage.

### Tile caching

The WiFi map and GPS map use OpenStreetMap tiles. Tiles are cached locally
in `~/ism-wifi-monitor/tile_cache/` after first access. The ISM settings page
has a tile pre-cache function to download tiles for your area in advance for
offline use.

---

## Troubleshooting

### Services not starting

Check the journal:
```bash
sudo journalctl -u ism-wifi-wifi-scan --since "5 min ago" --no-pager
```

Common causes:
- `RTNETLINK: Operation not possible due to RF-kill` — run `sudo rfkill unblock all`
- `name '_parse_ssid' is not defined` — redeploy `wifi_scanner.py` from the repo
- `no such table: associations` — the database was not initialised, run
  `python3 db_wifi.py` from the venv

### GPS not working

- Check `sudo gpspipe -w -n 5` — if it hangs, gpsd is not connected to the device
- Check `/etc/default/gpsd` has `DEVICES="/dev/ttyACM0"` not `DEVICES=""`
- Check `sudo dmesg | grep ttyACM` confirms the device is present
- Check antenna orientation — flat side must face up

### WiFi scanner not seeing APs

- Check `iw dev` shows wlan1 in monitor mode
- Check `sudo systemctl status ism-wifi-wifi-scan` for errors
- The Pi Zero 2W's onboard WiFi being active as a hotspot can cause minor
  interference but should not prevent the MT7612U from working

### Web UI not loading

- Check the relevant service: `sudo systemctl status ism-wifi-landing`
- Check the venv exists: `ls ~/ism-wifi-monitor/venv/bin/python`
- Check port conflicts: `sudo ss -tlnp | grep <port>`

---

## File structure

```
ism-wifi-monitor/
├── config.py                   # All configuration constants
├── db_wifi.py                  # WiFi database schema + init
├── db_history.py               # WiFi history database schema + init
├── db_ism.py                   # ISM database schema + init
├── gps_reader_async.py         # Async gpsd client
├── gps_reader_sync.py          # Sync gpsd client (for scanner thread)
├── ie_parser.py                # 802.11 IE parser + SHA-256 fingerprinting
├── oui.py                      # IEEE OUI vendor lookup
├── wifi_scanner.py             # Main WiFi frame capture (runs as root)
├── wifi_web.py                 # Flask WiFi web server (port 8091)
├── wifi_history_monitor.py     # Passive probe request recorder (runs as root)
├── wifi_history_web.py         # WiFi history aiohttp server (port 8095)
├── ism_monitor.py              # ISM monitor + rtl_433 wrapper (port 8092)
├── gps_web.py                  # GPS dashboard Flask server (port 8093)
├── skymap3d.py                 # 3D satellite skymap Flask server (port 8094)
├── landing_server.py           # Landing page aiohttp server (port 80)
├── terminal_server.py          # PTY terminal aiohttp server (port 8096)
├── notes_server.py             # Notes aiohttp REST server (port 8097)
├── services_server.py          # Services control aiohttp server (port 8098)
├── raspi-style.css             # Shared dark theme stylesheet
├── config/
│   └── hostapd.conf            # 5 GHz hotspot config (ch 100, DFS, outdoor-legal DE/EU)
├── install.sh                  # Installer for Pi 4B
├── install_pizero.sh           # Installer for Pi Zero 2W
├── data/
│   └── oui.csv                 # IEEE OUI vendor database
├── templates/                  # Jinja2 / standalone HTML templates
│   ├── landing.html
│   ├── wifi_index.html         # Channel usage dashboard
│   ├── wifi_aps.html           # Sortable AP list
│   ├── wifi_ap_detail.html     # Per-AP detail with clients and map
│   ├── wifi_map.html           # Leaflet AP map
│   ├── ism_feed.html           # Live ISM signal feed
│   ├── ism_map.html            # ISM transmitter map
│   ├── ism_settings.html       # ISM settings + tile cache
│   ├── history_base.html       # Shared history page base template
│   ├── history_index.html      # Recent probe requests
│   ├── history_ssids.html      # Directed SSID list with device chips
│   ├── history_devices.html    # Device fingerprint list
│   ├── history_device_detail.html
│   ├── history_aps.html        # Beacon-derived AP history
│   ├── history_associations.html
│   ├── history_probes.html
│   ├── terminal.html           # xterm.js browser terminal
│   ├── notes.html              # Two-panel notes app
│   └── services.html           # Services control panel
└── systemd/                    # systemd service unit files
    ├── rfkill-unblock.service
    ├── ism-wifi-landing.service
    ├── ism-wifi-wifi-scan.service
    ├── ism-wifi-wifi-web.service
    ├── ism-wifi-history-monitor.service
    ├── ism-wifi-history-web.service
    ├── ism-wifi-ism.service
    ├── ism-wifi-skymap3d.service
    ├── ism-wifi-gps.service
    ├── ism-wifi-terminal.service
    ├── ism-wifi-notes.service
    └── ism-wifi-services.service
```

---

## Dependencies

Python packages (installed in venv):

| Package | Use |
|---|---|
| aiohttp | Async HTTP/WebSocket servers |
| flask | Synchronous web routes |
| scapy | Raw 802.11 packet capture |
| manuf | OUI vendor lookup (fallback) |
| aiofiles | Async file I/O |

System packages:

| Package | Use |
|---|---|
| gpsd, gpsd-clients | GPS daemon and tools |
| rtl-433 | ISM signal decoder |
| iw | WiFi interface control |
| rfkill | Radio kill switch control |
| sqlite3 | Database CLI |

---

## Colour scheme

All pages use a consistent dark theme defined in `raspi-style.css`:

| Variable | Value | Use |
|---|---|---|
| `--bg` | `#080818` | Page background |
| `--panel` | `#0d0d20` | Card/panel background |
| `--border` | `#4a4a8a` | Panel borders |
| `--text` | `#f0f0ff` | Body text |
| `--heading` | `#8888cc` | Section headings |
| `--value-green` | `#88ee88` | Positive values, good signal |
| `--value-warn` | `#ddaa44` | Warning values |
| `--value-alert` | `#ff6666` | Alert/error values |
| `--muted` | `#aaaadd` | Secondary text |
| `--dim` | `#7878aa` | Tertiary text |

Text is never darker than `#777799` to ensure readability on the dark background.

---

## Licence

MIT — see LICENSE file.
