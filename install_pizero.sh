#!/bin/bash
# install_pizero.sh  —  ism-wifi-monitor installer for Raspberry Pi Zero 2W
#
# Usage (run ON the Pi Zero 2W):
#   sudo bash install_pizero.sh
#
# Prerequisites:
#   - Raspberry Pi OS Bookworm Lite 32-bit, headless
#   - Hotspot already configured on wlan0 via NetworkManager
#   - MT7612U USB WiFi dongle plugged in
#   - GPS dongle plugged in
#   - Powered USB hub strongly recommended (three USB devices share one port)
#   - Internet access during install (via hotspot uplink or ethernet adapter)
#
# What this script does vs install.sh (Pi 4B version):
#   - Detects MT7612U interface name (may not be wlan1 on Zero 2W)
#   - Updates hotspot SSID to match current hostname
#   - Includes services_server.py and ism-wifi-services.service
#   - All services installed including ISM/RTL-SDR (disabled if no dongle plugged in)
#
# To stop RTL-SDR services if no dongle is connected, use the Services page
# at http://<hostname>:8098 after install.

set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
DEPLOY_DIR="/home/user/ism-wifi-monitor"
VENV="$DEPLOY_DIR/venv"
SVCDIR="/etc/systemd/system"
HOSTNAME_NOW="$(hostname)"

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: Run as root:  sudo bash install_pizero.sh" >&2
    exit 1
fi

echo "==================================================================="
echo "  ism-wifi-monitor — Pi Zero 2W installer"
echo "  Hostname : $HOSTNAME_NOW"
echo "  Repo     : $REPO_DIR"
echo "  Deploy   : $DEPLOY_DIR"
echo "==================================================================="
echo ""

# ── 1. System packages ────────────────────────────────────────────────────────
echo "[1/9] Installing system packages"
apt-get update -qq
apt-get install -y \
    python3 python3-venv \
    rtl-433 \
    sqlite3 \
    iw rfkill \
    gpsd gpsd-clients

# ── 2. Detect MT7612U interface ───────────────────────────────────────────────
echo "[2/9] Detecting WiFi monitor interface"

# Give udev a moment if the dongle was just plugged in
sleep 2

SCAN_IFACE="wlan1"
if ip link show wlan1 &>/dev/null 2>&1; then
    echo "     MT7612U found as: wlan1 (expected)"
else
    # Find any wlan interface that is NOT wlan0 (the hotspot)
    DETECTED=$(iw dev 2>/dev/null | awk '/Interface/{print $2}' | grep -v '^wlan0$' | head -1 || true)
    if [ -n "$DETECTED" ]; then
        SCAN_IFACE="$DETECTED"
        echo "     MT7612U found as: $SCAN_IFACE (not wlan1 — config.py will be updated)"
    else
        echo "     WARNING: MT7612U not found. Is the dongle plugged in?"
        echo "              Defaulting to wlan1 in config.py."
        echo "              After plugging in the dongle, check with 'iw dev' and"
        echo "              update WIFI_IFACE in $DEPLOY_DIR/config.py if needed."
        SCAN_IFACE="wlan1"
    fi
fi

# ── 3. Create deploy directories ──────────────────────────────────────────────
echo "[3/9] Creating deploy directories"
mkdir -p "$DEPLOY_DIR"/{db,tile_cache,tiles,templates,data}
chown -R user:user "$DEPLOY_DIR"

# ── 4. Copy files ─────────────────────────────────────────────────────────────
echo "[4/9] Copying application files"
cp "$REPO_DIR"/config.py                 "$DEPLOY_DIR/"
cp "$REPO_DIR"/gps_reader_async.py       "$DEPLOY_DIR/"
cp "$REPO_DIR"/gps_reader_sync.py        "$DEPLOY_DIR/"
cp "$REPO_DIR"/db_ism.py                 "$DEPLOY_DIR/"
cp "$REPO_DIR"/db_wifi.py                "$DEPLOY_DIR/"
cp "$REPO_DIR"/db_history.py             "$DEPLOY_DIR/"
cp "$REPO_DIR"/ism_monitor.py            "$DEPLOY_DIR/"
cp "$REPO_DIR"/wifi_scanner.py           "$DEPLOY_DIR/"
cp "$REPO_DIR"/wifi_web.py               "$DEPLOY_DIR/"
cp "$REPO_DIR"/gps_web.py               "$DEPLOY_DIR/"
cp "$REPO_DIR"/skymap3d.py               "$DEPLOY_DIR/"
cp "$REPO_DIR"/landing_server.py         "$DEPLOY_DIR/"
cp "$REPO_DIR"/wifi_history_monitor.py   "$DEPLOY_DIR/"
cp "$REPO_DIR"/wifi_history_web.py       "$DEPLOY_DIR/"
cp "$REPO_DIR"/ie_parser.py              "$DEPLOY_DIR/"
cp "$REPO_DIR"/oui.py                    "$DEPLOY_DIR/"
cp "$REPO_DIR"/terminal_server.py        "$DEPLOY_DIR/"
cp "$REPO_DIR"/notes_server.py           "$DEPLOY_DIR/"
cp "$REPO_DIR"/services_server.py        "$DEPLOY_DIR/"
cp "$REPO_DIR"/raspi-style.css           "$DEPLOY_DIR/"
cp "$REPO_DIR"/templates/*.html          "$DEPLOY_DIR/templates/"
cp -r "$REPO_DIR"/data/                  "$DEPLOY_DIR/"
chown -R user:user "$DEPLOY_DIR"

# Patch WIFI_IFACE in config.py if the interface is not wlan1
if [ "$SCAN_IFACE" != "wlan1" ]; then
    sed -i "s/^WIFI_IFACE.*=.*/WIFI_IFACE        = '$SCAN_IFACE'/" "$DEPLOY_DIR/config.py"
    echo "     Patched WIFI_IFACE to '$SCAN_IFACE' in config.py"
fi

# ── 5. Python venv ────────────────────────────────────────────────────────────
echo "[5/9] Creating Python venv and installing packages"
if [ ! -f "$VENV/bin/python" ]; then
    sudo -u user python3 -m venv "$VENV"
else
    echo "     Venv already exists — skipping creation"
fi
sudo -u user "$VENV/bin/pip" install --upgrade pip wheel --quiet
sudo -u user "$VENV/bin/pip" install \
    aiohttp aiofiles \
    flask requests \
    scapy \
    manuf \
    || { echo "ERROR: pip install failed"; exit 1; }
echo "     Venv ready: $VENV"

# ── 6. Download OUI database ──────────────────────────────────────────────────
echo "[6/9] Downloading IEEE OUI database"
sudo -u user wget -q -O "$DEPLOY_DIR/data/oui.csv" \
    https://standards-oui.ieee.org/oui/oui.csv 2>/dev/null \
    && echo "     OUI database downloaded" \
    || echo "     OUI download failed — fallback hardcoded DB will be used"

# ── 7. Initialise databases ───────────────────────────────────────────────────
echo "[7/9] Initialising databases"
sudo -u user "$VENV/bin/python" "$DEPLOY_DIR/db_wifi.py"
sudo -u user "$VENV/bin/python" "$DEPLOY_DIR/db_ism.py"

# ── 8. Network configuration ──────────────────────────────────────────────────
echo "[8/9] Configuring network"

# Unblock all radios
rfkill unblock all 2>/dev/null || true

# Ensure wlan0 is up before NM tries to use it
ip link set wlan0 up 2>/dev/null || true

# Enable WiFi in NetworkManager (may be disabled on fresh install)
nmcli radio wifi on 2>/dev/null || true

# Configure gpsd to use the GPS dongle on ttyACM0
cat > /etc/default/gpsd << GPSDEOF
START_DAEMON="true"
USBAUTO="true"
DEVICES="/dev/ttyACM0"
GPSD_OPTIONS="-n"
GPSDEOF
echo "     gpsd configured for /dev/ttyACM0"
systemctl enable gpsd gpsd.socket
systemctl restart gpsd

# Mark the scan interface as unmanaged by NetworkManager
NM_CONF_DIR="/etc/NetworkManager/conf.d"
mkdir -p "$NM_CONF_DIR"
cat > "$NM_CONF_DIR/99-ism-wifi-unmanaged.conf" << NMEOF
[keyfile]
unmanaged-devices=interface-name:${SCAN_IFACE}
NMEOF
echo "     $SCAN_IFACE marked unmanaged by NetworkManager"

# Restart NM so it picks up the unmanaged conf and recognises wlan0
systemctl restart NetworkManager
sleep 3

# Update existing hotspot or create a new one
echo "     Configuring hotspot SSID: $HOSTNAME_NOW  password: password"
HOT_UUID=$(nmcli -t -f UUID,TYPE con show 2>/dev/null | grep ':wifi$' | head -1 | cut -d: -f1 || true)
if [ -n "$HOT_UUID" ]; then
    nmcli con modify "$HOT_UUID" \
        802-11-wireless.ssid "$HOSTNAME_NOW" \
        wifi-sec.psk 'password' \
        connection.interface-name wlan0 2>/dev/null || true
    echo "     Updated existing hotspot connection"
else
    # No hotspot exists — create one
    nmcli con add \
        type wifi ifname wlan0 \
        con-name "${HOSTNAME_NOW}-hotspot" \
        autoconnect yes \
        ssid "$HOSTNAME_NOW" \
        -- \
        wifi-sec.key-mgmt wpa-psk \
        wifi-sec.psk 'password' \
        802-11-wireless.mode ap \
        802-11-wireless.band bg \
        ipv4.method shared 2>/dev/null \
        && echo "     Created new hotspot: $HOSTNAME_NOW" \
        || echo "     WARNING: Could not create hotspot — configure manually after reboot"
    HOT_UUID=$(nmcli -t -f UUID,TYPE con show 2>/dev/null | grep ':wifi$' | head -1 | cut -d: -f1 || true)
fi

# Bring the hotspot up
if [ -n "$HOT_UUID" ]; then
    nmcli con up "$HOT_UUID" 2>/dev/null \
        && echo "     Hotspot activated" \
        || echo "     Hotspot will activate on reboot"
fi

# ── 9. Install and enable systemd services ────────────────────────────────────
echo "[9/9] Installing systemd services"
cp "$REPO_DIR"/systemd/rfkill-unblock.service            "$SVCDIR/"
cp "$REPO_DIR"/systemd/ism-wifi-landing.service          "$SVCDIR/"
cp "$REPO_DIR"/systemd/ism-wifi-gps.service              "$SVCDIR/"
cp "$REPO_DIR"/systemd/ism-wifi-ism.service              "$SVCDIR/"
cp "$REPO_DIR"/systemd/ism-wifi-skymap3d.service         "$SVCDIR/"
cp "$REPO_DIR"/systemd/ism-wifi-wifi-scan.service        "$SVCDIR/"
cp "$REPO_DIR"/systemd/ism-wifi-wifi-web.service         "$SVCDIR/"
cp "$REPO_DIR"/systemd/ism-wifi-history-monitor.service  "$SVCDIR/"
cp "$REPO_DIR"/systemd/ism-wifi-history-web.service      "$SVCDIR/"
cp "$REPO_DIR"/systemd/ism-wifi-terminal.service         "$SVCDIR/"
cp "$REPO_DIR"/systemd/ism-wifi-notes.service            "$SVCDIR/"
cp "$REPO_DIR"/systemd/ism-wifi-services.service         "$SVCDIR/"

systemctl daemon-reload

for svc in \
    rfkill-unblock \
    ism-wifi-landing \
    ism-wifi-gps \
    ism-wifi-ism \
    ism-wifi-skymap3d \
    ism-wifi-wifi-scan \
    ism-wifi-wifi-web \
    ism-wifi-history-monitor \
    ism-wifi-history-web \
    ism-wifi-terminal \
    ism-wifi-notes \
    ism-wifi-services
do
    systemctl enable "$svc"
    echo "     Enabled: $svc"
done

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "==================================================================="
echo "  Install complete."
echo ""
echo "  If RTL-SDR dongle is NOT connected, stop ISM services:"
echo "    sudo systemctl stop ism-wifi-ism ism-wifi-skymap3d"
echo "  (or use the Services page at http://$(hostname -I | awk '{print $1}'):8098)"
echo ""
echo "  Start all services:"
echo ""
echo "    sudo systemctl start \\"
echo "      rfkill-unblock ism-wifi-landing ism-wifi-gps ism-wifi-ism \\"
echo "      ism-wifi-skymap3d ism-wifi-wifi-scan ism-wifi-wifi-web \\"
echo "      ism-wifi-history-monitor ism-wifi-history-web \\"
echo "      ism-wifi-terminal ism-wifi-notes ism-wifi-services"
echo ""
echo "  Then reboot to verify all services start cleanly on boot:"
echo "    sudo reboot"
echo ""
IP=$(hostname -I | awk '{print $1}')
echo "  Access at: http://$IP"
echo ""
echo "  Port summary:"
echo "    80    — Landing page"
echo "    8091  — WiFi APs / channel usage"
echo "    8092  — ISM Monitor (RTL-SDR required)"
echo "    8093  — GPS Dashboard"
echo "    8094  — 3D Satellite Skymap"
echo "    8095  — WiFi History"
echo "    8096  — Terminal"
echo "    8097  — Notes"
echo "    8098  — Services control"
echo ""
echo "  Interfaces:"
echo "    wlan0 — hotspot '$HOSTNAME_NOW' (managed by NetworkManager)"
echo "    $SCAN_IFACE — MT7612U WiFi scanner (monitor mode, unmanaged)"
echo "==================================================================="
