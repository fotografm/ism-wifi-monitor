#!/bin/bash
# install.sh  —  ism-wifi-monitor installer for Raspberry Pi 4B
# Run as root on the Pi:  sudo bash install.sh
# Preserves existing wlan0 hotspot (NetworkManager).
# Marks wlan1 (MT7612U) as unmanaged so NM does not interfere with monitor mode.

set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
DEPLOY_DIR="/home/user/ism-wifi-monitor"
VENV="$DEPLOY_DIR/venv"
SVCDIR="/etc/systemd/system"

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: Run as root:  sudo bash install.sh" >&2
    exit 1
fi

echo "==================================================================="
echo "  ism-wifi-monitor — Pi 4B installer"
echo "  Repo   : $REPO_DIR"
echo "  Deploy : $DEPLOY_DIR"
echo "==================================================================="
echo ""

# ── 1. System packages ────────────────────────────────────────────────────────
echo "[1/8] Installing system packages"
apt-get update -qq
apt-get install -y \
    python3 python3-venv \
    rtl-433 \
    sqlite3 \
    iw rfkill \
    gpsd gpsd-clients

# ── 2. Create deploy directories ──────────────────────────────────────────────
echo "[2/8] Creating deploy directories"
mkdir -p "$DEPLOY_DIR"/{db,tile_cache,tiles,templates,data}
chown -R user:user "$DEPLOY_DIR"

# ── 3. Copy files ─────────────────────────────────────────────────────────────
echo "[3/8] Copying application files"
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

# ── 4. Python venv ────────────────────────────────────────────────────────────
echo "[4/8] Creating Python venv and installing packages"
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

# ── 5. Download OUI database ──────────────────────────────────────────────────
echo "[5/8] Downloading IEEE OUI database"
sudo -u user wget -q -O "$DEPLOY_DIR/data/oui.csv" \
    https://standards-oui.ieee.org/oui/oui.csv 2>/dev/null \
    && echo "     OUI database downloaded" \
    || echo "     OUI download failed — fallback hardcoded DB will be used"

# ── 6. Initialise databases ───────────────────────────────────────────────────
echo "[6/8] Initialising databases"
sudo -u user "$VENV/bin/python" "$DEPLOY_DIR/db_wifi.py"
sudo -u user "$VENV/bin/python" "$DEPLOY_DIR/db_ism.py"
sudo -u user "$VENV/bin/python" "$DEPLOY_DIR/db_history.py"
# Ensure all DB files are user-owned so services running as 'user' can write them.
# Root services (wifi-scan, history-monitor) can always write to user-owned files.
chown user:user "$DEPLOY_DIR"/db/ "$DEPLOY_DIR"/db/*.db "$DEPLOY_DIR"/db/*.db-shm "$DEPLOY_DIR"/db/*.db-wal 2>/dev/null || true

# ── 7. Network — configure gpsd and mark wlan1 unmanaged ─────────────────────
echo "[7/8] Configuring network and gpsd"

# Configure gpsd to use the GPS dongle on ttyACM0
cat > /etc/default/gpsd << GPSDEOF
START_DAEMON="true"
USBAUTO="true"
DEVICES="/dev/ttyACM0"
GPSD_OPTIONS="-n"
GPSD_SOCKET="/var/run/gpsd.sock"
GPSDEOF
echo "     gpsd configured for /dev/ttyACM0"
systemctl enable gpsd gpsd.socket
systemctl restart gpsd 2>/dev/null || true

rfkill unblock all 2>/dev/null || true

NM_CONF_DIR="/etc/NetworkManager/conf.d"
mkdir -p "$NM_CONF_DIR"
cat > "$NM_CONF_DIR/99-ism-wifi-unmanaged.conf" << 'NMEOF'
[keyfile]
unmanaged-devices=interface-name:wlan1
NMEOF
echo "     wlan1 marked unmanaged by NetworkManager"
systemctl reload NetworkManager 2>/dev/null || true

# ── 8. Install and enable systemd services ────────────────────────────────────
echo "[8/8] Installing systemd services"
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
echo "    wlan0 — hotspot (managed by NetworkManager, unchanged)"
echo "    wlan1 — MT7612U WiFi scanner (monitor mode, unmanaged by NM)"
echo "==================================================================="
