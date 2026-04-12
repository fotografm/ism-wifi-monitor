#!/bin/bash
# install.sh  —  raspi81 ism-wifi-monitor
# Run as root on the Pi 4B:  sudo bash install.sh
# Preserves existing wlan0 hotspot (NetworkManager).
# Marks wlan1 (MT7612U) as unmanaged so NM does not interfere with monitor mode.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
DEPLOY_DIR="/home/user/ism-wifi-monitor"
VENV="$DEPLOY_DIR/venv"
SVCDIR="/etc/systemd/system"

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: Run as root:  sudo bash install.sh" >&2
    exit 1
fi

echo "===  raspi81 ism-wifi-monitor install  ==="
echo "     Repo:   $REPO_DIR"
echo "     Deploy: $DEPLOY_DIR"
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
mkdir -p "$DEPLOY_DIR"/{db,tile_cache,tiles,templates}
chown -R user:user "$DEPLOY_DIR"

# ── 3. Copy files ─────────────────────────────────────────────────────────────
echo "[3/8] Copying files"
cp "$REPO_DIR"/config.py           "$DEPLOY_DIR/"
cp "$REPO_DIR"/gps_reader_async.py "$DEPLOY_DIR/"
cp "$REPO_DIR"/gps_reader_sync.py  "$DEPLOY_DIR/"
cp "$REPO_DIR"/db_ism.py           "$DEPLOY_DIR/"
cp "$REPO_DIR"/db_wifi.py          "$DEPLOY_DIR/"
cp "$REPO_DIR"/ism_monitor.py      "$DEPLOY_DIR/"
cp "$REPO_DIR"/wifi_scanner.py     "$DEPLOY_DIR/"
cp "$REPO_DIR"/wifi_web.py         "$DEPLOY_DIR/"
cp "$REPO_DIR"/gps_web.py          "$DEPLOY_DIR/"
cp "$REPO_DIR"/skymap3d.py         "$DEPLOY_DIR/"
cp "$REPO_DIR"/landing_server.py   "$DEPLOY_DIR/"
cp "$REPO_DIR"/raspi-style.css     "$DEPLOY_DIR/"
cp "$REPO_DIR"/templates/*.html    "$DEPLOY_DIR/templates/"
chown -R user:user "$DEPLOY_DIR"

# ── 4. Python venv ────────────────────────────────────────────────────────────
echo "[4/8] Creating Python venv and installing packages"
sudo -u user python3 -m venv "$VENV"
sudo -u user "$VENV/bin/pip" install --upgrade pip wheel --quiet
sudo -u user "$VENV/bin/pip" install \
    aiohttp aiofiles \
    flask requests \
    scapy \
    manuf \
    --quiet
echo "     Venv ready: $VENV"

# ── 5. Initialise databases ───────────────────────────────────────────────────
echo "[5/8] Initialising WiFi logger database"
sudo -u user "$VENV/bin/python" "$DEPLOY_DIR/db_wifi.py"

# ── 6. Network — mark wlan1 unmanaged by NetworkManager ──────────────────────
echo "[6/8] Configuring network interfaces"

# Unblock all radios (hotspot wlan0 will be restored by NM on next restart)
rfkill unblock all

# Mark the MT7612U (wlan1) as unmanaged so NetworkManager never takes it
# out of monitor mode or reassigns it
NM_CONF_DIR="/etc/NetworkManager/conf.d"
mkdir -p "$NM_CONF_DIR"
cat > "$NM_CONF_DIR/99-ism-wifi-unmanaged.conf" << 'NMEOF'
[keyfile]
unmanaged-devices=interface-name:wlan1
NMEOF
echo "     wlan1 marked unmanaged by NetworkManager"
systemctl reload NetworkManager 2>/dev/null || true

# ── 7. Install and enable systemd services ────────────────────────────────────
echo "[7/8] Installing systemd services"
cp "$REPO_DIR"/systemd/rfkill-unblock.service        "$SVCDIR/"
cp "$REPO_DIR"/systemd/ism-wifi-landing.service      "$SVCDIR/"
cp "$REPO_DIR"/systemd/ism-wifi-gps.service          "$SVCDIR/"
cp "$REPO_DIR"/systemd/ism-wifi-ism.service          "$SVCDIR/"
cp "$REPO_DIR"/systemd/ism-wifi-skymap3d.service     "$SVCDIR/"
cp "$REPO_DIR"/systemd/ism-wifi-wifi-scan.service    "$SVCDIR/"
cp "$REPO_DIR"/systemd/ism-wifi-wifi-web.service     "$SVCDIR/"

systemctl daemon-reload

for svc in \
    rfkill-unblock \
    ism-wifi-landing \
    ism-wifi-gps \
    ism-wifi-ism \
    ism-wifi-skymap3d \
    ism-wifi-wifi-scan \
    ism-wifi-wifi-web
do
    systemctl enable "$svc"
    echo "     Enabled: $svc"
done

# ── 8. Done ───────────────────────────────────────────────────────────────────
echo ""
echo "[8/8] Install complete."
echo ""
echo "Start all services now with:"
echo ""
echo "  sudo systemctl start rfkill-unblock ism-wifi-landing ism-wifi-gps ism-wifi-ism ism-wifi-skymap3d ism-wifi-wifi-scan ism-wifi-wifi-web"
echo ""
IP=$(hostname -I | awk '{print $1}')
echo "Access at: http://$IP"
echo ""
echo "Port summary:"
echo "  80    — Combined landing page"
echo "  8091  — WiFi Logger (dashboard + APs)"
echo "  8092  — ISM Monitor (feed + map + status)"
echo "  8093  — GPS Dashboard"
echo "  8094  — 3D Satellite Skymap"
echo ""
echo "Interfaces:"
echo "  wlan0 — hotspot (managed by NetworkManager, UNCHANGED)"
echo "  wlan1 — MT7612U WiFi scanner (monitor mode, unmanaged by NM)"
