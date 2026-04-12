"""
config.py  —  raspi81 ism-wifi-monitor
Shared configuration for all services.
"""

from pathlib import Path

BASE_DIR = Path.home() / "ism-wifi-monitor"

# ── Hardware ──────────────────────────────────────────────────────────────────
WIFI_IFACE      = 'wlan1'           # MT7612U AC1300 (set to monitor mode by service)
HOTSPOT_IFACE   = 'wlan0'
HOTSPOT_SUBNET  = '10.42.0.0/24'
HOTSPOT_IP      = '10.42.0.1'

# ── Paths ─────────────────────────────────────────────────────────────────────
DB_ISM_PATH     = BASE_DIR / 'db' / 'ism_monitor.db'
DB_WIFI_PATH    = BASE_DIR / 'db' / 'wifi_logger.db'
DB_HISTORY_PATH = BASE_DIR / 'db' / 'wifi_history.db'
GPS_HISTORY_DB  = BASE_DIR / 'db' / 'gps_history.db'
TILES_DB_PATH   = str(BASE_DIR / 'tiles' / 'tiles.mbtiles')
TILE_CACHE_DIR  = BASE_DIR / 'tile_cache'

# ── GPS (gpsd) ────────────────────────────────────────────────────────────────
GPS_HOST        = '127.0.0.1'
GPS_PORT        = 2947

# ── Web server ports ──────────────────────────────────────────────────────────
WEB_HOST        = '0.0.0.0'
LANDING_PORT    = 80
WIFI_WEB_PORT   = 8091
ISM_PORT        = 8092
GPS_WEB_PORT      = 8093
SKYMAP3D_PORT     = 8094
WIFI_HISTORY_PORT = 8095

# ── ISM — rtl_433 ─────────────────────────────────────────────────────────────
RTL433_UDP_PORT  = 1433
RTL433_SAMPLE_HZ = 250_000

ISM_BANDS: dict = {
    "315": 315_000_000,
    "345": 345_000_000,
    "433": 433_920_000,
    "868": 868_000_000,
    "915": 915_000_000,
}
ISM_DEFAULT_BAND = "433"

# ── WiFi scanner ──────────────────────────────────────────────────────────────
CHANNEL_DWELL     = 0.3       # seconds per channel
SIGHTING_INTERVAL = 10        # min seconds between full sightings rows for same BSSID
SIGHTING_DISTANCE = 0.0001    # min degrees movement (~10 m) to force new sighting

# EU 2.4 GHz (1-13) + EU 5 GHz (ETSI, incl. DFS)
CHANNELS_24 = list(range(1, 14))
CHANNELS_50 = [36, 40, 44, 48, 52, 56, 60, 64,
               100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140,
               149, 153, 157, 161, 165]
ALL_CHANNELS = CHANNELS_24 + CHANNELS_50

# ── OSM tile caching (WiFi map) ───────────────────────────────────────────────
OSM_TILE_URL     = 'https://tile.openstreetmap.org/{z}/{x}/{y}.png'
OSM_USER_AGENT   = 'ism-wifi-monitor/1.0 (private use; Raspberry Pi)'
CACHE_RADIUS_KM  = 5.0
CACHE_ZOOM_MIN   = 8
CACHE_ZOOM_MAX   = 16
TILE_RATE_LIMIT  = 0.15       # seconds between OSM requests
ONLINE_CHECK_TTL = 30         # seconds to cache online/offline status
