"""
db_wifi.py  —  raspi81 ism-wifi-monitor
WiFi logger database initialisation.
DB path: ~/ism-wifi-monitor/db/wifi_logger.db  (WAL mode)
Safe to re-run — all statements use IF NOT EXISTS.
"""

import sqlite3

from config import DB_WIFI_PATH


def init_db() -> None:
    DB_WIFI_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_WIFI_PATH))
    conn.execute('PRAGMA journal_mode=WAL')

    conn.executescript('''
        CREATE TABLE IF NOT EXISTS access_points (
            bssid        TEXT PRIMARY KEY,
            ssid         TEXT,
            encryption   TEXT,
            capabilities TEXT,
            first_seen   TEXT NOT NULL,
            last_seen    TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS sightings (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            bssid          TEXT    NOT NULL REFERENCES access_points(bssid),
            signal_dbm     INTEGER,
            channel        INTEGER,
            frequency_mhz  INTEGER,
            latitude       REAL,
            longitude      REAL,
            altitude_m     REAL,
            gps_fix        INTEGER NOT NULL DEFAULT 0,
            timestamp      TEXT    NOT NULL
        );

        CREATE TABLE IF NOT EXISTS associations (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp      TEXT    NOT NULL,
            frame_subtype  INTEGER NOT NULL,
            client_mac     TEXT    NOT NULL,
            bssid          TEXT    NOT NULL,
            ssid           TEXT,
            signal_dbm     INTEGER,
            channel        INTEGER
        );

        CREATE TABLE IF NOT EXISTS client_sightings (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp      TEXT    NOT NULL,
            client_mac     TEXT    NOT NULL,
            bssid          TEXT    NOT NULL,
            signal_dbm     INTEGER,
            channel        INTEGER,
            latitude       REAL,
            longitude      REAL,
            gps_fix        INTEGER NOT NULL DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_sightings_bssid
            ON sightings(bssid);
        CREATE INDEX IF NOT EXISTS idx_sightings_timestamp
            ON sightings(timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_sightings_latlon
            ON sightings(latitude, longitude)
            WHERE latitude IS NOT NULL;
        CREATE INDEX IF NOT EXISTS idx_assoc_bssid
            ON associations(bssid);
        CREATE INDEX IF NOT EXISTS idx_assoc_client
            ON associations(client_mac);
        CREATE INDEX IF NOT EXISTS idx_assoc_ts
            ON associations(timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_client_bssid
            ON client_sightings(bssid);
        CREATE INDEX IF NOT EXISTS idx_client_mac
            ON client_sightings(client_mac);
        CREATE INDEX IF NOT EXISTS idx_client_ts
            ON client_sightings(timestamp DESC);
    ''')

    conn.commit()
    conn.close()
    print(f'WiFi database ready: {DB_WIFI_PATH}')


if __name__ == '__main__':
    init_db()
