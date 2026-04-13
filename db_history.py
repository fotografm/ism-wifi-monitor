"""
db_history.py  —  raspi81 ism-wifi-monitor
SQLite database layer for the WiFi History Diagnostic.
Ported from raspi70/db.py — DB path updated to ~/ism-wifi-monitor/db/wifi_history.db
WAL mode: monitor writes continuously; web server reads without blocking.
"""

import json
import logging
import sqlite3
import time
from pathlib import Path

log = logging.getLogger(__name__)

DB_PATH = Path.home() / 'ism-wifi-monitor' / 'db' / 'wifi_history.db'

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;

CREATE TABLE IF NOT EXISTS probe_requests (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        REAL    NOT NULL,
    src_mac   TEXT    NOT NULL,
    ssid      TEXT,
    rssi      INTEGER,
    channel   INTEGER,
    ie_fp     TEXT,
    raw_ies   BLOB,
    is_random INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS beacons (
    bssid        TEXT PRIMARY KEY,
    ssid         TEXT,
    channel      INTEGER,
    rssi         INTEGER,
    capabilities INTEGER,
    first_seen   REAL NOT NULL,
    last_seen    REAL NOT NULL,
    beacon_count INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS associations (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            REAL    NOT NULL,
    frame_subtype INTEGER NOT NULL,
    src_mac       TEXT    NOT NULL,
    dst_mac       TEXT    NOT NULL,
    bssid         TEXT    NOT NULL,
    ssid          TEXT,
    rssi          INTEGER,
    channel       INTEGER
);

CREATE TABLE IF NOT EXISTS data_sightings (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        REAL    NOT NULL,
    src_mac   TEXT    NOT NULL,
    bssid     TEXT    NOT NULL,
    rssi      INTEGER,
    channel   INTEGER
);

CREATE TABLE IF NOT EXISTS ie_fingerprints (
    fp_hash     TEXT PRIMARY KEY,
    ie_ids      TEXT NOT NULL,
    ht_caps     BLOB,
    vht_caps    BLOB,
    vendor_ouis TEXT,
    os_hint     TEXT,
    first_seen  REAL NOT NULL,
    last_seen   REAL NOT NULL,
    probe_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS mac_fp_map (
    src_mac     TEXT NOT NULL,
    fp_hash     TEXT NOT NULL,
    first_seen  REAL NOT NULL,
    last_seen   REAL NOT NULL,
    sight_count INTEGER DEFAULT 1,
    PRIMARY KEY (src_mac, fp_hash)
);

CREATE INDEX IF NOT EXISTS idx_probe_ts     ON probe_requests(ts DESC);
CREATE INDEX IF NOT EXISTS idx_probe_mac    ON probe_requests(src_mac);
CREATE INDEX IF NOT EXISTS idx_probe_ssid   ON probe_requests(ssid)
    WHERE ssid IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_probe_fp     ON probe_requests(ie_fp);
CREATE INDEX IF NOT EXISTS idx_assoc_mac    ON associations(src_mac);
CREATE INDEX IF NOT EXISTS idx_assoc_ts     ON associations(ts DESC);
CREATE INDEX IF NOT EXISTS idx_data_mac     ON data_sightings(src_mac);
CREATE INDEX IF NOT EXISTS idx_macfp_fp     ON mac_fp_map(fp_hash);
"""


# ── connection ────────────────────────────────────────────────────────────────

def get_connection():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    try:
        conn.executescript(SCHEMA)
        conn.commit()
        log.info('History DB initialised at %s', DB_PATH)
    finally:
        conn.close()


# ── writes ────────────────────────────────────────────────────────────────────

def insert_probe(conn, ts, src_mac, ssid, rssi, channel, ie_fp, raw_ies, is_random):
    conn.execute(
        'INSERT INTO probe_requests '
        '(ts, src_mac, ssid, rssi, channel, ie_fp, raw_ies, is_random) '
        'VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        (ts, src_mac, ssid, rssi, channel, ie_fp, raw_ies, int(is_random))
    )


def upsert_beacon(conn, ts, bssid, ssid, channel, rssi, capabilities):
    conn.execute(
        """
        INSERT INTO beacons
            (bssid, ssid, channel, rssi, capabilities, first_seen, last_seen, beacon_count)
        VALUES (?, ?, ?, ?, ?, ?, ?, 1)
        ON CONFLICT(bssid) DO UPDATE SET
            ssid         = excluded.ssid,
            channel      = excluded.channel,
            rssi         = excluded.rssi,
            capabilities = excluded.capabilities,
            last_seen    = excluded.last_seen,
            beacon_count = beacon_count + 1
        """,
        (bssid, ssid, channel, rssi, capabilities, ts, ts)
    )


def insert_association(conn, ts, frame_subtype, src_mac, dst_mac, bssid, ssid,
                       rssi, channel):
    conn.execute(
        'INSERT INTO associations '
        '(ts, frame_subtype, src_mac, dst_mac, bssid, ssid, rssi, channel) '
        'VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        (ts, frame_subtype, src_mac, dst_mac, bssid, ssid, rssi, channel)
    )


def insert_data_sighting(conn, ts, src_mac, bssid, rssi, channel):
    conn.execute(
        'INSERT INTO data_sightings (ts, src_mac, bssid, rssi, channel) '
        'VALUES (?, ?, ?, ?, ?)',
        (ts, src_mac, bssid, rssi, channel)
    )


def upsert_fingerprint(conn, fp_hash, ie_ids, ht_caps, vht_caps, vendor_ouis,
                       os_hint):
    now = time.time()
    conn.execute(
        """
        INSERT INTO ie_fingerprints
            (fp_hash, ie_ids, ht_caps, vht_caps, vendor_ouis, os_hint,
             first_seen, last_seen, probe_count)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
        ON CONFLICT(fp_hash) DO UPDATE SET
            last_seen   = excluded.last_seen,
            probe_count = probe_count + 1
        """,
        (fp_hash, json.dumps(ie_ids), ht_caps or None, vht_caps or None,
         json.dumps(vendor_ouis), os_hint, now, now)
    )


def upsert_mac_fp(conn, src_mac, fp_hash):
    now = time.time()
    conn.execute(
        """
        INSERT INTO mac_fp_map (src_mac, fp_hash, first_seen, last_seen, sight_count)
        VALUES (?, ?, ?, ?, 1)
        ON CONFLICT(src_mac, fp_hash) DO UPDATE SET
            last_seen   = excluded.last_seen,
            sight_count = sight_count + 1
        """,
        (src_mac, fp_hash, now, now)
    )


def prune_old_data(conn, days=30):
    cutoff = time.time() - days * 86400
    conn.execute('DELETE FROM probe_requests  WHERE ts < ?', (cutoff,))
    conn.execute('DELETE FROM associations    WHERE ts < ?', (cutoff,))
    conn.execute('DELETE FROM data_sightings  WHERE ts < ?', (cutoff,))
    conn.commit()
    log.info('pruned data older than %d days', days)


# ── reads — summary ───────────────────────────────────────────────────────────

def q_stats(conn):
    now = time.time()
    result = {}
    for label, since in [('1h', now - 3600), ('24h', now - 86400), ('all', 0)]:
        r = conn.execute(
            'SELECT COUNT(*) AS c FROM probe_requests WHERE ts >= ?', (since,)
        ).fetchone()
        result[f'probes_{label}'] = r['c']
    result['unique_fps'] = conn.execute(
        'SELECT COUNT(*) AS c FROM ie_fingerprints'
    ).fetchone()['c']
    result['unique_aps'] = conn.execute(
        'SELECT COUNT(*) AS c FROM beacons'
    ).fetchone()['c']
    result['unique_ssids'] = conn.execute(
        "SELECT COUNT(DISTINCT ssid) AS c FROM probe_requests "
        "WHERE ssid IS NOT NULL AND ssid != ''"
    ).fetchone()['c']
    return result


def q_recent_probes(conn, limit=50, offset=0, mac_filter=None, ssid_filter=None):
    clauses = []
    params  = []
    if mac_filter:
        clauses.append('p.src_mac LIKE ?')
        params.append(f'%{mac_filter}%')
    if ssid_filter:
        clauses.append('p.ssid LIKE ?')
        params.append(f'%{ssid_filter}%')
    where = ('WHERE ' + ' AND '.join(clauses)) if clauses else ''
    params += [limit, offset]
    return conn.execute(
        f"""
        SELECT p.id, p.ts, p.src_mac, p.ssid, p.rssi, p.channel,
               p.ie_fp, p.is_random, f.os_hint
        FROM probe_requests p
        LEFT JOIN ie_fingerprints f ON p.ie_fp = f.fp_hash
        {where}
        ORDER BY p.ts DESC LIMIT ? OFFSET ?
        """,
        params
    ).fetchall()


def q_probes_per_channel(conn):
    return conn.execute(
        'SELECT channel, COUNT(*) AS cnt FROM probe_requests '
        'WHERE channel IS NOT NULL GROUP BY channel ORDER BY channel'
    ).fetchall()


def q_probes_per_minute(conn, minutes=60):
    since = time.time() - minutes * 60
    return conn.execute(
        """
        SELECT CAST((ts - ?) / 60 AS INTEGER) AS bucket, COUNT(*) AS cnt
        FROM probe_requests WHERE ts >= ?
        GROUP BY bucket ORDER BY bucket
        """,
        (since, since)
    ).fetchall()


def q_devices(conn):
    return conn.execute(
        """
        SELECT f.fp_hash, f.os_hint, f.probe_count,
               f.first_seen, f.last_seen,
               f.vendor_ouis, f.ie_ids,
               COUNT(DISTINCT m.src_mac) AS mac_count,
               (SELECT src_mac FROM mac_fp_map
                WHERE fp_hash = f.fp_hash
                ORDER BY last_seen DESC LIMIT 1) AS last_mac
        FROM ie_fingerprints f
        LEFT JOIN mac_fp_map m ON f.fp_hash = m.fp_hash
        GROUP BY f.fp_hash
        ORDER BY f.last_seen DESC
        """
    ).fetchall()


def q_device_by_hash(conn, fp_hash):
    return conn.execute(
        """
        SELECT f.fp_hash, f.os_hint, f.probe_count,
               f.first_seen, f.last_seen,
               f.vendor_ouis, f.ie_ids, f.ht_caps, f.vht_caps,
               COUNT(DISTINCT m.src_mac) AS mac_count
        FROM ie_fingerprints f
        LEFT JOIN mac_fp_map m ON f.fp_hash = m.fp_hash
        WHERE f.fp_hash = ?
        GROUP BY f.fp_hash
        """,
        (fp_hash,)
    ).fetchone()


def q_device_macs(conn, fp_hash):
    return conn.execute(
        'SELECT src_mac, first_seen, last_seen, sight_count '
        'FROM mac_fp_map WHERE fp_hash = ? ORDER BY last_seen DESC',
        (fp_hash,)
    ).fetchall()


def q_device_ssids(conn, fp_hash):
    return conn.execute(
        """
        SELECT DISTINCT ssid FROM probe_requests
        WHERE ie_fp = ? AND ssid IS NOT NULL AND ssid != ''
        ORDER BY ssid
        """,
        (fp_hash,)
    ).fetchall()


def q_device_probes(conn, fp_hash, limit=50):
    return conn.execute(
        """
        SELECT id, ts, src_mac, ssid, rssi, channel, is_random
        FROM probe_requests WHERE ie_fp = ?
        ORDER BY ts DESC LIMIT ?
        """,
        (fp_hash, limit)
    ).fetchall()


def q_device_assoc_by_fp(conn, fp_hash, limit=50):
    macs = [r['src_mac'] for r in conn.execute(
        'SELECT src_mac FROM mac_fp_map WHERE fp_hash = ?', (fp_hash,)
    ).fetchall()]
    if not macs:
        return []
    placeholders = ','.join('?' * len(macs))
    return conn.execute(
        f'SELECT * FROM associations WHERE src_mac IN ({placeholders}) '
        f'ORDER BY ts DESC LIMIT ?',
        macs + [limit]
    ).fetchall()


def q_device_channel_dist(conn, fp_hash):
    return conn.execute(
        """
        SELECT channel, COUNT(*) AS cnt
        FROM probe_requests
        WHERE ie_fp = ? AND channel IS NOT NULL
        GROUP BY channel ORDER BY channel
        """,
        (fp_hash,)
    ).fetchall()


def q_aps(conn):
    return conn.execute(
        'SELECT * FROM beacons ORDER BY last_seen DESC'
    ).fetchall()


def q_ssids(conn):
    return conn.execute(
        """
        SELECT ssid,
               COUNT(*)                      AS probe_count,
               COUNT(DISTINCT src_mac)       AS mac_count,
               COUNT(DISTINCT ie_fp)         AS device_count,
               MIN(ts)                       AS first_seen,
               MAX(ts)                       AS last_seen,
               GROUP_CONCAT(DISTINCT ie_fp)  AS fp_hashes
        FROM probe_requests
        WHERE ssid IS NOT NULL AND ssid != ''
        GROUP BY ssid
        ORDER BY last_seen DESC
        """
    ).fetchall()


def q_associations(conn, limit=200):
    return conn.execute(
        'SELECT * FROM associations ORDER BY ts DESC LIMIT ?', (limit,)
    ).fetchall()
