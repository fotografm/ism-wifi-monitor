"""
db_ism.py  —  raspi81 ism-wifi-monitor
SQLite database schema and helpers for the ISM monitor.
DB path: ~/ism-wifi-monitor/db/ism_monitor.db  (WAL mode)
"""

import json
import logging
import sqlite3

from config import DB_ISM_PATH as DB_PATH

log = logging.getLogger("db_ism")

# ── Schema ────────────────────────────────────────────────────────────────────

_DDL = [
    """
    CREATE TABLE IF NOT EXISTS signals (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        ts          TEXT    NOT NULL,
        lat         REAL,
        lon         REAL,
        gps_fix     INTEGER DEFAULT 0,
        frequency   INTEGER,
        protocol    TEXT,
        model       TEXT,
        device_id   TEXT,
        channel     INTEGER,
        rssi        REAL,
        snr         REAL,
        noise       REAL,
        category    TEXT,
        data_json   TEXT
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_signals_ts    ON signals(ts DESC)",
    "CREATE INDEX IF NOT EXISTS idx_signals_model ON signals(model, device_id)",
    """
    CREATE TABLE IF NOT EXISTS transmitters (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        model           TEXT    NOT NULL,
        device_id       TEXT    NOT NULL,
        first_seen      TEXT,
        last_seen       TEXT,
        last_lat        REAL,
        last_lon        REAL,
        last_gps_fix    INTEGER DEFAULT 0,
        packet_count    INTEGER DEFAULT 0,
        category        TEXT,
        last_data_json  TEXT,
        UNIQUE(model, device_id)
    )
    """,
]


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA synchronous=NORMAL")
    con.row_factory = sqlite3.Row
    return con


_con: sqlite3.Connection | None = None


def init_db() -> None:
    global _con
    _con = _connect()
    for ddl in _DDL:
        _con.execute(ddl)
    _con.commit()
    log.info("ISM database ready: %s", DB_PATH)


def _ensure() -> sqlite3.Connection:
    if _con is None:
        raise RuntimeError("db_ism.init_db() not called")
    return _con


# ── Writes ────────────────────────────────────────────────────────────────────

def insert_signal(row: dict) -> int:
    con = _ensure()
    cur = con.execute(
        """
        INSERT INTO signals
            (ts, lat, lon, gps_fix, frequency, protocol, model, device_id,
             channel, rssi, snr, noise, category, data_json)
        VALUES
            (:ts, :lat, :lon, :gps_fix, :frequency, :protocol, :model, :device_id,
             :channel, :rssi, :snr, :noise, :category, :data_json)
        """,
        row,
    )
    con.commit()
    return cur.lastrowid


def upsert_transmitter(row: dict) -> None:
    con = _ensure()
    con.execute(
        """
        INSERT INTO transmitters
            (model, device_id, first_seen, last_seen, last_lat, last_lon,
             last_gps_fix, packet_count, category, last_data_json)
        VALUES
            (:model, :device_id, :last_seen, :last_seen, :last_lat, :last_lon,
             :last_gps_fix, 1, :category, :last_data_json)
        ON CONFLICT(model, device_id) DO UPDATE SET
            last_seen       = excluded.last_seen,
            last_lat        = CASE WHEN excluded.last_gps_fix THEN excluded.last_lat
                                   ELSE transmitters.last_lat END,
            last_lon        = CASE WHEN excluded.last_gps_fix THEN excluded.last_lon
                                   ELSE transmitters.last_lon END,
            last_gps_fix    = excluded.last_gps_fix OR transmitters.last_gps_fix,
            packet_count    = transmitters.packet_count + 1,
            last_data_json  = excluded.last_data_json
        """,
        row,
    )
    con.commit()


# ── Reads ─────────────────────────────────────────────────────────────────────

def get_recent_signals(limit: int = 200) -> list[dict]:
    con = _ensure()
    rows = con.execute(
        "SELECT * FROM signals ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(r) for r in rows]


def get_transmitters() -> list[dict]:
    con = _ensure()
    rows = con.execute(
        "SELECT * FROM transmitters ORDER BY last_seen DESC"
    ).fetchall()
    return [dict(r) for r in rows]


def get_signal_count() -> dict:
    con = _ensure()
    total = con.execute("SELECT COUNT(*) FROM signals").fetchone()[0]
    today = con.execute(
        "SELECT COUNT(*) FROM signals WHERE ts >= date('now')"
    ).fetchone()[0]
    return {"total": total, "today": today}


def get_tile_cache_stats(cache_dir) -> dict:
    if not cache_dir.exists():
        return {"count": 0, "size_mb": 0.0}
    tiles = list(cache_dir.rglob("*.png"))
    size = sum(t.stat().st_size for t in tiles)
    return {"count": len(tiles), "size_mb": round(size / 1_048_576, 2)}
