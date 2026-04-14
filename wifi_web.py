#!/usr/bin/env python3
"""
wifi_web.py  —  raspi81 ism-wifi-monitor
Flask web server for WiFi AP logger (port 8091).
Serves:
  /               — dashboard (recent APs, channel chart)
  /aps            — full AP list with sort/filter
  /raspi-style.css
  /api/aps        — JSON list of all APs with latest sighting
  /api/stats      — JSON counts + GPS position + tile count
  /api/sysinfo    — JSON system info (uptime, cpu, ram)
  /api/ap/<bssid> — JSON detail for one AP
  /tiles/z/x/y    — Leaflet XYZ tile endpoint (MBTiles + OSM proxy)
  /api/cache_area — POST: trigger background tile pre-download
  /api/cache_status — GET: progress of running cache operation
  /api/shutdown   — POST: action=reboot|shutdown
"""

import logging
import math
import os
import socket
import sqlite3
import subprocess
import threading
import time
from pathlib import Path
from typing import Optional, Tuple

import requests
from flask import Flask, Response, g, jsonify, render_template, request, send_from_directory

from config import (
    BASE_DIR,
    CACHE_RADIUS_KM, CACHE_ZOOM_MAX, CACHE_ZOOM_MIN,
    DB_WIFI_PATH as DB_PATH,
    ONLINE_CHECK_TTL, OSM_TILE_URL, OSM_USER_AGENT,
    TILE_RATE_LIMIT, TILES_DB_PATH, WEB_HOST,
    WIFI_WEB_PORT as WEB_PORT,
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [wifi-web] %(levelname)s %(message)s',
    datefmt='%Y-%m-%dT%H:%M:%S',
)
log = logging.getLogger('wifi_web')

APP_DIR = Path.home() / "ism-wifi-monitor"

# ── OUI / manufacturer lookup ─────────────────────────────────────────────────

_MANUF_FILE      = str(BASE_DIR / 'manuf')
_mac_parser      = None
_mac_parser_lock = threading.Lock()


def _load_mac_parser() -> None:
    global _mac_parser
    try:
        from manuf import manuf as _mm
        if os.path.exists(_MANUF_FILE):
            try:
                p = _mm.MacParser(manuf_name=_MANUF_FILE, update=False)
                with _mac_parser_lock:
                    _mac_parser = p
                log.info('OUI database loaded from %s', _MANUF_FILE)
                return
            except Exception as exc:
                log.warning('Could not load %s: %s — trying bundled DB', _MANUF_FILE, exc)
        p = _mm.MacParser(update=False)
        with _mac_parser_lock:
            _mac_parser = p
        log.info('OUI database loaded from bundled manuf package')
    except Exception as exc:
        log.warning('manuf library not available: %s', exc)


def _update_mac_parser_bg() -> None:
    global _mac_parser
    MANUF_URL = 'https://www.wireshark.org/download/automated/data/manuf'
    try:
        from manuf import manuf as _mm
        log.info('OUI database: downloading from %s', MANUF_URL)
        resp = requests.get(MANUF_URL, timeout=15,
                            headers={'User-Agent': 'ism-wifi-monitor/1.0 (OUI update)'})
        resp.raise_for_status()
        with open(_MANUF_FILE, 'w', encoding='utf-8', errors='replace') as f:
            f.write(resp.text)
        p = _mm.MacParser(manuf_name=_MANUF_FILE, update=False)
        with _mac_parser_lock:
            _mac_parser = p
        log.info('OUI database updated (%d bytes)', len(resp.content))
    except Exception as exc:
        log.warning('OUI database background update failed: %s', exc)


_load_mac_parser()
threading.Thread(target=_update_mac_parser_bg, daemon=True, name='oui-updater').start()


def _oui_lookup(bssid: str):
    oui = ':'.join(bssid.upper().split(':')[:3])
    with _mac_parser_lock:
        parser = _mac_parser
    if parser:
        try:
            long_name  = parser.get_manuf_long(bssid) or ''
            short_name = parser.get_manuf(bssid)      or ''
            return oui, long_name or short_name or 'Unknown', short_name or long_name or 'Unknown'
        except Exception:
            pass
    return oui, 'Unknown', 'Unknown'


# ── 802.11 capability helpers ─────────────────────────────────────────────────

_CAP_LABELS = {
    'ESS':            'ESS (AP mode)',
    'IBSS':           'IBSS (Ad-hoc)',
    'CFP':            'CF-Pollable',
    'CFP-Req':        'CF-Poll Request',
    'privacy':        'Privacy',
    'short-preamble': 'Short Preamble',
    'PBCC':           'PBCC',
    'ch-agility':     'Channel Agility',
    'spectrum-mgmt':  'Spectrum Mgmt (DFS/TPC)',
    'QoS':            'WMM / QoS',
    'short-slot':     'Short Slot Time',
    'APSD':           'APSD (power save)',
    'radio-measure':  '802.11k Radio Measure',
    'DSSS-OFDM':      'DSSS-OFDM',
    'del-BA':         'Delayed Block Ack',
    'imm-BA':         'Immediate Block Ack',
}


def _parse_caps(cap_str: str) -> list:
    if not cap_str:
        return []
    flags = [f.strip() for f in cap_str.split('+') if f.strip()]
    return [{'raw': f, 'label': _CAP_LABELS.get(f, f)} for f in flags]


def _infer_generation(frequency_mhz, cap_flags: list) -> str:
    flag_names = {f['raw'] for f in cap_flags}
    has_short_slot = 'short-slot' in flag_names
    if frequency_mhz and frequency_mhz >= 5000:
        return '>= 802.11a  (5 GHz)'
    if has_short_slot:
        return '>= 802.11g  (short-slot)'
    if frequency_mhz and frequency_mhz < 3000:
        return '802.11b / g  (2.4 GHz)'
    return 'Unknown'


# ── Template helper functions ─────────────────────────────────────────────────

def rssi_class(rssi) -> str:
    if rssi is None:
        return 'rssi-none'
    if rssi >= -60:
        return 'rssi-good'
    if rssi >= -75:
        return 'rssi-ok'
    return 'rssi-weak'


def fmt_ts(ts: str) -> str:
    if not ts:
        return '—'
    try:
        return ts.replace('T', ' ')[:16]
    except Exception:
        return str(ts)[:16]


# ── System info ───────────────────────────────────────────────────────────────

def _get_sysinfo() -> dict:
    try:
        with open('/proc/uptime') as f:
            uptime_s = float(f.read().split()[0])
        days  = int(uptime_s // 86400)
        hours = int((uptime_s % 86400) // 3600)
        mins  = int((uptime_s % 3600) // 60)
        if days:
            uptime_str = f'{days}d {hours}h {mins}m'
        elif hours:
            uptime_str = f'{hours}h {mins}m'
        else:
            uptime_str = f'{mins}m'
    except Exception:
        uptime_str = '—'
    try:
        with open('/proc/stat') as f:
            line = f.readline()
        vals = list(map(int, line.split()[1:]))
        idle, total = vals[3], sum(vals)
        time.sleep(0.1)
        with open('/proc/stat') as f:
            line = f.readline()
        vals2 = list(map(int, line.split()[1:]))
        d_idle  = vals2[3] - idle
        d_total = sum(vals2) - total
        cpu_str = f'{round(100 * (1 - d_idle / d_total)) if d_total else 0}%'
    except Exception:
        cpu_str = '—'
    try:
        with open('/proc/meminfo') as f:
            lines = f.readlines()
        mem = {}
        for line in lines:
            k, v = line.split(':')
            mem[k.strip()] = int(v.split()[0])
        total_mb = mem['MemTotal'] // 1024
        avail_mb = mem['MemAvailable'] // 1024
        used_mb  = total_mb - avail_mb
        ram_pct  = round(100 * used_mb / total_mb) if total_mb else 0
    except Exception:
        total_mb = used_mb = ram_pct = 0
    return {
        'uptime': uptime_str,
        'cpu':    cpu_str,
        'mem':    {'used': used_mb, 'total': total_mb, 'pct': ram_pct},
    }


# ── Flask app ─────────────────────────────────────────────────────────────────

app = Flask(__name__, template_folder=str(APP_DIR / 'templates'))
app.jinja_env.globals.update(rssi_class=rssi_class, fmt_ts=fmt_ts)


# ── CORS (allows landing page at port 80 to fetch from port 8091) ─────────────

@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response


# ── Per-request DB connection ─────────────────────────────────────────────────

def get_db() -> sqlite3.Connection:
    if 'db' not in g:
        conn = sqlite3.connect(str(DB_PATH))
        conn.execute('PRAGMA journal_mode=WAL')
        conn.row_factory = sqlite3.Row
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(_err) -> None:
    db = g.pop('db', None)
    if db:
        db.close()


# ── MBTiles DB ────────────────────────────────────────────────────────────────

def _init_tiles_db() -> None:
    os.makedirs(os.path.dirname(TILES_DB_PATH), exist_ok=True)
    conn = sqlite3.connect(TILES_DB_PATH)
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS tiles (
            zoom_level   INTEGER NOT NULL,
            tile_column  INTEGER NOT NULL,
            tile_row     INTEGER NOT NULL,
            tile_data    BLOB    NOT NULL,
            PRIMARY KEY (zoom_level, tile_column, tile_row)
        );
        CREATE TABLE IF NOT EXISTS metadata (
            name  TEXT PRIMARY KEY,
            value TEXT
        );
    ''')
    for name, value in [('name', 'ism-wifi-monitor'), ('format', 'png'), ('type', 'baselayer')]:
        conn.execute('INSERT OR IGNORE INTO metadata (name, value) VALUES (?, ?)', (name, value))
    conn.commit()
    conn.close()
    log.info('Tiles DB ready: %s', TILES_DB_PATH)


def _get_tile(z: int, x: int, tms_y: int) -> Optional[bytes]:
    try:
        conn = sqlite3.connect(f'file:{TILES_DB_PATH}?mode=ro', uri=True)
        row  = conn.execute(
            'SELECT tile_data FROM tiles WHERE zoom_level=? AND tile_column=? AND tile_row=?',
            (z, x, tms_y),
        ).fetchone()
        conn.close()
        return bytes(row[0]) if row else None
    except Exception:
        return None


_tiles_write_lock = threading.Lock()


def _store_tile(z: int, x: int, tms_y: int, data: bytes) -> None:
    with _tiles_write_lock:
        conn = sqlite3.connect(TILES_DB_PATH)
        conn.execute('PRAGMA journal_mode=WAL')
        try:
            conn.execute(
                'INSERT OR REPLACE INTO tiles (zoom_level, tile_column, tile_row, tile_data) '
                'VALUES (?, ?, ?, ?)',
                (z, x, tms_y, sqlite3.Binary(data)),
            )
            conn.commit()
        finally:
            conn.close()


def _tile_count() -> int:
    try:
        conn = sqlite3.connect(f'file:{TILES_DB_PATH}?mode=ro', uri=True)
        n    = conn.execute('SELECT COUNT(*) FROM tiles').fetchone()[0]
        conn.close()
        return n
    except Exception:
        return 0


# ── Coordinate helpers ────────────────────────────────────────────────────────

def _xyz_to_tms_y(z: int, y: int) -> int:
    return (2 ** z - 1) - y


def _lat_lon_to_tile(lat: float, lon: float, z: int) -> Tuple[int, int]:
    n     = 2 ** z
    x     = int((lon + 180.0) / 360.0 * n)
    lat_r = math.radians(lat)
    y     = int((1.0 - math.log(math.tan(lat_r) + 1.0 / math.cos(lat_r)) / math.pi) / 2.0 * n)
    return max(0, min(n - 1, x)), max(0, min(n - 1, y))


def _tiles_for_bbox(lat_min, lat_max, lon_min, lon_max, z):
    x_min, y_min = _lat_lon_to_tile(lat_max, lon_min, z)
    x_max, y_max = _lat_lon_to_tile(lat_min, lon_max, z)
    for tx in range(x_min, x_max + 1):
        for ty in range(y_min, y_max + 1):
            yield z, tx, ty


def _bbox_for_radius(lat, lon, r_km):
    d_lat = r_km / 111.0
    d_lon = r_km / (111.0 * math.cos(math.radians(lat)))
    return lat - d_lat, lat + d_lat, lon - d_lon, lon + d_lon


# ── Online check ──────────────────────────────────────────────────────────────

_online_cache = {'status': None, 'ts': 0.0}
_online_lock  = threading.Lock()


def _is_online() -> bool:
    with _online_lock:
        if time.time() - _online_cache['ts'] < ONLINE_CHECK_TTL:
            return bool(_online_cache['status'])
    try:
        socket.setdefaulttimeout(2)
        socket.getaddrinfo('tile.openstreetmap.org', 443)
        status = True
    except Exception:
        status = False
    with _online_lock:
        _online_cache['status'] = status
        _online_cache['ts']     = time.time()
    return status


# ── OSM tile fetch ────────────────────────────────────────────────────────────

_osm_sem = threading.Semaphore(2)


def _fetch_osm_tile(z: int, x: int, y: int) -> bytes:
    url = OSM_TILE_URL.format(z=z, x=x, y=y)
    with _osm_sem:
        resp = requests.get(url, headers={'User-Agent': OSM_USER_AGENT}, timeout=10)
        resp.raise_for_status()
        return resp.content


# ── Flask routes ──────────────────────────────────────────────────────────────

@app.route('/raspi-style.css')
def serve_css():
    return send_from_directory(str(APP_DIR), 'raspi-style.css', mimetype='text/css')


@app.route('/')
def index():
    dbconn  = get_db()
    total   = dbconn.execute('SELECT COUNT(*) FROM access_points').fetchone()[0]
    new_24h = dbconn.execute(
        "SELECT COUNT(*) FROM access_points WHERE first_seen >= datetime('now', '-24 hours')"
    ).fetchone()[0]
    recent = dbconn.execute('''
        SELECT
            ap.bssid,
            ap.ssid,
            ap.encryption,
            ap.last_seen,
            s.signal_dbm    AS rssi,
            s.channel,
            (SELECT COUNT(*) FROM sightings WHERE bssid = ap.bssid) AS seen_count
        FROM access_points ap
        LEFT JOIN sightings s ON s.id = (
            SELECT id FROM sightings WHERE bssid = ap.bssid ORDER BY timestamp DESC LIMIT 1
        )
        ORDER BY ap.last_seen DESC
        LIMIT 10
    ''').fetchall()
    ch_dist = dbconn.execute('''
        SELECT channel, COUNT(*) AS cnt
        FROM sightings
        WHERE channel IS NOT NULL
        GROUP BY channel
        ORDER BY channel
    ''').fetchall()
    return render_template('wifi_index.html',
        total=total,
        new_24h=new_24h,
        recent=[dict(r) for r in recent],
        ch_dist=[dict(r) for r in ch_dist])


@app.route('/aps')
def aps():
    dbconn      = get_db()
    ssid_filter = request.args.get('ssid', '').strip()
    sort        = request.args.get('sort', 'last_seen')
    order       = request.args.get('order', 'desc')

    valid_sorts = {'ssid', 'channel', 'rssi', 'first_seen', 'last_seen', 'seen_count'}
    if sort not in valid_sorts:
        sort = 'last_seen'
    order_sql = 'ASC' if order == 'asc' else 'DESC'

    query = '''
        SELECT
            ap.bssid,
            ap.ssid,
            ap.encryption,
            ap.first_seen,
            ap.last_seen,
            s.signal_dbm    AS rssi,
            s.channel,
            s.frequency_mhz AS frequency,
            (SELECT COUNT(*) FROM sightings WHERE bssid = ap.bssid) AS seen_count
        FROM access_points ap
        LEFT JOIN sightings s ON s.id = (
            SELECT id FROM sightings WHERE bssid = ap.bssid ORDER BY timestamp DESC LIMIT 1
        )
    '''
    params = []
    if ssid_filter:
        query += ' WHERE ap.ssid LIKE ?'
        params.append(f'%{ssid_filter}%')
    query += f' GROUP BY ap.bssid ORDER BY {sort} {order_sql}'

    rows = dbconn.execute(query, params).fetchall()
    return render_template('wifi_aps.html',
        aps=[dict(r) for r in rows],
        ssid_filter=ssid_filter,
        sort=sort,
        order=order)


@app.route('/map')
def wifi_map():
    return send_from_directory(str(APP_DIR / 'templates'), 'wifi_map.html',
                               mimetype='text/html')


@app.route('/api/aps')
def api_aps():
    limit  = int(request.args.get('limit', 200))
    offset = int(request.args.get('offset', 0))
    dbconn = get_db()
    rows = dbconn.execute('''
        SELECT
            ap.bssid, ap.ssid, ap.encryption, ap.capabilities,
            ap.first_seen, ap.last_seen,
            s.signal_dbm, s.channel, s.frequency_mhz,
            s.latitude, s.longitude, s.gps_fix, s.timestamp AS sighting_time,
            (SELECT COUNT(*) FROM sightings WHERE bssid = ap.bssid) AS seen_count
        FROM access_points ap
        LEFT JOIN sightings s ON s.id = (
            SELECT id FROM sightings WHERE bssid = ap.bssid
            ORDER BY timestamp DESC LIMIT 1
        )
        ORDER BY ap.last_seen DESC
        LIMIT ? OFFSET ?
    ''', (limit, offset)).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        d['manufacturer'] = _oui_lookup(r['bssid'])
        result.append(d)
    return jsonify(result)


@app.route('/api/ap_locations')
def api_ap_locations():
    dbconn = get_db()
    rows = dbconn.execute('''
        SELECT
            ap.bssid,
            ap.ssid,
            ap.encryption,
            ap.last_seen,
            s.signal_dbm,
            s.channel,
            s.frequency_mhz,
            s.latitude,
            s.longitude,
            s.timestamp AS sighting_time
        FROM access_points ap
        JOIN sightings s ON s.id = (
            SELECT id FROM sightings
            WHERE bssid = ap.bssid AND gps_fix = 1
            ORDER BY timestamp DESC LIMIT 1
        )
        WHERE s.latitude IS NOT NULL AND s.longitude IS NOT NULL
        ORDER BY ap.last_seen DESC
    ''').fetchall()
    return jsonify([dict(r) for r in rows])


@app.route('/api/stats')
def api_stats():
    dbconn      = get_db()
    ap_count    = dbconn.execute('SELECT COUNT(*) FROM access_points').fetchone()[0]
    sight_count = dbconn.execute('SELECT COUNT(*) FROM sightings').fetchone()[0]
    gps_row     = dbconn.execute(
        'SELECT latitude, longitude, altitude_m, gps_fix '
        'FROM sightings WHERE gps_fix=1 ORDER BY timestamp DESC LIMIT 1'
    ).fetchone()
    return jsonify({
        'ap_count':       ap_count,
        'sighting_count': sight_count,
        'tile_count':     _tile_count(),
        'gps': {
            'lat': gps_row['latitude']    if gps_row else None,
            'lon': gps_row['longitude']   if gps_row else None,
            'alt': gps_row['altitude_m']  if gps_row else None,
            'fix': bool(gps_row['gps_fix']) if gps_row else False,
        },
    })


@app.route('/api/sysinfo')
def api_sysinfo():
    return jsonify(_get_sysinfo())


@app.route('/tiles/<int:z>/<int:x>/<int:y>')
def serve_tile(z: int, x: int, y: int):
    tms_y     = _xyz_to_tms_y(z, y)
    tile_data = _get_tile(z, x, tms_y)
    if tile_data:
        return Response(tile_data, mimetype='image/png',
                        headers={'Cache-Control': 'public, max-age=86400'})
    if _is_online():
        try:
            tile_data = _fetch_osm_tile(z, x, y)
            _store_tile(z, x, tms_y, tile_data)
            return Response(tile_data, mimetype='image/png',
                            headers={'Cache-Control': 'public, max-age=86400'})
        except Exception as exc:
            log.debug('OSM tile fetch failed z=%d x=%d y=%d: %s', z, x, y, exc)
    return Response(status=204)


# ── Cache Area ────────────────────────────────────────────────────────────────

_cache_lock   = threading.Lock()
_cache_status = {
    'running': False, 'total': 0, 'done': 0, 'new': 0,
    'failed': 0, 'finished': True, 'message': 'idle',
}


def _get_cache_status() -> dict:
    with _cache_lock:
        return dict(_cache_status)


def _update_cache(**kwargs) -> None:
    with _cache_lock:
        _cache_status.update(kwargs)


@app.route('/api/cache_area', methods=['POST'])
def api_cache_area():
    status = _get_cache_status()
    if status['running']:
        return jsonify({'error': 'A cache operation is already running'}), 409

    body = request.get_json(silent=True) or {}
    lat  = body.get('lat')
    lon  = body.get('lon')

    if lat is None or lon is None:
        row = get_db().execute(
            'SELECT latitude, longitude FROM sightings '
            'WHERE gps_fix=1 ORDER BY timestamp DESC LIMIT 1'
        ).fetchone()
        if row:
            lat, lon = row['latitude'], row['longitude']

    if lat is None or lon is None:
        return jsonify({'error': 'No GPS position available'}), 400
    if not _is_online():
        return jsonify({'error': 'No internet connection detected'}), 503

    _update_cache(running=True, total=0, done=0, new=0, failed=0,
                  finished=False, message='Building tile list...')
    threading.Thread(
        target=_do_cache_area, args=(float(lat), float(lon)),
        daemon=True, name='cache-area',
    ).start()
    return jsonify({'ok': True, 'lat': lat, 'lon': lon})


@app.route('/api/cache_status')
def api_cache_status():
    return jsonify(_get_cache_status())


def _do_cache_area(lat: float, lon: float) -> None:
    try:
        bbox    = _bbox_for_radius(lat, lon, CACHE_RADIUS_KM)
        all_xyz = []
        for z in range(CACHE_ZOOM_MIN, CACHE_ZOOM_MAX + 1):
            all_xyz.extend(_tiles_for_bbox(*bbox, z))

        total = len(all_xyz)
        _update_cache(total=total,
                      message=f'Downloading {total} tiles (zoom {CACHE_ZOOM_MIN}-{CACHE_ZOOM_MAX})...')

        for i, (z, tx, ty) in enumerate(all_xyz):
            tms_y = _xyz_to_tms_y(z, ty)
            if _get_tile(z, tx, tms_y) is not None:
                _update_cache(done=i + 1)
                continue
            try:
                data = _fetch_osm_tile(z, tx, ty)
                _store_tile(z, tx, tms_y, data)
                with _cache_lock:
                    _cache_status['new'] += 1
                time.sleep(TILE_RATE_LIMIT)
            except Exception as exc:
                log.warning('Cache download failed z=%d x=%d y=%d: %s', z, tx, ty, exc)
                with _cache_lock:
                    _cache_status['failed'] += 1
            _update_cache(done=i + 1)

        new    = _get_cache_status()['new']
        failed = _get_cache_status()['failed']
        _update_cache(running=False, finished=True,
                      message=f'Done — {new} new tiles downloaded, {failed} failed.')
    except Exception as exc:
        log.error('Cache area thread error: %s', exc)
        _update_cache(running=False, finished=True, message=f'Error: {exc}')


@app.route('/ap/<bssid>')
def ap_detail_page(bssid: str):
    return render_template('wifi_ap_detail.html', bssid=bssid)


@app.route('/api/client/<mac>')
def api_client_detail(mac: str):
    dbconn = get_db()

    # All APs this client has been seen connected to
    aps = dbconn.execute('''
        SELECT cs.bssid,
               ap.ssid,
               ap.encryption,
               COUNT(*)        AS sight_count,
               MIN(cs.timestamp) AS first_seen,
               MAX(cs.timestamp) AS last_seen,
               ROUND(AVG(cs.signal_dbm)) AS avg_signal
        FROM client_sightings cs
        LEFT JOIN access_points ap ON ap.bssid = cs.bssid
        WHERE cs.client_mac = ?
        GROUP BY cs.bssid
        ORDER BY last_seen DESC
    ''', (mac,)).fetchall()

    # Association frames for this client
    assocs = dbconn.execute('''
        SELECT timestamp, frame_subtype, bssid, ssid, signal_dbm, channel,
               CASE frame_subtype
                   WHEN 0  THEN "Assoc Req"
                   WHEN 1  THEN "Assoc Resp"
                   WHEN 2  THEN "Reassoc Req"
                   WHEN 3  THEN "Reassoc Resp"
                   WHEN 11 THEN "Auth"
                   ELSE CAST(frame_subtype AS TEXT)
               END AS frame_label
        FROM associations
        WHERE client_mac = ?
        ORDER BY timestamp DESC
        LIMIT 100
    ''', (mac,)).fetchall()

    # Signal history (last 50 sightings across all APs)
    history = dbconn.execute('''
        SELECT timestamp, bssid, signal_dbm, channel
        FROM client_sightings
        WHERE client_mac = ?
        ORDER BY timestamp DESC
        LIMIT 50
    ''', (mac,)).fetchall()

    oui, manuf_long, _ = _oui_lookup(mac)

    return jsonify({
        'mac':          mac,
        'oui':          oui,
        'manufacturer': manuf_long,
        'aps':          [dict(r) for r in aps],
        'associations': [dict(r) for r in assocs],
        'history':      [dict(r) for r in history],
    })


def api_ap_associations(bssid: str):
    dbconn = get_db()
    rows = dbconn.execute('''
        SELECT timestamp, frame_subtype, client_mac, ssid, signal_dbm, channel
        FROM associations
        WHERE bssid = ?
        ORDER BY timestamp DESC
        LIMIT 200
    ''', (bssid,)).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        d['manufacturer'] = _oui_lookup(r['client_mac'])[1]
        d['frame_label']  = {0:'Assoc Req', 1:'Assoc Resp',
                              2:'Reassoc Req', 3:'Reassoc Resp',
                              11:'Auth'}.get(r['frame_subtype'], str(r['frame_subtype']))
        result.append(d)
    return jsonify(result)


@app.route('/api/ap/<bssid>/clients')
def api_ap_clients(bssid: str):
    """Most recent data-frame sighting per client MAC — shows currently/recently connected clients."""
    dbconn = get_db()
    rows = dbconn.execute('''
        SELECT client_mac,
               MAX(timestamp)  AS last_seen,
               MIN(timestamp)  AS first_seen,
               COUNT(*)        AS sight_count,
               AVG(signal_dbm) AS avg_signal,
               MAX(signal_dbm) AS best_signal
        FROM client_sightings
        WHERE bssid = ?
        GROUP BY client_mac
        ORDER BY last_seen DESC
        LIMIT 200
    ''', (bssid,)).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        d['manufacturer'] = _oui_lookup(r['client_mac'])[1]
        d['avg_signal']   = round(d['avg_signal']) if d['avg_signal'] is not None else None
        result.append(d)
    return jsonify(result)


# ── AP detail ─────────────────────────────────────────────────────────────────

@app.route('/api/ap/<bssid>')
def api_ap_detail(bssid: str):
    dbconn = get_db()

    ap = dbconn.execute(
        'SELECT bssid, ssid, encryption, capabilities, first_seen, last_seen '
        'FROM access_points WHERE bssid = ?', (bssid,)
    ).fetchone()
    if not ap:
        return jsonify({'error': 'Not found'}), 404

    stats = dbconn.execute('''
        SELECT
            COUNT(*)        AS total_sightings,
            MIN(signal_dbm) AS sig_min,
            MAX(signal_dbm) AS sig_max,
            ROUND(AVG(signal_dbm)) AS sig_avg,
            COUNT(CASE WHEN gps_fix = 1 THEN 1 END) AS gps_sightings
        FROM sightings WHERE bssid = ?
    ''', (bssid,)).fetchone()

    radio_row = dbconn.execute('''
        SELECT channel, frequency_mhz, COUNT(*) AS n
        FROM sightings
        WHERE bssid = ? AND channel IS NOT NULL
        GROUP BY channel ORDER BY n DESC LIMIT 1
    ''', (bssid,)).fetchone()

    sightings = dbconn.execute('''
        SELECT timestamp, signal_dbm, channel, frequency_mhz,
               latitude, longitude, altitude_m, gps_fix
        FROM sightings
        WHERE bssid = ?
        ORDER BY timestamp DESC
        LIMIT 200
    ''', (bssid,)).fetchall()

    oui, manuf_long, manuf_short = _oui_lookup(bssid)
    cap_flags  = _parse_caps(ap['capabilities'] or '')
    freq       = radio_row['frequency_mhz'] if radio_row else None
    generation = _infer_generation(freq, cap_flags)

    return jsonify({
        'ap':       dict(ap),
        'stats':    dict(stats),
        'sightings': [dict(s) for s in sightings],
        'technical': {
            'oui':           oui,
            'manuf_long':    manuf_long,
            'manuf_short':   manuf_short,
            'cap_flags':     cap_flags,
            'generation':    generation,
            'channel':       radio_row['channel']        if radio_row else None,
            'frequency_mhz': radio_row['frequency_mhz']  if radio_row else None,
            'band':          ('5 GHz' if freq and freq >= 5000 else '2.4 GHz') if freq else None,
            'hidden_ssid':   not bool(ap['ssid']),
            'ssid_len':      len(ap['ssid']) if ap['ssid'] else 0,
        },
    })


# ── Shutdown ──────────────────────────────────────────────────────────────────

@app.route('/api/shutdown', methods=['POST'])
def api_shutdown():
    action = (request.get_json(silent=True) or {}).get('action', '')
    if action == 'reboot':
        log.info('Reboot requested via web UI')
        threading.Thread(
            target=lambda: (time.sleep(1), subprocess.run(['sudo', 'reboot'])),
            daemon=True,
        ).start()
        return jsonify({'ok': True, 'action': 'reboot'})
    elif action == 'shutdown':
        log.info('Shutdown requested via web UI')
        threading.Thread(
            target=lambda: (time.sleep(1), subprocess.run(['sudo', 'shutdown', '-h', 'now'])),
            daemon=True,
        ).start()
        return jsonify({'ok': True, 'action': 'shutdown'})
    return jsonify({'error': 'Invalid action — use reboot or shutdown'}), 400


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == '__main__':
    from db_wifi import init_db as init_wifi_db
    init_wifi_db()
    _init_tiles_db()
    app.run(host=WEB_HOST, port=WEB_PORT, threaded=True, debug=False)
