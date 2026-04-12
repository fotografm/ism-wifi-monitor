#!/usr/bin/env python3
"""
gps_web.py  —  raspi81 ism-wifi-monitor
GPS dashboard web server (port 8093).
Uses raw gpsd socket (no python-gps module needed).
Features:
  - Reads TPV + SKY from gpsd via JSON socket
  - 24-hour satellite history sampled every 30 seconds
  - History persisted to SQLite — survives service restarts and reboots
  - /api/gps         — current position, satellites, DOP, Maidenhead
  - /api/gps_history — 24h history per PRN for skyplot/graphs
  - /api/shutdown    — POST reboot/shutdown
"""
import json
import logging
import os
import socket
import sqlite3
import subprocess
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional

from flask import Flask, jsonify, render_template, request

from config import GPS_HOST, GPS_PORT, GPS_WEB_PORT, GPS_HISTORY_DB, WEB_HOST

WEB_PORT = GPS_WEB_PORT
APP_DIR  = str(Path.home() / 'ism-wifi-monitor')
HISTORY_DB = str(GPS_HISTORY_DB)

HISTORY_INTERVAL = 30
HISTORY_MAXAGE   = 86400

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [gps-web] %(levelname)s %(message)s',
    datefmt='%Y-%m-%dT%H:%M:%S',
)
log = logging.getLogger('gps_web')

_lock = threading.Lock()
_stop = threading.Event()

_position: dict = {
    'lat': None, 'lon': None, 'alt': None, 'speed': None,
    'fix': False, 'mode': 0,
}
_sky: dict = {
    'hdop': None, 'vdop': None, 'pdop': None, 'satellites': [],
}
_history: Dict[str, List] = {}
_history_lock = threading.Lock()


# ── SQLite history DB ─────────────────────────────────────────────────────────
def _init_history_db() -> None:
    os.makedirs(os.path.dirname(HISTORY_DB), exist_ok=True)
    conn = sqlite3.connect(HISTORY_DB)
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS sat_history (
            id  INTEGER PRIMARY KEY AUTOINCREMENT,
            prn TEXT    NOT NULL,
            ts  REAL    NOT NULL,
            az  REAL    NOT NULL,
            el  REAL    NOT NULL,
            ss  REAL    NOT NULL
        )
    ''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_sh_ts  ON sat_history(ts)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_sh_prn ON sat_history(prn, ts)')
    conn.commit()
    conn.close()
    log.info('History DB ready: %s', HISTORY_DB)


def _load_history_from_db() -> None:
    cutoff = time.time() - HISTORY_MAXAGE
    try:
        conn = sqlite3.connect(HISTORY_DB)
        rows = conn.execute(
            'SELECT prn, ts, az, el, ss FROM sat_history WHERE ts >= ? ORDER BY ts ASC',
            (cutoff,),
        ).fetchall()
        conn.close()
        with _history_lock:
            for prn, ts, az, el, ss in rows:
                if prn not in _history:
                    _history[prn] = []
                _history[prn].append([ts, az, el, ss])
        log.info('Loaded %d history rows from DB (%d PRNs)', len(rows), len(_history))
    except Exception as exc:
        log.warning('Failed to load history from DB: %s', exc)


def _write_history_to_db(new_points: List) -> None:
    cutoff = time.time() - HISTORY_MAXAGE
    try:
        conn = sqlite3.connect(HISTORY_DB)
        conn.execute('PRAGMA journal_mode=WAL')
        conn.executemany(
            'INSERT INTO sat_history (prn, ts, az, el, ss) VALUES (?,?,?,?,?)',
            new_points,
        )
        conn.execute('DELETE FROM sat_history WHERE ts < ?', (cutoff,))
        conn.commit()
        conn.close()
    except Exception as exc:
        log.warning('DB write error: %s', exc)


# ── gpsd reader thread (raw socket, no python-gps dependency) ─────────────────
def _gps_thread() -> None:
    while not _stop.is_set():
        try:
            sock = socket.create_connection((GPS_HOST, GPS_PORT), timeout=5)
            sock.sendall(b'?WATCH={"enable":true,"json":true}\n')
            log.info('GPS reader connected to gpsd %s:%d', GPS_HOST, GPS_PORT)
            buf = ''
            while not _stop.is_set():
                sock.settimeout(65)
                chunk = sock.recv(4096).decode('utf-8', errors='replace')
                if not chunk:
                    break
                buf += chunk
                while '\n' in buf:
                    line, buf = buf.split('\n', 1)
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        msg = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    cls = msg.get('class')
                    if cls == 'TPV':
                        mode = int(msg.get('mode', 0))
                        with _lock:
                            _position.update({
                                'lat':   msg.get('lat'),
                                'lon':   msg.get('lon'),
                                'alt':   msg.get('alt'),
                                'speed': msg.get('speed'),
                                'fix':   mode >= 2,
                                'mode':  mode,
                            })
                    elif cls == 'SKY':
                        sats_raw = msg.get('satellites', []) or []
                        sats = [{
                            'prn':  s.get('PRN'),
                            'el':   s.get('el'),
                            'az':   s.get('az'),
                            'ss':   s.get('ss'),
                            'used': bool(s.get('used', False)),
                        } for s in sats_raw]
                        with _lock:
                            _sky.update({
                                'hdop':       msg.get('hdop'),
                                'vdop':       msg.get('vdop'),
                                'pdop':       msg.get('pdop'),
                                'satellites': sats,
                            })
            sock.close()
        except Exception as exc:
            log.warning('gpsd error: %s — retrying in 5s', exc)
            with _lock:
                _position['fix']   = False
                _sky['satellites'] = []
        time.sleep(5)


# ── History sampler thread ────────────────────────────────────────────────────
def _history_thread() -> None:
    while not _stop.is_set():
        time.sleep(HISTORY_INTERVAL)
        now    = time.time()
        cutoff = now - HISTORY_MAXAGE
        with _lock:
            sats = list(_sky['satellites'])
        new_db_rows = []
        with _history_lock:
            for s in sats:
                prn = s.get('prn')
                az  = s.get('az')
                el  = s.get('el')
                ss  = s.get('ss')
                if prn is None or az is None or el is None:
                    continue
                key = str(prn)
                pt  = [now, az, el, ss if ss is not None else 0]
                if key not in _history:
                    _history[key] = []
                _history[key].append(pt)
                new_db_rows.append((key, now, az, el, ss if ss is not None else 0))
            for key in list(_history.keys()):
                _history[key] = [p for p in _history[key] if p[0] >= cutoff]
                if not _history[key]:
                    del _history[key]
        if new_db_rows:
            _write_history_to_db(new_db_rows)


# ── Maidenhead ────────────────────────────────────────────────────────────────
def _maidenhead(lat: float, lon: float) -> str:
    try:
        lat += 90.0; lon += 180.0
        a = chr(ord('A') + int(lon / 20))
        b = chr(ord('A') + int(lat / 10))
        c = str(int((lon % 20) / 2))
        d = str(int(lat % 10))
        e = chr(ord('a') + int((lon % 2) * 12))
        f = chr(ord('a') + int((lat % 1) * 24))
        return a + b + c + d + e + f
    except Exception:
        return '--'


def _fmtf(v) -> Optional[str]:
    return f'{v:.1f}' if v is not None else None


# ── Flask ─────────────────────────────────────────────────────────────────────
app = Flask(__name__, template_folder=os.path.join(APP_DIR, 'templates'))


@app.route('/')
def index():
    return render_template('gps.html')


@app.route('/api/gps')
def api_gps():
    with _lock:
        pos  = dict(_position)
        sky  = dict(_sky)
        sats = list(sky['satellites'])
    maidenhead = None
    if pos['lat'] is not None and pos['lon'] is not None:
        maidenhead = _maidenhead(pos['lat'], pos['lon'])
    sats_sorted = sorted(sats, key=lambda s: (not s['used'], -(s['ss'] or 0)))
    return jsonify({
        'position': pos,
        'sky': {
            'hdop':       _fmtf(sky['hdop']),
            'vdop':       _fmtf(sky['vdop']),
            'pdop':       _fmtf(sky['pdop']),
            'satellites': sats_sorted,
            'sat_count':  len(sats),
            'used_count': sum(1 for s in sats if s['used']),
        },
        'maidenhead': maidenhead,
    })


@app.route('/api/gps_history')
def api_gps_history():
    now = time.time()
    with _history_lock:
        out = {
            prn: [[round(now - p[0]), p[1], p[2], p[3]] for p in pts]
            for prn, pts in _history.items()
        }
    return jsonify(out)


@app.route('/api/shutdown', methods=['POST'])
def api_shutdown():
    action = (request.get_json(silent=True) or {}).get('action', '')
    if action == 'reboot':
        threading.Thread(
            target=lambda: (time.sleep(1), subprocess.run(['sudo', 'reboot'])),
            daemon=True,
        ).start()
        return jsonify({'ok': True, 'action': 'reboot'})
    elif action == 'shutdown':
        threading.Thread(
            target=lambda: (time.sleep(1), subprocess.run(['sudo', 'shutdown', '-h', 'now'])),
            daemon=True,
        ).start()
        return jsonify({'ok': True, 'action': 'shutdown'})
    return jsonify({'error': 'Invalid action'}), 400


if __name__ == '__main__':
    _init_history_db()
    _load_history_from_db()
    threading.Thread(target=_gps_thread,     daemon=True, name='gps-reader').start()
    threading.Thread(target=_history_thread, daemon=True, name='gps-history').start()
    log.info('GPS dashboard starting on port %d', WEB_PORT)
    app.run(host=WEB_HOST, port=WEB_PORT, threaded=True, debug=False)
