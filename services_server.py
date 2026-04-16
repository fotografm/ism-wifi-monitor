"""
services_server.py  —  raspi81 ism-wifi-monitor
Service control panel backend on port 8098.
Runs as root so it can call systemctl start/stop.

Endpoints:
  GET  /                          — serves services.html
  GET  /api/services              — status of all services
  POST /api/service/<name>/start  — start a service
  POST /api/service/<name>/stop   — stop a service
  GET  /api/db                    — info (count, size) for each DB
  POST /api/db/<name>/clear       — delete and recreate a DB
"""

import asyncio
import logging
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

# Add ism-wifi-monitor dir to path so we can import the DB init modules
sys.path.insert(0, '/home/user/ism-wifi-monitor')

from aiohttp import web

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [services] %(levelname)s %(message)s',
    datefmt='%Y-%m-%dT%H:%M:%S',
)
log = logging.getLogger('services')

PORT    = 8098
APP_DIR = Path('/home/user/ism-wifi-monitor')

# ── Service definitions ───────────────────────────────────────────────────────

SERVICES = [
    {'name': 'ism-wifi-landing',         'label': 'Landing Page',          'port': 80},
    {'name': 'ism-wifi-wifi-web',        'label': 'WiFi Web',              'port': 8091},
    {'name': 'ism-wifi-ism',             'label': 'ISM Monitor',           'port': 8092},
    {'name': 'ism-wifi-gps',             'label': 'GPS Dashboard',         'port': 8093},
    {'name': 'ism-wifi-skymap3d',        'label': '3D Skymap',             'port': 8094},
    {'name': 'ism-wifi-history-web',     'label': 'WiFi History Web',      'port': 8095},
    {'name': 'ism-wifi-terminal',        'label': 'Terminal Server',       'port': 8096},
    {'name': 'ism-wifi-notes',           'label': 'Notes Server',          'port': 8097},
    {'name': 'ism-wifi-services',        'label': 'Services Control',      'port': 8098},
    {'name': 'ism-wifi-wifi-scan',       'label': 'WiFi Scanner (root)',   'port': None},
    {'name': 'ism-wifi-history-monitor', 'label': 'History Monitor (root)','port': None},
    {'name': 'rfkill-unblock',           'label': 'RF Kill Unblock',       'port': None},
]

# Only allow start/stop of these — protect rfkill and self
ALLOWED_CONTROL = {s['name'] for s in SERVICES} - {'rfkill-unblock', 'ism-wifi-services'}

# ── Database definitions ──────────────────────────────────────────────────────

DB_BASE = APP_DIR / 'db'

DATABASES = {
    'wifi': {
        'label':  'WiFi Logger',
        'path':   DB_BASE / 'wifi_logger.db',
        'tables': ['access_points', 'sightings', 'associations', 'client_sightings'],
        'init':   'wifi',
    },
    'history': {
        'label':  'WiFi History',
        'path':   DB_BASE / 'wifi_history.db',
        'tables': ['probe_requests', 'beacons', 'ie_fingerprints', 'mac_fp_map', 'associations'],
        'init':   'history',
    },
    'ism': {
        'label':  'ISM Monitor',
        'path':   DB_BASE / 'ism_monitor.db',
        'tables': ['signals', 'transmitters'],
        'init':   'ism',
    },
    'gps': {
        'label':  'GPS History',
        'path':   DB_BASE / 'gps_history.db',
        'tables': ['positions'],
        'init':   'gps',
    },
}

# ── Helpers ───────────────────────────────────────────────────────────────────

def _svc_status(name: str) -> str:
    """Returns 'active', 'inactive', 'failed', or 'unknown'."""
    try:
        r = subprocess.run(
            ['systemctl', 'is-active', name],
            capture_output=True, text=True, timeout=3
        )
        return r.stdout.strip()
    except Exception:
        return 'unknown'


def _db_info(db: dict) -> dict:
    path = db['path']
    size_bytes = path.stat().st_size if path.exists() else 0

    counts = {}
    if path.exists():
        try:
            conn = sqlite3.connect(str(path))
            for table in db['tables']:
                try:
                    row = conn.execute(f'SELECT COUNT(*) FROM {table}').fetchone()
                    counts[table] = row[0] if row else 0
                except Exception:
                    counts[table] = None
            conn.close()
        except Exception:
            pass

    return {
        'exists':     path.exists(),
        'size_bytes': size_bytes,
        'size_human': _fmt_size(size_bytes),
        'counts':     counts,
        'total_rows': sum(v for v in counts.values() if v is not None),
    }


def _fmt_size(n: int) -> str:
    if n < 1024:        return f'{n} B'
    if n < 1024 ** 2:   return f'{n/1024:.1f} KB'
    if n < 1024 ** 3:   return f'{n/1024**2:.1f} MB'
    return f'{n/1024**3:.2f} GB'


def _reinit_db(key: str):
    """Recreate empty tables for the given DB key."""
    try:
        if key == 'wifi':
            from db_wifi import init_db
            init_db()
        elif key == 'history':
            from db_history import init_db
            init_db()
        elif key == 'ism':
            from db_ism import init_db
            init_db()
        elif key == 'gps':
            # GPS DB init is inline in gps_web.py — replicate it here
            db = DATABASES['gps']
            path = db['path']
            path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(path))
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
    except Exception as e:
        log.warning('reinit_db %s error: %s', key, e)


def _clear_db(key: str) -> dict:
    db   = DATABASES[key]
    path = db['path']
    try:
        path.unlink(missing_ok=True)
        for ext in ('.db-wal', '.db-shm'):
            (path.parent / (path.name + ext)).unlink(missing_ok=True)
        log.info('Cleared DB: %s', path)
        _reinit_db(key)
        log.info('Reinitialised empty tables for %s', key)
        return {'ok': True, 'message': f'{db["label"]} cleared and ready.'}
    except Exception as e:
        log.error('Clear DB error: %s', e)
        return {'ok': False, 'message': str(e)}


def json_resp(data, status=200):
    import json
    return web.Response(
        text=json.dumps(data),
        content_type='application/json',
        status=status,
    )

# ── Route handlers ────────────────────────────────────────────────────────────

async def handle_root(request):
    path = APP_DIR / 'templates' / 'services.html'
    return web.Response(text=path.read_text(), content_type='text/html')


async def api_services(request):
    loop = asyncio.get_event_loop()
    result = []
    for svc in SERVICES:
        status = await loop.run_in_executor(None, _svc_status, svc['name'])
        result.append({
            'name':            svc['name'],
            'label':           svc['label'],
            'port':            svc['port'],
            'status':          status,
            'controllable':    svc['name'] in ALLOWED_CONTROL,
        })
    return json_resp(result)


async def api_service_start(request):
    name = request.match_info['name']
    if name not in ALLOWED_CONTROL:
        return json_resp({'ok': False, 'message': 'Not allowed'}, 403)
    try:
        r = subprocess.run(['systemctl', 'start', name],
                           capture_output=True, text=True, timeout=10)
        ok = r.returncode == 0
        log.info('START %s → %s', name, 'ok' if ok else r.stderr.strip())
        return json_resp({'ok': ok, 'message': r.stderr.strip() or 'Started'})
    except Exception as e:
        return json_resp({'ok': False, 'message': str(e)}, 500)


async def api_service_stop(request):
    name = request.match_info['name']
    if name not in ALLOWED_CONTROL:
        return json_resp({'ok': False, 'message': 'Not allowed'}, 403)
    try:
        r = subprocess.run(['systemctl', 'stop', name],
                           capture_output=True, text=True, timeout=10)
        ok = r.returncode == 0
        log.info('STOP %s → %s', name, 'ok' if ok else r.stderr.strip())
        return json_resp({'ok': ok, 'message': r.stderr.strip() or 'Stopped'})
    except Exception as e:
        return json_resp({'ok': False, 'message': str(e)}, 500)


async def api_db_info(request):
    loop   = asyncio.get_event_loop()
    result = {}
    for key, db in DATABASES.items():
        info = await loop.run_in_executor(None, _db_info, db)
        result[key] = {'label': db['label'], **info}
    return json_resp(result)


async def api_db_clear(request):
    key = request.match_info['name']
    if key not in DATABASES:
        return json_resp({'ok': False, 'message': 'Unknown database'}, 404)
    loop   = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, _clear_db, key)
    return json_resp(result)


# ── CORS + app ────────────────────────────────────────────────────────────────

@web.middleware
async def cors_mw(request, handler):
    if request.method == 'OPTIONS':
        return web.Response(headers={
            'Access-Control-Allow-Origin':  '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type',
        })
    resp = await handler(request)
    resp.headers['Access-Control-Allow-Origin'] = '*'
    return resp


def build_app():
    app = web.Application(middlewares=[cors_mw])
    app.router.add_get('/',                         handle_root)
    app.router.add_get('/api/services',             api_services)
    app.router.add_post('/api/service/{name}/start', api_service_start)
    app.router.add_post('/api/service/{name}/stop',  api_service_stop)
    app.router.add_get('/api/db',                   api_db_info)
    app.router.add_post('/api/db/{name}/clear',      api_db_clear)
    return app


if __name__ == '__main__':
    log.info('Services server starting on port %d', PORT)
    web.run_app(build_app(), host='0.0.0.0', port=PORT, access_log=None)
