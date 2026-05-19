#!/usr/bin/env python3
"""
landing_server.py  —  raspi81 ism-wifi-monitor
aiohttp combined landing page server (port 80).
Serves:
  /               — combined landing.html
  /raspi-style.css — shared stylesheet
  /api/sysinfo    — uptime, CPU, RAM, disk, CPU temp (JSON)
  /api/gps        — proxy to GPS dashboard at port 8093 (avoids cross-origin fetch)
  /{everything else} — 302 redirect to http://hostname:8092{path}
Requires AmbientCapabilities=CAP_NET_BIND_SERVICE in systemd service.
"""

import asyncio
import logging
import os
import time
from pathlib import Path

import aiohttp
from aiohttp import web

from config import LANDING_PORT, WEB_HOST

APP_DIR  = Path.home() / 'ism-wifi-monitor'
TMPL_DIR = APP_DIR / 'templates'

GPS_API_URL = 'http://127.0.0.1:8093/api/gps'

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [landing] %(levelname)s %(message)s',
    datefmt='%Y-%m-%dT%H:%M:%S',
)
log = logging.getLogger('landing')


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
        idle = vals[3]
        total = sum(vals)
        time.sleep(0.1)
        with open('/proc/stat') as f:
            line = f.readline()
        vals2 = list(map(int, line.split()[1:]))
        d_idle  = vals2[3] - idle
        d_total = sum(vals2) - total
        cpu_pct = round(100 * (1 - d_idle / d_total)) if d_total else 0
    except Exception:
        cpu_pct = 0

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
    except Exception:
        total_mb = used_mb = 0

    try:
        st = os.statvfs('/home/user/ism-wifi-monitor')
        disk_total_mb = (st.f_blocks * st.f_frsize) // (1024 * 1024)
        disk_free_mb  = (st.f_bavail * st.f_frsize) // (1024 * 1024)
        disk_used_mb  = disk_total_mb - disk_free_mb
    except Exception:
        disk_total_mb = disk_used_mb = 0

    try:
        with open('/sys/class/thermal/thermal_zone0/temp') as f:
            cpu_temp = round(int(f.read().strip()) / 1000.0, 1)
    except Exception:
        cpu_temp = None

    return {
        'uptime':        uptime_str,
        'cpu_pct':       cpu_pct,
        'cpu_temp':      cpu_temp,
        'ram_used_mb':   used_mb,
        'ram_total_mb':  total_mb,
        'disk_used_mb':  disk_used_mb,
        'disk_total_mb': disk_total_mb,
    }


async def handle_landing(req: web.Request) -> web.Response:
    text = (TMPL_DIR / 'landing.html').read_text()
    return web.Response(text=text, content_type='text/html')


async def handle_css(req: web.Request) -> web.Response:
    text = (APP_DIR / 'raspi-style.css').read_text()
    return web.Response(text=text, content_type='text/css')


async def handle_ism_settings(req: web.Request) -> web.Response:
    text = (TMPL_DIR / 'ism_settings.html').read_text()
    return web.Response(text=text, content_type='text/html')


async def handle_sysinfo(req: web.Request) -> web.Response:
    loop = asyncio.get_event_loop()
    info = await loop.run_in_executor(None, _get_sysinfo)
    return web.json_response(info)


async def handle_gps_proxy(req: web.Request) -> web.Response:
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(GPS_API_URL, timeout=aiohttp.ClientTimeout(total=3)) as resp:
                data = await resp.json()
        return web.json_response(data)
    except Exception as exc:
        log.debug('GPS proxy error: %s', exc)
        return web.json_response({'error': str(exc)}, status=502)


async def handle_redirect(req: web.Request) -> web.Response:
    host = req.host.split(':')[0]
    raise web.HTTPFound(f'http://{host}:8092{req.path_qs}')


def build_app() -> web.Application:
    app = web.Application()
    app.router.add_get('/', handle_landing)
    app.router.add_get('/raspi-style.css', handle_css)
    app.router.add_get('/settings', handle_ism_settings)
    app.router.add_get('/api/sysinfo', handle_sysinfo)
    app.router.add_get('/api/gps', handle_gps_proxy)
    app.router.add_route('*', '/{path:.*}', handle_redirect)
    return app


if __name__ == '__main__':
    log.info('Landing server starting on port %d', LANDING_PORT)
    web.run_app(build_app(), host=WEB_HOST, port=LANDING_PORT, access_log=None)
