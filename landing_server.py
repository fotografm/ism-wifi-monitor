#!/usr/bin/env python3
"""
landing_server.py  —  raspi81 ism-wifi-monitor
aiohttp combined landing page server (port 80).
Serves:
  /               — combined landing.html
  /raspi-style.css — shared stylesheet
  /{everything else} — 302 redirect to http://hostname:8092{path}
Requires AmbientCapabilities=CAP_NET_BIND_SERVICE in systemd service.
"""

import logging
from pathlib import Path

from aiohttp import web

from config import LANDING_PORT, WEB_HOST

APP_DIR  = Path.home() / 'ism-wifi-monitor'
TMPL_DIR = APP_DIR / 'templates'

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [landing] %(levelname)s %(message)s',
    datefmt='%Y-%m-%dT%H:%M:%S',
)
log = logging.getLogger('landing')


async def handle_landing(req: web.Request) -> web.Response:
    text = (TMPL_DIR / 'landing.html').read_text()
    return web.Response(text=text, content_type='text/html')


async def handle_css(req: web.Request) -> web.Response:
    text = (APP_DIR / 'raspi-style.css').read_text()
    return web.Response(text=text, content_type='text/css')


async def handle_redirect(req: web.Request) -> web.Response:
    host = req.host.split(':')[0]
    raise web.HTTPFound(f'http://{host}:8092{req.path_qs}')


def build_app() -> web.Application:
    app = web.Application()
    app.router.add_get('/', handle_landing)
    app.router.add_get('/raspi-style.css', handle_css)
    app.router.add_route('*', '/{path:.*}', handle_redirect)
    return app


if __name__ == '__main__':
    log.info('Landing server starting on port %d', LANDING_PORT)
    web.run_app(build_app(), host=WEB_HOST, port=LANDING_PORT, access_log=None)
