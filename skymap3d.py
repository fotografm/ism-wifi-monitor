#!/usr/bin/env python3
"""
skymap3d.py  —  raspi81 ism-wifi-monitor
3D satellite skymap web server (port 8094).
Serves the Three.js 3D visualisation page.
Proxies /api/gps and /api/gps_history from gps_web.py.
"""
import logging
import os
from pathlib import Path

import requests
from flask import Flask, jsonify, render_template

from config import SKYMAP3D_PORT as WEB_PORT, GPS_WEB_PORT, WEB_HOST

GPS_API_BASE = f'http://127.0.0.1:{GPS_WEB_PORT}'
APP_DIR      = str(Path.home() / 'ism-wifi-monitor')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [skymap3d] %(levelname)s %(message)s',
    datefmt='%Y-%m-%dT%H:%M:%S',
)
log = logging.getLogger('skymap3d')

app = Flask(__name__, template_folder=os.path.join(APP_DIR, 'templates'))


@app.route('/')
def index():
    return render_template('skymap3d.html')


@app.route('/api/gps')
def proxy_gps():
    try:
        r = requests.get(f'{GPS_API_BASE}/api/gps', timeout=3)
        return jsonify(r.json())
    except Exception as exc:
        log.warning('GPS proxy error: %s', exc)
        return jsonify({'error': 'GPS service unavailable'}), 503


@app.route('/api/gps_history')
def proxy_history():
    try:
        r = requests.get(f'{GPS_API_BASE}/api/gps_history', timeout=5)
        return jsonify(r.json())
    except Exception as exc:
        log.warning('History proxy error: %s', exc)
        return jsonify({}), 503


if __name__ == '__main__':
    log.info('3D Skymap starting on port %d', WEB_PORT)
    app.run(host=WEB_HOST, port=WEB_PORT, threaded=True, debug=False)
