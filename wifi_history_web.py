"""
wifi_history_web.py  —  raspi81 ism-wifi-monitor
aiohttp web server for WiFi History Diagnostic (port 8095).

Ported from raspi70/web_server.py with changes:
  - Port 8095
  - Template folder: ~/ism-wifi-monitor/templates (files prefixed history_)
  - Serves raspi-style.css at /raspi-style.css
  - CORS headers on all responses
  - New route: /history/devices/<fp_hash> for full device detail page
  - Imports db_history, oui (not db)
"""

import asyncio
import json
import logging
import time
from datetime import datetime
from pathlib import Path

from aiohttp import web
from jinja2 import Environment, FileSystemLoader

import db_history as db
import oui

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s: %(message)s'
)
log = logging.getLogger('wifi_history_web')

BASE_DIR = Path.home() / 'ism-wifi-monitor'
PORT     = 8095

# ── Jinja2 ────────────────────────────────────────────────────────────────────

jinja = Environment(
    loader=FileSystemLoader(str(BASE_DIR / 'templates')),
    autoescape=True,
)


def _fmt_ts(ts):
    if ts is None:
        return '—'
    return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')


def _fmt_ago(ts):
    if ts is None:
        return '—'
    delta = int(time.time() - ts)
    if delta < 60:
        return f'{delta}s ago'
    if delta < 3600:
        return f'{delta // 60}m ago'
    if delta < 86400:
        return f'{delta // 3600}h ago'
    return f'{delta // 86400}d ago'


def _fmt_subtype(st):
    return {0: 'Assoc Req', 1: 'Assoc Resp', 11: 'Auth'}.get(st, str(st))


jinja.globals['fmt_ts']      = _fmt_ts
jinja.globals['fmt_ago']     = _fmt_ago
jinja.globals['fmt_subtype'] = _fmt_subtype
jinja.filters['tojson']      = json.dumps
jinja.filters['fromjson']    = json.loads


def render(template_name, page='', **ctx):
    t = jinja.get_template(template_name)
    return web.Response(
        text=t.render(page=page, **ctx),
        content_type='text/html',
        headers={'Access-Control-Allow-Origin': '*'},
    )


def json_resp(data):
    return web.Response(
        text=json.dumps(data),
        content_type='application/json',
        headers={'Access-Control-Allow-Origin': '*'},
    )


# ── DB helper ─────────────────────────────────────────────────────────────────

def _run_db(fn, *args, **kwargs):
    conn = db.get_connection()
    try:
        return fn(conn, *args, **kwargs)
    finally:
        conn.close()


async def db_call(fn, *args, **kwargs):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _run_db, fn, *args, **kwargs)


# ── static ────────────────────────────────────────────────────────────────────

async def handle_css(request):
    text = (BASE_DIR / 'raspi-style.css').read_text()
    return web.Response(text=text, content_type='text/css',
                        headers={'Access-Control-Allow-Origin': '*'})


# ── page routes ───────────────────────────────────────────────────────────────

async def handle_index(request):
    stats        = await db_call(db.q_stats)
    probes       = await db_call(db.q_recent_probes, 25)
    channel_dist = await db_call(db.q_probes_per_channel)
    trend        = await db_call(db.q_probes_per_minute, 60)
    return render(
        'history_index.html', page='index',
        stats=stats,
        probes=[dict(p) for p in probes],
        channel_dist=[dict(c) for c in channel_dist],
        trend=[dict(t) for t in trend],
    )


async def handle_probes(request):
    mac_filter  = request.rel_url.query.get('mac',  '').strip()
    ssid_filter = request.rel_url.query.get('ssid', '').strip()
    page_num    = max(1, int(request.rel_url.query.get('page', 1)))
    limit       = 100
    offset      = (page_num - 1) * limit
    rows = await db_call(
        db.q_recent_probes, limit, offset,
        mac_filter or None, ssid_filter or None
    )
    return render(
        'history_probes.html', page='probes',
        probes=[dict(p) for p in rows],
        mac_filter=mac_filter,
        ssid_filter=ssid_filter,
        page_num=page_num,
    )


async def handle_devices(request):
    devices = await db_call(db.q_devices)
    device_list = []
    for d in devices:
        dd = dict(d)
        dd['vendor'] = oui.lookup(d['last_mac']) if d['last_mac'] else None
        device_list.append(dd)
    return render('history_devices.html', page='devices', devices=device_list)


async def handle_device_detail_page(request):
    fp_hash = request.match_info['fp_hash']
    device  = await db_call(db.q_device_by_hash, fp_hash)
    if not device:
        raise web.HTTPNotFound()
    macs   = await db_call(db.q_device_macs,         fp_hash)
    ssids  = await db_call(db.q_device_ssids,         fp_hash)
    probes = await db_call(db.q_device_probes,        fp_hash, 50)
    assocs = await db_call(db.q_device_assoc_by_fp,   fp_hash, 50)
    ch_dist = await db_call(db.q_device_channel_dist, fp_hash)

    mac_list = []
    for m in macs:
        md = dict(m)
        md['vendor'] = oui.lookup(m['src_mac'])
        mac_list.append(md)

    dd = dict(device)
    dd['vendor'] = oui.lookup(mac_list[0]['src_mac']) if mac_list else None

    return render(
        'history_device_detail.html', page='devices',
        device=dd,
        mac_list=mac_list,
        ssid_list=[r['ssid'] for r in ssids],
        probes=[dict(p) for p in probes],
        assocs=[dict(a) for a in assocs],
        ch_dist=[dict(c) for c in ch_dist],
    )


async def handle_aps(request):
    aps = await db_call(db.q_aps)
    return render('history_aps.html', page='aps', aps=[dict(a) for a in aps])


async def handle_ssids(request):
    ssids = await db_call(db.q_ssids)
    return render('history_ssids.html', page='ssids', ssids=[dict(s) for s in ssids])


async def handle_associations(request):
    assocs = await db_call(db.q_associations)
    return render('history_associations.html', page='associations',
                  assocs=[dict(a) for a in assocs])


# ── JSON API ──────────────────────────────────────────────────────────────────

async def api_stats(request):
    return json_resp(await db_call(db.q_stats))


async def api_recent_probes(request):
    limit  = int(request.rel_url.query.get('limit', 200))
    offset = int(request.rel_url.query.get('offset', 0))
    rows = await db_call(db.q_recent_probes, limit, offset)
    result = []
    for r in rows:
        d = dict(r)
        d['vendor'] = oui.lookup(r['src_mac'])
        result.append(d)
    return json_resp(result)


async def api_ssids(request):
    rows = await db_call(db.q_ssids)
    return json_resp([dict(r) for r in rows])


async def api_aps(request):
    rows = await db_call(db.q_aps)
    return json_resp([dict(r) for r in rows])


async def api_devices(request):
    devices = await db_call(db.q_devices)
    result = []
    for d in devices:
        dd = dict(d)
        dd['vendor'] = oui.lookup(d['last_mac']) if d['last_mac'] else None
        result.append(dd)
    return json_resp(result)


async def api_associations(request):
    rows = await db_call(db.q_associations, 500)
    return json_resp([dict(r) for r in rows])


async def api_channel_dist(request):
    rows = await db_call(db.q_probes_per_channel)
    return json_resp([dict(r) for r in rows])


async def api_trend(request):
    rows = await db_call(db.q_probes_per_minute, 60)
    return json_resp([dict(r) for r in rows])


async def api_device_detail(request):
    fp_hash = request.match_info['fp_hash']
    macs    = await db_call(db.q_device_macs,  fp_hash)
    ssids   = await db_call(db.q_device_ssids, fp_hash)
    return json_resp({
        'macs':  [dict(m) for m in macs],
        'ssids': [r['ssid'] for r in ssids],
    })


# ── app ───────────────────────────────────────────────────────────────────────

def make_app():
    app = web.Application()
    app.router.add_get('/raspi-style.css',                  handle_css)
    app.router.add_get('/',                                  handle_index)
    app.router.add_get('/probes',                            handle_probes)
    app.router.add_get('/devices',                           handle_devices)
    app.router.add_get('/devices/{fp_hash}',                 handle_device_detail_page)
    app.router.add_get('/devices/{fp_hash}/detail',          api_device_detail)
    app.router.add_get('/aps',                               handle_aps)
    app.router.add_get('/ssids',                             handle_ssids)
    app.router.add_get('/associations',                      handle_associations)
    app.router.add_get('/api/stats',                         api_stats)
    app.router.add_get('/api/probes/recent',                 api_recent_probes)
    app.router.add_get('/api/channel_dist',                  api_channel_dist)
    app.router.add_get('/api/trend',                         api_trend)
    app.router.add_get('/api/ssids',                         api_ssids)
    app.router.add_get('/api/aps',                           api_aps)
    app.router.add_get('/api/devices',                       api_devices)
    app.router.add_get('/api/associations',                  api_associations)
    return app


def main():
    db.init_db()
    app = make_app()
    log.info('WiFi History web server starting on port %d', PORT)
    web.run_app(app, host='0.0.0.0', port=PORT, access_log=None)


if __name__ == '__main__':
    main()
