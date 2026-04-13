"""
notes_server.py  —  raspi81 ism-wifi-monitor
Persistent notes server on port 8097.

Serves notes.html at / and a JSON REST API at /api/notes.
Notes stored in ~/ism-wifi-monitor/db/notes.json.
Ported from raspi20 notes.html API pattern.
"""

import json
import logging
import time
from pathlib import Path

from aiohttp import web

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [notes] %(levelname)s %(message)s',
    datefmt='%Y-%m-%dT%H:%M:%S',
)
log = logging.getLogger('notes')

PORT      = 8097
APP_DIR   = Path.home() / 'ism-wifi-monitor'
NOTES_DB  = APP_DIR / 'db' / 'notes.json'


def load_notes() -> list:
    if not NOTES_DB.exists():
        return []
    try:
        return json.loads(NOTES_DB.read_text())
    except Exception:
        return []


def save_notes(notes: list):
    NOTES_DB.parent.mkdir(parents=True, exist_ok=True)
    NOTES_DB.write_text(json.dumps(notes, indent=2))


def next_id(notes: list) -> int:
    if not notes:
        return 1
    return max(n['id'] for n in notes) + 1


# ── Routes ────────────────────────────────────────────────────────────────────

async def handle_root(request):
    path = APP_DIR / 'templates' / 'notes.html'
    return web.Response(text=path.read_text(), content_type='text/html')


async def api_get_notes(request):
    return web.json_response(load_notes())


async def api_create_note(request):
    body = await request.json()
    notes = load_notes()
    note = {
        'id':      next_id(notes),
        'title':   body.get('title', ''),
        'content': body.get('content', ''),
        'ts':      time.time(),
    }
    notes.append(note)
    save_notes(notes)
    log.info('Created note id=%d', note['id'])
    return web.json_response(note)


async def api_update_note(request):
    note_id = int(request.match_info['id'])
    body    = await request.json()
    notes   = load_notes()
    for n in notes:
        if n['id'] == note_id:
            n['title']   = body.get('title',   n.get('title', ''))
            n['content'] = body.get('content', n.get('content', ''))
            n['ts']      = time.time()
            save_notes(notes)
            return web.json_response(n)
    raise web.HTTPNotFound()


async def api_delete_note(request):
    note_id = int(request.match_info['id'])
    notes   = load_notes()
    new     = [n for n in notes if n['id'] != note_id]
    if len(new) == len(notes):
        raise web.HTTPNotFound()
    save_notes(new)
    log.info('Deleted note id=%d', note_id)
    return web.json_response({'ok': True})


# ── CORS ──────────────────────────────────────────────────────────────────────

@web.middleware
async def cors_middleware(request, handler):
    if request.method == 'OPTIONS':
        return web.Response(headers={
            'Access-Control-Allow-Origin':  '*',
            'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type',
        })
    response = await handler(request)
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response


def build_app():
    app = web.Application(middlewares=[cors_middleware])
    app.router.add_get('/',                  handle_root)
    app.router.add_get('/api/notes',         api_get_notes)
    app.router.add_post('/api/notes',        api_create_note)
    app.router.add_put('/api/notes/{id}',    api_update_note)
    app.router.add_delete('/api/notes/{id}', api_delete_note)
    return app


if __name__ == '__main__':
    log.info('Notes server starting on port %d', PORT)
    web.run_app(build_app(), host='0.0.0.0', port=PORT, access_log=None)
