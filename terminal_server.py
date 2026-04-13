"""
terminal_server.py  —  raspi81 ism-wifi-monitor
Headless PTY terminal server on port 8096.

Serves terminal.html at / and a WebSocket PTY bridge at /ws.
Single-session guard: only one terminal connection at a time.
Uses aiohttp WebSockets (already in venv).

Ported from raspi20/rns-web.py terminal section.
"""

import asyncio
import fcntl
import json
import logging
import os
import pty
import struct
import termios
from pathlib import Path

from aiohttp import web, WSMsgType

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [terminal] %(levelname)s %(message)s',
    datefmt='%Y-%m-%dT%H:%M:%S',
)
log = logging.getLogger('terminal')

PORT    = 8096
APP_DIR = Path.home() / 'ism-wifi-monitor'

_session_active = False


async def handle_root(request):
    path = APP_DIR / 'templates' / 'terminal.html'
    return web.Response(text=path.read_text(), content_type='text/html')


async def handle_ws(request):
    global _session_active

    ws = web.WebSocketResponse()
    await ws.prepare(request)

    if _session_active:
        log.warning('Terminal WS rejected — session already active')
        await ws.send_bytes(
            b'\r\n\x1b[33mTerminal in use elsewhere. '
            b'Only one session supported at a time.\x1b[0m\r\n'
        )
        await ws.close()
        return ws

    _session_active = True
    log.info('Terminal WS connected: %s', request.remote)

    master_fd, slave_fd = pty.openpty()
    fcntl.ioctl(master_fd, termios.TIOCSWINSZ,
                struct.pack('HHHH', 24, 80, 0, 0))

    env = {
        'TERM':    'xterm-256color',
        'HOME':    '/home/user',
        'USER':    'user',
        'LOGNAME': 'user',
        'SHELL':   '/bin/bash',
        'PATH':    '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
        'LANG':    'en_GB.UTF-8',
    }

    def _setup_child():
        os.setsid()
        fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)

    try:
        proc = await asyncio.create_subprocess_exec(
            '/bin/bash', '--login',
            stdin=slave_fd, stdout=slave_fd, stderr=slave_fd,
            close_fds=True, env=env, cwd='/home/user',
            preexec_fn=_setup_child,
        )
    except Exception as e:
        log.error('Failed to start bash: %s', e)
        os.close(slave_fd)
        os.close(master_fd)
        _session_active = False
        return ws

    os.close(slave_fd)

    flags = fcntl.fcntl(master_fd, fcntl.F_GETFL)
    fcntl.fcntl(master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

    loop = asyncio.get_event_loop()
    pty_queue: asyncio.Queue = asyncio.Queue()
    stop = asyncio.Event()

    def _on_readable():
        try:
            data = os.read(master_fd, 4096)
            if data:
                loop.call_soon_threadsafe(pty_queue.put_nowait, data)
        except OSError:
            loop.call_soon_threadsafe(pty_queue.put_nowait, None)

    loop.add_reader(master_fd, _on_readable)

    async def pty_to_ws():
        while not stop.is_set():
            try:
                data = await asyncio.wait_for(pty_queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            if data is None:
                break
            try:
                await ws.send_bytes(data)
            except Exception:
                break
        stop.set()

    async def ws_to_pty():
        try:
            async for msg in ws:
                if msg.type == WSMsgType.BINARY:
                    try:
                        os.write(master_fd, msg.data)
                    except OSError:
                        break
                elif msg.type == WSMsgType.TEXT:
                    try:
                        ctrl = json.loads(msg.data)
                        if ctrl.get('type') == 'resize':
                            cols = max(1, int(ctrl.get('cols', 80)))
                            rows = max(1, int(ctrl.get('rows', 24)))
                            fcntl.ioctl(master_fd, termios.TIOCSWINSZ,
                                        struct.pack('HHHH', rows, cols, 0, 0))
                    except Exception:
                        pass
                elif msg.type in (WSMsgType.CLOSE, WSMsgType.ERROR):
                    break
        finally:
            stop.set()

    try:
        await asyncio.gather(pty_to_ws(), ws_to_pty())
    finally:
        _session_active = False
        loop.remove_reader(master_fd)
        try:
            os.close(master_fd)
        except OSError:
            pass
        try:
            proc.kill()
        except Exception:
            pass
        await proc.wait()
        log.info('Terminal WS closed: %s', request.remote)

    return ws


@web.middleware
async def cors_middleware(request, handler):
    if request.method == 'OPTIONS':
        return web.Response(headers={
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type',
        })
    response = await handler(request)
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response


def build_app():
    app = web.Application(middlewares=[cors_middleware])
    app.router.add_get('/',   handle_root)
    app.router.add_get('/ws', handle_ws)
    return app


if __name__ == '__main__':
    log.info('Terminal server starting on port %d', PORT)
    web.run_app(build_app(), host='0.0.0.0', port=PORT, access_log=None)
