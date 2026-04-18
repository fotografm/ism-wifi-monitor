"""
ism_monitor.py  —  raspi81 ism-wifi-monitor
Main aiohttp web server for ISM signal monitoring.
  - Manages rtl_433 as a subprocess
  - Receives decoded signals via UDP syslog (127.0.0.1:1433)
  - Tags each signal with current GPS position
  - Stores to SQLite, broadcasts to WebSocket clients
  - Serves tile proxy (OSM tiles cached on disk)
  - Handles band switching via POST /api/band
Port: 8092
"""

import asyncio
import json
import logging
import os
import socket
import time
from pathlib import Path

import aiofiles
import aiohttp
from aiohttp import web

import db_ism as db
from config import ISM_BANDS as BANDS, ISM_DEFAULT_BAND as DEFAULT_BAND
from gps_reader_async import GpsReader


def _get_sysinfo() -> dict:
    """Return uptime, CPU usage and RAM stats."""
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
        ram_pct  = round(100 * used_mb / total_mb) if total_mb else 0
    except Exception:
        total_mb = used_mb = ram_pct = 0
    try:
        st = os.statvfs('/home/user/ism-wifi-monitor')
        disk_total_mb = (st.f_blocks * st.f_frsize) // (1024 * 1024)
        disk_free_mb  = (st.f_bavail * st.f_frsize) // (1024 * 1024)
        disk_used_mb  = disk_total_mb - disk_free_mb
        disk_pct      = round(100 * disk_used_mb / disk_total_mb) if disk_total_mb else 0
    except Exception:
        disk_total_mb = disk_used_mb = disk_pct = 0
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
        'ram_pct':       ram_pct,
        'disk_used_mb':  disk_used_mb,
        'disk_total_mb': disk_total_mb,
        'disk_pct':      disk_pct,
    }


# ── Configuration ─────────────────────────────────────────────────────────────

HOST        = "0.0.0.0"
PORT        = 8092
APP_DIR     = Path.home() / "ism-wifi-monitor"
TILE_CACHE  = APP_DIR / "tile_cache"
STATIC_DIR  = APP_DIR
TMPL_DIR    = APP_DIR / "templates"

RTL433_UDP_PORT  = 1433
RTL433_SAMPLE_HZ = 250_000

OSM_TILE_URL = "https://tile.openstreetmap.org/{z}/{x}/{y}.png"
OSM_UA       = "raspi81-ISM-Monitor/1.0 (+https://github.com/fotografm/ism-wifi-monitor)"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("ism")


# ── Protocol categorisation ───────────────────────────────────────────────────

_TPMS_KW    = {"tpms", "schrader", "tiremate", "jansite", "pacific-pmv",
               "citroen", "renault-0435r", "pmv-107j", "toyota-tpms",
               "mazda-tpms", "ford-tpms", "fiat-tpms"}
_SENSOR_KW  = {"temp", "humid", "rain", "wind", "weather", "thermo",
               "oregon", "lacrosse", "acurite", "nexus", "hideki",
               "sensor", "probe", "water", "smoke", "motion", "bresser",
               "davis", "fine-offset", "ambient", "ws-", "gt-wt"}
_REMOTE_KW  = {"remote", "switch", "door", "bell", "key", "socket",
               "intertek", "linear", "holtek", "pt2262", "ev1527",
               "nexa", "proove", "brennenstuhl", "elro", "mumbi"}


def categorize(model: str) -> str:
    if not model:
        return "other"
    m = model.lower()
    if any(k in m for k in _TPMS_KW):
        return "tpms"
    if any(k in m for k in _SENSOR_KW):
        return "sensor"
    if any(k in m for k in _REMOTE_KW):
        return "remote"
    return "other"


# ── rtl_433 subprocess manager ────────────────────────────────────────────────

class Rtl433Manager:
    def __init__(self) -> None:
        self.band       = DEFAULT_BAND
        self.proc: asyncio.subprocess.Process | None = None
        self.packet_count   = 0
        self.last_signal_ts = 0.0
        self._restart_evt   = asyncio.Event()
        self._running       = False
        self.signal_queue: asyncio.Queue = asyncio.Queue()

    async def set_band(self, band: str) -> bool:
        if band not in BANDS:
            return False
        if band == self.band:
            return True
        self.band = band
        self._restart_evt.set()
        return True

    @property
    def running(self) -> bool:
        return self.proc is not None and self.proc.returncode is None

    @property
    def status(self) -> dict:
        return {
            "running":      self.running,
            "band":         self.band,
            "frequency":    BANDS[self.band],
            "packet_count": self.packet_count,
            "last_signal":  self.last_signal_ts,
        }

    async def run_forever(self) -> None:
        self._running = True
        while self._running:
            self._restart_evt.clear()
            await self._start()
            while self.running and not self._restart_evt.is_set():
                await asyncio.sleep(0.5)
            await self._stop()
            if self._restart_evt.is_set():
                await asyncio.sleep(0.3)
            else:
                log.warning("rtl_433 exited unexpectedly, retrying in 5s")
                await asyncio.sleep(5)

    async def _start(self) -> None:
        freq = BANDS[self.band]
        cmd = [
            "rtl_433",
            "-f",  str(freq),
            "-s",  str(RTL433_SAMPLE_HZ),
            "-F",  f"syslog:127.0.0.1:{RTL433_UDP_PORT}",
            "-M", "utc",
            "-M", "level",
            "-M", "noise",
        ]
        log.info("Starting rtl_433: %s", " ".join(cmd))
        try:
            self.proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            log.error("rtl_433 not found — is rtl-433 installed?")
            self.proc = None
            await asyncio.sleep(10)

    async def _stop(self) -> None:
        if self.proc and self.proc.returncode is None:
            try:
                self.proc.terminate()
                await asyncio.wait_for(self.proc.wait(), timeout=4.0)
            except asyncio.TimeoutError:
                self.proc.kill()
                try:
                    await asyncio.wait_for(self.proc.wait(), timeout=2.0)
                except asyncio.TimeoutError:
                    pass
        self.proc = None


# ── UDP syslog receiver for rtl_433 output ────────────────────────────────────

class _UdpSyslogProtocol(asyncio.DatagramProtocol):
    def __init__(self, queue: asyncio.Queue) -> None:
        self._queue = queue

    def datagram_received(self, data: bytes, addr) -> None:
        try:
            text = data.decode("utf-8", errors="replace")
            idx = text.find("{")
            if idx >= 0:
                self._queue.put_nowait(json.loads(text[idx:]))
        except Exception:
            pass

    def error_received(self, exc: Exception) -> None:
        log.debug("UDP error: %s", exc)


# ── Internet / tile helpers ───────────────────────────────────────────────────

_inet_ok      = False
_inet_checked = 0.0
_INET_TTL     = 30.0


async def _has_internet() -> bool:
    global _inet_ok, _inet_checked
    now = time.monotonic()
    if now - _inet_checked < _INET_TTL:
        return _inet_ok
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection("tile.openstreetmap.org", 80), timeout=2.0
        )
        writer.close()
        _inet_ok = True
    except Exception:
        _inet_ok = False
    _inet_checked = now
    return _inet_ok


async def _fetch_tile(session: aiohttp.ClientSession, z: int, x: int, y: int) -> bytes | None:
    path = TILE_CACHE / str(z) / str(x) / f"{y}.png"
    if path.exists():
        async with aiofiles.open(path, "rb") as f:
            return await f.read()
    if not await _has_internet():
        return None
    url = OSM_TILE_URL.format(z=z, x=x, y=y)
    try:
        async with session.get(url, headers={"User-Agent": OSM_UA},
                               timeout=aiohttp.ClientTimeout(total=8)) as resp:
            if resp.status == 200:
                data = await resp.read()
                path.parent.mkdir(parents=True, exist_ok=True)
                async with aiofiles.open(path, "wb") as f:
                    await f.write(data)
                return data
    except Exception as exc:
        log.debug("Tile fetch error %d/%d/%d: %s", z, x, y, exc)
    return None


# ── Application ───────────────────────────────────────────────────────────────

class App:
    def __init__(self) -> None:
        self.rtl   = Rtl433Manager()
        self.gps   = GpsReader()
        self.ws_clients: set[web.WebSocketResponse] = set()
        self._gps_pos  = self.gps.position()
        self._tile_session: aiohttp.ClientSession | None = None

    # ── Signal processing ─────────────────────────────────────────────────────

    async def _process_signal(self, msg: dict) -> None:
        self.rtl.packet_count += 1
        self.rtl.last_signal_ts = time.time()

        model     = msg.get("model", "Unknown")
        device_id = str(msg.get("id", msg.get("device", "")))
        ts        = msg.get("time", "")
        cat       = categorize(model)
        pos       = self._gps_pos

        sig = {
            "ts":           ts,
            "lat":          pos["lat"],
            "lon":          pos["lon"],
            "gps_fix":      1 if pos["fix"] else 0,
            "frequency":    BANDS[self.rtl.band],
            "protocol":     msg.get("protocol", ""),
            "model":        model,
            "device_id":    device_id,
            "channel":      msg.get("channel"),
            "rssi":         msg.get("rssi"),
            "snr":          msg.get("snr"),
            "noise":        msg.get("noise"),
            "category":     cat,
            "data_json":    json.dumps(msg),
        }

        loop = asyncio.get_event_loop()
        sig_id = await loop.run_in_executor(None, db.insert_signal, sig)

        tx = {
            "model":          model,
            "device_id":      device_id,
            "last_seen":      ts,
            "last_lat":       pos["lat"],
            "last_lon":       pos["lon"],
            "last_gps_fix":   1 if pos["fix"] else 0,
            "category":       cat,
            "last_data_json": json.dumps(msg),
        }
        await loop.run_in_executor(None, db.upsert_transmitter, tx)

        sig["id"] = sig_id
        await self._broadcast({"type": "signal", "data": sig})

    async def _signal_consumer(self) -> None:
        while True:
            msg = await self.rtl.signal_queue.get()
            try:
                await self._process_signal(msg)
            except Exception as exc:
                log.error("Signal processing error: %s", exc)

    # ── GPS callback ──────────────────────────────────────────────────────────

    async def _on_gps_update(self, pos: dict) -> None:
        self._gps_pos = pos
        await self._broadcast({"type": "gps", "data": pos})

    # ── WebSocket broadcast ───────────────────────────────────────────────────

    async def _broadcast(self, msg: dict) -> None:
        if not self.ws_clients:
            return
        text = json.dumps(msg)
        dead = set()
        for ws in self.ws_clients:
            try:
                await ws.send_str(text)
            except Exception:
                dead.add(ws)
        self.ws_clients -= dead

    # ── Route handlers ────────────────────────────────────────────────────────

    async def handle_static_css(self, req: web.Request) -> web.Response:
        f = STATIC_DIR / "raspi-style.css"
        text = f.read_text()
        return web.Response(text=text, content_type="text/css")

    async def _render(self, name: str) -> web.Response:
        path = TMPL_DIR / name
        text = path.read_text()
        return web.Response(text=text, content_type="text/html")

    async def handle_root(self, req: web.Request) -> web.Response:
        """Redirect / to the combined landing page at port 80."""
        host = req.host.split(':')[0]
        raise web.HTTPFound(f"http://{host}")

    async def handle_feed(self, req: web.Request) -> web.Response:
        return await self._render("ism_feed.html")

    async def handle_map(self, req: web.Request) -> web.Response:
        return await self._render("ism_map.html")

    async def handle_settings(self, req: web.Request) -> web.Response:
        return await self._render("ism_settings.html")

    async def handle_ws(self, req: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse(heartbeat=30)
        await ws.prepare(req)
        self.ws_clients.add(ws)
        log.info("WS client connected (%d total)", len(self.ws_clients))
        await ws.send_str(json.dumps({"type": "gps",    "data": self._gps_pos}))
        await ws.send_str(json.dumps({"type": "status", "data": self.rtl.status}))
        try:
            async for _ in ws:
                pass
        finally:
            self.ws_clients.discard(ws)
            log.info("WS client disconnected (%d total)", len(self.ws_clients))
        return ws

    # ── API endpoints ─────────────────────────────────────────────────────────

    async def api_status(self, req: web.Request) -> web.Response:
        loop = asyncio.get_event_loop()
        counts  = await loop.run_in_executor(None, db.get_signal_count)
        stats   = await loop.run_in_executor(None, db.get_tile_cache_stats, TILE_CACHE)
        sysinfo = await loop.run_in_executor(None, _get_sysinfo)
        return web.json_response({
            "rtl433":     self.rtl.status,
            "gps":        self._gps_pos,
            "signals":    counts,
            "tile_cache": stats,
            "sysinfo":    sysinfo,
        })

    async def api_signals(self, req: web.Request) -> web.Response:
        limit = int(req.rel_url.query.get("limit", 500))
        loop  = asyncio.get_event_loop()
        rows  = await loop.run_in_executor(None, db.get_recent_signals, limit)
        return web.json_response(rows)

    async def api_transmitters(self, req: web.Request) -> web.Response:
        loop = asyncio.get_event_loop()
        rows = await loop.run_in_executor(None, db.get_transmitters)
        return web.json_response(rows)

    async def api_set_band(self, req: web.Request) -> web.Response:
        try:
            body = await req.json()
            band = body.get("band", "")
        except Exception:
            return web.json_response({"ok": False, "error": "bad JSON"}, status=400)
        ok = await self.rtl.set_band(band)
        if not ok:
            return web.json_response({"ok": False, "error": f"unknown band: {band}"}, status=400)
        await asyncio.sleep(0.8)
        await self._broadcast({"type": "status", "data": self.rtl.status})
        return web.json_response({"ok": True, "band": band, "frequency": BANDS[band]})

    async def api_shutdown(self, req: web.Request) -> web.Response:
        log.info("Shutdown requested via web UI")
        asyncio.ensure_future(_delayed_shell("sudo shutdown -h now", 1.5))
        return web.json_response({"ok": True})

    async def api_reboot(self, req: web.Request) -> web.Response:
        log.info("Reboot requested via web UI")
        asyncio.ensure_future(_delayed_shell("sudo reboot", 1.5))
        return web.json_response({"ok": True})

    async def api_clear_tile_cache(self, req: web.Request) -> web.Response:
        import shutil
        if TILE_CACHE.exists():
            shutil.rmtree(TILE_CACHE)
        TILE_CACHE.mkdir(parents=True, exist_ok=True)
        return web.json_response({"ok": True})

    async def handle_tile(self, req: web.Request) -> web.Response:
        try:
            z = int(req.match_info["z"])
            x = int(req.match_info["x"])
            y = int(req.match_info["y"])
        except (KeyError, ValueError):
            raise web.HTTPBadRequest()
        if not (0 <= z <= 19 and 0 <= x < 2**z and 0 <= y < 2**z):
            raise web.HTTPBadRequest()
        data = await _fetch_tile(self._tile_session, z, x, y)
        if data is None:
            raise web.HTTPNotFound()
        return web.Response(body=data, content_type="image/png",
                            headers={"Cache-Control": "public, max-age=86400"})

    async def _rtl433_watchdog(self) -> None:
        """Restart rtl_433 if it stops producing output for WATCHDOG_SECS."""
        WATCHDOG_SECS = 300  # 5 minutes — plenty of time even in quiet areas
        GRACE_SECS    = 120  # don't watchdog until rtl_433 has been up this long
        await asyncio.sleep(GRACE_SECS)
        while True:
            await asyncio.sleep(60)
            if not self.rtl.running:
                continue
            if self.rtl.last_signal_ts == 0.0:
                continue  # never received a signal yet — not a hang
            silent_for = time.time() - self.rtl.last_signal_ts
            if silent_for > WATCHDOG_SECS:
                log.warning(
                    "rtl_433 watchdog: no signal for %.0fs — forcing restart",
                    silent_for,
                )
                self.rtl._restart_evt.set()

    # ── Startup / shutdown ────────────────────────────────────────────────────

    async def start(self, _app: web.Application) -> None:
        TILE_CACHE.mkdir(parents=True, exist_ok=True)
        db.init_db()
        self._tile_session = aiohttp.ClientSession()
        self.gps.set_callback(self._on_gps_update)
        asyncio.ensure_future(self.gps.run())
        asyncio.ensure_future(self.rtl.run_forever())
        asyncio.ensure_future(self._signal_consumer())
        asyncio.ensure_future(self._udp_listener())
        asyncio.ensure_future(self._status_broadcaster())
        asyncio.ensure_future(self._rtl433_watchdog())
        log.info("ISM-Monitor started on http://%s:%d", HOST, PORT)

    async def stop(self, _app: web.Application) -> None:
        await self.rtl._stop()
        if self._tile_session:
            await self._tile_session.close()

    async def _udp_listener(self) -> None:
        loop = asyncio.get_event_loop()
        try:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: _UdpSyslogProtocol(self.rtl.signal_queue),
                local_addr=("127.0.0.1", RTL433_UDP_PORT),
            )
            log.info("UDP syslog listener on 127.0.0.1:%d", RTL433_UDP_PORT)
        except OSError as exc:
            log.error("Cannot bind UDP %d: %s", RTL433_UDP_PORT, exc)

    async def _status_broadcaster(self) -> None:
        while True:
            await asyncio.sleep(5)
            await self._broadcast({"type": "status", "data": self.rtl.status})


async def _delayed_shell(cmd: str, delay: float) -> None:
    await asyncio.sleep(delay)
    os.system(cmd)


# ── CORS middleware (allows landing page at port 80 to fetch from port 8092) ──

@web.middleware
async def cors_middleware(request: web.Request, handler) -> web.Response:
    if request.method == 'OPTIONS':
        return web.Response(headers={
            'Access-Control-Allow-Origin':  '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type',
        })
    response = await handler(request)
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response


# ── Wire up routes ────────────────────────────────────────────────────────────

def build_app() -> web.Application:
    app_obj = App()
    wa = web.Application(middlewares=[cors_middleware])
    wa.on_startup.append(app_obj.start)
    wa.on_cleanup.append(app_obj.stop)

    wa.router.add_get("/",                    app_obj.handle_root)
    wa.router.add_get("/feed",                app_obj.handle_feed)
    wa.router.add_get("/map",                 app_obj.handle_map)
    wa.router.add_get("/settings",            app_obj.handle_settings)
    wa.router.add_get("/raspi-style.css",     app_obj.handle_static_css)
    wa.router.add_get("/ws",                  app_obj.handle_ws)
    wa.router.add_get("/tiles/{z}/{x}/{y}",   app_obj.handle_tile)
    wa.router.add_get("/api/status",          app_obj.api_status)
    wa.router.add_get("/api/signals",         app_obj.api_signals)
    wa.router.add_get("/api/transmitters",    app_obj.api_transmitters)
    wa.router.add_post("/api/band",           app_obj.api_set_band)
    wa.router.add_post("/api/shutdown",       app_obj.api_shutdown)
    wa.router.add_post("/api/reboot",         app_obj.api_reboot)
    wa.router.add_post("/api/clear-tiles",    app_obj.api_clear_tile_cache)
    return wa


if __name__ == "__main__":
    web.run_app(build_app(), host=HOST, port=PORT)
