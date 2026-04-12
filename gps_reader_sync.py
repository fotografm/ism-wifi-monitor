"""
gps_reader_sync.py  —  raspi81 ism-wifi-monitor
Thread-safe gpsd client.  Used by wifi_scanner.py.
Reconnects automatically on connection loss.
python3-gps must be installed:  sudo apt install python3-gps
"""

import logging
import threading
import time
from typing import Dict, Optional

log = logging.getLogger('gps_reader')

_EMPTY_POS: Dict = {
    'lat':   None,
    'lon':   None,
    'alt':   None,
    'speed': None,
    'fix':   False,
    'mode':  0,
}


class GPSReader:
    """
    Start with .start(), stop with .stop().
    Call .get_position() from any thread — returns a plain dict snapshot.
    """

    def __init__(self, host: str = '127.0.0.1', port: int = 2947) -> None:
        self.host = host
        self.port = port
        self._lock     = threading.Lock()
        self._position = dict(_EMPTY_POS)
        self._stop     = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._run, daemon=True, name='gps-reader'
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def get_position(self) -> Dict:
        with self._lock:
            return dict(self._position)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                import gps as gpsd_mod

                session = gpsd_mod.gps(
                    host=self.host,
                    port=self.port,
                    mode=gpsd_mod.WATCH_ENABLE | gpsd_mod.WATCH_NEWSTYLE,
                )
                log.info('Connected to gpsd at %s:%d', self.host, self.port)

                for report in session:
                    if self._stop.is_set():
                        return
                    if report.get('class') != 'TPV':
                        continue
                    mode = int(getattr(report, 'mode', 0))
                    fix  = mode >= 2
                    with self._lock:
                        self._position = {
                            'lat':   getattr(report, 'lat',   None),
                            'lon':   getattr(report, 'lon',   None),
                            'alt':   getattr(report, 'alt',   None),
                            'speed': getattr(report, 'speed', None),
                            'fix':   fix,
                            'mode':  mode,
                        }

            except Exception as exc:
                log.warning('gpsd error: %s — retrying in 5 s', exc)
                with self._lock:
                    self._position = dict(_EMPTY_POS)
                time.sleep(5)
