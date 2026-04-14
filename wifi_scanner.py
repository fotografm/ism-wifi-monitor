#!/usr/bin/env python3
"""
wifi_scanner.py  —  raspi81 ism-wifi-monitor
Captures 802.11 beacon frames and probe responses on the MT7612U AC1300
adapter (wlan1) in monitor mode.  Hops across all EU 2.4 GHz and 5 GHz
channels.  Writes access_points and throttled sightings to SQLite.

Must run as root (raw socket + iw channel set).
"""

import logging
import os
import signal
import sqlite3
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Optional

import logging as _logging
_logging.getLogger('scapy.runtime').setLevel(_logging.ERROR)

from scapy.all import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp, RadioTap, sniff

from config import (
    ALL_CHANNELS, CHANNEL_DWELL, DB_WIFI_PATH as DB_PATH,
    GPS_HOST, GPS_PORT, SIGHTING_DISTANCE, SIGHTING_INTERVAL, WIFI_IFACE,
)
from db_wifi import init_db
from gps_reader_sync import GPSReader

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [scanner] %(levelname)s %(message)s',
    datefmt='%Y-%m-%dT%H:%M:%S',
)
log = logging.getLogger('scanner')

_stop = threading.Event()

gps = GPSReader(host=GPS_HOST, port=GPS_PORT)

_last_sighting: dict = {}
_throttle_lock = threading.Lock()

# Rate-limit client sightings from data frames: write at most once per 30s per (client, bssid)
_last_client_sight: dict = {}
_client_lock = threading.Lock()

# Rate-limit association writes: dedupe within 5s per (client, bssid, subtype)
_last_assoc: dict = {}
_assoc_lock = threading.Lock()


def _should_sight(bssid: str, lat: Optional[float], lon: Optional[float]) -> bool:
    now = time.monotonic()
    with _throttle_lock:
        prev = _last_sighting.get(bssid)
        if prev is None:
            _last_sighting[bssid] = (now, lat, lon)
            return True
        prev_t, prev_lat, prev_lon = prev
        if now - prev_t >= SIGHTING_INTERVAL:
            _last_sighting[bssid] = (now, lat, lon)
            return True
        if lat is not None and lon is not None and prev_lat is not None and prev_lon is not None:
            if abs(lat - prev_lat) > SIGHTING_DISTANCE or abs(lon - prev_lon) > SIGHTING_DISTANCE:
                _last_sighting[bssid] = (now, lat, lon)
                return True
    return False


_db_local = threading.local()


def _get_conn() -> sqlite3.Connection:
    if not hasattr(_db_local, 'conn'):
        conn = sqlite3.connect(str(DB_PATH))
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('PRAGMA synchronous=NORMAL')
        _db_local.conn = conn
    return _db_local.conn


def _upsert_ap(bssid: str, ssid: str, encryption: str,
               capabilities: str, now: str) -> None:
    _get_conn().execute('''
        INSERT INTO access_points
            (bssid, ssid, encryption, capabilities, first_seen, last_seen)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(bssid) DO UPDATE SET
            ssid         = excluded.ssid,
            encryption   = excluded.encryption,
            capabilities = excluded.capabilities,
            last_seen    = excluded.last_seen
    ''', (bssid, ssid, encryption, capabilities, now, now))
    _get_conn().commit()


def _update_ap_rssi(bssid: str, signal_dbm: Optional[int],
                    channel: Optional[int], now: str) -> None:
    """Update the latest sighting row's signal/channel and AP last_seen on every beacon.
    This keeps the AP list live without writing a new sightings row every frame."""
    _get_conn().execute(
        "UPDATE access_points SET last_seen = ? WHERE bssid = ?",
        (now, bssid)
    )
    # Update the most recent sighting's signal if one exists
    _get_conn().execute('''
        UPDATE sightings SET signal_dbm = ?, channel = ?, timestamp = ?
        WHERE id = (SELECT id FROM sightings WHERE bssid = ? ORDER BY timestamp DESC LIMIT 1)
    ''', (signal_dbm, channel, now, bssid))
    _get_conn().commit()


def _insert_sighting(bssid: str, signal_dbm: Optional[int],
                     channel: Optional[int], frequency_mhz: Optional[int],
                     lat: Optional[float], lon: Optional[float],
                     alt: Optional[float], fix: int, ts: str) -> None:
    _get_conn().execute('''
        INSERT INTO sightings
            (bssid, signal_dbm, channel, frequency_mhz,
             latitude, longitude, altitude_m, gps_fix, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (bssid, signal_dbm, channel, frequency_mhz, lat, lon, alt, fix, ts))
    _get_conn().commit()


def _insert_association(timestamp: str, frame_subtype: int, client_mac: str,
                         bssid: str, ssid: Optional[str],
                         signal_dbm: Optional[int], channel: Optional[int]) -> None:
    _get_conn().execute('''
        INSERT INTO associations
            (timestamp, frame_subtype, client_mac, bssid, ssid, signal_dbm, channel)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (timestamp, frame_subtype, client_mac, bssid, ssid, signal_dbm, channel))
    _get_conn().commit()


def _insert_client_sighting(timestamp: str, client_mac: str, bssid: str,
                              signal_dbm: Optional[int], channel: Optional[int],
                              lat: Optional[float], lon: Optional[float],
                              fix: int) -> None:
    _get_conn().execute('''
        INSERT INTO client_sightings
            (timestamp, client_mac, bssid, signal_dbm, channel,
             latitude, longitude, gps_fix)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (timestamp, client_mac, bssid, signal_dbm, channel, lat, lon, fix))
    _get_conn().commit()


def _parse_ssid(pkt) -> str:
    elt = pkt.getlayer(Dot11Elt)
    if elt and elt.ID == 0:
        try:
            return elt.info.decode('utf-8', errors='replace').rstrip('\x00')
        except Exception:
            return ''
    return ''


def _parse_channel(pkt) -> Optional[int]:
    elt = pkt.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 3 and len(elt.info) >= 1:
            return int(elt.info[0])
        elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None
    return None


def _channel_to_freq(ch: int) -> Optional[int]:
    if 1 <= ch <= 13:
        return 2412 + (ch - 1) * 5
    if ch == 14:
        return 2484
    if 36 <= ch <= 177:
        return 5180 + (ch - 36) * 5
    return None


def _parse_rsn(data: bytes) -> str:
    """Parse RSN (802.11i) information element to detect WPA3/SAE."""
    try:
        if len(data) < 4:
            return 'WPA2'
        # Skip version (2 bytes) + group cipher suite (4 bytes)
        offset = 2
        if offset + 4 > len(data):
            return 'WPA2'
        offset += 4  # skip group cipher

        # Pairwise cipher count + suites
        if offset + 2 > len(data):
            return 'WPA2'
        pw_count = int.from_bytes(data[offset:offset + 2], 'little')
        offset += 2 + pw_count * 4

        # AKM count + suites
        if offset + 2 > len(data):
            return 'WPA2'
        akm_count = int.from_bytes(data[offset:offset + 2], 'little')
        offset += 2
        for i in range(akm_count):
            if offset + 4 > len(data):
                break
            akm_type = data[offset + 3]
            # 8=SAE, 9=FT-SAE, 18=OWE (WPA3), 24=PASN
            if akm_type in (8, 9, 18, 24):
                return 'WPA3'
            offset += 4
        return 'WPA2'
    except Exception:
        return 'WPA2'


def _parse_encryption(pkt) -> str:
    try:
        if pkt.haslayer(Dot11Beacon):
            cap = pkt[Dot11Beacon].cap
        else:
            cap = pkt[Dot11ProbeResp].cap
        has_privacy = bool(cap & 0x0010)
    except Exception:
        has_privacy = False

    has_rsn = False
    has_wpa = False
    rsn_label = 'WPA2'

    elt = pkt.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 48:
            has_rsn   = True
            rsn_label = _parse_rsn(bytes(elt.info))
        elif elt.ID == 221:
            info = bytes(elt.info)
            if info[:4] == b'\x00\x50\xf2\x01':
                has_wpa = True
        elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None

    if rsn_label == 'WPA3' and has_wpa:
        return 'WPA3/WPA2'
    if rsn_label == 'WPA3':
        return 'WPA3'
    if has_rsn and has_wpa:
        return 'WPA/WPA2'
    if has_rsn:
        return 'WPA2'
    if has_wpa:
        return 'WPA'
    if has_privacy:
        return 'WEP'
    return 'OPEN'


def _parse_signal(pkt) -> Optional[int]:
    if pkt.haslayer(RadioTap):
        try:
            val = pkt[RadioTap].dBm_AntSignal
            if val is not None:
                return int(val)
        except Exception:
            pass
    return None


def _cap_str(pkt) -> str:
    try:
        if pkt.haslayer(Dot11Beacon):
            return str(pkt[Dot11Beacon].cap)
        return str(pkt[Dot11ProbeResp].cap)
    except Exception:
        return ''


def _radiotap_channel(pkt) -> Optional[int]:
    """Extract channel from RadioTap — safe for all frame types, no IE walk."""
    try:
        freq = int(pkt[RadioTap].Channel)
        if 2412 <= freq <= 2472:
            return (freq - 2412) // 5 + 1
        if freq == 2484:
            return 14
        if 5170 <= freq <= 5825:
            return (freq - 5000) // 5
    except Exception:
        pass
    return None


def handle_association(pkt, subtype: int) -> None:
    """Capture management frames: assoc req(0), assoc resp(1), reassoc req(2),
    reassoc resp(3), auth(11). Records client MAC associating with BSSID."""
    try:
        dot11 = pkt[Dot11]
        if subtype in (0, 2, 11):   # client→AP direction
            client_mac = dot11.addr2
            bssid      = dot11.addr1 if subtype == 11 else dot11.addr3
        else:                        # AP→client resp
            client_mac = dot11.addr1
            bssid      = dot11.addr2

        if not client_mac or not bssid:
            return
        if bssid == 'ff:ff:ff:ff:ff:ff':
            return

        signal_dbm = _parse_signal(pkt)
        channel    = _radiotap_channel(pkt)

        ssid = None
        if subtype in (0, 2):
            ssid = _parse_ssid(pkt) or None

        now = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

        key = (client_mac, bssid, subtype)
        with _assoc_lock:
            now_mono = time.monotonic()
            if now_mono - _last_assoc.get(key, 0) < 5.0:
                return
            _last_assoc[key] = now_mono

        _insert_association(now, subtype, client_mac, bssid, ssid, signal_dbm, channel)
        log.debug('Assoc subtype=%d client=%s bssid=%s', subtype, client_mac, bssid)
    except Exception as exc:
        log.debug('handle_association error: %s', exc)


def handle_data(pkt) -> None:
    """Extract client↔AP relationships from data frames using DS bits.
    Uses RadioTap for channel — never walks IEs (data frames have none)."""
    try:
        dot11   = pkt[Dot11]
        fc      = int(dot11.FCfield)
        to_ds   = bool(fc & 0x01)
        from_ds = bool(fc & 0x02)

        if to_ds and not from_ds:
            bssid      = dot11.addr1
            client_mac = dot11.addr2
        elif from_ds and not to_ds:
            client_mac = dot11.addr1
            bssid      = dot11.addr2
        else:
            return

        if not client_mac or not bssid:
            return
        if bssid == 'ff:ff:ff:ff:ff:ff' or client_mac == 'ff:ff:ff:ff:ff:ff':
            return
        if int(client_mac.split(':')[0], 16) & 0x01:
            return  # multicast

        key      = (client_mac, bssid)
        now_mono = time.monotonic()
        with _client_lock:
            if now_mono - _last_client_sight.get(key, 0) < 30.0:
                return
            _last_client_sight[key] = now_mono

        signal_dbm = _parse_signal(pkt)
        channel    = _radiotap_channel(pkt)   # no IE walk
        pos        = gps.get_position()
        now        = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

        _insert_client_sighting(now, client_mac, bssid, signal_dbm, channel,
                                pos['lat'], pos['lon'], 1 if pos['fix'] else 0)
        log.debug('Client: %s → %s sig=%s ch=%s', client_mac, bssid, signal_dbm, channel)
    except Exception as exc:
        log.debug('handle_data error: %s', exc)


def handle_frame(pkt) -> None:
    if not pkt.haslayer(Dot11):
        return

    try:
        ftype   = pkt[Dot11].type
        subtype = pkt[Dot11].subtype
    except Exception:
        return

    if ftype == 0:  # management
        if subtype in (8, 5):  # beacon, probe resp — CRITICAL PATH
            try:
                if not (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)):
                    return
                bssid = pkt[Dot11].addr3
                if not bssid or bssid == 'ff:ff:ff:ff:ff:ff':
                    return
                ssid       = _parse_ssid(pkt)
                signal_dbm = _parse_signal(pkt)
                channel    = _parse_channel(pkt)
                freq       = _channel_to_freq(channel) if channel else None
                encryption = _parse_encryption(pkt)
                caps       = _cap_str(pkt)
                pos = gps.get_position()
                lat = pos['lat']; lon = pos['lon']; alt = pos['alt']
                fix = 1 if pos['fix'] else 0
                now = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
                _upsert_ap(bssid, ssid, encryption, caps, now)
                if _should_sight(bssid, lat, lon):
                    _insert_sighting(bssid, signal_dbm, channel, freq,
                                     lat, lon, alt, fix, now)
                else:
                    _update_ap_rssi(bssid, signal_dbm, channel, now)
            except Exception as exc:
                log.error('Beacon handler error for %s: %s', bssid if 'bssid' in dir() else '?', exc)

        elif subtype in (0, 1, 2, 3, 11):  # assoc/auth — best effort
            try:
                handle_association(pkt, subtype)
            except Exception as exc:
                log.debug('Assoc dispatch error: %s', exc)

    elif ftype == 2:  # data — best effort, never touches beacon tables
        try:
            handle_data(pkt)
        except Exception as exc:
            log.debug('Data dispatch error: %s', exc)


def channel_hopper() -> None:
    idx = 0
    while not _stop.is_set():
        ch = ALL_CHANNELS[idx % len(ALL_CHANNELS)]
        try:
            subprocess.run(
                ['iw', 'dev', WIFI_IFACE, 'set', 'channel', str(ch)],
                capture_output=True, timeout=2,
            )
        except Exception as exc:
            log.warning('iw channel set failed ch=%s: %s', ch, exc)
        idx += 1
        _stop.wait(CHANNEL_DWELL)


def _handle_signal(signum, _frame) -> None:
    log.info('Signal %s received — shutting down', signum)
    _stop.set()


def main() -> None:
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT,  _handle_signal)

    log.info('Initialising database tables')
    init_db()

    log.info('WiFi scanner starting on interface %s', WIFI_IFACE)
    log.info('Channels: %d total, dwell %.1f s each', len(ALL_CHANNELS), CHANNEL_DWELL)

    gps.start()
    log.info('GPS reader started')

    hopper = threading.Thread(
        target=channel_hopper, daemon=True, name='ch-hopper'
    )
    hopper.start()
    log.info('Channel hopper started')

    log.info('Starting packet capture — press Ctrl-C or send SIGTERM to stop')
    while not _stop.is_set():
        sniff(iface=WIFI_IFACE, prn=handle_frame, store=False, timeout=5)

    log.info('Capture stopped — cleaning up')
    hopper.join(timeout=3)
    gps.stop()
    log.info('Scanner exited cleanly')


if __name__ == '__main__':
    main()
