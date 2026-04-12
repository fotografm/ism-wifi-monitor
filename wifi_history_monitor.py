"""
wifi_history_monitor.py  —  raspi81 ism-wifi-monitor
WiFi frame capture daemon for WiFi History Diagnostic (port 8095).

Ported from raspi70/wifi_monitor.py with key changes for raspi81:
  - Interface: wlan1 (already in monitor mode, managed by ism-wifi-wifi-scan.service)
  - NO channel hopping — piggybacks on wifi_scanner.py's channel hopper.
    Both processes can sniff the same monitor interface simultaneously.
    wlan1 changes channel every 0.3 s courtesy of wifi_scanner.py.
  - DB: ~/ism-wifi-monitor/db/wifi_history.db (via db_history.py)

Frame types captured:
  Management subtype 4   — Probe Request  (with IE fingerprinting)
  Management subtype 8   — Beacon
  Management subtype 0   — Association Request
  Management subtype 1   — Association Response
  Management subtype 11  — Authentication
  Data (type 2)          — Client <-> AP sightings (rate-limited)

Run as root (required for raw socket).
"""

import logging
import signal
import sys
import threading
import time

import logging as _logging
_logging.getLogger('scapy.runtime').setLevel(_logging.ERROR)

from scapy.all import sniff, Dot11, RadioTap, Dot11Beacon
from scapy.config import conf as scapy_conf

scapy_conf.use_pcap = True

import db_history as db
import ie_parser

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s: %(message)s'
)
log = logging.getLogger('wifi_history_monitor')

# ── configuration ─────────────────────────────────────────────────────────────

IFACE = 'wlan1'   # already in monitor mode — do NOT change channel here

PROBE_LOG_INTERVAL = 5    # s — min gap between probe_requests rows per MAC
BEACON_INTERVAL    = 30   # s — min gap between beacon DB updates per BSSID
DATA_INTERVAL      = 60   # s — min gap between data_sightings rows per pair

PRUNE_INTERVAL = 3600   # s — how often to prune old rows
PRUNE_DAYS     = 30     # days of history to keep

SNIFF_TIMEOUT  = 10     # s — sniff burst length; keeps the loop responsive

# ── globals ───────────────────────────────────────────────────────────────────

_running = True
_conn    = None

_probe_cache  = {}   # src_mac          -> last logged ts
_beacon_cache = {}   # bssid            -> last updated ts
_data_cache   = {}   # (src_mac, bssid) -> last inserted ts


# ── helpers ───────────────────────────────────────────────────────────────────

def _get_rssi(pkt):
    try:
        return int(pkt[RadioTap].dBm_AntSignal)
    except Exception:
        return None


def _get_channel(pkt):
    try:
        return ie_parser.freq_to_channel(pkt[RadioTap].Channel)
    except Exception:
        return None


# ── frame handlers ────────────────────────────────────────────────────────────

def handle_probe_request(pkt):
    parsed = ie_parser.parse_probe_request(pkt)
    if not parsed:
        return

    ts      = time.time()
    src_mac = parsed['src_mac']

    db.upsert_fingerprint(
        _conn,
        parsed['ie_fp'],
        parsed['ie_ids'],
        parsed['ht_caps'],
        parsed['vht_caps'],
        parsed['vendor_ouis'],
        parsed['os_hint'],
    )
    db.upsert_mac_fp(_conn, src_mac, parsed['ie_fp'])

    if ts - _probe_cache.get(src_mac, 0) >= PROBE_LOG_INTERVAL:
        _probe_cache[src_mac] = ts
        db.insert_probe(
            _conn, ts, src_mac,
            parsed['ssid'],
            parsed['rssi'],
            parsed['channel'],
            parsed['ie_fp'],
            parsed['raw_ies'],
            parsed['is_random'],
        )

    _conn.commit()


def handle_beacon(pkt):
    try:
        bssid = pkt[Dot11].addr3
        if not bssid:
            return
        now = time.time()
        if now - _beacon_cache.get(bssid, 0) < BEACON_INTERVAL:
            return
        _beacon_cache[bssid] = now

        ies     = ie_parser.extract_ies(pkt)
        ssid    = ie_parser.decode_ssid(ie_parser.get_first_ie(ies, 0))
        channel = _get_channel(pkt)
        if channel is None:
            ds = ie_parser.get_first_ie(ies, 3)
            if ds:
                channel = ds[0]
        rssi = _get_rssi(pkt)
        caps = None
        try:
            caps = int(pkt[Dot11Beacon].cap)
        except Exception:
            pass

        db.upsert_beacon(_conn, now, bssid, ssid, channel, rssi, caps)
        _conn.commit()
    except Exception as e:
        log.debug('beacon handler error: %s', e)


def handle_association(pkt, subtype):
    try:
        dot11   = pkt[Dot11]
        src_mac = dot11.addr2
        dst_mac = dot11.addr1
        bssid   = dot11.addr3
        if not src_mac or not bssid:
            return
        rssi    = _get_rssi(pkt)
        channel = _get_channel(pkt)
        ssid    = None
        if subtype in (0, 1):
            ies  = ie_parser.extract_ies(pkt)
            ssid = ie_parser.decode_ssid(ie_parser.get_first_ie(ies, 0))
        db.insert_association(
            _conn, time.time(), subtype,
            src_mac, dst_mac, bssid, ssid, rssi, channel
        )
        _conn.commit()
    except Exception as e:
        log.debug('association handler error: %s', e)


def handle_data(pkt):
    try:
        dot11   = pkt[Dot11]
        fc      = int(dot11.FCfield)
        to_ds   = bool(fc & 0x01)
        from_ds = bool(fc & 0x02)
        if to_ds and not from_ds:
            src_mac = dot11.addr2
            bssid   = dot11.addr1
        elif from_ds and not to_ds:
            src_mac = dot11.addr3
            bssid   = dot11.addr2
        else:
            return
        if not src_mac or not bssid:
            return
        now = time.time()
        key = (src_mac, bssid)
        if now - _data_cache.get(key, 0) < DATA_INTERVAL:
            return
        _data_cache[key] = now
        db.insert_data_sighting(_conn, now, src_mac, bssid,
                                _get_rssi(pkt), _get_channel(pkt))
        _conn.commit()
    except Exception as e:
        log.debug('data handler error: %s', e)


def packet_handler(pkt):
    try:
        if not pkt.haslayer(Dot11):
            return
        ftype   = pkt[Dot11].type
        subtype = pkt[Dot11].subtype
        if ftype == 0:
            if subtype == 4:
                handle_probe_request(pkt)
            elif subtype == 8:
                handle_beacon(pkt)
            elif subtype in (0, 1, 11):
                handle_association(pkt, subtype)
        elif ftype == 2:
            handle_data(pkt)
    except Exception as e:
        log.debug('packet_handler error: %s', e)


# ── periodic pruning ──────────────────────────────────────────────────────────

def _pruner():
    while _running:
        time.sleep(PRUNE_INTERVAL)
        if not _running:
            break
        try:
            prune_conn = db.get_connection()
            db.prune_old_data(prune_conn, PRUNE_DAYS)
            prune_conn.close()
        except Exception as e:
            log.warning('prune error: %s', e)


# ── entry point ───────────────────────────────────────────────────────────────

def shutdown(sig, frame):
    global _running
    log.info('shutdown signal received')
    _running = False


def main():
    global _conn, _running

    signal.signal(signal.SIGINT,  shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    db.init_db()
    _conn = db.get_connection()

    threading.Thread(target=_pruner, daemon=True, name='pruner').start()

    log.info('WiFi history monitor starting — passive sniff on %s', IFACE)
    log.info('Channel hopping handled by wifi_scanner.py — no hopping here')

    while _running:
        try:
            sniff(
                iface=IFACE,
                prn=packet_handler,
                store=False,
                timeout=SNIFF_TIMEOUT,
            )
        except Exception as e:
            if _running:
                log.warning('sniff error: %s — retrying in 3s', e)
                time.sleep(3)

    _conn.close()
    log.info('WiFi history monitor stopped')


if __name__ == '__main__':
    main()
