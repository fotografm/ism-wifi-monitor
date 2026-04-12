"""
ie_parser.py — 802.11 Information Element parser for raspi81 WiFi History
Ported verbatim from raspi70/ie_parser.py.

Extracts IEs from Scapy Dot11 frames, computes per-device fingerprint hashes,
and applies heuristic OS identification.

The fingerprint is built from:
  - sorted set of IE IDs present in the frame
  - raw HT Capabilities IE body  (ID 45, 26 bytes — chip/driver specific)
  - raw VHT Capabilities IE body (ID 191, 12 bytes — 5 GHz cap devices only)
  - sorted unique vendor OUIs from all ID=221 elements

Two probes from the same physical device, even with different randomized MACs,
will produce the same fp_hash as long as firmware has not changed between captures.
"""

import hashlib
import json
import logging

from scapy.all import Dot11, Dot11Elt, RadioTap

log = logging.getLogger(__name__)

OUI_APPLE     = '0017f2'
OUI_MICROSOFT = '0050f2'
OUI_WFA       = '506f9a'


def extract_ies(pkt):
    try:
        ies  = []
        elt  = pkt.getlayer(Dot11Elt)
        while elt and isinstance(elt, Dot11Elt):
            ie_data = bytes(elt.info) if elt.info else b''
            ies.append((int(elt.ID), ie_data))
            elt = elt.payload.getlayer(Dot11Elt)
        return ies
    except Exception as e:
        log.debug('extract_ies error: %s', e)
        return []


def serialize_ies(ies):
    result = b''
    for ie_id, ie_data in ies:
        result += bytes([ie_id, len(ie_data)]) + ie_data
    return result


def get_first_ie(ies, ie_id):
    for _id, data in ies:
        if _id == ie_id:
            return data
    return b''


def get_vendor_ouis(ies):
    ouis = set()
    for ie_id, ie_data in ies:
        if ie_id == 221 and len(ie_data) >= 3:
            ouis.add(ie_data[:3].hex())
    return sorted(ouis)


def compute_fp_hash(ies):
    ie_ids      = sorted(set(ie_id for ie_id, _ in ies))
    ht_caps     = get_first_ie(ies, 45)
    vht_caps    = get_first_ie(ies, 191)
    vendor_ouis = get_vendor_ouis(ies)
    fp_input = (
        json.dumps(ie_ids).encode()
        + ht_caps
        + vht_caps
        + json.dumps(vendor_ouis).encode()
    )
    return hashlib.sha256(fp_input).hexdigest()


def get_os_hint(ies, src_mac):
    vendor_ouis = get_vendor_ouis(ies)
    ie_id_set   = set(ie_id for ie_id, _ in ies)
    if OUI_APPLE in vendor_ouis:
        return 'ios'
    is_local = is_randomized_mac(src_mac)
    has_ht   = 45  in ie_id_set
    has_vht  = 191 in ie_id_set
    if has_ht and is_local:
        return 'android'
    if not has_ht and not has_vht:
        return 'iot'
    return 'unknown'


def is_randomized_mac(src_mac):
    try:
        first_octet = int(src_mac.split(':')[0], 16)
        return bool(first_octet & 0x02)
    except Exception:
        return False


def decode_ssid(ssid_bytes):
    if not ssid_bytes:
        return None
    try:
        s = ssid_bytes.decode('utf-8')
        return s if s else None
    except UnicodeDecodeError:
        return ssid_bytes.hex()


def freq_to_channel(freq):
    if freq is None:
        return None
    if 2412 <= freq <= 2472:
        return (freq - 2412) // 5 + 1
    if freq == 2484:
        return 14
    if 5170 <= freq <= 5825:
        return (freq - 5000) // 5
    return None


def parse_probe_request(pkt):
    try:
        src_mac = pkt[Dot11].addr2
        if not src_mac:
            return None
        rssi = None
        try:
            rssi = int(pkt[RadioTap].dBm_AntSignal)
        except Exception:
            pass
        channel = None
        try:
            channel = freq_to_channel(pkt[RadioTap].Channel)
        except Exception:
            pass
        ies     = extract_ies(pkt)
        ssid    = decode_ssid(get_first_ie(ies, 0))
        if channel is None:
            ds = get_first_ie(ies, 3)
            if ds:
                channel = ds[0]
        fp_hash     = compute_fp_hash(ies)
        ie_ids      = sorted(set(ie_id for ie_id, _ in ies))
        ht_caps     = get_first_ie(ies, 45)   or None
        vht_caps    = get_first_ie(ies, 191)  or None
        vendor_ouis = get_vendor_ouis(ies)
        os_hint     = get_os_hint(ies, src_mac)
        is_random   = is_randomized_mac(src_mac)
        raw_ies     = serialize_ies(ies)
        return {
            'src_mac':     src_mac,
            'ssid':        ssid,
            'rssi':        rssi,
            'channel':     channel,
            'ie_fp':       fp_hash,
            'raw_ies':     raw_ies,
            'is_random':   is_random,
            'ie_ids':      ie_ids,
            'ht_caps':     ht_caps,
            'vht_caps':    vht_caps,
            'vendor_ouis': vendor_ouis,
            'os_hint':     os_hint,
        }
    except Exception as e:
        log.debug('parse_probe_request error: %s', e)
        return None
