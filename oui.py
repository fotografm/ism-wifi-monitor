"""
oui.py — IEEE OUI to vendor name lookup for raspi81 ism-wifi-monitor
Ported verbatim from raspi70/oui.py.

Loads from data/oui.csv (IEEE MA-L registry, downloaded during install).
Falls back to a small hardcoded dict of common OUIs if the file is absent.

Download command (run in ~/ism-wifi-monitor/):
    mkdir -p data
    wget -q -O data/oui.csv https://standards-oui.ieee.org/oui/oui.csv
"""

import csv
import logging
from pathlib import Path

log = logging.getLogger(__name__)

BASE_DIR = Path(__file__).parent
OUI_CSV  = BASE_DIR / 'data' / 'oui.csv'

_FALLBACK = {
    '000393': 'Apple Inc.', '000A27': 'Apple Inc.', '000A95': 'Apple Inc.',
    '000D93': 'Apple Inc.', '001124': 'Apple Inc.', '001451': 'Apple Inc.',
    '0016CB': 'Apple Inc.', '0017F2': 'Apple Inc.', '0019E3': 'Apple Inc.',
    '001B63': 'Apple Inc.', '001CB3': 'Apple Inc.', '001D4F': 'Apple Inc.',
    '001E52': 'Apple Inc.', '001EC2': 'Apple Inc.', '001F5B': 'Apple Inc.',
    '001FF3': 'Apple Inc.', '0021E9': 'Apple Inc.', '002241': 'Apple Inc.',
    '002312': 'Apple Inc.', '002332': 'Apple Inc.', '00236C': 'Apple Inc.',
    '0023DF': 'Apple Inc.', '002436': 'Apple Inc.', '002500': 'Apple Inc.',
    '00254B': 'Apple Inc.', '0025BC': 'Apple Inc.', '002608': 'Apple Inc.',
    '00264A': 'Apple Inc.', '0026B0': 'Apple Inc.', '0026BB': 'Apple Inc.',
    '3C0754': 'Apple Inc.', '3C2EFF': 'Apple Inc.', '3CA832': 'Apple Inc.',
    '4C8D79': 'Apple Inc.', '5C96AD': 'Apple Inc.', '6C4008': 'Apple Inc.',
    '6C70A0': 'Apple Inc.', '7831C1': 'Apple Inc.', '7CF05F': 'Apple Inc.',
    '8C7B9D': 'Apple Inc.', '9801A7': 'Apple Inc.', 'A8BE27': 'Apple Inc.',
    'AC3C0B': 'Apple Inc.', 'B8782E': 'Apple Inc.', 'C82A14': 'Apple Inc.',
    'D4619D': 'Apple Inc.', 'D8BB2C': 'Apple Inc.', 'E0B9BA': 'Apple Inc.',
    'E4CE8F': 'Apple Inc.', 'F0B479': 'Apple Inc.', 'F4F15A': 'Apple Inc.',
    'F81EDF': 'Apple Inc.',
    'B827EB': 'Raspberry Pi Foundation', 'DCA632': 'Raspberry Pi Foundation',
    'E45F01': 'Raspberry Pi Foundation', 'D83ADD': 'Raspberry Pi Foundation',
    '2CCF67': 'Raspberry Pi Foundation',
    '18FE34': 'Espressif Inc.', '240AC4': 'Espressif Inc.',
    '246F28': 'Espressif Inc.', '2CF432': 'Espressif Inc.',
    '30AEA4': 'Espressif Inc.', '3C71BF': 'Espressif Inc.',
    '50D2F5': 'Espressif Inc.', '54435B': 'Espressif Inc.',
    '5C5B35': 'Espressif Inc.', '5C8D4E': 'Espressif Inc.',
    '7CDFA1': 'Espressif Inc.', '84F3EB': 'Espressif Inc.',
    '8CAAB5': 'Espressif Inc.', '94B97E': 'Espressif Inc.',
    'A4CF12': 'Espressif Inc.', 'AC67B2': 'Espressif Inc.',
    'B4E62D': 'Espressif Inc.', 'BCDDC2': 'Espressif Inc.',
    'CC50E3': 'Espressif Inc.', 'D8BFC0': 'Espressif Inc.',
    'E09806': 'Espressif Inc.', 'EC94CB': 'Espressif Inc.',
    'F008D1': 'Espressif Inc.',
    'F4F5D8': 'Google Inc.', '3C5AB4': 'Google Inc.', '54527E': 'Google Inc.',
    '1C9169': 'Google Inc.', 'A47733': 'Google Inc.',
    '001599': 'Samsung Electronics', '0016DB': 'Samsung Electronics',
    '001A8A': 'Samsung Electronics', '002339': 'Samsung Electronics',
    '002567': 'Samsung Electronics', '0026E2': 'Samsung Electronics',
    '6C2F2C': 'Samsung Electronics', '8C771F': 'Samsung Electronics',
    'B857D8': 'Samsung Electronics', 'F4428F': 'Samsung Electronics',
    '001B21': 'Intel Corporate', '002170': 'Intel Corporate',
    '00216A': 'Intel Corporate', '0024D7': 'Intel Corporate',
    '005048': 'Intel Corporate', '3C970E': 'Intel Corporate',
    '4C7999': 'Intel Corporate', '5CF951': 'Intel Corporate',
    '7085C2': 'Intel Corporate', '8C8D28': 'Intel Corporate',
    'A0A8CD': 'Intel Corporate', 'AC9E17': 'Intel Corporate',
    'D4BED9': 'Intel Corporate',
    '00E04C': 'Realtek Semiconductor', 'E84E06': 'Realtek Semiconductor',
    '00401C': 'Realtek Semiconductor',
    '000AEB': 'TP-Link Technologies', '001D0F': 'TP-Link Technologies',
    '1C61B4': 'TP-Link Technologies', '50C7BF': 'TP-Link Technologies',
    '54E6FC': 'TP-Link Technologies', '6466B3': 'TP-Link Technologies',
    '90F652': 'TP-Link Technologies', 'A0F3C1': 'TP-Link Technologies',
    'C025E9': 'TP-Link Technologies',
    '002404': 'AVM GmbH', '3C3786': 'AVM GmbH', 'AC37B5': 'AVM GmbH',
    'C42602': 'AVM GmbH', 'DCE834': 'AVM GmbH',
    '001569': 'Xiaomi Communications', '28E31F': 'Xiaomi Communications',
    '34CE00': 'Xiaomi Communications', '50EC50': 'Xiaomi Communications',
    '642737': 'Xiaomi Communications', '74606D': 'Xiaomi Communications',
    '98FAE3': 'Xiaomi Communications', 'AC3713': 'Xiaomi Communications',
    'F0B429': 'Xiaomi Communications',
    '001E10': 'Huawei Technologies', '002568': 'Huawei Technologies',
    '0026B9': 'Huawei Technologies', '30D17E': 'Huawei Technologies',
    '40187A': 'Huawei Technologies', '5404A6': 'Huawei Technologies',
    '60DE44': 'Huawei Technologies', '8C34FD': 'Huawei Technologies',
    '041361': 'OnePlus Technology', '94654B': 'OnePlus Technology',
    'E098EB': 'Heltec Automation',
}

_db: dict = {}


def _load():
    global _db
    if OUI_CSV.exists():
        try:
            with open(OUI_CSV, newline='', encoding='utf-8', errors='replace') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    oui  = row.get('Assignment', '').strip().upper()
                    name = row.get('Organization Name', '').strip()
                    if oui and name:
                        _db[oui] = name
            log.info('OUI database loaded: %d entries from %s', len(_db), OUI_CSV)
            return
        except Exception as e:
            log.warning('OUI CSV load failed: %s — using fallback', e)
    else:
        log.info('OUI CSV not found — using fallback (%d entries)', len(_FALLBACK))
    _db = dict(_FALLBACK)


def lookup(mac: str) -> str | None:
    if not mac:
        return None
    oui = mac.replace(':', '').replace('-', '').upper()[:6]
    return _db.get(oui)


_load()
