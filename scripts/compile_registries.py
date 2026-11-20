#!/usr/bin/env python3
"""
Compile Vendor Registries for ThreatScan.
Generates two datasets:
1. signatures/threat_signatures_light.json (~180 KB)
2. signatures/registry_full.json (~1.4 MB compact)
"""

import os
import sys
import json
import urllib.request
import csv
import io
import re
from datetime import datetime

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "signatures")
os.makedirs(OUTPUT_DIR, exist_ok=True)

LIGHT_OUTPUT = os.path.join(OUTPUT_DIR, "threat_signatures_light.json")
FULL_OUTPUT = os.path.join(OUTPUT_DIR, "registry_full.json")

IEEE_CSV_URL = "https://standards-oui.ieee.org/oui/oui.csv"
BT_YAML_URL = "https://bitbucket.org/bluetooth-SIG/public/raw/main/assigned_numbers/company_identifiers/company_identifiers.yaml"

# Curated core signatures for light database
CURATED_LIGHT_OUIS = {
    # CCTV & Surveillance Hardware
    "4419B6": {"v": "Hangzhou Hikvision Digital Technology", "t": "CCTV Surveillance Camera", "r": 2},
    "E0508B": {"v": "Hangzhou Hikvision Digital Technology", "t": "CCTV Surveillance Camera", "r": 2},
    "105BAD": {"v": "Hangzhou Hikvision Digital Technology", "t": "CCTV Surveillance Camera", "r": 2},
    "54C415": {"v": "Hangzhou Hikvision Digital Technology", "t": "CCTV Surveillance Camera", "r": 2},
    "BC5451": {"v": "Hangzhou Hikvision Digital Technology", "t": "CCTV Surveillance Camera", "r": 2},
    "A41437": {"v": "Hangzhou Hikvision Digital Technology", "t": "CCTV Surveillance Camera", "r": 2},
    "2857BE": {"v": "Hangzhou Hikvision Digital Technology", "t": "CCTV Surveillance Camera", "r": 2},
    "9002A9": {"v": "Zhejiang Dahua Technology", "t": "CCTV Surveillance Camera", "r": 2},
    "3CEF8C": {"v": "Zhejiang Dahua Technology", "t": "CCTV Surveillance Camera", "r": 2},
    "B00247": {"v": "Zhejiang Dahua Technology", "t": "CCTV Surveillance Camera", "r": 2},
    "48EA63": {"v": "Zhejiang Dahua Technology", "t": "CCTV Surveillance Camera", "r": 2},
    "001212": {"v": "Hangzhou Xiongmai Technology", "t": "Covert IP Camera / XM Module", "r": 2},
    "EC71DB": {"v": "Reolink Innovation Inc.", "t": "IP Camera System", "r": 2},
    "00626E": {"v": "Shenzhen Reolink Technology", "t": "IP Camera System", "r": 2},
    "000C43": {"v": "VStarcam / Ralink Technology", "t": "IP Surveillance Camera", "r": 2},
    "00408C": {"v": "Axis Communications AB", "t": "Network Camera / Surveillance", "r": 2},
    "ACCC8E": {"v": "Axis Communications AB", "t": "Network Camera / Surveillance", "r": 2},
    "B8A44F": {"v": "Axis Communications AB", "t": "Network Camera / Surveillance", "r": 2},
    "E4AAEC": {"v": "Wyze Labs Inc.", "t": "Smart Security Camera", "r": 2},
    "2CAA8E": {"v": "Wyze Labs Inc.", "t": "Smart Security Camera", "r": 2},
    "A4DA22": {"v": "Anker Innovations (Eufy Security)", "t": "Security Camera / IoT", "r": 2},
    "F4B85E": {"v": "Ring LLC (Amazon Ring)", "t": "Video Doorbell / Camera", "r": 2},
    "641666": {"v": "Amcrest Technologies", "t": "IP Camera / Security", "r": 2},
    "C0395A": {"v": "Foscam Intelligent Technology", "t": "IP Camera", "r": 2},
    "1C521D": {"v": "Zhejiang Uniview Technologies", "t": "Surveillance Camera System", "r": 2},

    # Tuya Smart & IoT Modules (Potential Bugs / Hidden Cams)
    "FC3CD7": {"v": "Tuya Smart Inc.", "t": "Tuya Smart IoT (Module / Spy Cam / Plug)", "r": 1},
    "508A06": {"v": "Tuya Smart Inc.", "t": "Tuya Smart IoT Module", "r": 1},
    "D81E5E": {"v": "Tuya Smart Inc.", "t": "Tuya Smart IoT Module", "r": 1},
    "1C90FF": {"v": "Tuya Smart Inc.", "t": "Tuya Smart IoT Module", "r": 1},
    "68572D": {"v": "Tuya Smart Inc.", "t": "Tuya Smart IoT Module", "r": 1},
    "7CF666": {"v": "Tuya Smart Inc.", "t": "Tuya Smart IoT Module", "r": 1},
    "840D8E": {"v": "Tuya Smart Inc.", "t": "Tuya Smart IoT Module", "r": 1},
    "A09208": {"v": "Tuya Smart Inc.", "t": "Tuya Smart IoT Module", "r": 1},
    "B4E62D": {"v": "Tuya Smart Inc.", "t": "Tuya Smart IoT Module", "r": 1},
    "C44EAC": {"v": "Tuya Smart Inc.", "t": "Tuya Smart IoT Module", "r": 1},
    "30B0E3": {"v": "Tuya Smart Inc.", "t": "Tuya Smart IoT Module", "r": 1},
    "0C9F3A": {"v": "Tuya Smart Inc.", "t": "Tuya Smart IoT Module", "r": 1},

    # Espressif Systems (ESP32/ESP8266 IoT & DIY Pinhole Cams)
    "3C71BF": {"v": "Espressif Systems", "t": "ESP32/ESP8266 IoT (Possible DIY Bug/Cam)", "r": 1},
    "A4CF12": {"v": "Espressif Systems", "t": "ESP32/ESP8266 IoT (AZW Beelink / Smart)", "r": 1},
    "246F28": {"v": "Espressif Systems", "t": "ESP32/ESP8266 IoT Chipset", "r": 1},
    "70039F": {"v": "Espressif Systems", "t": "ESP32/ESP8266 IoT Chipset", "r": 1},
    "D8F15B": {"v": "Espressif Systems", "t": "ESP32/ESP8266 IoT Chipset", "r": 1},
    "30AEA4": {"v": "Espressif Systems", "t": "ESP32/ESP8266 IoT Chipset", "r": 1},
    "240AC4": {"v": "Espressif Systems", "t": "ESP32/ESP8266 IoT Chipset", "r": 1},
    "84CCA8": {"v": "Espressif Systems", "t": "ESP32/ESP8266 IoT Chipset", "r": 1},
    "84F3EB": {"v": "Espressif Systems", "t": "ESP32/ESP8266 IoT Chipset", "r": 1},
    "A47B9D": {"v": "Espressif Systems", "t": "ESP32/ESP8266 IoT Chipset", "r": 1},
    "CC50E3": {"v": "Espressif Systems", "t": "ESP32/ESP8266 IoT Chipset", "r": 1},

    # Smart Locks & Access Control
    "DC8E95": {"v": "Allegion (Schlage Commercial Lock)", "t": "Electronic Smart Door Lock", "r": 0},
    "70AC08": {"v": "Silicon Laboratories (Smart Locks / IoT)", "t": "Smart Door Lock Chipset", "r": 0},

    # Hotel Infrastructure, Routers & Mesh Nodes
    "C8B82F": {"v": "Amazon Eero Mesh Router", "t": "Wi-Fi Router Gateway", "r": 0},
    "B4B9E6": {"v": "Amazon Eero Mesh Node", "t": "Wi-Fi Mesh Repeater", "r": 0},
    "00155D": {"v": "Microsoft Corporation (WSL / Hyper-V)", "t": "Host Virtual Network Adapter", "r": 0},

    # Consumer Tech, Audio, Appliances & Medical
    "76405D": {"v": "Amazon Technologies, Inc.", "t": "Amazon Echo / Alexa (Active Mic)", "r": 1},
    "44650D": {"v": "Amazon Technologies, Inc.", "t": "Amazon Smart Hardware", "r": 0},
    "6837E9": {"v": "Amazon Technologies, Inc.", "t": "Amazon Smart Hardware", "r": 0},
    "5854B6": {"v": "Bose Corporation", "t": "Bose Bluetooth Audio / Speaker", "r": 0},
    "50EC50": {"v": "Bose Corporation", "t": "Bose Bluetooth Audio / Speaker", "r": 0},
    "30C922": {"v": "Nespresso (Nestle Nespresso S.A.)", "t": "Nespresso Vertuo Smart Coffee Machine", "r": 0},
    "A46DD4": {"v": "ResMed Corp", "t": "ResMed CPAP / Sleep Apnea Medical Device", "r": 0},
    "78EE4C": {"v": "Levoit (VeSync Corp)", "t": "Levoit Smart Ultrasonic Humidifier", "r": 0},
    "D41368": {"v": "Govee (Shenzhen Intellirocks)", "t": "Govee Smart Sensor / Light", "r": 0},
    "EB6A45": {"v": "Govee (Shenzhen Intellirocks)", "t": "Govee Smart Sensor / Light", "r": 0},
    "C05D89": {"v": "TCL King Electrical Appliances", "t": "TCL Smart TV / Screen", "r": 0},
    "1C1338": {"v": "Zebra / Rongta", "t": "Portable Bluetooth Printer", "r": 0},
    "98B8BC": {"v": "Samsung Electronics", "t": "Samsung Consumer Device", "r": 0},
    "30CDA7": {"v": "Samsung Electronics", "t": "Samsung Network Printer / Device", "r": 0},
    "84C0EF": {"v": "Samsung Electronics", "t": "Samsung SmartTag / Galaxy", "r": 0},
    "70AED5": {"v": "Apple Inc.", "t": "Apple iPhone / Mac / Audio", "r": 0},
    "840F4C": {"v": "Apple Inc.", "t": "Apple iPhone / Mac / Audio", "r": 0},
    "F01898": {"v": "Apple Inc.", "t": "Apple iPhone / Mac / Audio", "r": 0},
    "ACBC32": {"v": "Apple Inc.", "t": "Apple iPhone / Mac / Audio", "r": 0},
    "BCD074": {"v": "Apple Inc.", "t": "Apple iPhone / Mac / Audio", "r": 0},
    "4FB99A": {"v": "Apple Inc.", "t": "Apple Device", "r": 0},
    "6F01D5": {"v": "Apple Inc.", "t": "Apple Device", "r": 0},
    "77D8A2": {"v": "Apple Inc.", "t": "Apple Device", "r": 0},
    "6DAF7F": {"v": "Apple Inc.", "t": "Apple Device", "r": 0},
    "545603": {"v": "Apple Inc.", "t": "Apple Device", "r": 0},
    "5D3FAE": {"v": "Apple Inc.", "t": "Apple Device", "r": 0},
    "7CEEC7": {"v": "Apple Inc.", "t": "Apple Device", "r": 0},
    "71B440": {"v": "Apple Inc.", "t": "Apple Device", "r": 0},
    "502E11": {"v": "Apple Inc.", "t": "Apple Device", "r": 0},
    "D52202": {"v": "Apple Inc.", "t": "Apple Device", "r": 0},
    "F12354": {"v": "Apple Inc.", "t": "Apple Device", "r": 0},
    "F20216": {"v": "Apple Inc.", "t": "Apple Device", "r": 0},
    "E2D14B": {"v": "Apple Inc.", "t": "Apple Device", "r": 0},
    "C0D7A3": {"v": "Apple Inc.", "t": "Apple Device", "r": 0},
    "F9BAFD": {"v": "Apple Inc.", "t": "Apple Device", "r": 0},
    "CC2BA5": {"v": "Apple Inc.", "t": "Apple Device", "r": 0},
    "D47830": {"v": "Apple Inc.", "t": "Apple Device", "r": 0},
    "F5A50B": {"v": "Apple Inc.", "t": "Apple Device", "r": 0},
    "C0F8B4": {"v": "Apple Inc.", "t": "Apple Device", "r": 0},
    "DD31B6": {"v": "Apple Inc.", "t": "Apple Device", "r": 0},
    "D69EE9": {"v": "Apple Inc.", "t": "Apple Device", "r": 0},
    "3D362C": {"v": "Apple Inc.", "t": "Apple Device", "r": 0},
    "587E61": {"v": "Apple Inc.", "t": "Apple Device", "r": 0},
    "F9956B": {"v": "Apple Inc.", "t": "Apple Device", "r": 0},
    "C0B883": {"v": "Intel Corporate", "t": "Intel Network Adapter", "r": 0},
    "F4B301": {"v": "Intel Corporate", "t": "Intel Network Adapter", "r": 0},
    "3C6A9D": {"v": "Intel Corporate", "t": "Intel Network Adapter", "r": 0},
    "A4C138": {"v": "Telink Semiconductor", "t": "Smart Sensor / IoT Chipset", "r": 0},
    "D838FC": {"v": "Google Nest", "t": "Smart Home Hub / Speaker", "r": 1},
    "F40343": {"v": "Google LLC", "t": "Google Consumer Device", "r": 0},
    "48B02D": {"v": "Google LLC", "t": "Google Consumer Device", "r": 0},
    "001788": {"v": "Philips Lighting (Hue)", "t": "Smart Lighting Gateway", "r": 0},
    "DCA632": {"v": "Raspberry Pi Trading", "t": "Single Board Computer", "r": 1},
    "B827EB": {"v": "Raspberry Pi Foundation", "t": "Single Board Computer", "r": 1}
}

CURATED_LIGHT_COMPANIES = {
    "0006": {"v": "Microsoft Corporation", "t": "Windows Device", "r": 0},
    "004C": {"v": "Apple Inc.", "t": "Apple Ecosystem (AirTag / Device)", "r": 0},
    "0057": {"v": "Harman International (JBL/AKG)", "t": "Bluetooth Audio Endpoint", "r": 0},
    "0059": {"v": "Nordic Semiconductor ASA", "t": "IoT Beacon / Sensor", "r": 0},
    "0075": {"v": "Samsung Electronics Co. Ltd.", "t": "Samsung SmartTag / Galaxy", "r": 0},
    "009E": {"v": "Bose Corporation", "t": "Bose Bluetooth Audio", "r": 0},
    "00E0": {"v": "Google LLC", "t": "Google Device", "r": 0},
    "00EB": {"v": "ASSA ABLOY Hospitality", "t": "VingCard Commercial Hotel Lock", "r": 0},
    "0104": {"v": "Sonos, Inc.", "t": "Smart Audio Speaker", "r": 0},
    "013B": {"v": "Allegion", "t": "Schlage Commercial Door Lock", "r": 0},
    "0141": {"v": "Anker Innovations", "t": "Soundcore / Anker Peripheral", "r": 0},
    "0157": {"v": "Xiaomi Inc.", "t": "Xiaomi Smart Device", "r": 0},
    "0171": {"v": "Amazon.com Services LLC", "t": "Amazon Smart Hardware", "r": 0},
    "0180": {"v": "Dormakaba Group", "t": "Saflok Commercial Hotel Lock", "r": 0},
    "019A": {"v": "Huawei Technologies", "t": "Huawei Smart Device", "r": 0},
    "01D3": {"v": "Salto Systems", "t": "Salto Electronic Hotel Lock", "r": 0},
    "0211": {"v": "Telink Semiconductor", "t": "Smart Sensor Chipset", "r": 0},
    "0225": {"v": "Nest Labs Inc.", "t": "Google Nest Smart Device", "r": 1},
    "02AC": {"v": "Amazon Technologies, Inc.", "t": "Amazon Echo (Active Mic)", "r": 1},
    "0312": {"v": "Tile, Inc.", "t": "Tile Tracking Beacon", "r": 2},
    "04CE": {"v": "Roborock Technology", "t": "Robot Vacuum Cleaner", "r": 0},
    "0665": {"v": "Wyze Labs, Inc.", "t": "Wyze Smart Camera / Sensor", "r": 1},
    "07D0": {"v": "Tuya Smart Inc.", "t": "Tuya Smart IoT (Module / Spy Cam / Plug)", "r": 1},
    "0822": {"v": "Govee (Shenzhen Intellirocks)", "t": "Govee Smart Sensor / Light", "r": 0},
    "08A9": {"v": "Arlo Technologies, Inc.", "t": "Arlo Security Camera", "r": 2},
    "0982": {"v": "ResMed Corp", "t": "ResMed CPAP Medical Device", "r": 0},
    "0A2B": {"v": "Eufy Security (Anker)", "t": "Eufy Security Camera", "r": 2},
    "8843": {"v": "Govee (Shenzhen Intellirocks)", "t": "Govee Smart Sensor / Light", "r": 0},
    "FEED": {"v": "Tile Inc.", "t": "Tile Tracking Beacon", "r": 2}
}

CURATED_NAME_RULES = [
    {"pattern": "Echo", "v": "Amazon Technologies, Inc.", "t": "Smart Speaker / Active Mic", "r": 1},
    {"pattern": "Alexa", "v": "Amazon Technologies, Inc.", "t": "Smart Speaker / Active Mic", "r": 1},
    {"pattern": "Google Home", "v": "Google LLC", "t": "Smart Speaker / Active Mic", "r": 1},
    {"pattern": "Nest", "v": "Google LLC", "t": "Smart Speaker / Active Mic", "r": 1},
    {"pattern": "Bose", "v": "Bose Corporation", "t": "Bose Bluetooth Audio / Speaker", "r": 0},
    {"pattern": "Vertuo", "v": "Nespresso (Nestle Nespresso S.A.)", "t": "Nespresso Vertuo Smart Coffee Machine", "r": 0},
    {"pattern": "Nespresso", "v": "Nespresso (Nestle Nespresso S.A.)", "t": "Nespresso Vertuo Smart Coffee Machine", "r": 0},
    {"pattern": "ResMed", "v": "ResMed Corp", "t": "ResMed CPAP / Sleep Apnea Medical Device", "r": 0},
    {"pattern": "classic300s", "v": "Levoit (VeSync Corp)", "t": "Levoit Smart Ultrasonic Humidifier", "r": 0},
    {"pattern": "Levoit", "v": "Levoit (VeSync Corp)", "t": "Levoit Smart Ultrasonic Humidifier", "r": 0},
    {"pattern": "NARWAL", "v": "Narwal Robotics", "t": "Narwal Robot Vacuum Cleaner", "r": 0},
    {"pattern": "GVH", "v": "Govee (Shenzhen Intellirocks)", "t": "Govee Smart Sensor / Light", "r": 0},
    {"pattern": "Govee", "v": "Govee (Shenzhen Intellirocks)", "t": "Govee Smart Sensor / Light", "r": 0},
    {"pattern": "T_CL", "v": "TCL Electronics", "t": "TCL Smart TV / Screen", "r": 0},
    {"pattern": "TCL", "v": "TCL Electronics", "t": "TCL Smart TV / Screen", "r": 0},
    {"pattern": "Suite ", "v": "Allegion (Schlage Commercial)", "t": "Allegion / Schlage Smart Door Lock", "r": 0},
    {"pattern": "Schlage", "v": "Allegion (Schlage Commercial)", "t": "Allegion / Schlage Smart Door Lock", "r": 0},
    {"pattern": "VingCard", "v": "ASSA ABLOY Hospitality (VingCard)", "t": "VingCard Commercial Hotel Door Lock", "r": 0},
    {"pattern": "Salto", "v": "Salto Systems", "t": "Salto Electronic Hotel Door Lock", "r": 0},
    {"pattern": "Dormakaba", "v": "Dormakaba (Saflok Commercial)", "t": "Dormakaba / Saflok Hotel Door Lock", "r": 0},
    {"pattern": "Saflok", "v": "Dormakaba (Saflok Commercial)", "t": "Dormakaba / Saflok Hotel Door Lock", "r": 0},
    {"pattern": "AZW", "v": "Shenzhen AZW Technology (Beelink / IoT)", "t": "AZW Smart IoT / Media Hub", "r": 0},
    {"pattern": "Beelink", "v": "Shenzhen AZW Technology (Beelink / IoT)", "t": "AZW Smart IoT / Media Hub", "r": 0},
    {"pattern": "PR BT", "v": "Zebra / Rongta Portable Printer", "t": "Portable Bluetooth Printer", "r": 0},
    {"pattern": "TY", "v": "Tuya Smart Inc.", "t": "Tuya Smart IoT Module (Tineco / Appliance / Bug)", "r": 1}
]

def fetch_ieee_ouis():
    """Fetches full IEEE OUI CSV from official registry or falls back gracefully."""
    ouis = {}
    print(f"Fetching official IEEE OUI registry from {IEEE_CSV_URL}...")
    try:
        req = urllib.request.Request(IEEE_CSV_URL, headers={"User-Agent": "ThreatScanCompiler/3.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            content = resp.read().decode('utf-8', errors='ignore')
            reader = csv.reader(io.StringIO(content))
            header = next(reader, None)
            for row in reader:
                if len(row) >= 3:
                    assignment = row[1].strip().upper().replace(":", "").replace("-", "")
                    org_name = row[2].strip()
                    if len(assignment) == 6 and org_name:
                        ouis[assignment] = org_name
        print(f"Successfully fetched {len(ouis)} IEEE OUI records.")
    except Exception as e:
        print(f"Note: IEEE upstream fetch skipped or failed: {e}. Generating from curated catalog.")
    return ouis

def build_datasets():
    version_str = datetime.utcnow().strftime("%Y.%m.%d")
    timestamp_str = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    # 1. Build Tier 1: threat_signatures_light.json
    light_db = {
        "version": version_str,
        "generated_at": timestamp_str,
        "ouis": CURATED_LIGHT_OUIS,
        "companies": CURATED_LIGHT_COMPANIES,
        "name_rules": CURATED_NAME_RULES
    }

    with open(LIGHT_OUTPUT, "w", encoding="utf-8") as f:
        json.dump(light_db, f, indent=2)
    
    light_size_kb = os.path.getsize(LIGHT_OUTPUT) / 1024
    print(f"[OK] Generated Tier 1 Light DB: {LIGHT_OUTPUT} ({light_size_kb:.1f} KB)")

    # 2. Build Tier 2: registry_full.json
    full_ouis = fetch_ieee_ouis()

    # Merge curated entries into full dictionary
    for k, v in CURATED_LIGHT_OUIS.items():
        if k not in full_ouis:
            full_ouis[k] = v["v"]

    full_companies = {}
    for k, v in CURATED_LIGHT_COMPANIES.items():
        full_companies[k] = v["v"]

    full_db = {
        "version": version_str,
        "generated_at": timestamp_str,
        "ouis": full_ouis,
        "companies": full_companies
    }

    # Compact JSON output for minimal transfer payload
    with open(FULL_OUTPUT, "w", encoding="utf-8") as f:
        json.dump(full_db, f, separators=(',', ':'))

    full_size_kb = os.path.getsize(FULL_OUTPUT) / 1024
    print(f"[OK] Generated Tier 2 Full DB: {FULL_OUTPUT} ({full_size_kb:.1f} KB, ~{full_size_kb*0.28:.1f} KB gzipped)")

if __name__ == "__main__":
    build_datasets()
