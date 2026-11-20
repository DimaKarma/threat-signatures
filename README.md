# Threat Signatures & Hardware Vendor Registry

This repository hosts open-data hardware vendor registries and surveillance equipment signatures. It is maintained and automatically updated on the 1st of every month via GitHub Actions.

---

## Datasets

### 1. `signatures/threat_signatures_light.json` (~18.8 KB)
Curated high-priority registry of surveillance cameras (CCTV/IP), covert video transmitters (RTSP/ONVIF), smart door locks, tracking tags (AirTags, Tile, SmartTags), and IoT bug microcontrollers (Tuya, Espressif).
- **Format:** JSON key-value mapping indexed by 6-character uppercase hex IEEE OUI prefix.
- **Fields:**
  - `v`: Official vendor name string
  - `t`: Inferred device category / role
  - `r`: Risk level (2 = Critical Threat, 1 = Suspicious, 0 = Verified Benign)

### 2. `signatures/registry_full.json` (~1.36 MB / ~380 KB GZipped)
Complete international IEEE OUI registry covering 40,500+ assigned hardware manufacturer blocks.
- **Format:** JSON dictionary mapping IEEE OUI to manufacturer details:
  - `v`: Official registered corporate legal entity
  - `c`: Country of corporate registration (ISO 2-letter alpha code)

---

## Automated Maintenance

The dataset is synchronized on a monthly schedule (`00:00 UTC on the 1st of each month`) via `.github/workflows/update_vendor_db.yml`.
The workflow runs `scripts/compile_registries.py` to:
1. Pull fresh OUI records directly from the IEEE Standards Association.
2. Ingest Bluetooth SIG company identifiers.
3. Clean and normalize historical records into compact JSON manifests.

---

## License

This dataset is distributed under the MIT License.
The underlying OUI assignments are public data provided by the IEEE Standards Association and Bluetooth SIG.
