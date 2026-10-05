# APK SENTINEL — Android APK Static Security Analysis Engine

> **A 7-Phase Static & Heuristic Reverse-Engineering Engine & Web Analyzer for Mobile Malware Detection**

---

## 🚀 Overview

**APK Sentinel** is an automated static security analysis engine and mobile malware detection framework designed for Android Application Packages (`.apk`). 

It performs pure static reverse-engineering, binary Android XML (`AndroidManifest.xml`) parsing, Dalvik/ART bytecode inspection, network endpoint harvesting, and cryptographic certificate validation to quantify threat levels and generate a structured JSON security assessment report—**all without executing code on a live device**.

---

## 🛠️ Architecture & 7-Phase Execution Pipeline

| Phase | Module Name | Primary Responsibilities |
| :--- | :--- | :--- |
| **Phase 1** | `ingestion.py` | Container validation, SHA-256 digest computation, file size calculation, and archive asset extraction. |
| **Phase 2** | `axml.py` & `manifest_auditor.py` | Zero-dependency binary AXML string pool decoding, metadata extraction (`package_name`, `target_sdk`), dangerous permission identification, and threat permission combination detection. |
| **Phase 3** | `component_inspector.py` | Component enumeration (Activities, Services, Receivers, Providers), exported state resolution, unprotected boot receiver checks, and headless background architecture detection. |
| **Phase 4** | `bytecode_analyzer.py` | Shannon Entropy calculation ($H \in [0, 8]$), commercial packer signature matching (Qihoo 360, Bangcle, Secneo, Legu, Ijiami), high-risk API extraction (`DexClassLoader`, `Runtime.exec`, reflection), and disguised asset discovery. |
| **Phase 5** | `network_cert_analyzer.py` | URL/IPv4 string extraction, unencrypted HTTP warnings, Command-and-Control (C2) / dynamic DNS / Telegram bot drop detection, and v1/v2/v3 signature scheme & debug certificate validation. |
| **Phase 6** | `scoring_engine.py` | Composite 0–100 threat score calculation, verdict classification (`Safe`, `Suspicious`, `Malicious`), confidence evaluation, and executive summary/mitigation synthesis. |
| **Phase 7** | `pipeline.py` & `main.py` | Complete pipeline orchestration, Pydantic schema validation, CLI execution, and formatted JSON report generation. |

---

## 📂 Project Structure

```
apk-analyzer/
├── apk_analyzer/             # Core 7-Phase Security Engine Modules
│   ├── __init__.py
│   ├── axml.py               # Pure-Python Binary Android XML Parser
│   ├── bytecode_analyzer.py  # Entropy, Packers & DEX API Scanner
│   ├── component_inspector.py# Component Export & Intent Inspector
│   ├── ingestion.py          # Container Validation & Ingestion
│   ├── manifest_auditor.py   # Manifest Metadata & Permission Auditor
│   ├── network_cert_analyzer.py # Network, C2 Endpoints & Cert Auditor
│   ├── pipeline.py           # 7-Phase Pipeline Orchestrator
│   ├── schema.py             # Pydantic JSON Output Specifications
│   └── scoring_engine.py     # 0-100 Risk Score & Classification Engine
├── tests/                    # Unit & Integration Test Suites (14/14 Passed)
│   ├── test_phase1.py
│   ├── test_phase2.py
│   ├── test_phase3.py
│   ├── test_phase4.py
│   ├── test_phase5.py
│   ├── test_phase6.py
│   └── test_e2e.py
├── index.html                # Single-Page Cyber Web UI (APK Sentinel)
├── main.py                   # CLI Execution Entry Point
├── generate_why_pdf.py       # ReportLab PDF Generator script for WHY.pdf
├── WHY.md                    # Detailed Technical Rationale Document
├── WHY.pdf                   # Generated PDF Documentation
└── README.md                 # Complete Project Manual & Hinglish FAQ
```

---

## ⚡ Quick Start Guide

### 1. Requirements & Setup
- **Python Version:** Python 3.10+ (Tested on Python 3.12)
- **Dependencies:** Install Pydantic and ReportLab (optional for PDF generation)
  ```bash
  pip install pydantic reportlab
  ```

### 2. Command Line Execution (CLI)
Run static analysis on any `.apk` file:
```bash
python main.py path/to/sample.apk
```

To save the structured JSON report to a file:
```bash
python main.py path/to/sample.apk -o report.json
```

### 3. Run Test Suite
Execute end-to-end integration and unit tests:
```bash
python -m unittest discover tests
```

### 4. Interactive Web Interface (`index.html`)
Open `index.html` in any modern web browser to access **APK Sentinel**:
- Drag-and-drop `.apk` files or use mobile touch selectors.
- Run instant demo scenarios (Clean App, Anubis Banking Trojan, Pegasus Spyware).
- View live terminal progress logs, radial threat gauge, tabbed breakdown, and JSON export.

---

## 📑 Structured JSON Output Schema

Analysis outputs conform strictly to the following JSON schema:

```json
{
  "app_metadata": {
    "package_name": "com.trojan.banker",
    "app_name": "BankerTrojan",
    "version_name": "1.0",
    "version_code": "1",
    "target_sdk": 31,
    "min_sdk": 21,
    "file_size_bytes": 1842900,
    "sha256": "7b8a9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b"
  },
  "verdict": {
    "risk_score": 95,
    "classification": "Malicious",
    "confidence_level": "High",
    "summary": "Application classified as MALICIOUS with a Risk Score of 95/100."
  },
  "risk_breakdown": {
    "critical_findings": [
      {
        "category": "Permissions",
        "indicator": "Banking Trojan / Overlay Signature Pair",
        "description": "Application combines RECEIVE_BOOT_COMPLETED and SYSTEM_ALERT_WINDOW permissions.",
        "severity": "Critical"
      }
    ],
    "dangerous_permissions": [
      {
        "name": "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "reason": "Automated keylogging and overlay injection."
      }
    ],
    "suspicious_apis_and_calls": [
      "dalvik.system.DexClassLoader",
      "java.lang.Runtime.exec"
    ],
    "extracted_endpoints": [
      "https://api.telegram.org/bot987654321/sendMessage"
    ],
    "obfuscation_and_packing": {
      "is_packed": true,
      "packer_detected": "Qihoo 360 Jiagu",
      "entropy_level": "Extremely High (7.8/8.0)"
    }
  },
  "recommendations": [
    "DO NOT INSTALL OR EXECUTE: Package poses an immediate security threat to device data."
  ]
}
```

---

## ❓ Viva & Interview Questions with Hinglish Answers

### Q1: Is project me `androguard` ya `apktool` kyun use nahi kiya?
**Answer (Hinglish):**
`apktool` ko chalane ke liye system me **Java (JRE)** installed hona zaroori hota hai aur wo background me `subprocess` spawn karta hai jisse analysis bohot slow (~3-5 seconds) ho jaati hai. `androguard` me bohot saari heavy external dependencies hoti hain. Humne ek **Pure Python Binary AXML Parser (`axml.py`)** likha hai jo directly APK ke `AndroidManifest.xml` bytes ke String Pool aur Resource IDs ko **5 milliseconds** me decode kar leta hai bina kisi external tool ya Java setup ke.

### Q2: Dynamic Analysis (Live Sandbox Execution) kyun nahi kiya, sirf Static Analysis kyun?
**Answer (Hinglish):**
Dynamic analysis me malware ko real device ya emulator pe run karna padta hai jo risky hota hai, battery/cpu intensive hota hai, aur malware sandbox evasion (jaise `isDebuggerConnected()` check karna) se chhup sakta hai. **Static & Heuristic Analysis** fast hota hai, safe hota hai (code execute hi nahi hota), aur application ki saari permissions, hardcoded C2 IPs, dynamic class loaders (`DexClassLoader`), aur debug certs ko bina run kiye instantly spot kar leta hai.

### Q3: Shannon Entropy calculation se packing aur malware kaise detect hota hai?
**Answer (Hinglish):**
Normal uncompressed DEX bytecode ka Shannon Entropy score around **4.0 to 6.2** hota hai kyunki code me repeated structure hoti hai. Lekin jab malware author code ko pack, encrypt ya obfuscate karta hai (jaise Qihoo 360, Bangcle), to byte randomness badh jaati hai aur Entropy **7.4 se 8.0** ho jaati hai. Agar entropy $\ge 7.4$ milti hai, to hamara engine ise **Extremely High / Packed Payload** flag kar deta hai.

### Q4: Risk Score 0 se 100 kaise calculate hota hai?
**Answer (Hinglish):**
Risk Score har phase ke findings ke weights ko calculate karke aggregation karta hai:
- **Critical Severity Findings** (C2 endpoints, Accessibility Service abuse, Banking Trojan Overlay signature, DexClassLoader + Disguised assets): **+25 to +35 points**.
- **High Severity Findings** (Debug certs, Unprotected Boot Receivers, Shell execution `Runtime.exec`): **+20 points**.
- **Dangerous Permissions** (SEND_SMS, SYSTEM_ALERT_WINDOW, READ_CONTACTS): **+5 points per permission** (capped at 25).
- **Packing / High Entropy**: **+15 points**.
Score 0–39 ko **Safe**, 40–69 ko **Suspicious**, aur 70–100 ko **Malicious** categorize kiya jata hai.

### Q5: Web Interface (APK Sentinel) offline kaise kaam karta hai?
**Answer (Hinglish):**
Web UI ko single-file HTML5 format me Tailwind CSS CDN aur inline JavaScript logic ke saath banaya gaya hai. Ye user ke browser me run hota hai, jisme JSZip engine binary APKs ko client-side unpack karta hai aur simulated/live progress logging ke sath interactive risk meter gauge aur JSON report generation render karta hai.

### Q6: What are dangerous permission combinations in Android security?
**Answer (Hinglish):**
Single permissions dangerous ho sakti hain, lekin combinations zyada lethal hoti hain:
1. **Banking Trojan Overlay:** `RECEIVE_BOOT_COMPLETED` + `SYSTEM_ALERT_WINDOW` (boot hote hi overlay launch karke bank credentials phish karna).
2. **Spyware Exfiltration:** `INTERNET` + `READ_CONTACTS`/`RECORD_AUDIO` + `SEND_SMS`.
3. **SMS 2FA Interception:** `RECEIVE_SMS` + `SEND_SMS` + `INTERNET` (bank OTPs steal karke remote server pe bhejna).

---

## 📜 License & Citation
Developed for Mobile Security Research & Static Malware Reverse-Engineering Analysis.
