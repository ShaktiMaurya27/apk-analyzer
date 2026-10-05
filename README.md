# APK Analyzer (`apk-analyzer`)

> **Android Application Packages (APKs) Static & Heuristic Security Analysis Engine**

---

## 📌 Overview

**`apk-analyzer`** is a comprehensive, pure static security analysis and reverse-engineering engine for Android Application Packages (`.apk`).

It evaluates declared and used permissions, parses binary `AndroidManifest.xml` files, inspects Dalvik/ART DEX bytecode, extracts hardcoded network URLs/IPs/C2 signatures, and validates X.509 signing certificates to compute an aggregated 0–100 Risk Score—**without executing code on a live device**.

---

## 🛠️ Pipeline Architecture & 7 Evaluation Phases

| Phase | Module Name | Core Functionality |
| :--- | :--- | :--- |
| **Phase 1** | `ingestion.py` | Validates `.apk` ZIP archive structure, computes SHA-256 digest, reads file size, and extracts target assets (`AndroidManifest.xml`, `classes*.dex`, META-INF signatures). |
| **Phase 2** | `axml.py` & `manifest_auditor.py` | Uses pure-Python binary AXML decoder to extract package metadata (`package_name`, `version_name`, `target_sdk`, `min_sdk`), audit dangerous permissions, and detect lethal permission combinations (Overlay trojans, Spyware exfiltration, SMS 2FA interception). |
| **Phase 3** | `component_inspector.py` | Enumerates Activities, Services, Receivers, and Content Providers. Resolves exported states and flags unprotected exposed entry points, boot broadcast receivers (`BOOT_COMPLETED`), and headless background architectures. |
| **Phase 4** | `bytecode_analyzer.py` | Computes Shannon Entropy ($H \in [0.0, 8.0]$) across DEX byte streams, detects commercial packers (Qihoo 360 Jiagu, Bangcle, Secneo, Legu, Ijiami), flags suspicious API calls (`DexClassLoader`, `Runtime.exec`, reflection), and discovers disguised asset containers. |
| **Phase 5** | `network_cert_analyzer.py` | Extracts hardcoded URLs and IPv4 addresses, flags unencrypted HTTP calls, detects C2 / dynamic DNS / Telegram bot exfiltration endpoints, and verifies v1 JAR & v2/v3 signature scheme blocks and debug certificates. |
| **Phase 6** | `scoring_engine.py` | Computes composite Risk Score (0–100), classifies application (`Safe`: 0-39, `Suspicious`: 40-69, `Malicious`: 70-100), evaluates confidence level (`Low`, `Medium`, `High`), and synthesizes executive summaries & remediation guidelines. |
| **Phase 7** | `pipeline.py` & `main.py` | Orchestrates the end-to-end 7-phase analysis, enforces Pydantic schema compliance, provides CLI execution, and exports structured JSON reports. |

---

## 📂 Project Structure

```
apk-analyzer/
├── apk_analyzer/             # Core 7-Phase Analysis Package
│   ├── __init__.py
│   ├── axml.py               # Pure-Python Binary Android XML Parser
│   ├── bytecode_analyzer.py  # Entropy, Packer & DEX API Scanner
│   ├── component_inspector.py# Component Export & Intent Auditor
│   ├── ingestion.py          # Container Validation & Asset Extractor
│   ├── manifest_auditor.py   # Manifest & Permission Auditor
│   ├── network_cert_analyzer.py # Network, C2 Endpoints & Cert Auditor
│   ├── pipeline.py           # 7-Phase Analysis Pipeline Integrator
│   ├── schema.py             # Pydantic Output Specification Schemas
│   └── scoring_engine.py     # 0-100 Risk Score & Classification Engine
├── tests/                    # Complete Test Suite (14/14 Tests Passing)
│   ├── test_phase1.py
│   ├── test_phase2.py
│   ├── test_phase3.py
│   ├── test_phase4.py
│   ├── test_phase5.py
│   ├── test_phase6.py
│   └── test_e2e.py
├── index.html                # Responsive Web Interface (Drag-and-Drop & Mobile Picker)
├── main.py                   # Command Line Interface (CLI) Entry Point
├── generate_why_pdf.py       # ReportLab PDF Generator Script for WHY.pdf
├── WHY.md                    # Detailed Technical Rationale Document
├── WHY.pdf                   # Generated Technical Justification PDF
└── README.md                 # Complete Technical Manual & Hinglish FAQ
```

---

## ⚡ Quick Start & Usage

### 1. Installation
Install required Python packages:
```bash
pip install pydantic reportlab
```

### 2. Command Line Interface (CLI)
Analyze any Android APK file:
```bash
python main.py path/to/sample.apk
```

Save the JSON security assessment report to a file:
```bash
python main.py path/to/sample.apk -o output_report.json
```

### 3. Run Test Suite
Run unit tests across all 7 phases:
```bash
python -m unittest discover tests
```

### 4. Responsive Web Interface (`index.html`)
Open `index.html` in any browser to launch the web interface:
- **Desktop Drag & Drop Zone** + **Mobile Touch File Selector**.
- Real-time step-by-step progress logging.
- Animated circular threat score gauge and tabbed breakdown (Threat Overview, Permissions, API Heuristics, Network/C2, Remediation).
- **3 Instant Demo Scenarios** (Clean Utility App, Anubis Banking Trojan, Pegasus Spyware).
- Actionable JSON report copy/download and print view.

---

## 📑 Structured JSON Output Format

The output strictly complies with the requested specification:

```json
{
  "app_metadata": {
    "package_name": "com.system.flashplayer.update",
    "app_name": "FlashPlayer Update Service",
    "version_name": "2.1.0",
    "version_code": "21",
    "target_sdk": 28,
    "min_sdk": 19,
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

---

## 📜 License
Developed for Android Mobile Security & Static Reverse-Engineering Assessment (`apk-analyzer`).
