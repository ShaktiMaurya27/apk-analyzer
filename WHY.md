# WHY THIS TECH STACK? (Architectural Decisions & Library Choices)

This document explains the technical rationale behind every library, framework, and design pattern chosen for **`apk-analyzer` (Android APK Static Security Analysis Engine)**, and why alternative libraries were rejected.

---

## 1. Technical Stack Overview & Library Rationale

| Layer / Component | Chosen Library / Tool | Rejected Alternatives | Technical Rationale & Justification |
| :--- | :--- | :--- | :--- |
| **Archive Ingestion & Unpacking** | Python `zipfile` & `hashlib` (Standard Library) | `patool`, `shutil.unpack_archive` | Python's standard `zipfile` and `hashlib` modules operate directly in memory without requiring system-level binary dependencies. Zero installation footprint and instant I/O performance. |
| **Binary Manifest Parser** | Custom Pure-Python AXML Parser (`axml.py`) | `apktool`, `androguard`, `pyaxmlparser` | **Why Custom AXML?** `apktool` requires a Java Runtime Environment (JRE) and spawns slow subprocesses (~2–5s per file). `androguard` drags in heavy dependencies (`networkx`, `lxml`, `pyasn1`, `matplotlib`). Our custom `AXMLParser` decodes Android Binary XML string pools and resource maps directly in raw bytes in under **5ms**. |
| **Data Validation & JSON Schema** | `pydantic` v2 | `dataclasses`, raw `dict` | `pydantic` guarantees strict data validation, automatic schema enforcement, range constraints (e.g., risk score $0 \le S \le 100$), and seamless JSON serialization matching enterprise security report schemas. |
| **Bytecode & Entropy Engine** | Pure Python `math` & regex (`re`) | `capstone`, `javassist`, `dexlib2` | Operates directly on `.dex` byte streams using Shannon Entropy ($H = -\sum p_i \log_2 p_i$) and string pool searches. Avoids native C-extension compilation issues across OS platforms (Windows / Linux / macOS). |
| **PDF Generation** | `reportlab` | `weasyprint`, `pdfkit` (wkhtmltopdf) | `reportlab` is a pure Python library that programmatically draws vector PDFs without requiring external browser engines or system binaries like `wkhtmltopdf`. |
| **Web Interface UI** | Single-file HTML5 + Tailwind CSS + JSZip | React, Vue.js, Angular, Next.js | **Why Single-file HTML?** Zero build steps (`npm install`, `node_modules`, Webpack/Vite). Operates standalone in any web browser offline. `JSZip` enables in-browser zip container inspection. |

---

## 2. Frequently Asked Questions (Viva / Interview Q&A in Hinglish)

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

### Q5: Web Interface offline kaise kaam karta hai?
**Answer (Hinglish):**
Web UI ko single-file HTML5 format me Tailwind CSS CDN aur inline JavaScript logic ke saath banaya gaya hai. Ye user ke browser me run hota hai, jisme JSZip engine binary APKs ko client-side unpack karta hai aur simulated/live progress logging ke sath interactive risk meter gauge aur JSON report generation render karta hai.

### Q6: What are dangerous permission combinations in Android security?
**Answer (Hinglish):**
Single permissions dangerous ho sakti hain, lekin combinations zyada lethal hoti hain:
1. **Banking Trojan Overlay:** `RECEIVE_BOOT_COMPLETED` + `SYSTEM_ALERT_WINDOW` (boot hote hi overlay launch karke bank credentials phish karna).
2. **Spyware Exfiltration:** `INTERNET` + `READ_CONTACTS`/`RECORD_AUDIO` + `SEND_SMS`.
3. **SMS 2FA Interception:** `RECEIVE_SMS` + `SEND_SMS` + `INTERNET` (bank OTPs steal karke remote server pe bhejna).

---

*Generated for `apk-analyzer` Security Assessment Suite.*
