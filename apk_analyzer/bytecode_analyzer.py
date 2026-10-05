import math
import os
import re
from typing import Dict, List, Set, Tuple, Optional
from apk_analyzer.schema import ObfuscationAndPacking, CriticalFinding
from apk_analyzer.ingestion import APKContainer

# Known commercial Android packers and their signature indicators
PACKER_SIGNATURES: Dict[str, List[str]] = {
    "Bangcle / SecShell": ["libsecmain.so", "libsecexe.so", "libbangcle.so", "bangcle"],
    "Secneo": ["libsecneo.so", "libsecneo_demo.so", "secneo"],
    "Tencent / Legu": ["libtxa.so", "libshell.so", "libtup.so", "tencent.stub"],
    "Qihoo 360 Jiagu": ["libjiagu.so", "libjiagu_art.so", "libjiagu_a64.so", "qihoo360"],
    "Ijiami": ["libijm.so", "libexec.so", "ijm_rom.dat", "ijiami"],
    "APKProtect": ["libapkprotect.so"],
    "Baidu Protect": ["libbaiduprotect.so", "baiduprotect"]
}

# High-risk Android APIs and reflection methods
SUSPICIOUS_API_PATTERNS: Dict[str, str] = {
    "dalvik.system.DexClassLoader": "Dynamic DEX Class Loading (enables loading external unverified code at runtime)",
    "dalvik.system.PathClassLoader": "Dynamic Path Class Loading",
    "java.lang.reflect.Method.invoke": "Runtime Method Reflection (used to conceal malicious API calls)",
    "java.lang.reflect.Field": "Runtime Field Reflection",
    "java.lang.Runtime.exec": "Native Shell Command Execution",
    "java.lang.ProcessBuilder": "Native Process Builder Execution",
    "javax.crypto.Cipher": "Dynamic Cryptographic Engine (potential payload decryption)",
    "android.telephony.SmsManager": "Covert SMS Operations API",
    "android.app.admin.DevicePolicyManager": "Device Administrator Control API",
    "/system/bin/su": "SU Binary Path (Root Detection / Escalation Check)",
    "/system/xbin/su": "XBIN SU Binary Path (Root Check)",
    "getDeviceId": "Harvesting Device IMEI / Identifier",
    "getSubscriberId": "Harvesting SIM IMSI Identifier"
}

class BytecodeAnalyzer:
    """
    Performs bytecode, high-risk API call, file entropy, and packer detection analysis
    on DEX files and APK assets.
    """
    def __init__(self, apk_container: APKContainer):
        self.container = apk_container

    def analyze(self) -> Tuple[ObfuscationAndPacking, List[str], List[CriticalFinding]]:
        """
        Executes bytecode inspection and returns packing metadata, detected APIs,
        and critical security findings.
        """
        findings: List[CriticalFinding] = []
        detected_apis: Set[str] = set()
        
        dex_files = self.container.get_dex_files()
        
        # 1. Entropy calculation across DEX bytecode
        max_dex_entropy = 0.0
        for fname, data in dex_files:
            entropy = self._calculate_entropy(data)
            if entropy > max_dex_entropy:
                max_dex_entropy = entropy

        entropy_level = "Normal"
        if max_dex_entropy >= 7.4:
            entropy_level = "Extremely High"
        elif max_dex_entropy >= 6.8:
            entropy_level = "High"

        # 2. Packer Detection
        packer_name = self._detect_packer()
        is_packed = packer_name is not None or max_dex_entropy >= 7.4

        obfuscation_info = ObfuscationAndPacking(
            is_packed=is_packed,
            packer_detected=packer_name,
            entropy_level=entropy_level
        )

        if is_packed:
            findings.append(CriticalFinding(
                category="Bytecode",
                indicator=f"Packer / Encryption Detected ({packer_name or 'High Entropy'})",
                description=f"Application bytecode exhibits heavy packing or encryption (Entropy: {max_dex_entropy:.2f}/8.0). Packer: {packer_name or 'Unknown Custom Packer'}.",
                severity="Critical" if packer_name else "High"
            ))

        # 3. High-Risk API Call Extraction
        for fname, data in dex_files:
            apis = self._extract_suspicious_apis(data)
            detected_apis.update(apis)

        sorted_apis = sorted(list(detected_apis))
        
        # Flag Dynamic Class Loading / Reflection / Shell Execution
        if "dalvik.system.DexClassLoader" in detected_apis:
            findings.append(CriticalFinding(
                category="Bytecode",
                indicator="Dynamic Payload Class Loading (DexClassLoader)",
                description="DEX code uses DexClassLoader to dynamically load external secondary DEX/JAR payloads at runtime, bypassing static analysis.",
                severity="Critical"
            ))

        if "java.lang.Runtime.exec" in detected_apis or "java.lang.ProcessBuilder" in detected_apis:
            findings.append(CriticalFinding(
                category="Bytecode",
                indicator="Native Shell Execution Invocation",
                description="Bytecode contains invocations to Runtime.exec or ProcessBuilder to execute OS shell commands directly.",
                severity="High"
            ))

        if "java.lang.reflect.Method.invoke" in detected_apis:
            findings.append(CriticalFinding(
                category="Bytecode",
                indicator="Reflection Method Invocation",
                description="Application uses java.lang.reflect.Method.invoke to execute methods dynamically, concealing underlying API calls.",
                severity="Medium"
            ))

        # 4. Disguised Assets & Payload Container Scan
        disguised_assets = self._scan_disguised_assets()
        for asset_name, magic_type in disguised_assets:
            findings.append(CriticalFinding(
                category="Bytecode",
                indicator="Disguised Asset Container",
                description=f"Resource file '{asset_name}' uses a disguised extension but contains a hidden binary executable/payload ({magic_type}).",
                severity="Critical"
            ))

        return obfuscation_info, sorted_apis, findings

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculates Shannon entropy of a byte sequence (0.0 to 8.0)."""
        if not data:
            return 0.0
        
        byte_counts = [0] * 256
        for b in data:
            byte_counts[b] += 1

        entropy = 0.0
        data_len = len(data)
        for count in byte_counts:
            if count == 0:
                continue
            p = count / data_len
            entropy -= p * math.log2(p)
        return round(entropy, 2)

    def _detect_packer(self) -> Optional[str]:
        """Scans ZIP entries and DEX strings for known commercial packer signatures."""
        file_list = self.container.file_list

        for packer_name, sigs in PACKER_SIGNATURES.items():
            for sig in sigs:
                for file_entry in file_list:
                    if sig.lower() in file_entry.lower():
                        return packer_name
        return None

    def _extract_suspicious_apis(self, dex_bytes: bytes) -> Set[str]:
        """Searches DEX byte contents for suspicious API method and class references."""
        found_apis = set()
        for pattern, desc in SUSPICIOUS_API_PATTERNS.items():
            if pattern.encode("utf-8") in dex_bytes:
                found_apis.add(pattern)
        return found_apis

    def _scan_disguised_assets(self) -> List[Tuple[str, str]]:
        """Scans /assets and /res for disguised DEX, ELF, or ZIP containers disguised as images/media."""
        disguised = []
        if not self.container.zip_file:
            return disguised

        image_extensions = (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".pdf", ".mp3", ".wav")
        
        for name in self.container.file_list:
            if name.lower().endswith(image_extensions):
                try:
                    content = self.container.zip_file.read(name)
                    if len(content) < 8:
                        continue
                    
                    # Check magic headers
                    if content.startswith(b"dex\n"):
                        disguised.append((name, "DEX Bytecode"))
                    elif content.startswith(b"\x7fELF"):
                        disguised.append((name, "ELF Executable/Library"))
                    elif content.startswith(b"PK\x03\x04"):
                        disguised.append((name, "ZIP/APK Archive"))
                except Exception:
                    pass

        return disguised
