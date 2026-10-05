import re
import struct
from typing import Dict, List, Set, Tuple, Optional
from apk_analyzer.schema import CriticalFinding
from apk_analyzer.ingestion import APKContainer

# Regex patterns for URL, IPv4, and Domain extraction
URL_REGEX = re.compile(r'https?://[a-zA-Z0-9\.\-_]+(?::\d+)?(?:/[^\s"\'<>\(\)\x00-\x1f\x7f-\xff]*)?', re.IGNORECASE)
IPV4_REGEX = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')

# Known C2, Dynamic DNS, and Exfiltration drop services
C2_DYNAMIC_SERVICES = [
    "duckdns.org", "ngrok.io", "ngrok-free.app", "no-ip.com", "serveo.net",
    "portmap.host", "pastebin.com", "hastebin.com", "ghostbin.com", "paste.ee",
    "api.telegram.org/bot"
]

# Private / Local IP networks to ignore
PRIVATE_IP_PREFIXES = ("127.", "0.0.0.0", "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.30.", "172.31.")

class NetworkCertAnalyzer:
    """
    Extracts hardcoded network endpoints (URLs, IPs, C2 signatures) and evaluates
    APK signature schemes and certificate metadata.
    """
    def __init__(self, apk_container: APKContainer):
        self.container = apk_container

    def analyze(self) -> Tuple[List[str], List[CriticalFinding]]:
        """
        Extracts URLs/IPs and validates APK signing certificates.
        Returns extracted endpoint strings and critical security findings.
        """
        findings: List[CriticalFinding] = []
        extracted_endpoints: Set[str] = set()

        # 1. Network Endpoint & C2 Extraction
        endpoints, net_findings = self._extract_network_endpoints()
        extracted_endpoints.update(endpoints)
        findings.extend(net_findings)

        # 2. Certificate & Signature Validation
        cert_findings = self._validate_certificate()
        findings.extend(cert_findings)

        sorted_endpoints = sorted(list(extracted_endpoints))
        return sorted_endpoints, findings

    def _extract_network_endpoints(self) -> Tuple[Set[str], List[CriticalFinding]]:
        endpoints = set()
        findings = []
        insecure_http_count = 0
        c2_matches = set()

        # Gather strings from DEX files and text assets
        content_sources: List[bytes] = []
        
        for fname, dex_bytes in self.container.get_dex_files():
            content_sources.append(dex_bytes)

        if self.container.zip_file:
            for fname in self.container.file_list:
                if fname.endswith((".xml", ".json", ".txt", ".properties", ".html", ".js")):
                    try:
                        content_sources.append(self.container.zip_file.read(fname))
                    except Exception:
                        pass

        for content in content_sources:
            try:
                text = content.decode("utf-8", errors="ignore")
                
                # Extract URLs
                for url in URL_REGEX.findall(text):
                    # Filter out schema definitions and android namespace URLs
                    if "schemas.android.com" in url or "w3.org" in url:
                        continue
                    
                    endpoints.add(url)

                    if url.startswith("http://"):
                        insecure_http_count += 1

                    # Check for C2 / Exfiltration drop sites
                    for c2_service in C2_DYNAMIC_SERVICES:
                        if c2_service in url.lower():
                            c2_matches.add(url)

                # Extract IPv4 addresses
                for ip in IPV4_REGEX.findall(text):
                    if not ip.startswith(PRIVATE_IP_PREFIXES):
                        endpoints.add(ip)
                        # Flag raw IP endpoints as potential direct C2 servers
                        if not any(ip in url for url in endpoints if "http" in url):
                            c2_matches.add(f"http://{ip}")
            except Exception:
                pass

        # Report Insecure HTTP Communications
        if insecure_http_count > 0:
            findings.append(CriticalFinding(
                category="Network",
                indicator="Insecure Plain HTTP Endpoints Detected",
                description=f"Application contains {insecure_http_count} hardcoded unencrypted HTTP URL(s), exposing network traffic to Man-in-the-Middle (MitM) interception.",
                severity="Medium" if insecure_http_count < 3 else "High"
            ))

        # Report Command and Control (C2) / Exfiltration Endpoints
        if c2_matches:
            c2_sample = list(c2_matches)[0]
            findings.append(CriticalFinding(
                category="Network",
                indicator="Command-and-Control (C2) / Exfiltration Endpoint Detected",
                description=f"Hardcoded network endpoints contain known C2, dynamic DNS, or covert data exfiltration services: {c2_sample}",
                severity="Critical"
            ))

        return endpoints, findings

    def _validate_certificate(self) -> List[CriticalFinding]:
        findings = []
        sig_files = self.container.get_signature_files()

        if not sig_files:
            findings.append(CriticalFinding(
                category="Certificate",
                indicator="Missing APK Signature (Unsigned Package)",
                description="Application package lacks META-INF certificate signature files, indicating an unsigned or corrupted APK.",
                severity="Critical"
            ))
            return findings

        # Detect Signing Scheme Versions (v1, v2/v3)
        v1_present = any(name.endswith((".RSA", ".DSA", ".EC")) for name, _ in sig_files)
        v2_v3_present = self._check_v2_v3_signature()

        if not v1_present and not v2_v3_present:
            findings.append(CriticalFinding(
                category="Certificate",
                indicator="Invalid Certificate Signature Scheme",
                description="Failed to verify valid v1 JAR signature or v2/v3 APK signature scheme block.",
                severity="High"
            ))

        # Inspect Certificate Subject / Metadata for Debug Keys
        is_debug_cert = False
        debug_indicators = [b"Android Debug", b"CN=Android Debug", b"O=Android", b"testkey", b"androiddebugkey"]

        for name, cert_bytes in sig_files:
            for indicator in debug_indicators:
                if indicator.lower() in cert_bytes.lower():
                    is_debug_cert = True
                    break

        if is_debug_cert:
            findings.append(CriticalFinding(
                category="Certificate",
                indicator="Debug Certificate Signed Package",
                description="APK is signed with a generic Android Debug or Test Key certificate, rendering it vulnerable to key compromise and unauthorized updates.",
                severity="High"
            ))

        return findings

    def _check_v2_v3_signature(self) -> bool:
        """Scans the zip file bytes for APK Signature Scheme v2/v3 Block Magic ('APK Sig Block 42')."""
        try:
            with open(self.container.apk_path, "rb") as f:
                content = f.read()
                if b"APK Sig Block 42" in content:
                    return True
        except Exception:
            pass
        return False
