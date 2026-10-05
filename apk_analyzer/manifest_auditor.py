import xml.etree.ElementTree as ET
from typing import Dict, List, Set, Any, Tuple, Optional
from apk_analyzer.axml import AXMLParser
from apk_analyzer.schema import AppMetadata, DangerousPermission, CriticalFinding

# High-risk & Dangerous permissions mapping with rationale
DANGEROUS_PERMISSIONS_DB: Dict[str, str] = {
    "android.permission.SEND_SMS": "Allows app to send SMS messages silently, which can be used for premium-rate SMS fraud or covert exfiltration.",
    "android.permission.RECEIVE_SMS": "Allows app to monitor incoming SMS, enabling interception of two-factor authentication (2FA) OTP codes.",
    "android.permission.READ_SMS": "Allows app to read sensitive SMS messages and OTP codes.",
    "android.permission.WRITE_SMS": "Allows app to modify or delete SMS messages.",
    "android.permission.SYSTEM_ALERT_WINDOW": "Allows app to display system-level overlay windows, frequently abused by banking trojans for credential phishing.",
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "Grants complete control over user UI interaction, enabling automated keylogging, overlay attacks, and self-granting permissions.",
    "android.permission.BIND_DEVICE_ADMIN": "Grants device administrator rights, preventing app uninstallation and enabling remote lock/wipe capabilities.",
    "android.permission.RECEIVE_BOOT_COMPLETED": "Allows app to automatically start background services immediately upon device boot, ensuring persistence.",
    "android.permission.READ_PRIVILEGED_PHONE_STATE": "Allows app to access sensitive phone state information including IMEI, IMSI, and SIM serial numbers.",
    "android.permission.READ_PHONE_STATE": "Allows access to phone state, cellular network info, and unique device identifiers.",
    "android.permission.REQUEST_INSTALL_PACKAGES": "Allows app to prompt for installation of additional unknown APKs, enabling secondary payload dropping.",
    "android.permission.INSTALL_PACKAGES": "Directly installs software packages without user intervention.",
    "android.permission.RECORD_AUDIO": "Allows microphone recording without user awareness, enabling covert audio surveillance.",
    "android.permission.CAMERA": "Allows camera capture without user interaction.",
    "android.permission.ACCESS_FINE_LOCATION": "Allows high-precision GPS tracking of user physical location.",
    "android.permission.ACCESS_COARSE_LOCATION": "Allows coarse network-based location tracking.",
    "android.permission.READ_CONTACTS": "Allows harvesting sensitive contact lists for exfiltration.",
    "android.permission.READ_CALL_LOG": "Allows reading user call history and metadata.",
    "android.permission.WRITE_SETTINGS": "Allows modifying system settings, which can be abused to disable security protections.",
    "android.permission.USE_SIP": "Allows making SIP VoIP phone calls silently."
}

class ManifestAuditor:
    """
    Audits AndroidManifest.xml for package metadata, declared permissions,
    dangerous permissions, and threat permission combinations.
    """
    def __init__(self, raw_manifest: bytes):
        self.raw_manifest = raw_manifest
        self.root: ET.Element = None
        if raw_manifest:
            parser = AXMLParser(raw_manifest)
            self.root = parser.parse()

    def extract_metadata(self, initial_metadata: AppMetadata) -> AppMetadata:
        """Extracts package name, version, SDK target/min levels from manifest."""
        if self.root is None:
            return initial_metadata

        meta = initial_metadata.model_copy()
        
        # Package name & Version attributes
        meta.package_name = self._get_attr_value(self.root, ["package"]) or meta.package_name
        meta.version_name = self._get_attr_value(self.root, ["versionName", "android:versionName"]) or "1.0"
        meta.version_code = self._get_attr_value(self.root, ["versionCode", "android:versionCode"]) or "1"

        # SDK levels from <uses-sdk> tag
        uses_sdk = self.root.find("uses-sdk")
        if uses_sdk is not None:
            min_sdk_str = self._get_attr_value(uses_sdk, ["minSdkVersion", "android:minSdkVersion"])
            target_sdk_str = self._get_attr_value(uses_sdk, ["targetSdkVersion", "android:targetSdkVersion"])
            
            if min_sdk_str and min_sdk_str.isdigit():
                meta.min_sdk = int(min_sdk_str)
            if target_sdk_str and target_sdk_str.isdigit():
                meta.target_sdk = int(target_sdk_str)

        # App Label / Name from <application> tag
        application = self.root.find("application")
        if application is not None:
            app_name = self._get_attr_value(application, ["label", "android:label"])
            if app_name:
                meta.app_name = app_name
            else:
                meta.app_name = meta.package_name.split(".")[-1].capitalize()
        else:
            meta.app_name = meta.package_name.split(".")[-1].capitalize()

        return meta

    def extract_permissions(self) -> Set[str]:
        """Extracts all declared uses-permission names from the manifest."""
        permissions = set()
        if self.root is None:
            return permissions

        for tag in self.root.findall("uses-permission"):
            name = self._get_attr_value(tag, ["name", "android:name"])
            if name:
                permissions.add(name)

        for tag in self.root.findall("uses-permission-sdk-23"):
            name = self._get_attr_value(tag, ["name", "android:name"])
            if name:
                permissions.add(name)

        return permissions

    def audit_permissions(self, permissions: Set[str]) -> Tuple[List[DangerousPermission], List[CriticalFinding]]:
        """
        Identifies dangerous permissions and detects high-risk permission combinations.
        """
        dangerous_list: List[DangerousPermission] = []
        critical_findings: List[CriticalFinding] = []

        # 1. Identify individual dangerous permissions
        for perm in sorted(permissions):
            if perm in DANGEROUS_PERMISSIONS_DB:
                dangerous_list.append(DangerousPermission(
                    name=perm,
                    reason=DANGEROUS_PERMISSIONS_DB[perm]
                ))

        # 2. Evaluate dangerous permission combinations
        has_internet = "android.permission.INTERNET" in permissions
        has_boot = "android.permission.RECEIVE_BOOT_COMPLETED" in permissions
        has_overlay = "android.permission.SYSTEM_ALERT_WINDOW" in permissions
        has_accessibility = "android.permission.BIND_ACCESSIBILITY_SERVICE" in permissions
        has_contacts = "android.permission.READ_CONTACTS" in permissions
        has_send_sms = "android.permission.SEND_SMS" in permissions
        has_receive_sms = "android.permission.RECEIVE_SMS" in permissions
        has_install = "android.permission.REQUEST_INSTALL_PACKAGES" in permissions or "android.permission.INSTALL_PACKAGES" in permissions
        has_location = "android.permission.ACCESS_FINE_LOCATION" in permissions or "android.permission.ACCESS_COARSE_LOCATION" in permissions
        has_mic = "android.permission.RECORD_AUDIO" in permissions

        # Combo A: Overlay Banking Trojan Signature
        if has_boot and has_overlay:
            critical_findings.append(CriticalFinding(
                category="Permissions",
                indicator="Banking Trojan / Overlay Signature Pair",
                description="Application combines RECEIVE_BOOT_COMPLETED and SYSTEM_ALERT_WINDOW permissions, a high-confidence signature of overlay banking trojans.",
                severity="High"
            ))

        # Combo B: Spyware Exfiltration Pattern
        if has_internet and (has_contacts or has_location or has_mic) and has_send_sms:
            critical_findings.append(CriticalFinding(
                category="Permissions",
                indicator="Spyware Exfiltration Pattern",
                description="Application requests sensitive data access (Contacts/Location/Mic) combined with INTERNET and SEND_SMS permissions, indicating potential spyware data harvesting.",
                severity="Critical"
            ))

        # Combo C: SMS Interception / Fraud Pattern
        if has_receive_sms and has_send_sms and has_internet:
            critical_findings.append(CriticalFinding(
                category="Permissions",
                indicator="SMS Interception & Fraud Combination",
                description="Application possesses RECEIVE_SMS, SEND_SMS, and INTERNET permissions, allowing covert 2FA OTP interception and command-driven SMS relaying.",
                severity="Critical"
            ))

        # Combo D: Accessibility Service Abuse
        if has_accessibility:
            critical_findings.append(CriticalFinding(
                category="Permissions",
                indicator="Accessibility Service Privilege Escalation",
                description="Application requests BIND_ACCESSIBILITY_SERVICE which enables keylogging, overlay interaction, and automatic permission granting.",
                severity="Critical"
            ))

        # Combo E: Silent Payload Dropper
        if has_install and has_internet and has_boot:
            critical_findings.append(CriticalFinding(
                category="Permissions",
                indicator="Silent Payload Dropper Pattern",
                description="Application requests REQUEST_INSTALL_PACKAGES with boot persistence and INTERNET, characteristic of malicious payload droppers.",
                severity="High"
            ))

        return dangerous_list, critical_findings

    def _get_attr_value(self, element: ET.Element, candidate_names: List[str]) -> Optional[str]:
        for attr_key, attr_val in element.attrib.items():
            clean_key = attr_key.split("}")[-1] if "}" in attr_key else attr_key
            if clean_key in candidate_names or attr_key in candidate_names:
                return attr_val
        return None
