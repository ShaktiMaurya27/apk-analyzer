import unittest
import xml.etree.ElementTree as ET
from apk_analyzer.schema import AppMetadata
from apk_analyzer.manifest_auditor import ManifestAuditor, DANGEROUS_PERMISSIONS_DB

class TestPhase2ManifestAuditing(unittest.TestCase):
    def setUp(self):
        self.sample_manifest_xml = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.malicious.spyware"
    android:versionCode="42"
    android:versionName="2.1.0">
    
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="31"/>
    
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED"/>
    <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW"/>
    <uses-permission android:name="android.permission.READ_CONTACTS"/>
    <uses-permission android:name="android.permission.SEND_SMS"/>
    <uses-permission android:name="android.permission.RECEIVE_SMS"/>
    <uses-permission android:name="android.permission.BIND_ACCESSIBILITY_SERVICE"/>
    
    <application android:label="SpywareApp">
    </application>
</manifest>
""".encode("utf-8")

    def test_metadata_extraction(self):
        auditor = ManifestAuditor(self.sample_manifest_xml)
        initial_meta = AppMetadata(file_size_bytes=1024, sha256="abc123hash")
        metadata = auditor.extract_metadata(initial_meta)

        self.assertEqual(metadata.package_name, "com.malicious.spyware")
        self.assertEqual(metadata.app_name, "SpywareApp")
        self.assertEqual(metadata.version_name, "2.1.0")
        self.assertEqual(metadata.version_code, "42")
        self.assertEqual(metadata.min_sdk, 21)
        self.assertEqual(metadata.target_sdk, 31)

    def test_permission_extraction_and_dangerous_flagging(self):
        auditor = ManifestAuditor(self.sample_manifest_xml)
        permissions = auditor.extract_permissions()
        
        self.assertIn("android.permission.INTERNET", permissions)
        self.assertIn("android.permission.SEND_SMS", permissions)
        self.assertIn("android.permission.SYSTEM_ALERT_WINDOW", permissions)

        dangerous_perms, critical_findings = auditor.audit_permissions(permissions)
        
        # Check dangerous list size and content
        dangerous_names = [dp.name for dp in dangerous_perms]
        self.assertIn("android.permission.SEND_SMS", dangerous_names)
        self.assertIn("android.permission.RECEIVE_BOOT_COMPLETED", dangerous_names)
        self.assertIn("android.permission.SYSTEM_ALERT_WINDOW", dangerous_names)

        # Check critical combination findings
        finding_titles = [cf.indicator for cf in critical_findings]
        self.assertIn("Banking Trojan / Overlay Signature Pair", finding_titles)
        self.assertIn("Spyware Exfiltration Pattern", finding_titles)
        self.assertIn("SMS Interception & Fraud Combination", finding_titles)
        self.assertIn("Accessibility Service Privilege Escalation", finding_titles)

if __name__ == "__main__":
    unittest.main()
