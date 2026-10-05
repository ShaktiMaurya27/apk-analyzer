import os
import json
import zipfile
import tempfile
import unittest
from apk_analyzer.pipeline import APKAnalysisPipeline
from apk_analyzer.schema import SecurityReport

class TestE2EPipeline(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        
        # 1. Create a Malicious Mock APK
        self.malicious_apk = os.path.join(self.temp_dir.name, "malicious_trojan.apk")
        manifest_malicious = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.trojan.banker">
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED"/>
    <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW"/>
    <uses-permission android:name="android.permission.BIND_ACCESSIBILITY_SERVICE"/>
    <uses-permission android:name="android.permission.SEND_SMS"/>
    <application android:label="BankerTrojan">
        <service android:name=".StealthDaemon" android:exported="true"/>
        <receiver android:name=".BootStart">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED"/>
            </intent-filter>
        </receiver>
    </application>
</manifest>"""

        with zipfile.ZipFile(self.malicious_apk, 'w') as zf:
            zf.writestr("AndroidManifest.xml", manifest_malicious.encode("utf-8"))
            zf.writestr("classes.dex", b"dex\n035dalvik.system.DexClassLoader\x00java.lang.Runtime.exec\x00https://api.telegram.org/bot12345/sendMessage\x00")
            zf.writestr("lib/armeabi-v7a/libjiagu.so", b"QihooPackerData")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_e2e_malicious_apk_analysis(self):
        pipeline = APKAnalysisPipeline(self.malicious_apk)
        
        # Test direct report object return
        report = pipeline.run()
        self.assertIsInstance(report, SecurityReport)
        self.assertEqual(report.app_metadata.package_name, "com.trojan.banker")
        self.assertEqual(report.verdict.classification, "Malicious")
        self.assertGreaterEqual(report.verdict.risk_score, 70)
        self.assertEqual(report.verdict.confidence_level, "High")

        # Test JSON string generation & strict schema parsing
        json_output = pipeline.run_json(indent=2)
        parsed_dict = json.loads(json_output)
        
        # Verify JSON keys match requested Output Schema exactly
        self.assertIn("app_metadata", parsed_dict)
        self.assertIn("verdict", parsed_dict)
        self.assertIn("risk_breakdown", parsed_dict)
        self.assertIn("recommendations", parsed_dict)
        
        self.assertIn("critical_findings", parsed_dict["risk_breakdown"])
        self.assertIn("dangerous_permissions", parsed_dict["risk_breakdown"])
        self.assertIn("suspicious_apis_and_calls", parsed_dict["risk_breakdown"])
        self.assertIn("extracted_endpoints", parsed_dict["risk_breakdown"])
        self.assertIn("obfuscation_and_packing", parsed_dict["risk_breakdown"])

if __name__ == "__main__":
    unittest.main()
