import unittest
import xml.etree.ElementTree as ET
from apk_analyzer.component_inspector import ComponentInspector, ComponentInspectionResult

class TestPhase3ComponentInspection(unittest.TestCase):
    def test_component_enumeration_and_threats(self):
        manifest_xml = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test.app">
    <application>
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        
        <service android:name=".BackgroundStealthService" android:exported="true"/>
        
        <receiver android:name=".BootReceiver">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED"/>
            </intent-filter>
        </receiver>

        <provider android:name=".UserDataProvider" android:exported="true" android:authorities="com.test.provider"/>
    </application>
</manifest>
"""
        root = ET.fromstring(manifest_xml)
        inspector = ComponentInspector(root)
        result, findings = inspector.inspect()

        self.assertEqual(result.total_activities, 1)
        self.assertEqual(result.total_services, 1)
        self.assertEqual(result.total_receivers, 1)
        self.assertEqual(result.total_providers, 1)
        self.assertEqual(result.exported_count, 4)

        finding_indicators = [f.indicator for f in findings]
        self.assertTrue(any("Exposed Unprotected Components" in ind for ind in finding_indicators))
        self.assertIn("Exposed Boot Broadcast Receiver", finding_indicators)
        self.assertIn("Unprotected Exported Content Provider", finding_indicators)

    def test_headless_service_detection(self):
        headless_manifest_xml = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.headless.trojan">
    <application>
        <service android:name=".HiddenDaemonService" android:exported="true"/>
    </application>
</manifest>
"""
        root = ET.fromstring(headless_manifest_xml)
        inspector = ComponentInspector(root)
        result, findings = inspector.inspect()

        self.assertEqual(result.total_activities, 0)
        self.assertEqual(result.total_services, 1)
        
        finding_indicators = [f.indicator for f in findings]
        self.assertIn("Headless Application Architecture", finding_indicators)

if __name__ == "__main__":
    unittest.main()
