import unittest
from apk_analyzer.schema import CriticalFinding, DangerousPermission, ObfuscationAndPacking
from apk_analyzer.scoring_engine import ScoringEngine

class TestPhase6ScoringEngine(unittest.TestCase):
    def setUp(self):
        self.engine = ScoringEngine()

    def test_malicious_classification(self):
        findings = [
            CriticalFinding(
                category="Network",
                indicator="Command-and-Control (C2) / Exfiltration Endpoint Detected",
                description="Hardcoded endpoint contains C2 service",
                severity="Critical"
            ),
            CriticalFinding(
                category="Permissions",
                indicator="Accessibility Service Privilege Escalation",
                description="Accessibility service abuse",
                severity="Critical"
            )
        ]
        dangerous_perms = [
            DangerousPermission(name="android.permission.SEND_SMS", reason="SMS fraud"),
            DangerousPermission(name="android.permission.SYSTEM_ALERT_WINDOW", reason="Overlay")
        ]
        obfuscation = ObfuscationAndPacking(is_packed=True, entropy_level="Extremely High")

        verdict, recs = self.engine.compute_verdict(findings, dangerous_perms, obfuscation, [])

        self.assertGreaterEqual(verdict.risk_score, 70)
        self.assertEqual(verdict.classification, "Malicious")
        self.assertEqual(verdict.confidence_level, "High")
        self.assertIn("DO NOT INSTALL OR EXECUTE", recs[0])

    def test_suspicious_classification(self):
        findings = [
            CriticalFinding(
                category="Certificate",
                indicator="Debug Certificate Signed Package",
                description="Signed with debug key",
                severity="High"
            ),
            CriticalFinding(
                category="Network",
                indicator="Insecure Plain HTTP Endpoints Detected",
                description="Unencrypted HTTP URLs found",
                severity="Medium"
            )
        ]
        dangerous_perms = [
            DangerousPermission(name="android.permission.READ_CONTACTS", reason="Harvesting contacts"),
            DangerousPermission(name="android.permission.ACCESS_FINE_LOCATION", reason="Location tracking"),
            DangerousPermission(name="android.permission.RECORD_AUDIO", reason="Mic recording")
        ]
        obfuscation = ObfuscationAndPacking(is_packed=False, entropy_level="Normal")

        verdict, recs = self.engine.compute_verdict(findings, dangerous_perms, obfuscation, [])

        self.assertTrue(40 <= verdict.risk_score < 70)
        self.assertEqual(verdict.classification, "Suspicious")
        self.assertEqual(verdict.confidence_level, "Medium")

    def test_safe_classification(self):
        findings = []
        dangerous_perms = []
        obfuscation = ObfuscationAndPacking(is_packed=False, entropy_level="Normal")

        verdict, recs = self.engine.compute_verdict(findings, dangerous_perms, obfuscation, [])

        self.assertLess(verdict.risk_score, 40)
        self.assertEqual(verdict.classification, "Safe")
        self.assertEqual(verdict.confidence_level, "Low")

if __name__ == "__main__":
    unittest.main()
