import os
import zipfile
import tempfile
import unittest
from apk_analyzer.ingestion import APKContainer
from apk_analyzer.network_cert_analyzer import NetworkCertAnalyzer

class TestPhase5NetworkCertAnalysis(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.mock_apk_path = os.path.join(self.temp_dir.name, "network_sample.apk")
        
        # Build mock APK containing URLs, raw IPs, C2 endpoints, and a Debug Cert
        with zipfile.ZipFile(self.mock_apk_path, 'w') as zf:
            mock_dex_bytes = (
                b"dex\n035"
                b"http://insecure-api.example.com/login\x00"
                b"https://api.telegram.org/bot123456789:ABCDefgh/sendMessage\x00"
                b"185.220.101.5\x00"
            )
            zf.writestr("classes.dex", mock_dex_bytes)
            # Add Debug Cert
            zf.writestr("META-INF/CERT.RSA", b"SignatureBlockContent...CN=Android Debug,O=Android...")

        self.container = APKContainer(self.mock_apk_path)

    def tearDown(self):
        self.container.close()
        self.temp_dir.cleanup()

    def test_network_endpoint_extraction_and_c2(self):
        analyzer = NetworkCertAnalyzer(self.container)
        endpoints, findings = analyzer.analyze()

        # 1. Endpoint Extraction Verification
        self.assertIn("http://insecure-api.example.com/login", endpoints)
        self.assertIn("https://api.telegram.org/bot123456789:ABCDefgh/sendMessage", endpoints)
        self.assertIn("185.220.101.5", endpoints)

        # 2. Critical Findings Verification
        finding_indicators = [f.indicator for f in findings]
        self.assertIn("Insecure Plain HTTP Endpoints Detected", finding_indicators)
        self.assertIn("Command-and-Control (C2) / Exfiltration Endpoint Detected", finding_indicators)
        self.assertIn("Debug Certificate Signed Package", finding_indicators)

    def test_unsigned_apk_detection(self):
        unsigned_apk_path = os.path.join(self.temp_dir.name, "unsigned.apk")
        with zipfile.ZipFile(unsigned_apk_path, 'w') as zf:
            zf.writestr("classes.dex", b"dex\n035UnsignedContent")

        container = APKContainer(unsigned_apk_path)
        analyzer = NetworkCertAnalyzer(container)
        endpoints, findings = analyzer.analyze()
        container.close()

        finding_indicators = [f.indicator for f in findings]
        self.assertIn("Missing APK Signature (Unsigned Package)", finding_indicators)

if __name__ == "__main__":
    unittest.main()
