import os
import zipfile
import tempfile
import unittest
from apk_analyzer.ingestion import APKContainer
from apk_analyzer.bytecode_analyzer import BytecodeAnalyzer

class TestPhase4BytecodeAnalysis(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.mock_apk_path = os.path.join(self.temp_dir.name, "malware_sample.apk")
        
        # Build mock APK containing DEX with suspicious APIs, a Packer signature, and a Disguised Asset
        with zipfile.ZipFile(self.mock_apk_path, 'w') as zf:
            mock_dex_bytes = (
                b"dex\n035\x00Header"
                b"dalvik.system.DexClassLoader\x00"
                b"java.lang.Runtime.exec\x00"
                b"java.lang.reflect.Method.invoke\x00"
            )
            zf.writestr("classes.dex", mock_dex_bytes)
            # Add Packer lib signature
            zf.writestr("lib/armeabi-v7a/libjiagu.so", b"Qihoo360JiaguPackerMock")
            # Add Disguised asset: png containing DEX binary magic bytes
            zf.writestr("assets/fake_image.png", b"dex\n035HiddenDexPayloadContent")

        self.container = APKContainer(self.mock_apk_path)

    def tearDown(self):
        self.container.close()
        self.temp_dir.cleanup()

    def test_bytecode_analyzer_detection(self):
        analyzer = BytecodeAnalyzer(self.container)
        obfuscation_info, sorted_apis, findings = analyzer.analyze()

        # 1. Packer Detection Verification
        self.assertTrue(obfuscation_info.is_packed)
        self.assertEqual(obfuscation_info.packer_detected, "Qihoo 360 Jiagu")

        # 2. High-Risk API Extraction Verification
        self.assertIn("dalvik.system.DexClassLoader", sorted_apis)
        self.assertIn("java.lang.Runtime.exec", sorted_apis)
        self.assertIn("java.lang.reflect.Method.invoke", sorted_apis)

        # 3. Critical Findings Verification
        finding_indicators = [f.indicator for f in findings]
        self.assertTrue(any("Packer / Encryption Detected" in ind for ind in finding_indicators))
        self.assertIn("Dynamic Payload Class Loading (DexClassLoader)", finding_indicators)
        self.assertIn("Native Shell Execution Invocation", finding_indicators)
        self.assertIn("Disguised Asset Container", finding_indicators)

    def test_entropy_calculation(self):
        analyzer = BytecodeAnalyzer(self.container)
        
        # Low entropy test (repetitive bytes)
        low_entropy = analyzer._calculate_entropy(b"AAAAA" * 100)
        self.assertLess(low_entropy, 1.0)
        
        # High entropy test (pseudo-random bytes)
        import os
        random_bytes = os.urandom(1024)
        high_entropy = analyzer._calculate_entropy(random_bytes)
        self.assertGreaterEqual(high_entropy, 7.0)

if __name__ == "__main__":
    unittest.main()
