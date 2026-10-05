import os
import zipfile
import tempfile
import unittest
from apk_analyzer.ingestion import APKContainer, APKIngestionError

class TestPhase1Ingestion(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.mock_apk_path = os.path.join(self.temp_dir.name, "sample.apk")
        
        # Create a mock valid APK file
        with zipfile.ZipFile(self.mock_apk_path, 'w') as zf:
            zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00BinaryXmlContentMock")
            zf.writestr("classes.dex", b"dex\n035\x00DEXHeaderMock")
            zf.writestr("META-INF/CERT.RSA", b"CertDataMock")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_apk_container_ingestion(self):
        container = APKContainer(self.mock_apk_path)
        
        # Validate metadata calculation
        metadata = container.get_initial_metadata()
        self.assertGreater(metadata.file_size_bytes, 0)
        self.assertEqual(len(metadata.sha256), 64)  # SHA-256 hex string length
        
        # Validate manifest extraction
        raw_manifest = container.get_raw_manifest()
        self.assertIsNotNone(raw_manifest)
        self.assertTrue(b"BinaryXmlContentMock" in raw_manifest)

        # Validate dex extraction
        dex_files = container.get_dex_files()
        self.assertEqual(len(dex_files), 1)
        self.assertEqual(dex_files[0][0], "classes.dex")

        # Validate signature files extraction
        sig_files = container.get_signature_files()
        self.assertEqual(len(sig_files), 1)
        self.assertEqual(sig_files[0][0], "META-INF/CERT.RSA")

        container.close()

    def test_invalid_file_handling(self):
        non_existent_path = os.path.join(self.temp_dir.name, "nonexistent.apk")
        with self.assertRaises(APKIngestionError):
            APKContainer(non_existent_path)

        invalid_zip_path = os.path.join(self.temp_dir.name, "corrupt.apk")
        with open(invalid_zip_path, "wb") as f:
            f.write(b"Not a zip file content")
            
        with self.assertRaises(APKIngestionError):
            APKContainer(invalid_zip_path)

if __name__ == "__main__":
    unittest.main()
