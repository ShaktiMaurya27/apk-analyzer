import os
import zipfile
import hashlib
from typing import Dict, List, Optional, Tuple, Any
from apk_analyzer.schema import AppMetadata

class APKIngestionError(Exception):
    """Raised when an APK file fails ingestion or validation."""
    pass

class APKContainer:
    """
    Represents an ingested APK file and provides access to its raw archive contents,
    hashes, DEX files, and binary AndroidManifest.xml.
    """
    def __init__(self, apk_path: str):
        self.apk_path = os.path.abspath(apk_path)
        self.file_size = 0
        self.sha256 = ""
        self.zip_file: Optional[zipfile.ZipFile] = None
        self.file_list: List[str] = []
        self._validate_and_hash()

    def _validate_and_hash(self) -> None:
        if not os.path.isfile(self.apk_path):
            raise APKIngestionError(f"File not found: {self.apk_path}")
        
        self.file_size = os.path.getsize(self.apk_path)
        if self.file_size == 0:
            raise APKIngestionError(f"APK file is empty: {self.apk_path}")
        
        sha256_hash = hashlib.sha256()
        try:
            with open(self.apk_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    sha256_hash.update(chunk)
            self.sha256 = sha256_hash.hexdigest()
        except Exception as e:
            raise APKIngestionError(f"Failed to calculate SHA-256 hash: {e}")

        try:
            self.zip_file = zipfile.ZipFile(self.apk_path, 'r')
            self.file_list = self.zip_file.namelist()
        except zipfile.BadZipFile:
            raise APKIngestionError("Invalid APK format: File is not a valid ZIP archive.")

    def get_raw_manifest(self) -> Optional[bytes]:
        """Extracts the raw AndroidManifest.xml bytes from the APK archive."""
        if "AndroidManifest.xml" in self.file_list and self.zip_file:
            return self.zip_file.read("AndroidManifest.xml")
        return None

    def get_dex_files(self) -> List[Tuple[str, bytes]]:
        """Returns all classes.dex, classes2.dex, ... files found in the APK archive."""
        dex_files = []
        if not self.zip_file:
            return dex_files
            
        for name in self.file_list:
            if name.endswith(".dex") and not name.startswith("META-INF/"):
                try:
                    dex_files.append((name, self.zip_file.read(name)))
                except Exception:
                    pass
        return dex_files

    def get_signature_files(self) -> List[Tuple[str, bytes]]:
        """Extracts signature files from META-INF directory."""
        sig_files = []
        if not self.zip_file:
            return sig_files
            
        for name in self.file_list:
            if name.startswith("META-INF/") and (name.endswith(".RSA") or name.endswith(".DSA") or name.endswith(".EC") or name.endswith(".SF")):
                try:
                    sig_files.append((name, self.zip_file.read(name)))
                except Exception:
                    pass
        return sig_files

    def get_initial_metadata(self) -> AppMetadata:
        """Returns AppMetadata initialized with file size and hash."""
        return AppMetadata(
            file_size_bytes=self.file_size,
            sha256=self.sha256
        )

    def close(self) -> None:
        if self.zip_file:
            self.zip_file.close()
