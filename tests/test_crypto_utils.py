
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

import crypto_utils


PASSWORD = "TestPassword123!"


class CryptoUtilsTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Create temporary test storage. Existing project keys are untouched.
        cls.temp_directory = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp_directory.name)
        cls.keys_dir = cls.root / "keys"
        cls.keys_dir.mkdir()

        cls.private_key_path = cls.keys_dir / "private_key.pem"
        cls.public_key_path = cls.keys_dir / "public_key.pem"
        cls.wrong_public_key_path = cls.keys_dir / "wrong_public_key.pem"
        cls.signatures_dir = cls.root / "signatures"
        cls.signatures_dir.mkdir()

        # Generate test keys once to keep the suite reasonably fast.
        cls.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=3072,
        )
        cls.public_key = cls.private_key.public_key()

        cls.private_key_path.write_bytes(
            cls.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(
                    PASSWORD.encode("utf-8")
                ),
            )
        )

        cls.public_key_path.write_bytes(
            cls.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

        wrong_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=3072,
        )
        cls.wrong_public_key_path.write_bytes(
            wrong_private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

        # Redirect the module's key and signature paths to temporary storage.
        crypto_utils.PRIVATE_KEY_PATH = cls.private_key_path
        crypto_utils.PUBLIC_KEY_PATH = cls.public_key_path
        crypto_utils.SIGNATURES_DIR = cls.signatures_dir

    @classmethod
    def tearDownClass(cls):
        cls.temp_directory.cleanup()

    def create_file(self, name, content):
        path = self.root / name
        path.write_bytes(content)
        return path

    def sign(self, file_path, signature_path):
        with patch("crypto_utils.getpass.getpass", return_value=PASSWORD):
            crypto_utils.sign_file(file_path, signature_path)

    def test_01_unchanged_file_verifies(self):
        file_path = self.create_file("unchanged.txt", b"Original content")
        signature_path = self.signatures_dir / "unchanged.sig"

        self.sign(file_path, signature_path)

        self.assertTrue(
            crypto_utils.verify_file(
                file_path, signature_path, self.public_key_path
            )
        )

    def test_02_modified_file_fails(self):
        file_path = self.create_file("modified.txt", b"Original content")
        signature_path = self.signatures_dir / "modified.sig"

        self.sign(file_path, signature_path)
        file_path.write_bytes(b"Changed content")

        self.assertFalse(
            crypto_utils.verify_file(
                file_path, signature_path, self.public_key_path
            )
        )

    def test_03_wrong_public_key_fails(self):
        file_path = self.create_file("wrong_key.txt", b"Test content")
        signature_path = self.signatures_dir / "wrong_key.sig"

        self.sign(file_path, signature_path)

        self.assertFalse(
            crypto_utils.verify_file(
                file_path, signature_path, self.wrong_public_key_path
            )
        )

    def test_04_signature_from_another_file_fails(self):
        file_a = self.create_file("file_a.txt", b"File A")
        file_b = self.create_file("file_b.txt", b"File B")
        signature_path = self.signatures_dir / "file_a.sig"

        self.sign(file_a, signature_path)

        self.assertFalse(
            crypto_utils.verify_file(
                file_b, signature_path, self.public_key_path
            )
        )

    def test_05_empty_file_verifies(self):
        file_path = self.create_file("empty.txt", b"")
        signature_path = self.signatures_dir / "empty.sig"

        self.sign(file_path, signature_path)

        self.assertEqual(
            crypto_utils.calculate_sha256(file_path),
            hashlib.sha256(b"").hexdigest(),
        )
        self.assertTrue(
            crypto_utils.verify_file(
                file_path, signature_path, self.public_key_path
            )
        )

    def test_06_binary_file_verifies(self):
        binary_content = bytes(range(256)) + b"\x00\xff\x10"
        file_path = self.create_file("binary.bin", binary_content)
        signature_path = self.signatures_dir / "binary.sig"

        self.sign(file_path, signature_path)

        self.assertTrue(
            crypto_utils.verify_file(
                file_path, signature_path, self.public_key_path
            )
        )

    def test_07_missing_file_is_rejected(self):
        missing_path = self.root / "does_not_exist.txt"
        signature_path = self.signatures_dir / "missing.sig"

        with self.assertRaises(FileNotFoundError):
            crypto_utils.verify_file(
                missing_path, signature_path, self.public_key_path
            )

    def test_08_malformed_signature_is_rejected(self):
        file_path = self.create_file("malformed.txt", b"Test content")
        signature_path = self.signatures_dir / "malformed.sig"
        signature_path.write_bytes(b"not a valid RSA signature")

        self.assertFalse(
            crypto_utils.verify_file(
                file_path, signature_path, self.public_key_path
            )
        )

    def test_09_missing_public_key_is_rejected(self):
        file_path = self.create_file("no_key.txt", b"Test content")
        signature_path = self.signatures_dir / "no_key.sig"

        self.sign(file_path, signature_path)

        with self.assertRaises(FileNotFoundError):
            crypto_utils.verify_file(
                file_path,
                signature_path,
                self.root / "missing_public_key.pem",
            )

    def test_10_corrupted_signature_is_rejected(self):
        file_path = self.create_file("corrupted.txt", b"Test content")
        signature_path = self.signatures_dir / "corrupted.sig"

        self.sign(file_path, signature_path)

        corrupted = bytearray(signature_path.read_bytes())
        corrupted[0] ^= 1
        signature_path.write_bytes(corrupted)

        self.assertFalse(
            crypto_utils.verify_file(
                file_path, signature_path, self.public_key_path
            )
        )

    def test_11_signatures_cannot_be_swapped_between_files(self):
        file_a = self.create_file("multiple_a.txt", b"Content A")
        file_b = self.create_file("multiple_b.txt", b"Content B")
        signature_a = self.signatures_dir / "multiple_a.sig"
        signature_b = self.signatures_dir / "multiple_b.sig"

        self.sign(file_a, signature_a)
        self.sign(file_b, signature_b)

        self.assertTrue(
            crypto_utils.verify_file(
                file_a, signature_a, self.public_key_path
            )
        )
        self.assertTrue(
            crypto_utils.verify_file(
                file_b, signature_b, self.public_key_path
            )
        )
        self.assertFalse(
            crypto_utils.verify_file(
                file_a, signature_b, self.public_key_path
            )
        )
        self.assertFalse(
            crypto_utils.verify_file(
                file_b, signature_a, self.public_key_path
            )
        )

    def test_12_restoring_exact_original_bytes_restores_validity(self):
        original = b"Original bytes\x00\x01\x02"
        file_path = self.create_file("restored.bin", original)
        signature_path = self.signatures_dir / "restored.sig"

        self.sign(file_path, signature_path)

        file_path.write_bytes(b"Modified bytes")
        self.assertFalse(
            crypto_utils.verify_file(
                file_path, signature_path, self.public_key_path
            )
        )

        file_path.write_bytes(original)
        self.assertTrue(
            crypto_utils.verify_file(
                file_path, signature_path, self.public_key_path
            )
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
