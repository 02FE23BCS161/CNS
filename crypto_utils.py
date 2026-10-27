
import argparse
import getpass
import hashlib
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils


BASE_DIR = Path(__file__).resolve().parent
KEYS_DIR = BASE_DIR / "keys"
SIGNATURES_DIR = BASE_DIR / "signatures"

PRIVATE_KEY_PATH = KEYS_DIR / "private_key.pem"
PUBLIC_KEY_PATH = KEYS_DIR / "public_key.pem"


def calculate_sha256(file_path, chunk_size=1024 * 1024):
    """Calculate a file's SHA-256 digest without loading it all into memory."""
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    if not path.is_file():
        raise ValueError(f"Not a regular file: {path}")
    if chunk_size <= 0:
        raise ValueError("Chunk size must be positive.")

    digest = hashlib.sha256()

    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(chunk_size), b""):
            digest.update(chunk)

    return digest.hexdigest()


def calculate_sha256_bytes(file_path, chunk_size=1024 * 1024):
    """Return the raw SHA-256 digest bytes for cryptographic operations."""
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    if not path.is_file():
        raise ValueError(f"Not a regular file: {path}")

    digest = hashlib.sha256()

    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(chunk_size), b""):
            digest.update(chunk)

    return digest.digest()


def generate_keys():
    """Generate an RSA-3072 key pair and protect the private key with a password."""
    KEYS_DIR.mkdir(parents=True, exist_ok=True)

    if PRIVATE_KEY_PATH.exists() or PUBLIC_KEY_PATH.exists():
        print("ERROR: A key file already exists.")
        print(f"Check this folder: {KEYS_DIR}")
        print("Existing keys were not overwritten.")
        return

    password = getpass.getpass("Create a password for the private key: ")
    confirmation = getpass.getpass("Confirm the password: ")

    if len(password) < 8:
        print("ERROR: Use a password containing at least 8 characters.")
        return

    if password != confirmation:
        print("ERROR: Passwords do not match.")
        return

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )

    public_key = private_key.public_key()

    encrypted_private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            password.encode("utf-8")
        ),
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    PRIVATE_KEY_PATH.write_bytes(encrypted_private_pem)
    PUBLIC_KEY_PATH.write_bytes(public_pem)

    print("\nRSA key pair generated successfully.")
    print(f"Private key: {PRIVATE_KEY_PATH}")
    print(f"Public key:  {PUBLIC_KEY_PATH}")
    print("Keep the private key and its password secure.")
    print("Share the public key only with people who need to verify signatures.")


def load_private_key(password=None):
    if not PRIVATE_KEY_PATH.exists():
        raise FileNotFoundError(
            f"Private key not found: {PRIVATE_KEY_PATH}"
        )

    if password is None:
        password = getpass.getpass("Enter private key password: ")

    if isinstance(password, str):
        password = password.encode("utf-8")

    with open(PRIVATE_KEY_PATH, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=password,
        )

    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise ValueError("The loaded private key is not an RSA key.")

    return private_key


def load_public_key(public_key_path):
    """Load an RSA public key from a PEM file."""
    path = Path(public_key_path)

    if not path.is_file():
        raise FileNotFoundError(f"Public key not found: {path}")

    key = serialization.load_pem_public_key(path.read_bytes())

    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("The supplied public key is not an RSA key.")

    return key


def sign_file(file_path, signature_path=None, password=None):
    """Sign a file's SHA-256 digest using RSA-PSS."""
    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    private_key = load_private_key(password)

    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise ValueError("The loaded private key is not an RSA key.")

    digest = calculate_sha256_bytes(path)

    signature = private_key.sign(
        digest,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        utils.Prehashed(hashes.SHA256()),
    )

    if signature_path is None:
        SIGNATURES_DIR.mkdir(parents=True, exist_ok=True)
        signature_path = SIGNATURES_DIR / f"{path.name}.sig"
    else:
        signature_path = Path(signature_path)
        signature_path.parent.mkdir(parents=True, exist_ok=True)

    signature_path.write_bytes(signature)

    print("\nFile signed successfully.")
    print(f"File:      {path}")
    print(f"SHA-256:   {digest.hex()}")
    print(f"Signature: {signature_path}")


def verify_file(file_path, signature_path, public_key_path=PUBLIC_KEY_PATH):
    """Verify a detached RSA-PSS signature against a file's current contents."""
    path = Path(file_path)
    sig_path = Path(signature_path)

    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")
    if not sig_path.is_file():
        raise FileNotFoundError(f"Signature file not found: {sig_path}")

    public_key = load_public_key(public_key_path)
    signature = sig_path.read_bytes()
    digest = calculate_sha256_bytes(path)

    try:
        public_key.verify(
            signature,
            digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            utils.Prehashed(hashes.SHA256()),
        )

        print("\nRESULT: SIGNATURE VERIFIED SUCCESSFULLY")
        print("The file contents match the signed contents.")
        print(f"File:    {path}")
        print(f"SHA-256: {digest.hex()}")
        return True

    except InvalidSignature:
        print("\nRESULT: SIGNATURE VERIFICATION FAILED")
        print("The file contents may have changed, or the signature")
        print("may be invalid or belong to another file.")
        print(f"File:    {path}")
        print(f"SHA-256: {digest.hex()}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="SHA-256 File Integrity and Digital Signature Tool"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("keygen", help="Generate an RSA-3072 key pair")

    hash_parser = subparsers.add_parser("hash", help="Calculate a SHA-256 hash")
    hash_parser.add_argument("file", help="Path to the file")

    sign_parser = subparsers.add_parser("sign", help="Sign a file")
    sign_parser.add_argument("file", help="Path to the file")
    sign_parser.add_argument(
        "--signature",
        help="Optional output path for the detached signature",
    )

    verify_parser = subparsers.add_parser(
        "verify", help="Verify a file's detached signature"
    )
    verify_parser.add_argument("file", help="Path to the file")
    verify_parser.add_argument("signature", help="Path to the signature file")
    verify_parser.add_argument(
        "--public-key",
        default=str(PUBLIC_KEY_PATH),
        help="Path to the trusted RSA public key",
    )

    args = parser.parse_args()

    try:
        if args.command == "keygen":
            generate_keys()

        elif args.command == "hash":
            digest = calculate_sha256(args.file)
            print(f"File:    {args.file}")
            print(f"SHA-256: {digest}")
            print(f"Length:  {len(digest)} hexadecimal characters")

        elif args.command == "sign":
            sign_file(args.file, args.signature)

        elif args.command == "verify":
            valid = verify_file(
                args.file,
                args.signature,
                args.public_key,
            )
            if not valid:
                sys.exit(1)

    except FileNotFoundError as error:
        print(f"ERROR: {error}")
        sys.exit(1)

    except InvalidSignature:
        print("ERROR: Signature verification failed.")
        sys.exit(1)

    except (ValueError, TypeError, PermissionError, OSError) as error:
        print(f"ERROR: {error}")
        sys.exit(1)

    except Exception as error:
        # Includes incorrect private-key passwords and malformed key files.
        print(f"ERROR: Operation could not be completed: {error}")
        sys.exit(1)


if __name__ == "__main__":
    main()
