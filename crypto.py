import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey
)
from cryptography.fernet import Fernet
from config import Config


def generate_key_pair():
    """Generate a new Ed25519 private/public key pair."""

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_key_bytes = private_key.private_bytes_raw()
    public_key_bytes = public_key.public_bytes_raw()

    return private_key_bytes, public_key_bytes


def encrypt_private_key(private_key_bytes):
    """Encrypt the user's private key before storing it."""

    fernet = Fernet(Config.PRIVATE_KEY_ENCRYPTION_KEY)

    encrypted_key = fernet.encrypt(private_key_bytes)

    return encrypted_key


def decrypt_private_key(encrypted_key):
    """Decrypt a user's private key when signing."""

    fernet = Fernet(Config.PRIVATE_KEY_ENCRYPTION_KEY)

    private_key_bytes = fernet.decrypt(encrypted_key)

    return private_key_bytes

def sign_hash(private_key_bytes, file_hash):
    """Create an Ed25519 signature for a SHA-256 hash."""

    private_key = Ed25519PrivateKey.from_private_bytes(
        private_key_bytes
    )

    signature = private_key.sign(
        file_hash.encode("utf-8")
    )

    return base64.b64encode(signature).decode("utf-8")

def verify_signature(public_key_hex, file_hash, signature_base64):
    """Verify an Ed25519 signature against a file hash."""

    try:
        public_key_bytes = bytes.fromhex(public_key_hex)

        public_key = Ed25519PublicKey.from_public_bytes(
            public_key_bytes
        )

        signature = base64.b64decode(signature_base64)

        public_key.verify(
            signature,
            file_hash.encode("utf-8")
        )

        return True

    except Exception:
        return False