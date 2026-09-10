"""Hashing, digital signatures and payload encryption.

Signature scheme is Ed25519. It is chosen over RSA-2048 because the signature
is 64 bytes rather than 256, and signature bytes compete directly with the
cover object's carrying capacity: at 1 LSB in a small PNG the difference is
material. Ed25519 also has no padding-mode footguns.
"""

from dataclasses import dataclass
import hashlib
import os

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SIGNATURE_LEN = 64
PBKDF2_ITERATIONS = 200_000
AES_NONCE_LEN = 12
AES_SALT_LEN = 16


class SignatureError(Exception):
    """Raised when a signature fails verification."""


class DecryptionError(Exception):
    """Raised when payload decryption fails (wrong passphrase or tampering)."""


# --------------------------------------------------------------------------
# Hashing
# --------------------------------------------------------------------------

def sha256(data: bytes) -> bytes:
    """SHA-256 digest as raw bytes."""
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    """SHA-256 digest as a lowercase hex string."""
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------
# Key management
# --------------------------------------------------------------------------

@dataclass
class KeyPair:
    """An Ed25519 signing keypair held in memory."""

    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey

    @property
    def fingerprint(self) -> str:
        """Short human-readable identifier for the public key.

        Displayed in the GUI so that a wrong-key demonstration is visibly
        caused rather than merely asserted.
        """
        raw = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        digest = hashlib.sha256(raw).hexdigest()[:16]
        return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


def generate_keypair() -> KeyPair:
    """Create a fresh Ed25519 keypair."""
    priv = Ed25519PrivateKey.generate()
    return KeyPair(private_key=priv, public_key=priv.public_key())


def serialize_private_key(key: Ed25519PrivateKey, password: bytes | None = None) -> bytes:
    """Encode a private key as PEM, optionally passphrase-protected."""
    if password:
        enc = serialization.BestAvailableEncryption(password)
    else:
        enc = serialization.NoEncryption()
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc,
    )


def serialize_public_key(key: Ed25519PublicKey) -> bytes:
    """Encode a public key as PEM."""
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_private_key(pem: bytes, password: bytes | None = None) -> Ed25519PrivateKey:
    """Read a PEM private key. Raises ValueError if the PEM is unusable."""
    key = serialization.load_pem_private_key(pem, password=password)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("expected an Ed25519 private key")
    return key


def load_public_key(pem: bytes) -> Ed25519PublicKey:
    """Read a PEM public key. Raises ValueError if the PEM is unusable."""
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("expected an Ed25519 public key")
    return key


def public_key_fingerprint(key: Ed25519PublicKey) -> str:
    """Fingerprint for a bare public key, matching KeyPair.fingerprint."""
    raw = key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    digest = hashlib.sha256(raw).hexdigest()[:16]
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


# --------------------------------------------------------------------------
# Signing
# --------------------------------------------------------------------------

def sign(private_key: Ed25519PrivateKey, data: bytes) -> bytes:
    """Produce a 64-byte Ed25519 signature over `data`."""
    return private_key.sign(data)


def verify_signature(public_key: Ed25519PublicKey, signature: bytes, data: bytes) -> bool:
    """Check a signature. Returns True/False rather than raising."""
    try:
        public_key.verify(signature, data)
        return True
    except InvalidSignature:
        return False


# --------------------------------------------------------------------------
# Payload confidentiality
# --------------------------------------------------------------------------

def derive_aes_key(passphrase: str, salt: bytes) -> bytes:
    """Stretch a passphrase into a 256-bit AES key using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt_payload(plaintext: bytes, passphrase: str) -> bytes:
    """Encrypt with AES-256-GCM. Returns salt || nonce || ciphertext+tag.

    GCM is authenticated, so this protects the hidden message's
    confidentiality and its integrity, which is what the custom payload case
    in the brief asks for.
    """
    salt = os.urandom(AES_SALT_LEN)
    nonce = os.urandom(AES_NONCE_LEN)
    key = derive_aes_key(passphrase, salt)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return salt + nonce + ct


def decrypt_payload(blob: bytes, passphrase: str) -> bytes:
    """Reverse encrypt_payload. Raises DecryptionError on any failure."""
    if len(blob) < AES_SALT_LEN + AES_NONCE_LEN + 16:
        raise DecryptionError("encrypted blob is too short to be valid")
    salt = blob[:AES_SALT_LEN]
    nonce = blob[AES_SALT_LEN : AES_SALT_LEN + AES_NONCE_LEN]
    ct = blob[AES_SALT_LEN + AES_NONCE_LEN :]
    key = derive_aes_key(passphrase, salt)
    try:
        return AESGCM(key).decrypt(nonce, ct, None)
    except InvalidTag:
        raise DecryptionError("wrong passphrase, or the ciphertext was altered")
