"""The verification payload record.

Serialised as canonical JSON: sorted keys, no incidental whitespace. Canonical
form matters because the signature is computed over these exact bytes, so
re-serialising the same record on another machine has to produce byte-identical
output or verification would fail for no real reason.

The message field is the part a user actually wants hidden. Everything else is
verification metadata. When encryption is enabled only the message is
encrypted, which keeps two properties separate and independently demonstrable:

  signature  -> authenticity and integrity, checkable by anyone with the
                public key, no passphrase needed
  encryption -> confidentiality, needs the passphrase, and its absence does
                not prevent the file being verified as authentic
"""

from dataclasses import dataclass, asdict
import base64
import datetime as dt
import json
import os
import uuid

from . import crypto_utils

NONCE_LEN = 16


@dataclass
class PayloadRecord:
    """Verification metadata plus the hidden message."""

    media_id: str
    media_type: str          # "image" or "audio"
    timestamp: str           # ISO 8601, UTC
    cover_hash: str          # SHA-256 hex of the stable representation
    nonce: str               # hex, freshness / replay defence
    issuer: str              # team-defined metadata
    n_lsb: int               # LSB depth used, recorded for auditability
    message: str             # plaintext, or base64 ciphertext when encrypted
    message_encrypted: bool

    def to_json(self) -> bytes:
        """Canonical JSON bytes. This is what gets signed."""
        return json.dumps(
            asdict(self),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

    @classmethod
    def from_json(cls, raw: bytes) -> "PayloadRecord":
        """Parse a payload record. Raises ValueError on malformed input."""
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"payload is not valid JSON: {exc}") from exc

        expected = set(cls.__dataclass_fields__)
        missing = expected - set(data)
        if missing:
            raise ValueError(f"payload is missing fields: {sorted(missing)}")

        return cls(**{k: data[k] for k in expected})

    def display_dict(self) -> dict:
        """Field ordering for the GUI, most useful first."""
        return {
            "Media ID": self.media_id,
            "Media type": self.media_type,
            "Issued": self.timestamp,
            "Issuer": self.issuer,
            "Cover hash": self.cover_hash,
            "Nonce": self.nonce,
            "LSB depth": self.n_lsb,
            "Message encrypted": self.message_encrypted,
        }


def build_record(
    media_type: str,
    cover_hash_hex: str,
    n_lsb: int,
    message: str,
    issuer: str,
    passphrase: str | None = None,
    media_id: str | None = None,
) -> PayloadRecord:
    """Create a fresh payload record, encrypting the message if asked."""
    encrypted = bool(passphrase)
    if encrypted:
        blob = crypto_utils.encrypt_payload(message.encode("utf-8"), passphrase)
        stored = base64.b64encode(blob).decode("ascii")
    else:
        stored = message

    return PayloadRecord(
        media_id=media_id or f"{media_type[:3].upper()}-{uuid.uuid4().hex[:12]}",
        media_type=media_type,
        timestamp=dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        cover_hash=cover_hash_hex,
        nonce=os.urandom(NONCE_LEN).hex(),
        issuer=issuer,
        n_lsb=n_lsb,
        message=stored,
        message_encrypted=encrypted,
    )


def read_message(record: PayloadRecord, passphrase: str | None = None) -> str:
    """Return the plaintext message, decrypting if necessary.

    Raises DecryptionError for a wrong passphrase, or ValueError when the
    record is encrypted and no passphrase was supplied.
    """
    if not record.message_encrypted:
        return record.message
    if not passphrase:
        raise ValueError("this message is encrypted; a passphrase is required")
    try:
        blob = base64.b64decode(record.message, validate=True)
    except Exception as exc:
        raise ValueError(f"encrypted message is not valid base64: {exc}") from exc
    return crypto_utils.decrypt_payload(blob, passphrase).decode("utf-8")
