"""The verification payload record.

Serialised as canonical JSON: sorted keys, no incidental whitespace. Canonical
form matters because the signature is computed over these exact bytes, so
re-serialising the same record on another machine has to produce
byte-identical output or verification would fail for no real reason.

A payload is always carried as bytes. Text is the simple case of that, not a
separate mechanism, so the signing, hashing and embedding paths never need to
know which kind they hold. Only the encoding of the stored `content` string
differs:

    kind=text,  plain      content is the text itself
    kind=text,  encrypted  content is base64(AES-GCM(utf-8 bytes))
    kind=file,  plain      content is base64(file bytes)
    kind=file,  encrypted  content is base64(AES-GCM(file bytes))

Text is stored unencoded when it is not encrypted, because base64 would cost a
third more capacity for no benefit. Anything binary has to be base64'd: JSON
strings cannot hold arbitrary bytes.

Everything other than `content` is verification metadata. When encryption is
enabled only the content is encrypted, which keeps two properties separate and
independently demonstrable:

  signature  -> authenticity and integrity, checkable by anyone with the
                public key, no passphrase needed
  encryption -> confidentiality, needs the passphrase, and its absence does
                not prevent the file being verified as authentic
"""

from dataclasses import dataclass, asdict
import base64
import datetime as dt
import json
import mimetypes
import os
import uuid

from . import crypto_utils

NONCE_LEN = 16

KIND_TEXT = "text"
KIND_FILE = "file"

TEXT_MIME = "text/plain"
DEFAULT_FILE_MIME = "application/octet-stream"

# Base64 grows by four output characters per three input bytes.
_B64_NUMERATOR = 4
_B64_DENOMINATOR = 3


def guess_mime(filename: str) -> str:
    """Best-effort MIME type from a filename.

    Only used to decide how to present a recovered payload. A wrong guess
    costs a nicer preview, never correctness, so a plain fallback is fine.
    """
    guessed, _ = mimetypes.guess_type(filename)
    return guessed or DEFAULT_FILE_MIME


def base64_length(n_bytes: int) -> int:
    """Length of the base64 encoding of n_bytes, including padding."""
    return _B64_NUMERATOR * ((n_bytes + _B64_DENOMINATOR - 1) // _B64_DENOMINATOR)


def encrypted_blob_length(n_bytes: int) -> int:
    """Size of encrypt_payload's output for a plaintext of n_bytes.

    AES-GCM does not expand its plaintext, so the overhead is exactly the
    salt, the nonce and the authentication tag. Knowing this lets capacity be
    estimated without performing a real (deliberately slow) key derivation.
    """
    return (
        crypto_utils.AES_SALT_LEN
        + crypto_utils.AES_NONCE_LEN
        + n_bytes
        + 16  # GCM authentication tag
    )


def content_stand_in(data: bytes, kind: str, encrypted: bool) -> str:
    """A placeholder the same serialised length as the real stored content.

    Used by capacity estimation so the figure shown to the user is the figure
    that will actually be embedded. Plain text is returned verbatim, because
    JSON escaping of quotes, backslashes and newlines changes its serialised
    length; base64 output contains no escapable characters, so a run of 'A's
    is exactly as long as the real thing.
    """
    if encrypted:
        return "A" * base64_length(encrypted_blob_length(len(data)))
    if kind == KIND_TEXT:
        # Decoded leniently: this value is only ever measured, never stored,
        # and a text payload that is not valid UTF-8 will be rejected later by
        # build_record anyway.
        return data.decode("utf-8", errors="replace")
    return "A" * base64_length(len(data))


@dataclass
class ExtractedPayload:
    """A payload recovered from a verified record."""

    kind: str
    data: bytes
    filename: str
    mime: str

    @property
    def is_text(self) -> bool:
        return self.kind == KIND_TEXT

    @property
    def size_bytes(self) -> int:
        return len(self.data)

    def as_text(self) -> str | None:
        """The payload decoded as UTF-8, or None if it is not valid UTF-8.

        Returning None rather than substituting replacement characters lets
        the caller distinguish "this is text" from "this is binary that would
        look like mojibake if printed", and offer a download instead of a wall
        of question marks. A payload that extracted cleanly but cannot be
        displayed is still a successful extraction.
        """
        try:
            return self.data.decode("utf-8")
        except UnicodeDecodeError:
            return None


@dataclass
class PayloadRecord:
    """Verification metadata plus the hidden content."""

    media_id: str
    media_type: str          # "image" or "audio"
    timestamp: str           # ISO 8601, UTC
    cover_hash: str          # SHA-256 hex of the stable representation
    nonce: str               # hex, freshness / replay defence
    issuer: str              # team-defined metadata
    n_lsb: int               # LSB depth used, recorded for auditability
    payload_kind: str        # "text" or "file"
    filename: str            # original name for file payloads, else ""
    mime: str                # how to present the recovered payload
    content: str             # see the module docstring for the encoding
    content_encrypted: bool

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
        rows = {
            "Media ID": self.media_id,
            "Media type": self.media_type,
            "Issued": self.timestamp,
            "Issuer": self.issuer,
            "Payload kind": self.payload_kind,
        }
        if self.payload_kind == KIND_FILE:
            rows["Filename"] = self.filename
            rows["Content type"] = self.mime
        rows.update(
            {
                "Cover hash": self.cover_hash,
                "Nonce": self.nonce,
                "LSB depth": self.n_lsb,
                "Content encrypted": self.content_encrypted,
            }
        )
        return rows


def build_record(
    media_type: str,
    cover_hash_hex: str,
    n_lsb: int,
    data: bytes,
    issuer: str,
    kind: str = KIND_TEXT,
    filename: str = "",
    mime: str | None = None,
    passphrase: str | None = None,
    media_id: str | None = None,
) -> PayloadRecord:
    """Create a fresh payload record, encrypting the content if asked."""
    if kind not in (KIND_TEXT, KIND_FILE):
        raise ValueError(f"unknown payload kind: {kind}")

    if mime is None:
        mime = TEXT_MIME if kind == KIND_TEXT else guess_mime(filename)

    if passphrase:
        blob = crypto_utils.encrypt_payload(data, passphrase)
        content = base64.b64encode(blob).decode("ascii")
        encrypted = True
    elif kind == KIND_TEXT:
        content = data.decode("utf-8")
        encrypted = False
    else:
        content = base64.b64encode(data).decode("ascii")
        encrypted = False

    return PayloadRecord(
        media_id=media_id or f"{media_type[:3].upper()}-{uuid.uuid4().hex[:12]}",
        media_type=media_type,
        timestamp=dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        cover_hash=cover_hash_hex,
        nonce=os.urandom(NONCE_LEN).hex(),
        issuer=issuer,
        n_lsb=n_lsb,
        payload_kind=kind,
        filename=filename if kind == KIND_FILE else "",
        mime=mime,
        content=content,
        content_encrypted=encrypted,
    )


def read_payload(record: PayloadRecord, passphrase: str | None = None) -> ExtractedPayload:
    """Recover the payload, decrypting if necessary.

    Raises DecryptionError for a wrong passphrase, or ValueError when the
    record is encrypted and no passphrase was supplied.
    """
    if record.content_encrypted:
        if not passphrase:
            raise ValueError("this payload is encrypted; a passphrase is required")
        try:
            blob = base64.b64decode(record.content, validate=True)
        except Exception as exc:
            raise ValueError(f"encrypted content is not valid base64: {exc}") from exc
        data = crypto_utils.decrypt_payload(blob, passphrase)
    elif record.payload_kind == KIND_FILE:
        try:
            data = base64.b64decode(record.content, validate=True)
        except Exception as exc:
            raise ValueError(f"file content is not valid base64: {exc}") from exc
    else:
        data = record.content.encode("utf-8")

    return ExtractedPayload(
        kind=record.payload_kind,
        data=data,
        filename=record.filename,
        mime=record.mime,
    )