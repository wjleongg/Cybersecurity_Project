"""The binary container that actually gets written into the LSB planes.

Layout, in order:

    magic         4 bytes   keyed marker (see location.derive_magic)
    version       1 byte    container format version
    flags         1 byte    bit 0 = message field is encrypted
    payload_len   4 bytes   big-endian length of the payload record
    header_crc    4 bytes   CRC32 over the preceding 10 bytes
    payload       variable  canonical JSON payload record
    signature    64 bytes   Ed25519 over version|flags|payload_len|payload

The header CRC is not a security control; the signature is. Its job is to stop
a read at the wrong offset from interpreting random bits as a four-gigabyte
length and trying to allocate it. Without it, a wrong-location extraction
fails as a crash rather than as a verdict.
"""

from dataclasses import dataclass
import struct
import zlib

from .crypto_utils import SIGNATURE_LEN

MAGIC_LEN = 4
VERSION = 1
FLAG_ENCRYPTED = 0b0000_0001

_HEADER_BODY = struct.Struct(">BBI")           # version, flags, payload_len
HEADER_LEN = MAGIC_LEN + _HEADER_BODY.size + 4  # + crc32
MAX_PAYLOAD_LEN = 8 * 1024 * 1024               # sanity ceiling: 8 MB


class ContainerError(Exception):
    """Raised when the bytes at a given location are not a valid container."""


@dataclass
class Container:
    """A parsed container."""

    version: int
    flags: int
    payload: bytes
    signature: bytes

    @property
    def is_encrypted(self) -> bool:
        return bool(self.flags & FLAG_ENCRYPTED)

    def signed_bytes(self) -> bytes:
        """Exactly the bytes the signature covers."""
        return signed_region(self.version, self.flags, self.payload)


def signed_region(version: int, flags: int, payload: bytes) -> bytes:
    """Build the byte string that gets signed.

    Version, flags and length are included alongside the payload so that an
    attacker cannot flip the encrypted bit or truncate the record and still
    present a valid signature.
    """
    return _HEADER_BODY.pack(version, flags, len(payload)) + payload


def build(magic: bytes, payload: bytes, signature: bytes, encrypted: bool) -> bytes:
    """Assemble a complete container ready for embedding."""
    if len(magic) != MAGIC_LEN:
        raise ValueError(f"magic must be {MAGIC_LEN} bytes")
    if len(signature) != SIGNATURE_LEN:
        raise ValueError(f"signature must be {SIGNATURE_LEN} bytes")

    flags = FLAG_ENCRYPTED if encrypted else 0
    body = _HEADER_BODY.pack(VERSION, flags, len(payload))
    header = magic + body
    crc = zlib.crc32(header) & 0xFFFFFFFF
    return header + struct.pack(">I", crc) + payload + signature


def total_size(payload_len: int) -> int:
    """Container size in bytes for a payload of the given length."""
    return HEADER_LEN + payload_len + SIGNATURE_LEN


def parse_header(raw: bytes, expected_magic: bytes) -> tuple[int, int, int]:
    """Validate a header and return (version, flags, payload_len).

    Raises ContainerError if the magic does not match, the CRC fails, or the
    declared length is implausible.
    """
    if len(raw) < HEADER_LEN:
        raise ContainerError("not enough data for a container header")

    if raw[:MAGIC_LEN] != expected_magic:
        raise ContainerError("magic marker not found at this location")

    body = raw[MAGIC_LEN : MAGIC_LEN + _HEADER_BODY.size]
    stored_crc = struct.unpack(">I", raw[MAGIC_LEN + _HEADER_BODY.size : HEADER_LEN])[0]
    if (zlib.crc32(raw[:MAGIC_LEN] + body) & 0xFFFFFFFF) != stored_crc:
        raise ContainerError("header checksum failed; the header is corrupted")

    version, flags, payload_len = _HEADER_BODY.unpack(body)
    if version != VERSION:
        raise ContainerError(f"unsupported container version {version}")
    if payload_len == 0 or payload_len > MAX_PAYLOAD_LEN:
        raise ContainerError(f"declared payload length {payload_len} is implausible")

    return version, flags, payload_len


def parse_body(raw: bytes, payload_len: int, version: int, flags: int) -> Container:
    """Split payload and signature out of a full container read."""
    need = total_size(payload_len)
    if len(raw) < need:
        raise ContainerError("container is truncated; the cover object is too small")

    payload = raw[HEADER_LEN : HEADER_LEN + payload_len]
    signature = raw[HEADER_LEN + payload_len : need]
    if len(signature) != SIGNATURE_LEN:
        raise ContainerError("signature is truncated")

    return Container(version=version, flags=flags, payload=payload, signature=signature)
