"""Simple redundancy layer for resilient LSB payload transport.

This project keeps the baseline container format and signature flow intact. The
robust layer sits immediately above the payload: a payload that is about to be
embedded is first encoded with a repetition-based codec, and then, on extract, a
matching decoder reconstructs the original bytes before the usual signature and
hash checks run.

The implementation intentionally stays explainable and easy to audit:

  - a fixed magic marker identifies the robust header
  - codec type is explicit so the scheme can be extended later
  - original payload length and a CRC32 make truncation and corruption visible
  - repetition coding with majority voting survives a small number of LSB bit
    flips without changing the rest of the embedding logic

This is a defensive "innovation" layer suitable for the assignment: it is much
simpler than BCH/Hamming and far easier to explain in a report or demo while
still making the payload robust against mild noise.
"""

from __future__ import annotations

import struct
import zlib

import numpy as np

MAGIC = b"RLC1"
CODEC_REPEAT_3 = 1
DEFAULT_REPETITIONS = 3
_HEADER = struct.Struct(">4sBII")  # magic, codec type, original length, crc32


class RobustCodecError(ValueError):
    """Raised when the payload cannot be reconstructed reliably."""


def encode(payload: bytes, codec_type: int = CODEC_REPEAT_3, repetitions: int = DEFAULT_REPETITIONS) -> bytes:
    """Apply a simple repetition code to `payload`.

    Each payload bit is repeated `repetitions` times. The decoder later applies a
    majority vote over each group to recover the original bit. This is resilient
    to a small number of random bit flips, while still being deterministic and
    easy to explain as "three copies of each bit, take the most common value".
    """
    if codec_type != CODEC_REPEAT_3:
        raise ValueError(f"unsupported codec type: {codec_type}")
    if repetitions <= 0 or repetitions % 2 == 0:
        raise ValueError("repetition count must be a positive odd integer")

    bits = np.unpackbits(np.frombuffer(payload, dtype=np.uint8), axis=0)
    repeated = np.repeat(bits, repetitions)
    encoded = np.packbits(repeated.astype(np.uint8), bitorder="big")
    crc = zlib.crc32(payload) & 0xFFFFFFFF
    header = _HEADER.pack(MAGIC, codec_type, len(payload), crc)
    return header + encoded.tobytes()


def decode(data: bytes, codec_type: int = CODEC_REPEAT_3, repetitions: int = DEFAULT_REPETITIONS) -> bytes:
    """Recover the original payload from a repetition-coded stream."""
    if len(data) < _HEADER.size:
        raise RobustCodecError("robust header is truncated")

    magic, stored_type, original_len, stored_crc = _HEADER.unpack(data[: _HEADER.size])
    if magic != MAGIC:
        raise RobustCodecError("robust magic marker was not found")
    if stored_type != codec_type:
        raise RobustCodecError(f"unsupported robust codec type: {stored_type}")
    if original_len < 0:
        raise RobustCodecError("original payload length is invalid")
    if repetitions <= 0 or repetitions % 2 == 0:
        raise ValueError("repetition count must be a positive odd integer")

    encoded_payload = data[_HEADER.size :]
    if not encoded_payload:
        raise RobustCodecError("robust payload is empty")

    bits = np.unpackbits(np.frombuffer(encoded_payload, dtype=np.uint8), axis=0)
    needed_bits = original_len * 8 * repetitions
    if len(bits) < needed_bits:
        raise RobustCodecError(
            f"robust payload is truncated: need {needed_bits} bits but saw {len(bits)}"
        )

    groups = bits[:needed_bits].reshape(-1, repetitions)
    recovered_bits = (groups.sum(axis=1) >= (repetitions / 2)).astype(np.uint8)
    payload = np.packbits(recovered_bits, bitorder="big").tobytes()[:original_len]

    if zlib.crc32(payload) & 0xFFFFFFFF != stored_crc:
        raise RobustCodecError("robust payload checksum failed; corruption is beyond repair")
    return payload


def flip_lsb_bits(carriers: np.ndarray, bit_count: int, start: int | None = None, seed: int = 0, n_lsb: int = 1) -> np.ndarray:
    """Randomly flip LSB bits in a carrier array.

    This is a deliberately simple simulation helper for the demo and tests. It
    helps show that a narrow repetition code can survive a few random bit flips,
    while a larger number of flips crosses the repair threshold and fails cleanly.
    """
    if bit_count < 0:
        raise ValueError("bit_count must be non-negative")
    if carriers.size == 0:
        raise ValueError("cannot corrupt an empty carrier array")

    out = carriers.copy()
    if bit_count == 0:
        return out

    rng = np.random.default_rng(seed)
    if start is None:
        idx = rng.choice(out.size, size=min(bit_count, out.size), replace=False)
    else:
        idx = np.arange(start, min(start + bit_count, out.size), dtype=int) % out.size

    for pos in idx:
        # toggle the lowest bit plane that the embedding path would have used
        if n_lsb > 0:
            out[pos] = out[pos] ^ 1
    return out
