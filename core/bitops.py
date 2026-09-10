"""Bit-level primitives for LSB replacement steganography.

Carrier-agnostic: works on any 1-D numpy array of unsigned integers, whether
those integers came from image pixel channels (uint8) or audio samples
(uint16 view of int16 PCM). All masking is derived from the array's own dtype
so the same code is correct at both widths.
"""

import numpy as np


class CapacityError(Exception):
    """Raised when a payload cannot fit in the chosen cover object."""


def _width_bits(arr: np.ndarray) -> int:
    """Number of bits per carrier unit, taken from the array dtype."""
    return arr.dtype.itemsize * 8


def _work_dtype(arr: np.ndarray):
    """A dtype wide enough to do masking without overflow."""
    return np.uint32 if _width_bits(arr) > 8 else np.uint16


def bytes_to_bits(data: bytes) -> np.ndarray:
    """Expand bytes into a flat array of bits, most significant bit first."""
    arr = np.frombuffer(data, dtype=np.uint8)
    return np.unpackbits(arr)


def bits_to_bytes(bits: np.ndarray) -> bytes:
    """Pack a flat bit array back into bytes. Length must be a multiple of 8."""
    if len(bits) % 8 != 0:
        raise ValueError("bit array length must be a multiple of 8")
    return np.packbits(bits.astype(np.uint8)).tobytes()


def capacity_bits(num_carriers: int, n_lsb: int) -> int:
    """Total bits available in a cover object using n_lsb bit-planes."""
    return num_carriers * n_lsb


def _carrier_indices(start: int, count: int, total: int) -> np.ndarray:
    """Carrier positions for `count` units starting at `start`, wrapping around.

    Wrap-around is what allows the start location to be genuinely anywhere in
    the cover object. Without it, a start location near the end of the file
    would silently reduce usable capacity to almost nothing.
    """
    return np.arange(start, start + count, dtype=np.int64) % total


def embed_bits(carriers: np.ndarray, bits: np.ndarray, start: int, n_lsb: int) -> np.ndarray:
    """Write `bits` into the low `n_lsb` planes of `carriers`, from `start`.

    Returns a modified copy; the input array is not mutated. Bits are grouped
    n_lsb at a time, with the first bit of each group landing in the most
    significant of the modified planes.
    """
    width = _width_bits(carriers)
    if not 1 <= n_lsb <= width:
        raise ValueError(f"n_lsb must be between 1 and {width} for this carrier")

    total = len(carriers)
    n_bits = len(bits)
    if n_bits > capacity_bits(total, n_lsb):
        raise CapacityError(
            f"payload needs {n_bits} bits but cover holds only "
            f"{capacity_bits(total, n_lsb)} bits at {n_lsb} LSB(s)"
        )

    pad = (-n_bits) % n_lsb
    if pad:
        bits = np.concatenate([bits, np.zeros(pad, dtype=np.uint8)])

    wdt = _work_dtype(carriers)
    groups = bits.reshape(-1, n_lsb).astype(wdt)
    weights = (1 << np.arange(n_lsb - 1, -1, -1)).astype(wdt)
    values = (groups * weights).sum(axis=1).astype(wdt)

    idx = _carrier_indices(start, len(values), total)
    mask = int((1 << n_lsb) - 1)
    keep = wdt(((1 << width) - 1) ^ mask)

    out = carriers.astype(wdt)
    out[idx] = (out[idx] & keep) | values
    return out.astype(carriers.dtype)


def extract_bits(carriers: np.ndarray, n_bits: int, start: int, n_lsb: int) -> np.ndarray:
    """Read `n_bits` bits out of the low `n_lsb` planes, starting at `start`."""
    width = _width_bits(carriers)
    if not 1 <= n_lsb <= width:
        raise ValueError(f"n_lsb must be between 1 and {width} for this carrier")

    total = len(carriers)
    n_groups = (n_bits + n_lsb - 1) // n_lsb
    if n_groups > total:
        raise CapacityError("requested more bits than the cover object holds")

    wdt = _work_dtype(carriers)
    idx = _carrier_indices(start, n_groups, total)
    mask = wdt((1 << n_lsb) - 1)
    values = carriers[idx].astype(wdt) & mask

    shifts = np.arange(n_lsb - 1, -1, -1).astype(wdt)
    bits = ((values[:, None] >> shifts) & 1).astype(np.uint8).reshape(-1)
    return bits[:n_bits]


def clear_lsb_planes(carriers: np.ndarray, n_lsb: int) -> np.ndarray:
    """Zero the low `n_lsb` planes across the whole array.

    This produces the "stable representation" that is hashed at both encode
    and verify time. Because embedding only ever touches those same planes,
    the hash is identical before and after embedding, while any change to the
    higher bits (real tampering) changes it.
    """
    width = _width_bits(carriers)
    if not 1 <= n_lsb <= width:
        raise ValueError(f"n_lsb must be between 1 and {width} for this carrier")
    wdt = _work_dtype(carriers)
    keep = wdt(((1 << width) - 1) ^ ((1 << n_lsb) - 1))
    return (carriers.astype(wdt) & keep).astype(carriers.dtype)
