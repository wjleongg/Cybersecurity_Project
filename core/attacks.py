"""Tamper simulation, for producing negative cases on demand.

Each function returns modified carriers plus a description of what it did, so
the demo can show a specific attack and the verdict it produces rather than
vaguely "editing the file". Every attack here maps to a verdict the tool is
required to distinguish.

    edit_above_planes          -> Tampered
    add_noise                  -> Tampered
    destructive_edit           -> Payload Missing
    corrupt_payload_region     -> Signature Invalid
    strip_lsb_planes           -> Payload Missing

Note which attacks the design is deliberately blind to. Anything that only
disturbs the embedding planes cannot change the media hash, because the hash
is computed with those planes masked out. Such a change is caught by the
signature or the container CRC instead. That is a design trade-off, not an
oversight: the alternative is a hash that changes every time you embed, which
cannot be signed before embedding at all.
"""

import numpy as np

from . import bitops


def edit_above_planes(
    carriers: np.ndarray,
    n_lsb: int,
    amount: int = 16,
    signed: bool = False,
) -> tuple[np.ndarray, str]:
    """Alter the media while leaving the embedding planes byte-identical.

    The carrier is split into a high field and the low n_lsb bits, the high
    field is shifted, and the low bits are put back untouched. Splitting is
    necessary rather than simply adding a multiple of 2**n_lsb: near the top
    of the range an addition would saturate, and saturation rewrites the low
    bits, which would destroy the payload.

    Keeping the payload readable is what isolates the hash check and produces
    a clean Tampered verdict. A careless edit in a real editor changes the low
    bits too, which is what destructive_edit models.
    """
    low_mask = (1 << n_lsb) - 1
    low = carriers.astype(np.int64) & low_mask

    if signed:
        view = carriers.astype(np.uint16).view(np.int16).astype(np.int64)
        high = view >> n_lsb
        step = max(1, amount >> n_lsb)
        high = np.clip(high + step, -(1 << (16 - n_lsb - 1)), (1 << (16 - n_lsb - 1)) - 1)
        out = ((high << n_lsb) | low).astype(np.int16).view(np.uint16)
        return out, f"Shifted the audio level, leaving the low {n_lsb} bit(s) untouched"

    width = carriers.dtype.itemsize * 8
    high = carriers.astype(np.int64) >> n_lsb
    step = max(1, amount >> n_lsb)
    high = np.clip(high + step, 0, (1 << (width - n_lsb)) - 1)
    out = ((high << n_lsb) | low).astype(carriers.dtype)
    return out, f"Brightened the image, leaving the low {n_lsb} bit(s) untouched"


def destructive_edit(carriers: np.ndarray, amount: int = 10) -> tuple[np.ndarray, str]:
    """A careless edit that carries into the embedding planes.

    This is what an ordinary brightness or gain adjustment actually does. The
    payload does not survive it, so the verdict is Payload Missing rather than
    Tampered: the tool can tell you the file is not trustworthy, but not what
    it originally said.
    """
    info = np.iinfo(carriers.dtype)
    out = np.clip(carriers.astype(np.int64) + amount, info.min, info.max)
    return out.astype(carriers.dtype), f"Added {amount} to every carrier, payload planes included"


def add_noise(carriers: np.ndarray, fraction: float = 0.01, seed: int = 7) -> tuple[np.ndarray, str]:
    """Perturb a random subset of carriers in the high-order bits."""
    rng = np.random.default_rng(seed)
    info = np.iinfo(carriers.dtype)
    n = max(1, int(len(carriers) * fraction))
    idx = rng.choice(len(carriers), size=n, replace=False)

    out = carriers.astype(np.int64)
    # Step by 4 so the change lands above the usual embedding planes.
    out[idx] = np.clip(out[idx] + rng.choice([-4, 4], size=n), info.min, info.max)
    return out.astype(carriers.dtype), f"Perturbed {n:,} carriers ({fraction * 100:.1f}%)"


def corrupt_payload_region(
    carriers: np.ndarray,
    start: int,
    n_lsb: int,
    n_carriers: int = 64,
    seed: int = 11,
) -> tuple[np.ndarray, str]:
    """Randomise the embedding planes over a stretch of the payload.

    Deliberately skips the container header so the payload is still located
    and read, but fails its signature check. Corrupting the header instead
    would produce Payload Missing, which is a different demonstration.
    """
    rng = np.random.default_rng(seed)
    total = len(carriers)
    header_carriers = (14 * 8 + n_lsb - 1) // n_lsb  # skip past the header

    idx = (np.arange(start + header_carriers, start + header_carriers + n_carriers) % total)
    random_bits = rng.integers(0, 2, size=len(idx) * n_lsb).astype(np.uint8)

    out = bitops.embed_bits(carriers, random_bits, int(idx[0]), n_lsb)
    return out, f"Randomised {n_carriers} carriers inside the signed payload"


def strip_lsb_planes(carriers: np.ndarray, n_lsb: int) -> tuple[np.ndarray, str]:
    """Zero the embedding planes across the whole file.

    Simulates a re-encode or a sanitiser. The visible media is essentially
    unchanged and the stable hash still matches, but the payload is gone.
    """
    out = bitops.clear_lsb_planes(carriers, n_lsb)
    return out, f"Zeroed the low {n_lsb} bit-plane(s) across the entire file"


IMAGE_ATTACKS = {
    "Brighten, preserving payload planes": lambda c, ctx: edit_above_planes(
        c, ctx["n_lsb"], 16
    ),
    "Brighten carelessly (destroys payload)": lambda c, ctx: destructive_edit(c, 10),
    "Add noise to 1% of pixels": lambda c, ctx: add_noise(c, 0.01),
    "Corrupt the embedded payload": lambda c, ctx: corrupt_payload_region(
        c, ctx["start"], ctx["n_lsb"]
    ),
    "Strip the LSB planes": lambda c, ctx: strip_lsb_planes(c, ctx["n_lsb"]),
}

AUDIO_ATTACKS = {
    "Shift level, preserving payload planes": lambda c, ctx: edit_above_planes(
        c, ctx["n_lsb"], 64, signed=True
    ),
    "Shift level carelessly (destroys payload)": lambda c, ctx: destructive_edit(c, 10),
    "Add noise to 1% of samples": lambda c, ctx: add_noise(c, 0.01),
    "Corrupt the embedded payload": lambda c, ctx: corrupt_payload_region(
        c, ctx["start"], ctx["n_lsb"]
    ),
    "Strip the LSB planes": lambda c, ctx: strip_lsb_planes(c, ctx["n_lsb"]),
}

VIDEO_ATTACKS = IMAGE_ATTACKS
