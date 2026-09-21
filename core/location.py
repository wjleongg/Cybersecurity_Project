"""Start-location design.

The payload does not begin at carrier 0. Its start position is derived from a
shared secret (the stego key) using HMAC-SHA256, so two parties holding the
key agree on the location without transmitting it, and a third party without
the key has no better strategy than exhaustive search.

Two modes are supported:

  derived  start = HMAC(key, media_type | num_carriers | n_lsb) mod num_carriers
  manual   start = an explicit carrier index typed by the operator

Manual mode exists because the brief asks that the payload "may begin at any
chosen start location". It is also what makes the wrong-start-location
negative case demonstrable: embed manually at one offset, verify with the
derived offset, and watch the extraction fail.

Video: derive_frame_index applies the identical formula over frame_count
instead of carrier count, then derive_video_start reuses derive_start inside
that frame for the per-carrier offset. The combined flat index still plugs
straight into the same bitops calls image and audio use.

The container's magic marker is keyed the same way. A fixed marker such as the
ASCII bytes "STEG" would let anyone scan every offset for it and recover the
location without the key, which would defeat the whole scheme. Deriving the
marker from the key means only a key holder can scan.
"""

import hmac
import hashlib

import numpy as np

from . import bitops

MAGIC_LEN = 4


def _hmac(key: str, message: str) -> bytes:
    """HMAC-SHA256 over a UTF-8 message with a UTF-8 key."""
    return hmac.new(key.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).digest()


def derive_magic(stego_key: str, seed: str = "") -> bytes:
    """Four-byte marker that identifies the start of a container.

    Derived from the key and optional seed, so the marker differs per key and 
    seed. With a seed, the same key produces different markers, preventing 
    location prediction across files.
    """
    material = f"magic-marker-v1|seed-{seed}"
    return _hmac(stego_key, material)[:MAGIC_LEN]


def derive_start(stego_key: str, media_type: str, num_carriers: int, n_lsb: int, seed: str = "") -> int:
    """Compute the derived start carrier index.

    Binding num_carriers, n_lsb, and optional seed into the HMAC input means 
    the same key produces a different location for different seeds, cover objects, 
    or LSB settings. This prevents location prediction across files.
    """
    if num_carriers <= 0:
        raise ValueError("cover object has no carriers")
    material = f"{media_type}|{num_carriers}|{n_lsb}|seed-{seed}|start-v1"
    digest = _hmac(stego_key, material)
    return int.from_bytes(digest[:8], "big") % num_carriers


def derive_frame_index(stego_key: str, media_type: str, frame_count: int, n_lsb: int, seed: str = "") -> int:
    if frame_count <= 0:
        raise ValueError("cover object has no frames")
    material = f"{media_type}|{frame_count}|{n_lsb}|seed-{seed}|frame-v1"
    digest = _hmac(stego_key, material)
    return int.from_bytes(digest[:8], "big") % frame_count


def derive_video_start(
    stego_key: str,
    media_type: str,
    frame_count: int,
    per_frame_carriers: int,
    n_lsb: int,
    seed: str = "",
) -> int:
    frame_index = derive_frame_index(stego_key, media_type, frame_count, n_lsb, seed)
    offset_in_frame = derive_start(stego_key, media_type, per_frame_carriers, n_lsb, seed)
    return frame_index * per_frame_carriers + offset_in_frame


def resolve_start(
    mode: str,
    stego_key: str,
    media_type: str,
    num_carriers: int,
    n_lsb: int,
    manual_offset: int | None = None,
    frame_count: int | None = None,
    seed: str = "",
) -> int:
    if mode == "derived":
        if frame_count:
            per_frame_carriers = num_carriers // frame_count
            return derive_video_start(
                stego_key, media_type, frame_count, per_frame_carriers, n_lsb, seed
            )
        return derive_start(stego_key, media_type, num_carriers, n_lsb, seed)
    if mode == "manual":
        if manual_offset is None:
            raise ValueError("manual mode requires an offset")
        if not 0 <= manual_offset < num_carriers:
            raise ValueError(
                f"offset must be between 0 and {num_carriers - 1} for this cover object"
            )
        return manual_offset
    raise ValueError(f"unknown start-location mode: {mode}")


def scan_for_magic(
    carriers: np.ndarray,
    magic: bytes,
    n_lsb: int,
    limit: int = 1,
) -> list[int]:
    """Search every carrier offset for the keyed magic marker.
    
    Used only as a diagnostic, to tell "the payload is somewhere else" apart
    from "there is no payload here at all". The magic marker is keyed to the
    stego key and seed, so only a key/seed holder can scan for it.
    
    Returns up to `limit` matching offsets.
    """
    total = len(carriers)
    if total == 0:
        return []

    all_bits = bitops.extract_bits(carriers, total * n_lsb, 0, n_lsb)
    magic_bits = bitops.bytes_to_bits(magic)
    need = len(magic_bits)

    # A container starting at carrier s begins at bit index s * n_lsb in the
    # stream above. Appending the first `need` bits lets a container that
    # wraps past the end of the cover still be matched by plain slicing.
    doubled = np.concatenate([all_bits, all_bits[:need]])

    # sliding_window_view is a stride trick, not a copy, so this stays cheap
    # even on a megapixel cover.
    windows = np.lib.stride_tricks.sliding_window_view(doubled, need)
    aligned = windows[:: n_lsb][:total]

    # Prefilter on the first byte before comparing the full marker: most
    # offsets die on bit one, so the full comparison runs on a tiny remainder.
    prefilter = (aligned[:, :8] == magic_bits[:8]).all(axis=1)
    candidate_idx = np.flatnonzero(prefilter)
    if candidate_idx.size == 0:
        return []

    confirmed = (aligned[candidate_idx] == magic_bits).all(axis=1)
    offsets = candidate_idx[confirmed].tolist()
    return offsets[:limit]
