"""Encode and verify workflows, shared by both media types.

This module is deliberately media-agnostic. It talks to cover objects through
a small duck-typed interface — `carriers`, `num_carriers`, `stable_hash_input`
— which both ImageCover and AudioCover satisfy. Adding video later would mean
writing one more adapter, not touching the verification logic.

The brief's verdict vocabulary is a "such as" list, not a closed one. Every
path through verification ends at exactly one of these, with a reason
attached:

    AUTHENTIC             signature valid, hash matches, nothing wrong
    TAMPERED              signature valid, but the media hash no longer matches
    SIGNATURE_INVALID     a payload was found, but not signed by this key
    PAYLOAD_MISSING       no container anywhere in this file for this key
    WRONG_START_LOCATION  a container exists, but not where we looked
    CANNOT_VERIFY         we could not complete the check (bad input, no key)
    REPLAY_DETECTED       genuine and unaltered, but already seen or too old

REPLAY_DETECTED only applies when the caller opts in with a `replay_guard`
(see `core/replay_guard.py`) — signature and hash verification never depend
on it, so passing nothing preserves the original six-verdict behaviour
exactly.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import numpy as np

from . import bitops, container, crypto_utils, location, payload as payload_mod
from .replay_guard import ReplayGuard


class Verdict(str, Enum):
    """The six outcomes the brief asks the tool to distinguish."""

    AUTHENTIC = "Authentic"
    TAMPERED = "Tampered"
    SIGNATURE_INVALID = "Signature Invalid"
    PAYLOAD_MISSING = "Payload Missing"
    WRONG_START_LOCATION = "Wrong Start Location"
    CANNOT_VERIFY = "Cannot Verify"
    REPLAY_DETECTED = "Replay Detected"


# Severity ordering used by the GUI to pick a colour.
VERDICT_TONE = {
    Verdict.AUTHENTIC: "success",
    Verdict.TAMPERED: "danger",
    Verdict.SIGNATURE_INVALID: "danger",
    Verdict.PAYLOAD_MISSING: "warning",
    Verdict.WRONG_START_LOCATION: "warning",
    Verdict.CANNOT_VERIFY: "warning",
    Verdict.REPLAY_DETECTED: "danger",
}


class EncodeError(Exception):
    """Raised when embedding cannot proceed."""


@dataclass
class CapacityReport:
    """Answers the brief's capacity-check requirement."""

    payload_bits: int
    capacity_bits: int
    num_carriers: int
    n_lsb: int

    @property
    def fits(self) -> bool:
        return self.payload_bits <= self.capacity_bits

    @property
    def utilisation_pct(self) -> float:
        if self.capacity_bits == 0:
            return 100.0
        return self.payload_bits / self.capacity_bits * 100.0

    def summary(self) -> str:
        if self.fits:
            return (
                f"{self.payload_bits:,} of {self.capacity_bits:,} bits used "
                f"({self.utilisation_pct:.2f}%)"
            )
        shortfall = self.payload_bits - self.capacity_bits
        return (
            f"Payload needs {self.payload_bits:,} bits but this cover holds "
            f"{self.capacity_bits:,} at {self.n_lsb} LSB(s). "
            f"Short by {shortfall:,} bits."
        )


@dataclass
class EncodeResult:
    """Everything the GUI needs after a successful embed."""

    stego_carriers: np.ndarray
    record: payload_mod.PayloadRecord
    start_index: int
    n_lsb: int
    capacity: CapacityReport
    container_bytes: int


@dataclass
class VerifyResult:
    """Outcome of a verification attempt."""

    verdict: Verdict
    reason: str
    record: payload_mod.PayloadRecord | None = None
    payload: payload_mod.ExtractedPayload | None = None
    checks: dict[str, Any] = field(default_factory=dict)
    start_index: int | None = None
    found_at: int | None = None

    @property
    def tone(self) -> str:
        return VERDICT_TONE[self.verdict]


# --------------------------------------------------------------------------
# Capacity
# --------------------------------------------------------------------------

def estimate_capacity(
    cover,
    n_lsb: int,
    data: bytes,
    encrypted: bool,
    issuer: str = "Team P1-4",
    kind: str = payload_mod.KIND_TEXT,
    filename: str = "",
) -> CapacityReport:
    """Estimate whether a payload will fit, before doing any work.

    The estimate builds a record with the same shape as the real one, so JSON
    overhead, base64 expansion, the filename, the MIME type and the signature
    are all counted. Sizing from the raw payload length alone would understate
    the requirement by a few hundred bytes, and for a file payload by a third
    again on top of that.

    Nothing is actually encrypted here. This runs on every rerun — every
    slider drag, every keystroke — and a real encryption would mean a PBKDF2
    derivation each time, which is deliberately slow. AES-GCM does not expand
    its plaintext, so the stored length is exactly derivable instead.
    """
    mime = (
        payload_mod.TEXT_MIME
        if kind == payload_mod.KIND_TEXT
        else payload_mod.guess_mime(filename)
    )
    probe = payload_mod.PayloadRecord(
        media_id="IMG-000000000000",
        media_type="image",
        timestamp="2026-01-01T00:00:00+00:00",
        cover_hash="0" * 64,
        nonce="0" * (payload_mod.NONCE_LEN * 2),
        issuer=issuer,
        n_lsb=n_lsb,
        payload_kind=kind,
        filename=filename if kind == payload_mod.KIND_FILE else "",
        mime=mime,
        content=payload_mod.content_stand_in(data, kind, encrypted),
        content_encrypted=encrypted,
    )
    payload_bytes = probe.to_json()
    total = container.total_size(len(payload_bytes))
    return CapacityReport(
        payload_bits=total * 8,
        capacity_bits=bitops.capacity_bits(cover.num_carriers, n_lsb),
        num_carriers=cover.num_carriers,
        n_lsb=n_lsb,
    )


# --------------------------------------------------------------------------
# Encode
# --------------------------------------------------------------------------

def encode(
    cover,
    media_type: str,
    data: bytes,
    issuer: str,
    n_lsb: int,
    stego_key: str,
    private_key,
    seed: str = "",
    start_mode: str = "derived",
    manual_offset: int | None = None,
    passphrase: str | None = None,
    kind: str = payload_mod.KIND_TEXT,
    filename: str = "",
    mime: str | None = None,
) -> EncodeResult:
    """Hash, build, sign and embed. Returns the modified carriers.

    Order matters here. The cover hash is computed over the stable
    representation — the carriers with the embedding planes already zeroed —
    so the value signed at encode time is the same value recomputed at verify
    time, even though the file's bytes change in between.
    """
    if not stego_key:
        raise EncodeError("a stego key is required to derive the start location")
    if not 1 <= n_lsb <= 8:
        raise EncodeError("LSB depth must be between 1 and 8")

    cover_hash = crypto_utils.sha256_hex(cover.stable_hash_input(n_lsb))

    record = payload_mod.build_record(
        media_type=media_type,
        cover_hash_hex=cover_hash,
        n_lsb=n_lsb,
        data=data,
        issuer=issuer,
        kind=kind,
        filename=filename,
        mime=mime,
        passphrase=passphrase,
    )
    payload_bytes = record.to_json()

    signature = crypto_utils.sign(
        private_key,
        container.signed_region(
            container.VERSION,
            container.FLAG_ENCRYPTED if record.content_encrypted else 0,
            payload_bytes,
        ),
    )

    blob = container.build(
        magic=location.derive_magic(stego_key, seed),
        payload=payload_bytes,
        signature=signature,
        encrypted=record.content_encrypted,
    )

    capacity = CapacityReport(
        payload_bits=len(blob) * 8,
        capacity_bits=bitops.capacity_bits(cover.num_carriers, n_lsb),
        num_carriers=cover.num_carriers,
        n_lsb=n_lsb,
    )
    if not capacity.fits:
        raise EncodeError(capacity.summary())

    start = location.resolve_start(
        mode=start_mode,
        stego_key=stego_key,
        media_type=media_type,
        num_carriers=cover.num_carriers,
        n_lsb=n_lsb,
        manual_offset=manual_offset,
        frame_count=getattr(cover, "frame_count", None),
        seed = seed,
    )

    stego = bitops.embed_bits(
        cover.carriers, bitops.bytes_to_bits(blob), start, n_lsb
    )

    return EncodeResult(
        stego_carriers=stego,
        record=record,
        start_index=start,
        n_lsb=n_lsb,
        capacity=capacity,
        container_bytes=len(blob),
    )


# --------------------------------------------------------------------------
# Verify
# --------------------------------------------------------------------------

def _read_container_at(carriers: np.ndarray, start: int, n_lsb: int, magic: bytes):
    """Attempt to read a container at one offset. Raises ContainerError."""
    header_bits = bitops.extract_bits(carriers, container.HEADER_LEN * 8, start, n_lsb)
    header = bitops.bits_to_bytes(header_bits)
    version, flags, payload_len = container.parse_header(header, magic)

    need_bytes = container.total_size(payload_len)
    if need_bytes * 8 > bitops.capacity_bits(len(carriers), n_lsb):
        raise container.ContainerError(
            "the declared container is larger than this cover object can hold"
        )

    full_bits = bitops.extract_bits(carriers, need_bytes * 8, start, n_lsb)
    full = bitops.bits_to_bytes(full_bits)
    return container.parse_body(full, payload_len, version, flags)


def verify(
    cover,
    media_type: str,
    n_lsb: int,
    stego_key: str,
    public_key,
    seed: str = "",
    start_mode: str = "derived",
    manual_offset: int | None = None,
    passphrase: str | None = None,
    scan_on_miss: bool = True,
    replay_guard: ReplayGuard | None = None,
    max_age_seconds: int | None = None,
) -> VerifyResult:
    """Locate, extract, authenticate and return a verdict.

    The checks run in a fixed order, and each failure has its own exit. That
    ordering is the point: a signature check on a payload you could not find
    is meaningless, and a hash comparison on a payload whose signature failed
    tells you nothing about authenticity.

    `replay_guard` is opt-in. Leaving it `None` (the default) reproduces the
    original six-verdict behaviour exactly — every existing caller that
    doesn't know about replay detection is unaffected. Passing a guard adds
    a check, after signature and hash both pass, for whether this exact
    payload (by nonce) has been verified before, or is older than
    `max_age_seconds` allows.
    """
    checks: dict[str, Any] = {}

    if public_key is None:
        return VerifyResult(
            verdict=Verdict.CANNOT_VERIFY,
            reason="No public key is loaded, so no signature can be checked.",
            checks=checks,
        )
    if not stego_key:
        return VerifyResult(
            verdict=Verdict.CANNOT_VERIFY,
            reason="No stego key was supplied, so the start location cannot be derived.",
            checks=checks,
        )

    magic = location.derive_magic(stego_key, seed)

    try:
        start = location.resolve_start(
            mode=start_mode,
            stego_key=stego_key,
            media_type=media_type,
            num_carriers=cover.num_carriers,
            n_lsb=n_lsb,
            manual_offset=manual_offset,
            frame_count=getattr(cover, "frame_count", None),
            seed = seed,
        )
    except ValueError as exc:
        return VerifyResult(
            verdict=Verdict.CANNOT_VERIFY,
            reason=str(exc),
            checks=checks,
        )

    checks["Start location"] = f"{start:,} ({start_mode})"
    frame_count = getattr(cover, "frame_count", None)
    if frame_count:
        per_frame = cover.num_carriers // frame_count
        checks["Start frame"] = f"{start // per_frame:,} of {frame_count:,}"

    # Step 1: is there a container where we expect one?
    try:
        parsed = _read_container_at(cover.carriers, start, n_lsb, magic)
        found_at = start
    except container.ContainerError as exc:
        checks["Container at start location"] = f"not found ({exc})"

        if scan_on_miss:
            hits = location.scan_for_magic(cover.carriers, magic, n_lsb, limit=1)
            if hits:
                elsewhere = hits[0]
                checks["Container found elsewhere"] = f"carrier {elsewhere:,}"
                return VerifyResult(
                    verdict=Verdict.WRONG_START_LOCATION,
                    reason=(
                        f"Nothing readable at carrier {start:,}, but a container "
                        f"for this key exists at carrier {elsewhere:,}. The start "
                        "location used to verify does not match the one used to embed."
                    ),
                    checks=checks,
                    start_index=start,
                    found_at=elsewhere,
                )

        return VerifyResult(
            verdict=Verdict.PAYLOAD_MISSING,
            reason=(
                "No container for this stego key was found anywhere in the file. "
                "Either nothing was embedded, the stego key is wrong, or the LSB "
                "depth does not match the one used at embedding."
            ),
            checks=checks,
            start_index=start,
        )

    checks["Container at start location"] = "found"
    checks["Payload size"] = f"{len(parsed.payload):,} bytes"
    checks["Content encrypted"] = parsed.is_encrypted

    # Step 2: does the signature hold?
    sig_ok = crypto_utils.verify_signature(
        public_key, parsed.signature, parsed.signed_bytes()
    )
    checks["Signature"] = "valid" if sig_ok else "INVALID"
    if not sig_ok:
        return VerifyResult(
            verdict=Verdict.SIGNATURE_INVALID,
            reason=(
                "A payload was extracted, but its signature does not verify against "
                "the loaded public key. Either the payload was altered after signing, "
                "or it was signed by a different party."
            ),
            checks=checks,
            start_index=start,
            found_at=found_at,
        )

    # Step 3: is the payload itself well-formed?
    try:
        record = payload_mod.PayloadRecord.from_json(parsed.payload)
    except ValueError as exc:
        return VerifyResult(
            verdict=Verdict.CANNOT_VERIFY,
            reason=f"The signature is valid but the payload could not be parsed: {exc}",
            checks=checks,
            start_index=start,
            found_at=found_at,
        )

    # Step 4: does the media still hash to the signed value?
    current_hash = crypto_utils.sha256_hex(cover.stable_hash_input(record.n_lsb))
    hash_ok = (current_hash == record.cover_hash)
    checks["Signed hash"] = record.cover_hash
    checks["Current hash"] = current_hash
    checks["Hash match"] = hash_ok

    if not hash_ok:
        return VerifyResult(
            verdict=Verdict.TAMPERED,
            reason=(
                "The signature is valid, so the payload is genuine, but the media "
                "no longer hashes to the value that was signed. The cover object "
                "was modified after it was protected."
            ),
            record=record,
            checks=checks,
            start_index=start,
            found_at=found_at,
        )

    # Step 5: has this exact payload been seen before, or has it gone stale?
    # Only reached once the file is otherwise indistinguishable from
    # authentic, so a tampered file is still reported as Tampered, never
    # masked by a replay finding.
    if replay_guard is not None:
        outcome = replay_guard.check(record.nonce, record.timestamp, max_age_seconds)
        checks["Replay check"] = outcome.reason or "first time seen"
        if not outcome.ok:
            return VerifyResult(
                verdict=Verdict.REPLAY_DETECTED,
                reason=outcome.reason,
                record=record,
                checks=checks,
                start_index=start,
                found_at=found_at,
            )
        replay_guard.record(record.nonce, record.timestamp)

    # Step 6: recover the payload content, if we can.
    extracted = None
    try:
        extracted = payload_mod.read_payload(record, passphrase)
        checks["Payload content"] = (
            f"recovered, {extracted.size_bytes:,} bytes ({extracted.mime})"
        )
    except (ValueError, crypto_utils.DecryptionError) as exc:
        checks["Payload content"] = f"not recovered ({exc})"

    return VerifyResult(
        verdict=Verdict.AUTHENTIC,
        reason=(
            "Signature verified against the loaded public key and the media hash "
            "matches the signed value. This file is intact and was issued by the "
            "holder of the corresponding private key."
        ),
        record=record,
        payload=extracted,
        checks=checks,
        start_index=start,
        found_at=found_at,
    )