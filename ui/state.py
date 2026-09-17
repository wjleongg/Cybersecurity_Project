"""Session state.

Streamlit re-executes the entire script on every widget interaction, including
switching tabs. Anything not held in st.session_state is rebuilt from scratch
each run, which for this app would mean losing the loaded keys, the stego file
just produced, and the last verdict. Every value that has to outlive a single
interaction is registered here.

State is namespaced per media type ("image", "audio") so the two tabs cannot
overwrite each other's results. Signing keys are deliberately not namespaced:
one keypair signs both media types, and duplicating it would let the two tabs
drift apart.
"""

import hashlib

import streamlit as st

MEDIA_TYPES = ("image", "audio")

# Results that must be cleared when a new file is uploaded, so a verdict from
# the previous file never sits on screen next to the current one.
_DERIVED_KEYS = (
    "stego_bytes",
    "stego_carriers",
    "encode_result",
    "verify_result",
    "attacked_bytes",
    "attack_description",
    "register_result",
    "ledger_result",
    "result_cover_id",
)


def init() -> None:
    """Create every key this app reads, once per session."""
    st.session_state.setdefault("keypair", None)
    st.session_state.setdefault("public_key", None)
    st.session_state.setdefault("public_key_source", None)
    st.session_state.setdefault("stego_key", "")

    for media in MEDIA_TYPES:
        st.session_state.setdefault(f"{media}:cover_bytes", None)
        st.session_state.setdefault(f"{media}:cover_id", None)
        st.session_state.setdefault(f"{media}:verify_bytes", None)
        st.session_state.setdefault(f"{media}:verify_id", None)
        for key in _DERIVED_KEYS:
            st.session_state.setdefault(f"{media}:{key}", None)


def get(media: str, key: str):
    """Read a namespaced value."""
    return st.session_state.get(f"{media}:{key}")


def put(media: str, key: str, value) -> None:
    """Write a namespaced value."""
    st.session_state[f"{media}:{key}"] = value


def clear_encode_results(media: str) -> None:
    """Drop everything derived from the previous cover object.

    Called whenever a new cover is uploaded. Without this a stale stego
    preview or an old Authentic verdict would remain visible beside a file it
    has nothing to do with, which during a demo reads as the tool being wrong.
    """
    for key in _DERIVED_KEYS:
        put(media, key, None)


def results_are_stale(media: str) -> bool:
    """True when the stored encode result came from a different cover file.

    A second, independent guard. clear_encode_results already runs on upload,
    but a single missed reset during a demo shows the marker a stego preview
    belonging to a file that is no longer on screen. Comparing the cover this
    result was produced from against the cover currently loaded catches that
    regardless of which code path forgot.
    """
    result = get(media, "encode_result")
    if result is None:
        return False
    produced_from = get(media, "result_cover_id")
    current = get(media, "cover_id")
    return produced_from is not None and produced_from != current


def reset_media(media: str) -> None:
    """Clear everything for one media tab, leaving the shared keys alone."""
    clear_encode_results(media)
    for slot in ("cover", "verify"):
        put(media, f"{slot}_bytes", None)
        put(media, f"{slot}_id", None)
    put(media, "verify_result", None)


def clear_verify_result(media: str) -> None:
    """Drop the verification outcome and the ledger opinion that went with it."""
    put(media, "verify_result", None)
    put(media, "ledger_result", None)


def content_id(data: bytes) -> str:
    """A short, definitive identifier for some file content.

    Identity is decided by the bytes, not by the filename and size. Two
    different files can easily share both: regenerating a sample produces the
    same name and, because the generator is deterministic, often the same
    length. Comparing metadata let a genuinely new upload look like the old
    one, so results from the previous file stayed on screen.
    """
    return hashlib.sha256(data).hexdigest()[:16]


def track_upload(media: str, slot: str, uploaded) -> bytes | None:
    """Store an uploaded file, resetting derived state if the content changed.

    `slot` is either "cover" (encode side) or "verify" (verify side).
    """
    id_key = f"{slot}_id"
    bytes_key = f"{slot}_bytes"

    if uploaded is None:
        return get(media, bytes_key)

    data = uploaded.getvalue()
    signature = content_id(data)
    if get(media, id_key) != signature:
        put(media, id_key, signature)
        put(media, bytes_key, data)
        if slot == "cover":
            clear_encode_results(media)
        else:
            clear_verify_result(media)

    return get(media, bytes_key)