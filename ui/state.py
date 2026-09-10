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
)


def init() -> None:
    """Create every key this app reads, once per session."""
    st.session_state.setdefault("keypair", None)
    st.session_state.setdefault("public_key", None)
    st.session_state.setdefault("public_key_source", None)
    st.session_state.setdefault("stego_key", "")

    for media in MEDIA_TYPES:
        st.session_state.setdefault(f"{media}:cover_bytes", None)
        st.session_state.setdefault(f"{media}:cover_name", None)
        st.session_state.setdefault(f"{media}:verify_bytes", None)
        st.session_state.setdefault(f"{media}:verify_name", None)
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


def clear_verify_result(media: str) -> None:
    """Drop only the verification outcome."""
    put(media, "verify_result", None)


def track_upload(media: str, slot: str, uploaded) -> bytes | None:
    """Store an uploaded file, resetting derived state if the file changed.

    `slot` is either "cover" (encode side) or "verify" (verify side).
    """
    name_key = f"{slot}_name"
    bytes_key = f"{slot}_bytes"

    if uploaded is None:
        return get(media, bytes_key)

    signature = f"{uploaded.name}:{uploaded.size}"
    if get(media, name_key) != signature:
        put(media, name_key, signature)
        put(media, bytes_key, uploaded.getvalue())
        if slot == "cover":
            clear_encode_results(media)
        else:
            clear_verify_result(media)

    return get(media, bytes_key)
