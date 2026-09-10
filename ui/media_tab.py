"""The encode / attack / verify workflow, shared by both media types.

Image and audio differ in how a cover object is loaded, previewed and measured
for quality, and in nothing else. Those differences are supplied by an adapter
(see image_tab.py and audio_tab.py); everything below is common.

Writing this once rather than twice is not only about repetition. It means a
fix to the verification flow cannot land in one tab and be forgotten in the
other, which would be very hard to spot during a demo and very easy for a
marker to find.
"""

from dataclasses import dataclass
from typing import Callable

import streamlit as st

from core import engine
from ui import components, messages, state


@dataclass
class MediaAdapter:
    """Everything that differs between the image and audio workflows."""

    media_type: str                 # "image" or "audio"
    label: str                      # shown on the tab
    extensions: list[str]
    load: Callable                  # bytes -> cover object
    format_error: type              # exception raised by load
    rebuild: Callable               # (cover, carriers) -> file bytes
    render_preview: Callable        # (bytes, caption) -> None
    diff_stats: Callable            # (cover, stego_carriers) -> dict
    quality_key: str                # "psnr_db" or "snr_db"
    quality_label: str
    attacks: dict
    download_name: str
    mime: str
    capacity_note: str


def render(adapter: MediaAdapter) -> None:
    """Draw one complete media tab."""
    media = adapter.media_type
    _encode_section(adapter, media)
    st.divider()
    _attack_section(adapter, media)
    st.divider()
    _verify_section(adapter, media)


# --------------------------------------------------------------------------
# Encode
# --------------------------------------------------------------------------

def _encode_section(adapter: MediaAdapter, media: str) -> None:
    components.section_label("ENCODE")

    uploaded = st.file_uploader(
        f"Cover {adapter.label}",
        type=adapter.extensions,
        key=f"{media}_cover_upload",
    )
    cover_bytes = state.track_upload(media, "cover", uploaded)

    if cover_bytes is None:
        st.info(
            f"Upload a cover {adapter.label} to begin. {adapter.capacity_note}",
            icon=":material/upload_file:",
        )
        return

    try:
        cover = adapter.load(cover_bytes)
    except adapter.format_error as exc:
        st.error(str(exc), icon=":material/error:")
        return

    with st.expander("Cover object details", expanded=False):
        st.dataframe(
            [{"Property": k, "Value": str(v)} for k, v in cover.describe().items()],
            hide_index=True,
            width="stretch",
        )

    # ---- configuration
    with st.container(border=True):
        c1, c2 = st.columns(2)
        with c1:
            n_lsb = st.slider(
                "LSB depth", 1, 8, 2, key=f"{media}_enc_lsb",
                help=(
                    "How many least significant bits per carrier are replaced. "
                    "Higher values carry more data and distort the media more."
                ),
            )
            issuer = st.text_input(
                "Issuer metadata", value="Team P1-4", key=f"{media}_issuer"
            )
        with c2:
            start_mode = st.radio(
                "Start location",
                ["derived", "manual"],
                key=f"{media}_enc_mode",
                horizontal=True,
                help=(
                    "Derived: HMAC of the stego key picks the offset, and the "
                    "verifier recomputes it. Manual: you choose, and the verifier "
                    "must be told separately."
                ),
            )
            manual_offset = None
            if start_mode == "manual":
                manual_offset = st.number_input(
                    "Carrier offset",
                    min_value=0,
                    max_value=max(0, cover.num_carriers - 1),
                    value=min(1000, cover.num_carriers - 1),
                    step=1,
                    key=f"{media}_enc_offset",
                )
            else:
                st.caption("Offset is computed from the stego key at embed time.")

        preset_name = st.selectbox(
            "Payload", list(messages.PRESETS), key=f"{media}_preset"
        )
        message = st.text_area(
            "Message to hide",
            value=messages.PRESETS[preset_name],
            height=110,
            key=f"{media}_message_{preset_name}",
        )

        encrypt = st.checkbox(
            "Encrypt the message (AES-256-GCM)",
            key=f"{media}_encrypt",
            help=(
                "Protects confidentiality. The signature still verifies without "
                "the passphrase; only reading the message needs it."
            ),
        )
        passphrase = None
        if encrypt:
            passphrase = st.text_input(
                "Message passphrase", type="password", key=f"{media}_enc_pass"
            )

        # ---- live capacity readout
        report = engine.estimate_capacity(cover, n_lsb, message, encrypt, issuer)
        components.capacity_meter(report)

    # ---- action
    stego_key = st.session_state.get("stego_key", "")
    keypair = st.session_state.get("keypair")

    blockers = []
    if not stego_key:
        blockers.append("set a stego key in the panel above")
    if keypair is None:
        blockers.append("generate or load a private key")
    if encrypt and not passphrase:
        blockers.append("enter a message passphrase")

    if st.button(
        "Embed and sign", type="primary", key=f"{media}_embed", width="stretch"
    ):
        if blockers:
            st.error("Cannot embed yet: " + ", ".join(blockers) + ".")
        else:
            _do_encode(
                adapter, media, cover, n_lsb, message, issuer, stego_key,
                keypair, start_mode, manual_offset, passphrase,
            )

    _render_encode_output(adapter, media, cover, cover_bytes)


def _do_encode(
    adapter, media, cover, n_lsb, message, issuer, stego_key,
    keypair, start_mode, manual_offset, passphrase,
):
    """Run the embed and store the result in session state."""
    try:
        result = engine.encode(
            cover=cover,
            media_type=adapter.media_type,
            message=message,
            issuer=issuer,
            n_lsb=n_lsb,
            stego_key=stego_key,
            private_key=keypair.private_key,
            start_mode=start_mode,
            manual_offset=int(manual_offset) if manual_offset is not None else None,
            passphrase=passphrase,
        )
    except engine.EncodeError as exc:
        st.error(str(exc), icon=":material/error:")
        return
    except Exception as exc:
        st.error(f"Embedding failed: {exc}", icon=":material/error:")
        return

    state.put(media, "encode_result", result)
    state.put(media, "stego_carriers", result.stego_carriers)
    state.put(media, "stego_bytes", adapter.rebuild(cover, result.stego_carriers))
    state.put(media, "attacked_bytes", None)
    state.put(media, "attack_description", None)


def _render_encode_output(adapter, media, cover, cover_bytes) -> None:
    """Side-by-side comparison, quality numbers and the download button."""
    result = state.get(media, "encode_result")
    stego_bytes = state.get(media, "stego_bytes")

    left, right = st.columns(2)
    with left:
        adapter.render_preview(cover_bytes, "Cover")
    with right:
        if stego_bytes is None:
            st.caption("Stego — appears after embedding")
            st.empty()
        else:
            adapter.render_preview(stego_bytes, "Stego")

    if result is None or stego_bytes is None:
        return

    stats = adapter.diff_stats(cover, result.stego_carriers)
    components.stats_row(stats, adapter.quality_key, adapter.quality_label)

    st.caption(
        f"Container {result.container_bytes:,} bytes  ·  start carrier "
        f"{result.start_index:,}  ·  {result.n_lsb} LSB  ·  media ID "
        f"`{result.record.media_id}`"
    )

    st.download_button(
        f"Download stego {adapter.label}",
        data=stego_bytes,
        file_name=adapter.download_name,
        mime=adapter.mime,
        width="stretch",
        key=f"{media}_download_stego",
    )


# --------------------------------------------------------------------------
# Attack simulation
# --------------------------------------------------------------------------

def _attack_section(adapter: MediaAdapter, media: str) -> None:
    components.section_label("TAMPER SIMULATION")

    result = state.get(media, "encode_result")
    if result is None:
        st.caption("Embed something first to generate a file to attack.")
        return

    cover_bytes = state.get(media, "cover_bytes")
    cover = adapter.load(cover_bytes)

    with st.container(border=True):
        choice = st.selectbox(
            "Attack", list(adapter.attacks), key=f"{media}_attack_choice"
        )
        if st.button("Apply attack", key=f"{media}_attack_go", width="stretch"):
            ctx = {"start": result.start_index, "n_lsb": result.n_lsb}
            attacked, description = adapter.attacks[choice](result.stego_carriers, ctx)
            state.put(media, "attacked_bytes", adapter.rebuild(cover, attacked))
            state.put(media, "attack_description", description)

    attacked_bytes = state.get(media, "attacked_bytes")
    if attacked_bytes is not None:
        st.caption(state.get(media, "attack_description"))
        st.download_button(
            f"Download tampered {adapter.label}",
            data=attacked_bytes,
            file_name=f"tampered_{adapter.download_name}",
            mime=adapter.mime,
            width="stretch",
            key=f"{media}_download_attacked",
        )
        st.info(
            "Upload this file in the verify section below to see which verdict "
            "it produces.",
            icon=":material/arrow_downward:",
        )


# --------------------------------------------------------------------------
# Verify
# --------------------------------------------------------------------------

def _verify_section(adapter: MediaAdapter, media: str) -> None:
    components.section_label("VERIFY")

    uploaded = st.file_uploader(
        f"{adapter.label} to verify",
        type=adapter.extensions,
        key=f"{media}_verify_upload",
        help=(
            "Upload the file as the recipient would receive it — after download, "
            "after email, after any edit."
        ),
    )
    verify_bytes = state.track_upload(media, "verify", uploaded)

    if verify_bytes is None:
        st.info(
            f"Upload a {adapter.label} to verify it.", icon=":material/upload_file:"
        )
        return

    try:
        subject = adapter.load(verify_bytes)
    except adapter.format_error as exc:
        st.error(str(exc), icon=":material/error:")
        return

    with st.container(border=True):
        c1, c2 = st.columns(2)
        with c1:
            n_lsb = st.slider(
                "LSB depth used at embedding", 1, 8, 2, key=f"{media}_ver_lsb"
            )
            passphrase = st.text_input(
                "Message passphrase (if encrypted)",
                type="password",
                key=f"{media}_ver_pass",
            )
        with c2:
            start_mode = st.radio(
                "Start location",
                ["derived", "manual"],
                key=f"{media}_ver_mode",
                horizontal=True,
            )
            manual_offset = None
            if start_mode == "manual":
                manual_offset = st.number_input(
                    "Carrier offset",
                    min_value=0,
                    max_value=max(0, subject.num_carriers - 1),
                    value=min(1000, subject.num_carriers - 1),
                    step=1,
                    key=f"{media}_ver_offset",
                )
            scan = st.checkbox(
                "Scan the file if nothing is found where expected",
                value=True,
                key=f"{media}_ver_scan",
                help=(
                    "Distinguishes Wrong Start Location from Payload Missing. "
                    "The scan needs the stego key, because the container's "
                    "marker is derived from it."
                ),
            )

    if st.button("Verify", type="primary", key=f"{media}_verify_go", width="stretch"):
        result = engine.verify(
            cover=subject,
            media_type=adapter.media_type,
            n_lsb=n_lsb,
            stego_key=st.session_state.get("stego_key", ""),
            public_key=st.session_state.get("public_key"),
            start_mode=start_mode,
            manual_offset=int(manual_offset) if manual_offset is not None else None,
            passphrase=passphrase or None,
            scan_on_miss=scan,
        )
        state.put(media, "verify_result", result)

    _render_verify_output(adapter, media, verify_bytes)


def _render_verify_output(adapter: MediaAdapter, media: str, verify_bytes: bytes) -> None:
    """Verdict, extracted payload, recovered message and the check trail."""
    result = state.get(media, "verify_result")
    if result is None:
        return

    components.verdict_block(result)

    adapter.render_preview(verify_bytes, "File under verification")

    if result.record is not None:
        st.markdown("**Extracted payload**")
        components.payload_table(result.record)

    if result.message is not None:
        st.markdown("**Recovered message**")
        st.code(result.message, language=None, wrap_lines=True)
    elif result.record is not None and result.record.message_encrypted:
        st.caption(
            "The message is encrypted and was not recovered. Signature and hash "
            "verification do not depend on it."
        )

    with st.expander("Verification trail", expanded=False):
        components.checks_table(result)
