"""The encode / attack / verify workflow, shared by all media types.

Image, audio and video differ in how a cover object is loaded, previewed and
measured for quality, and in nothing else. Those differences are supplied by
an adapter (see image_tab.py, audio_tab.py and video_tab.py); everything
below is common.

Writing this once rather than three times is not only about repetition. It
means a fix to the verification flow cannot land in one tab and be forgotten
in the others, which would be very hard to spot during a demo and very easy
for a marker to find.
"""

from dataclasses import dataclass
from typing import Callable


import streamlit as st

from core import crypto_utils, engine, payload as payload_mod, steganalysis
from ui import components, ledger_panel, messages, state


@dataclass
class MediaAdapter:
    """Everything that differs between the image, audio and video workflows."""

    media_type: str                 # "image", "audio" or "video"
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
    st.divider()
    _steganalysis_section(adapter, media)



# --------------------------------------------------------------------------
# Encode
# --------------------------------------------------------------------------

def _encode_section(adapter: MediaAdapter, media: str) -> None:
    components.section_label("ENCODE")

    upload_col, reset_col = st.columns([4, 1])
    with upload_col:
        uploaded = st.file_uploader(
            f"Cover {adapter.label}",
            type=adapter.extensions,
            key=f"{media}_cover_upload",
        )
    with reset_col:
        st.write("")
        st.write("")
        if st.button(
            "Clear results",
            key=f"{media}_reset",
            width="stretch",
            help=(
                "Drops the stego output, the tampered file and the verdict for "
                "this tab. The uploaded files and the signing keys stay."
            ),
        ):
            state.clear_encode_results(media)
            state.clear_verify_result(media)
            st.rerun()

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

        payload_kind = st.radio(
            "Payload type",
            ["Text message", "File"],
            key=f"{media}_payload_kind",
            horizontal=True,
            help=(
                "A file payload is embedded whole and played or displayed on "
                "extraction. Hiding a PNG inside a PNG, or a WAV inside a WAV, "
                "demonstrates the payload being executed rather than merely read."
            ),
        )

        if payload_kind == "Text message":
            preset_name = st.selectbox(
                "Preset", list(messages.PRESETS), key=f"{media}_preset"
            )
            message = st.text_area(
                "Message to hide",
                value=messages.PRESETS[preset_name],
                height=110,
                key=f"{media}_message_{preset_name}",
            )
            payload_data = message.encode("utf-8")
            kind = payload_mod.KIND_TEXT
            filename = ""
        else:
            payload_file = st.file_uploader(
                "File to hide",
                key=f"{media}_payload_file",
                help=(
                    "Any file. Images, audio and video are rendered inline on "
                    "extraction; everything else is offered as a download."
                ),
            )
            if payload_file is None:
                st.caption("Choose a file to see whether it fits.")
                payload_data = b""
                filename = ""
            else:
                payload_data = payload_file.getvalue()
                filename = payload_file.name
                st.caption(
                    f"`{filename}` · {len(payload_data):,} bytes · "
                    f"{payload_mod.guess_mime(filename)}"
                )
            kind = payload_mod.KIND_FILE

        encrypt = st.checkbox(
            "Encrypt the payload (AES-256-GCM)",
            key=f"{media}_encrypt",
            help=(
                "Protects confidentiality. The signature still verifies without "
                "the passphrase; only reading the content needs it."
            ),
        )
        passphrase = None
        if encrypt:
            passphrase = st.text_input(
                "Payload passphrase", type="password", key=f"{media}_enc_pass"
            )

        # ---- live capacity readout
        report = engine.estimate_capacity(
            cover, n_lsb, payload_data, encrypt, issuer, kind, filename
        )
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
        blockers.append("enter a payload passphrase")
    if not payload_data:
        blockers.append(
            "choose a file to hide" if kind == payload_mod.KIND_FILE
            else "enter a message"
        )
    if not report.fits:
        blockers.append("reduce the payload or raise the LSB depth")

    if st.button(
        "Embed and sign", type="primary", key=f"{media}_embed", width="stretch"
    ):
        if blockers:
            st.error("Cannot embed yet: " + ", ".join(blockers) + ".")
        else:
            _do_encode(
                adapter, media, cover, n_lsb, payload_data, issuer, stego_key,
                keypair, start_mode, manual_offset, passphrase, kind, filename,
            )

    _render_encode_output(adapter, media, cover, cover_bytes)


def _do_encode(
    adapter, media, cover, n_lsb, payload_data, issuer, stego_key,
    keypair, start_mode, manual_offset, passphrase, kind, filename,
):
    """Run the embed and store the result in session state."""
    try:
        result = engine.encode(
            cover=cover,
            media_type=adapter.media_type,
            data=payload_data,
            issuer=issuer,
            n_lsb=n_lsb,
            stego_key=stego_key,
            private_key=keypair.private_key,
            start_mode=start_mode,
            manual_offset=int(manual_offset) if manual_offset is not None else None,
            passphrase=passphrase,
            kind=kind,
            filename=filename,
        )
    except engine.EncodeError as exc:
        st.error(str(exc), icon=":material/error:")
        return
    except Exception as exc:
        st.error(f"Embedding failed: {exc}", icon=":material/error:")
        return

    # Register the issuance. A ledger failure is reported but never undoes an
    # embed that already succeeded: the stego file exists either way.
    ledger = ledger_panel.get_ledger()
    if ledger.enabled:
        reg = ledger.register(result.record, st.session_state["keypair"].fingerprint)
        state.put(media, "register_result", reg)

    state.put(media, "encode_result", result)
    state.put(media, "result_cover_id", state.get(media, "cover_id"))
    state.put(media, "stego_carriers", result.stego_carriers)
    state.put(media, "stego_bytes", adapter.rebuild(cover, result.stego_carriers))
    state.put(media, "attacked_bytes", None)
    state.put(media, "attack_description", None)


def _render_encode_output(adapter, media, cover, cover_bytes) -> None:
    """Side-by-side comparison, quality numbers and the download button."""
    # Defensive: if the stored result belongs to a cover that is no longer
    # loaded, drop it rather than show it next to the wrong file.
    if state.results_are_stale(media):
        state.clear_encode_results(media)

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

    locate = getattr(cover, "locate_span", None)
    span = f"  ·  {locate(result.start_index, result.container_bytes, result.n_lsb)}" if locate else ""
    st.caption(
        f"Container {result.container_bytes:,} bytes  ·  start carrier "
        f"{result.start_index:,}  ·  {result.n_lsb} LSB  ·  media ID "
        f"`{result.record.media_id}`{span}"
    )

    reg = state.get(media, "register_result")
    if reg is not None and reg.status.value != "Ledger disabled":
        if reg.status.value == "Registered":
            st.caption(f"Ledger · {reg.message}")
        else:
            st.warning(f"Ledger · {reg.message}", icon=":material/database_off:")

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
                "Payload passphrase (if encrypted)",
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

        st.divider()
        rc1, rc2 = st.columns([2, 1])
        with rc1:
            enforce_freshness = st.checkbox(
                "Enforce freshness window",
                value=False,
                key=f"{media}_ver_freshness",
                help=(
                    "Reject a payload issued longer ago than the window below, "
                    "on top of the always-on check for a payload already "
                    "verified before. Neither check affects the signature or "
                    "hash outcome — both run only once a file already looks "
                    "authentic."
                ),
            )
            max_age_minutes = None
            if enforce_freshness:
                max_age_minutes = st.number_input(
                    "Max payload age (minutes)",
                    min_value=1,
                    value=5,
                    step=1,
                    key=f"{media}_ver_max_age",
                )
        with rc2:
            st.write("")
            st.write("")
            if st.button("Reset replay log", key=f"{media}_ver_replay_reset"):
                state.get_replay_guard().reset()
                st.success("Replay log cleared.")

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
            replay_guard=state.get_replay_guard(),
            max_age_seconds=(
                int(max_age_minutes) * 60 if max_age_minutes is not None else None
            ),
        )
        state.put(media, "verify_result", result)

        ledger = ledger_panel.get_ledger()
        if ledger.enabled and result.record is not None:
            check = ledger.check(result.record)
            state.put(media, "ledger_result", check)
            ledger.log_verification(
                media_id=result.record.media_id,
                media_type=adapter.media_type,
                verdict=result.verdict.value,
                ledger_status=check.status.value,
                signer_fingerprint=crypto_utils.public_key_fingerprint(
                    st.session_state["public_key"]
                ),
                detail=result.reason,
            )
        else:
            state.put(media, "ledger_result", None)

    st.caption(
        "Replay check: verifying the exact same untouched file a second time "
        "reports Replay Detected — no tampering needed to demonstrate it, "
        "since a signature and a hash alone cannot tell a resubmitted file "
        "from a fresh one."
    )

    _render_verify_output(adapter, media, verify_bytes)


def _render_verify_output(adapter: MediaAdapter, media: str, verify_bytes: bytes) -> None:
    """Verdict, extracted payload, recovered message and the check trail."""
    result = state.get(media, "verify_result")
    if result is None:
        return

    components.verdict_block(result)

    ledger_result = state.get(media, "ledger_result")
    if ledger_result is not None:
        ledger_panel.contradiction_banner(result.verdict, ledger_result)
        ledger_panel.status_line(ledger_result)

    adapter.render_preview(verify_bytes, "File under verification")

    if result.record is not None:
        st.markdown("**Extracted payload**")
        components.payload_table(result.record)

    if result.payload is not None:
        st.markdown("**Recovered payload**")
        components.payload_view(result.payload, key_prefix=media)
    elif result.record is not None and result.record.content_encrypted:
        st.caption(
            "The payload is encrypted and was not recovered. Signature and hash "
            "verification do not depend on it."
        )

    with st.expander("Verification trail", expanded=False):
        components.checks_table(result)
# --------------------------------------------------------------------------
# Steganalysis (no key required)
# --------------------------------------------------------------------------
#
# Unlike _verify_section above, nothing here needs the stego key, the
# signing keys, or the payload. It only looks at the carrier values
# themselves -- what an eavesdropper without the key could still infer. It
# reuses the file already uploaded to Verify, since a real analyst starts
# from the same suspect file they were trying to verify, not a fresh upload.

_SA_TONE = {
    steganalysis.Likelihood.LIKELY_CLEAN: "success",
    steganalysis.Likelihood.SUSPICIOUS: "warning",
    steganalysis.Likelihood.LIKELY_STEGO: "error",
    steganalysis.Likelihood.INCONCLUSIVE: "warning",
}


def _steganalysis_section(adapter: MediaAdapter, media: str) -> None:
    components.section_label("STEGANALYSIS")

    verify_bytes = state.get(media, "verify_bytes")
    if verify_bytes is None:
        st.caption(
            "Upload a file in the Verify section above, then run a scan here. "
            "This works without the stego key or signing keys -- it only "
            "looks at the carrier values themselves."
        )
        return

    try:
        subject = adapter.load(verify_bytes)
    except adapter.format_error as exc:
        st.error(str(exc), icon=":material/error:")
        return

    cover_bytes = state.get(media, "cover_bytes")
    cover = None
    if cover_bytes is not None:
        try:
            cover = adapter.load(cover_bytes)
        except adapter.format_error:
            cover = None

    with st.container(border=True):
        c1, c2, c3 = st.columns([2, 2, 1])
        with c1:
            n_lsb = st.slider(
                "LSB depth to test", 1, 8, 2, key=f"{media}_sa_lsb",
                help="Try the depth actually used at embedding first; a mismatch weakens the test.",
            )
        with c2:
            window = st.select_slider(
                "Window size (carriers)",
                options=[500, 1000, 2000, 5000, 10000, 20000],
                value=2000,
                key=f"{media}_sa_window",
                help=(
                    "Smaller windows localise a small payload better; larger "
                    "windows have more statistical power for a large one. "
                    "Unsure which fits? Use the sweep button below instead."
                ),
            )
        with c3:
            st.write("")
            st.write("")
            run = st.button("Run scan", key=f"{media}_sa_run", width="stretch")

        sweep = st.button(
            "Sweep window sizes instead (needs the cover file)",
            key=f"{media}_sa_sweep",
            width="stretch",
            help="Tries several window sizes and reports whichever one shows the clearest shift, instead of using the single size chosen above.",
        )

    if run:
        scan = steganalysis.chi_square_scan(subject.carriers, n_lsb=n_lsb, window_carriers=window)
        state.put(media, "sa_scan", scan)
        state.put(media, "sa_lsb", n_lsb)
        if cover is not None:
            cover_scan = steganalysis.chi_square_scan(cover.carriers, n_lsb=n_lsb, window_carriers=window)
            state.put(media, "sa_cover_scan", cover_scan)
            state.put(media, "sa_compare", steganalysis.compare_scans(cover_scan, scan))
        else:
            state.put(media, "sa_cover_scan", None)
            state.put(media, "sa_compare", None)
        state.put(media, "sa_sweep_result", None)

    if sweep:
        if cover is None:
            st.warning(
                "The sweep needs the cover file loaded in the Encode section above.",
                icon=":material/error:",
            )
        else:
            result = steganalysis.multiscale_compare(cover.carriers, subject.carriers, n_lsb=n_lsb)
            state.put(media, "sa_sweep_result", result)
            state.put(media, "sa_lsb", n_lsb)

    scan = state.get(media, "sa_scan")
    sweep_result = state.get(media, "sa_sweep_result")

    if scan is None and sweep_result is None:
        return

    if scan is not None:
        tone = _SA_TONE[scan.likelihood]
        message = f"**{scan.likelihood.value}** — {scan.summary}"
        {"success": st.success, "warning": st.warning, "error": st.error}[tone](
            message, icon=":material/query_stats:"
        )

        
        if scan.windows:
            st.caption(
                "z-score by window (lower = more statistically uniform = more "
                "consistent with embedding). Shown instead of raw p-values, "
                "which underflow to 0 on real photographic images and audio "
                "and would otherwise show as an empty chart."
            )
            st.bar_chart({"z-score": [w.z_score for w in scan.windows]}, height=140)

        with st.expander("Raw p-values by window", expanded=False):
            st.caption(
                "Shown as a table, not a chart, because on real files these "
                "numbers collapse to 0.0 for almost every window and a chart "
                "of them looks empty."
            )
            st.dataframe(
                [
                    {"window": i, "start": w.start, "end": w.end, "p_value": w.p_value, "z_score": w.z_score}
                    for i, w in enumerate(scan.windows)
                ],
                hide_index=True,
                width="stretch",
            )

        compare_text = state.get(media, "sa_compare")
        if compare_text:
            st.info(compare_text, icon=":material/compare_arrows:")
        elif cover is None:
            st.caption(
                "No cover file loaded in the Encode section above -- showing "
                "the single-file result only, which is the realistic case "
                "for a detector that never sees the original."
            )

    if sweep_result:
        st.info(f"Sweep result: {sweep_result}", icon=":material/search:")

    used_lsb = state.get(media, "sa_lsb") or n_lsb
    with st.expander("Bit-plane comparison", expanded=scan is not None):
        st.caption(
            f"Bit {used_lsb - 1} (0 = least significant) extracted as its own "
            "image/waveform. A plane carrying real payload data looks like "
            "noise; an unmodified plane keeps a visible trace of the cover."
        )
        bit_index = st.slider(
            "Which bit to show", 0, 7, min(used_lsb - 1, 7), key=f"{media}_sa_bit",
        )

        cols = st.columns(2) if cover is not None else st.columns(1)

        if media == "image":
            if cover is not None:
                with cols[0]:
                    st.image(steganalysis.bit_plane_image(cover, bit_index=bit_index), caption="Cover", width="stretch")
                with cols[1]:
                    st.image(steganalysis.bit_plane_image(subject, bit_index=bit_index), caption="Subject", width="stretch")
            else:
                with cols[0]:
                    st.image(steganalysis.bit_plane_image(subject, bit_index=bit_index), caption="Subject", width="stretch")
        elif media == "audio":
            if cover is not None:
                with cols[0]:
                    st.caption("Cover")
                    st.line_chart(steganalysis.bit_plane_waveform(cover, bit_index=bit_index)[:20000])
                with cols[1]:
                    st.caption("Subject")
                    st.line_chart(steganalysis.bit_plane_waveform(subject, bit_index=bit_index)[:20000])
            else:
                with cols[0]:
                    st.caption("Subject")
                    st.line_chart(steganalysis.bit_plane_waveform(subject, bit_index=bit_index)[:20000])
        else:
            st.caption("Bit-plane visualisation is defined for image and audio carriers only.")