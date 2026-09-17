"""Reusable presentation pieces.

Kept separate from the tab logic so that the two media tabs render a verdict
identically. During marking, a verifier that looks different depending on
which tab you are in invites the question of whether it is the same verifier.
"""

import streamlit as st

from core.engine import Verdict, VerifyResult

# Verdict styling. Green only for Authentic; everything else is visibly not a
# pass, with amber reserved for "we could not complete the check" as distinct
# from red "the check failed".
_VERDICT_STYLE = {
    Verdict.AUTHENTIC: ("#0F6E56", "#E1F5EE", "check"),
    Verdict.TAMPERED: ("#A32D2D", "#FCEBEB", "alert-triangle"),
    Verdict.SIGNATURE_INVALID: ("#A32D2D", "#FCEBEB", "shield-x"),
    Verdict.PAYLOAD_MISSING: ("#854F0B", "#FAEEDA", "search-off"),
    Verdict.WRONG_START_LOCATION: ("#854F0B", "#FAEEDA", "map-pin-off"),
    Verdict.CANNOT_VERIFY: ("#854F0B", "#FAEEDA", "help"),
    Verdict.REPLAY_DETECTED: ("#A32D2D", "#FCEBEB", "history"),
}


def section_label(text: str) -> None:
    """A quiet divider label between the encode and verify halves of a tab."""
    st.markdown(
        f"<div style='color:#888780;font-size:0.8rem;letter-spacing:0.04em;"
        f"margin:0.5rem 0 0.25rem;'>{text}</div>",
        unsafe_allow_html=True,
    )


def capacity_meter(report) -> None:
    """Show payload size against cover capacity, with a pass/fail line."""
    left, right = st.columns([3, 2])
    with left:
        st.caption(
            f"Payload {report.payload_bits:,} bits  ·  capacity "
            f"{report.capacity_bits:,} bits at {report.n_lsb} LSB"
        )
        st.progress(min(1.0, report.payload_bits / max(1, report.capacity_bits)))
    with right:
        if report.fits:
            st.success(f"Fits — {report.utilisation_pct:.2f}% used", icon=":material/check:")
        else:
            shortfall = report.payload_bits - report.capacity_bits
            st.error(f"Too large — short by {shortfall:,} bits", icon=":material/error:")


def verdict_block(result: VerifyResult) -> None:
    """The headline result. Deliberately the largest element on the page."""
    colour, background, _ = _VERDICT_STYLE[result.verdict]
    st.markdown(
        f"""
        <div style="border:2px solid {colour};background:{background};
                    border-radius:12px;padding:1rem 1.25rem;margin:0.5rem 0 1rem;">
          <div style="font-size:1.5rem;font-weight:500;color:{colour};
                      margin-bottom:0.35rem;">{result.verdict.value}</div>
          <div style="font-size:0.9rem;color:{colour};line-height:1.5;">
            {result.reason}
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def checks_table(result: VerifyResult) -> None:
    """Every check the engine performed, in the order it performed them."""
    if not result.checks:
        return
    rows = [{"Check": k, "Result": str(v)} for k, v in result.checks.items()]
    st.dataframe(rows, hide_index=True, width="stretch")


def payload_table(record) -> None:
    """The extracted verification payload, field by field."""
    rows = [{"Field": k, "Value": str(v)} for k, v in record.display_dict().items()]
    st.dataframe(rows, hide_index=True, width="stretch")


def stats_row(stats: dict, quality_key: str, quality_label: str) -> None:
    """Numeric evidence that the stego object barely moved from the cover."""
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Carriers changed", f"{stats['changed']:,}")
    c2.metric("Share of file", f"{stats['changed_pct']:.2f}%")
    c3.metric("Max delta", stats["max_delta"])
    value = stats[quality_key]
    c4.metric(quality_label, "lossless" if value == float("inf") else f"{value:.1f} dB")


def payload_view(extracted, key_prefix: str) -> None:
    """Present an extracted payload according to what it actually is.

    The brief asks the GUI to play or execute the payload, not merely print
    it. A hidden PNG is drawn, a hidden WAV gets a player, a hidden video gets
    a video element, and text is shown as text. Anything unrecognised falls
    back to a download button, which is the one presentation that always
    works.

    A download is offered for every file payload regardless, because the
    inline rendering is a convenience and the bytes are the actual artefact.
    """
    mime = extracted.mime or "application/octet-stream"

    if extracted.is_text:
        text = extracted.as_text()
        if text is None:
            st.warning("The payload is marked as text but is not valid UTF-8.")
        else:
            st.code(text, language=None, wrap_lines=True)
        return

    st.caption(
        f"`{extracted.filename or 'payload'}` · {mime} · "
        f"{extracted.size_bytes:,} bytes"
    )

    try:
        if mime.startswith("image/"):
            st.image(extracted.data, caption="Extracted payload", width="content")
        elif mime.startswith("audio/"):
            st.audio(extracted.data, format=mime)
        elif mime.startswith("video/"):
            st.video(extracted.data, format=mime)
        elif mime.startswith("text/") or mime == "application/json":
            text = extracted.as_text()
            if text is None:
                st.info("This payload is not valid UTF-8; download it instead.")
            else:
                st.code(text[:4000], language=None, wrap_lines=True)
                if len(text) > 4000:
                    st.caption("Truncated for display; download for the full file.")
        else:
            st.info(
                "No inline preview for this file type. Download it to open it.",
                icon=":material/description:",
            )
    except Exception as exc:
        # A payload that survived extraction but will not render is still a
        # successful extraction. Say so rather than showing a traceback.
        st.warning(f"The payload extracted cleanly but could not be previewed: {exc}")

    st.download_button(
        "Download extracted payload",
        data=extracted.data,
        file_name=extracted.filename or "extracted_payload.bin",
        mime=mime,
        width="stretch",
        key=f"{key_prefix}_download_payload",
    )