"""Audio tab: the WAV-specific half of the workflow.

Audio needs one thing the image tab does not. Two images can be compared by
eye side by side; two audio clips cannot be compared by ear side by side,
because you can only listen to one at a time and a few seconds apart is long
enough to lose the comparison. A waveform is drawn alongside the player so
there is something visible to point at.
"""

import numpy as np
import streamlit as st

from core import attacks, audio_stego
from ui.media_tab import MediaAdapter

WAVEFORM_POINTS = 800


def _render_preview(file_bytes: bytes, caption: str) -> None:
    """Play the clip and draw its envelope."""
    st.caption(caption)
    st.audio(file_bytes, format="audio/wav")

    try:
        cover = audio_stego.load_audio(file_bytes)
    except audio_stego.AudioFormatError:
        return

    wave = cover.to_float_waveform()
    if cover.n_channels > 1:
        wave = wave[:: cover.n_channels]

    # Downsample by taking the peak of each bucket. Plotting every sample would
    # be slow and would not look any different at this width.
    if wave.size > WAVEFORM_POINTS:
        usable = (wave.size // WAVEFORM_POINTS) * WAVEFORM_POINTS
        buckets = wave[:usable].reshape(WAVEFORM_POINTS, -1)
        envelope = np.max(np.abs(buckets), axis=1)
    else:
        envelope = np.abs(wave)

    st.line_chart(envelope, height=110)


def _diff_stats(cover: audio_stego.AudioCover, stego_carriers) -> dict:
    return audio_stego.difference_stats(cover, stego_carriers)


def _rebuild(cover: audio_stego.AudioCover, carriers) -> bytes:
    return cover.to_wav_bytes(carriers)


ADAPTER = MediaAdapter(
    media_type="audio",
    label="WAV",
    extensions=["wav"],
    load=audio_stego.load_audio,
    format_error=audio_stego.AudioFormatError,
    rebuild=_rebuild,
    render_preview=_render_preview,
    diff_stats=_diff_stats,
    quality_key="snr_db",
    quality_label="SNR",
    attacks=attacks.AUDIO_ATTACKS,
    download_name="stego_audio.wav",
    mime="audio/wav",
    capacity_note=(
        "Uncompressed PCM only, 8-bit or 16-bit. MP3 and AAC discard exactly "
        "the low-order detail the payload occupies."
    ),
)


def render() -> None:
    from ui import media_tab
    media_tab.render(ADAPTER)
