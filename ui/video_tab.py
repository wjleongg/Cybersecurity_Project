"""Video tab: the AVI-specific half of the workflow.

Browsers do not reliably play back a raw/uncompressed AVI through an HTML5
<video> element, so alongside the native player this adds a frame scrubber
built from st.image + st.slider, which always renders and is what actually
lets cover and stego be compared frame by frame.
"""

import streamlit as st

from core import attacks, video_stego
from ui.media_tab import MediaAdapter


def _render_preview(file_bytes: bytes, caption: str) -> None:
    st.caption(caption)

    try:
        cover = video_stego.load_video(file_bytes)
    except video_stego.VideoFormatError as exc:
        st.warning(f"Could not decode this AVI for preview: {exc}")
        return

    st.caption(
        f"{cover.frame_count} frame(s) · {cover.width}x{cover.height} · "
        f"{cover.fps:.1f} fps"
    )
    st.video(file_bytes, format="video/x-msvideo")

    frames = cover.to_frames()
    if cover.frame_count > 1:
        idx = st.slider(
            "Frame", 0, cover.frame_count - 1, 0,
            key=f"video_frame_slider_{caption.replace(' ', '_')}",
        )
    else:
        idx = 0
    st.image(frames[idx], caption=f"Frame {idx}", width="stretch")


def _diff_stats(cover: video_stego.VideoCover, stego_carriers) -> dict:
    return video_stego.difference_stats(cover.carriers, stego_carriers)


def _rebuild(cover: video_stego.VideoCover, carriers) -> bytes:
    return cover.to_avi_bytes(carriers)


ADAPTER = MediaAdapter(
    media_type="video",
    label="AVI",
    extensions=["avi"],
    load=video_stego.load_video,
    format_error=video_stego.VideoFormatError,
    rebuild=_rebuild,
    render_preview=_render_preview,
    diff_stats=_diff_stats,
    quality_key="psnr_db",
    quality_label="PSNR",
    attacks=attacks.VIDEO_ATTACKS,
    download_name="stego_video.avi",
    mime="video/x-msvideo",
    capacity_note=(
        "Uncompressed AVI only: consumer MP4/H.264 re-encodes lossily and "
        "destroys the payload, the same way JPEG does for images. The "
        "container is carried across the whole clip, so it can span a few "
        "consecutive frames from the derived start frame if one frame alone "
        "is not enough."
    ),
)


def render() -> None:
    from ui import media_tab
    media_tab.render(ADAPTER)
