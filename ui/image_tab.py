"""Image tab: the PNG-specific half of the workflow.

Only three things are genuinely image-specific — how a preview is drawn, how
quality loss is measured, and which attacks make sense — so this module is
thin. Everything else comes from media_tab.
"""

import streamlit as st

from core import attacks, image_stego
from ui.media_tab import MediaAdapter


def _render_preview(file_bytes: bytes, caption: str) -> None:
    """Draw a PNG at container width."""
    st.image(file_bytes, caption=caption, width="stretch")


def _diff_stats(cover: image_stego.ImageCover, stego_carriers) -> dict:
    return image_stego.difference_stats(cover.carriers, stego_carriers)


def _rebuild(cover: image_stego.ImageCover, carriers) -> bytes:
    return cover.to_png_bytes(carriers)


ADAPTER = MediaAdapter(
    media_type="image",
    label="PNG",
    extensions=["png"],
    load=image_stego.load_image,
    format_error=image_stego.ImageFormatError,
    rebuild=_rebuild,
    render_preview=_render_preview,
    diff_stats=_diff_stats,
    quality_key="psnr_db",
    quality_label="PSNR",
    attacks=attacks.IMAGE_ATTACKS,
    download_name="stego_image.png",
    mime="image/png",
    capacity_note=(
        "PNG only: its compression is lossless, so the embedded bits survive a "
        "save and reload exactly."
    ),
)


def render() -> None:
    from ui import media_tab
    media_tab.render(ADAPTER)
