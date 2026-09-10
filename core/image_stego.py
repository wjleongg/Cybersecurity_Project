"""PNG cover objects.

Carriers are the individual colour channel bytes of the image, flattened in
row-major order. A 640x480 RGB image therefore offers 921,600 carriers.

Design decisions worth defending in the demo:

  PNG only, by default. PNG is losslessly compressed, so the bytes written to
  the LSB planes survive a save/load cycle exactly. JPEG re-encodes with a
  lossy DCT and would destroy the payload immediately, which is why the brief
  asks any team using JPEG to explain the limitation rather than ignore it.

  Everything is converted to RGB on load. PNG legally comes in palette,
  grayscale, RGB and RGBA modes, and each has a different relationship between
  "a byte in the file" and "a pixel on screen". Normalising to RGB gives one
  carrier layout to reason about instead of four.

  Alpha is dropped rather than carried. Writing into an alpha channel is more
  visible than writing into colour, because a viewer may composite a partly
  transparent pixel against an arbitrary background.
"""

from dataclasses import dataclass
import io

import numpy as np
from PIL import Image

from . import bitops

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


class ImageFormatError(Exception):
    """Raised when the uploaded bytes are not a usable PNG."""


@dataclass
class ImageCover:
    """A PNG loaded and flattened into carriers."""

    carriers: np.ndarray   # 1-D uint8
    height: int
    width: int
    channels: int
    had_alpha: bool
    original_mode: str

    @property
    def num_carriers(self) -> int:
        return int(self.carriers.size)

    def describe(self) -> dict:
        """Human-readable summary for the GUI."""
        return {
            "Dimensions": f"{self.width} x {self.height}",
            "Mode on load": self.original_mode,
            "Working mode": "RGB" + (" (alpha dropped)" if self.had_alpha else ""),
            "Channels": self.channels,
            "Carriers": f"{self.num_carriers:,} bytes",
        }

    def to_array(self, carriers: np.ndarray | None = None) -> np.ndarray:
        """Reshape a carrier array back into an (H, W, C) image array."""
        source = self.carriers if carriers is None else carriers
        return source.reshape(self.height, self.width, self.channels)

    def to_png_bytes(self, carriers: np.ndarray | None = None) -> bytes:
        """Render carriers back into PNG file bytes."""
        arr = self.to_array(carriers)
        buf = io.BytesIO()
        Image.fromarray(arr, mode="RGB").save(buf, format="PNG", optimize=False)
        return buf.getvalue()

    def stable_hash_input(self, n_lsb: int, carriers: np.ndarray | None = None) -> bytes:
        """Bytes to hash: pixel data with the embedding planes zeroed.

        Dimensions are prefixed so that two images with identical pixel bytes
        but different shapes do not collide.
        """
        source = self.carriers if carriers is None else carriers
        masked = bitops.clear_lsb_planes(source, n_lsb)
        header = f"image|{self.width}|{self.height}|{self.channels}|".encode("ascii")
        return header + masked.tobytes()


def load_image(data: bytes) -> ImageCover:
    """Load PNG bytes into an ImageCover.

    The PNG signature is checked directly rather than trusting the filename,
    because a renamed .jpg would otherwise pass an extension filter and then
    fail confusingly much later.
    """
    if not data:
        raise ImageFormatError("no image data was provided")
    if not data.startswith(PNG_SIGNATURE):
        raise ImageFormatError(
            "this file is not a PNG. The first bytes do not match the PNG "
            "signature, whatever the file is named."
        )

    try:
        img = Image.open(io.BytesIO(data))
        img.load()
    except Exception as exc:
        raise ImageFormatError(f"the PNG could not be decoded: {exc}") from exc

    original_mode = img.mode
    had_alpha = original_mode in ("RGBA", "LA", "PA") or (
        original_mode == "P" and "transparency" in img.info
    )

    if original_mode != "RGB":
        img = img.convert("RGB")

    arr = np.asarray(img, dtype=np.uint8)
    if arr.ndim != 3 or arr.shape[2] != 3:
        raise ImageFormatError(f"unexpected image shape after conversion: {arr.shape}")

    height, width, channels = arr.shape
    return ImageCover(
        carriers=arr.reshape(-1).copy(),
        height=height,
        width=width,
        channels=channels,
        had_alpha=had_alpha,
        original_mode=original_mode,
    )


def difference_stats(cover: np.ndarray, stego: np.ndarray) -> dict:
    """Quantify how far the stego object drifted from the cover.

    Reported in the GUI so "looks identical" is backed by a number rather than
    left to the marker's eyesight.
    """
    a = cover.astype(np.int32)
    b = stego.astype(np.int32)
    diff = np.abs(a - b)
    changed = int(np.count_nonzero(diff))
    mse = float(np.mean((a - b) ** 2))
    psnr = float("inf") if mse == 0 else 10.0 * np.log10((255.0 ** 2) / mse)
    return {
        "changed": changed,
        "total": int(a.size),
        "changed_pct": (changed / a.size * 100.0) if a.size else 0.0,
        "max_delta": int(diff.max()) if diff.size else 0,
        "psnr_db": psnr,
    }
