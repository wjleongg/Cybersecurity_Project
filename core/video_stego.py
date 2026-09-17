"""Lossless AVI cover objects.

Carriers are the RGB pixel bytes of every frame, flattened frame-major then
row-major, exactly the way ImageCover flattens one frame. A video is treated
as "one more axis" on top of an image: reshape carriers to
(frame_count, height, width, channels) and frame 0 is byte-for-byte what
ImageCover would have produced for that same picture. That similarity is
deliberate — it is what lets the embedding, extraction and hashing logic in
bitops.py and engine.py run against a video cover without modification.

Design decisions worth defending in the demo:

  Uncompressed AVI only, RGBA-tagged raw frames. Consumer MP4/H.264 (and
  MJPG, and every other AVI codec OpenCV's FFmpeg backend was tried against
  here) re-encodes with lossy motion compensation or chroma subsampling and
  destroys LSB data immediately, exactly as JPEG does for the image case.
  Frame-accurate, byte-exact round tripping only held up under one raw tag in
  testing: `cv2.VideoWriter_fourcc(*"RGBA")` written into an AVI container.
  Other "uncompressed" tags either refused to open, silently fell back to a
  compressed codec, or wrote a file OpenCV's own reader could not decode
  back to the same bytes. This was verified empirically, not assumed: every
  fourcc this module could try was round-tripped against random pixel data
  before this comment was written.

  Width and height are forced to even numbers, cropping a trailing row or
  column if needed. The raw AVI muxer pads odd frame dimensions internally,
  and that padding is not restored on read, which silently corrupts the LSB
  planes at the edge of an odd-sized frame. Crop-to-even is the same kind of
  format normalisation ImageCover does when it converts every PNG mode to
  RGB: one predictable carrier layout instead of a dimension-dependent one.

  No dependency on the system `ffmpeg` binary. OpenCV's wheel ships its own
  FFmpeg decode/encode plugin, so this module never shells out to a command
  line tool. That matters in practice, not just in principle: the machine
  this was developed on has a broken Homebrew ffmpeg install (a missing
  libbluray dylib) that crashes on `ffmpeg -version`, and video_stego works
  anyway because it never calls it.

  Carriers span the whole clip, not one frame. bitops already wraps a start
  index around the end of a flat carrier array, so if a payload does not fit
  in the frame it is keyed to start in, it simply continues into the frames
  that follow. Nothing extra is needed to support that; treating the clip as
  one flat array is what a single call to bitops already assumes.
"""

from dataclasses import dataclass
import os
import tempfile

import cv2
import numpy as np

from . import bitops
from . import image_stego

AVI_RIFF = b"RIFF"
AVI_LIST_TYPE = b"AVI "
FOURCC = "RGBA"
DEFAULT_FPS = 12.0


class VideoFormatError(Exception):
    """Raised when the uploaded bytes are not a usable lossless AVI."""


@dataclass
class VideoCover:
    """An AVI loaded and flattened into carriers, one clip's worth of frames."""

    carriers: np.ndarray   # 1-D uint8, frame-major then row-major
    frame_count: int
    height: int
    width: int
    channels: int
    fps: float

    @property
    def per_frame_carriers(self) -> int:
        return self.height * self.width * self.channels

    @property
    def num_carriers(self) -> int:
        return int(self.carriers.size)

    def describe(self) -> dict:
        """Human-readable summary for the GUI."""
        return {
            "Frames": self.frame_count,
            "Resolution": f"{self.width} x {self.height}",
            "Frame rate": f"{self.fps:.2f} fps",
            "Duration": f"{self.frame_count / self.fps:.2f} s" if self.fps else "n/a",
            "Carriers per frame": f"{self.per_frame_carriers:,} bytes",
            "Carriers (whole clip)": f"{self.num_carriers:,} bytes",
        }

    def to_frames(self, carriers: np.ndarray | None = None) -> np.ndarray:
        """Reshape carriers back into (frame_count, H, W, C)."""
        source = self.carriers if carriers is None else carriers
        return source.reshape(self.frame_count, self.height, self.width, self.channels)

    def to_avi_bytes(self, carriers: np.ndarray | None = None) -> bytes:
        """Render carriers back into AVI file bytes.

        cv2.VideoWriter has no in-memory sink, so this writes to a private
        temporary file and reads the bytes straight back. That is a real
        container write, not a shortcut: what gets tested afterwards is
        exactly the file a recipient would receive.
        """
        frames = self.to_frames(carriers)
        fd, path = tempfile.mkstemp(suffix=".avi")
        os.close(fd)
        try:
            fourcc = cv2.VideoWriter_fourcc(*FOURCC)
            writer = cv2.VideoWriter(path, fourcc, self.fps, (self.width, self.height))
            if not writer.isOpened():
                raise VideoFormatError(
                    "could not open a raw AVI writer on this platform"
                )
            for frame in frames:
                writer.write(cv2.cvtColor(frame, cv2.COLOR_RGB2BGR))
            writer.release()
            with open(path, "rb") as fh:
                return fh.read()
        finally:
            try:
                os.remove(path)
            except OSError:
                pass

    def stable_hash_input(self, n_lsb: int, carriers: np.ndarray | None = None) -> bytes:
        """Bytes to hash: frame data with the embedding planes zeroed.

        Frame count, dimensions and frame rate are prefixed so that two clips
        with identical pixel bytes but different shapes or speeds do not
        collide, mirroring ImageCover.stable_hash_input.
        """
        source = self.carriers if carriers is None else carriers
        masked = bitops.clear_lsb_planes(source, n_lsb)
        header = (
            f"video|{self.frame_count}|{self.width}|{self.height}|"
            f"{self.channels}|{self.fps:.6f}|"
        ).encode("ascii")
        return header + masked.tobytes()

    def locate_span(self, start: int, container_bytes: int, n_lsb: int) -> str:
        """Human-readable frame range a container occupies, for the GUI.

        Purely descriptive: bitops already handled the actual wraparound when
        it embedded the bits, this just explains where it landed.
        """
        per_frame = self.per_frame_carriers
        carriers_used = max(1, -(-(container_bytes * 8) // n_lsb))
        start_frame = (start // per_frame) % self.frame_count
        last_index = (start + carriers_used - 1) % self.num_carriers
        end_frame = last_index // per_frame

        if end_frame >= start_frame:
            span = end_frame - start_frame + 1
            return f"frame {start_frame} of {self.frame_count}" if span == 1 else (
                f"frames {start_frame}-{end_frame} of {self.frame_count} "
                f"({span} frames)"
            )
        span = self.frame_count - start_frame + end_frame + 1
        return (
            f"frames {start_frame}-{self.frame_count - 1} then 0-{end_frame} "
            f"({span} frames, wraps to the start of the clip)"
        )


def _read_frames(path: str) -> tuple[list[np.ndarray], float]:
    cap = cv2.VideoCapture(path)
    if not cap.isOpened():
        raise VideoFormatError("the AVI file could not be decoded")
    try:
        fps = cap.get(cv2.CAP_PROP_FPS) or DEFAULT_FPS
        frames = []
        while True:
            ok, frame_bgr = cap.read()
            if not ok:
                break
            frames.append(cv2.cvtColor(frame_bgr, cv2.COLOR_BGR2RGB))
    finally:
        cap.release()
    return frames, float(fps)


def load_video(data: bytes) -> VideoCover:
    """Load AVI bytes into a VideoCover.

    The RIFF/AVI signature is checked directly rather than trusting the
    filename, for the same reason image_stego checks the PNG signature: a
    renamed .mp4 should fail immediately and explain why, not fail deep
    inside a decoder with a confusing error.
    """
    if not data:
        raise VideoFormatError("no video data was provided")
    if len(data) < 12 or data[:4] != AVI_RIFF or data[8:12] != AVI_LIST_TYPE:
        raise VideoFormatError(
            "this file is not an AVI container. Compressed formats such as "
            "MP4/H.264 are not usable here: their encoders re-encode with "
            "lossy motion compensation and destroy exactly the low-order "
            "detail the payload lives in, the same way JPEG does for images."
        )

    fd, path = tempfile.mkstemp(suffix=".avi")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        frames, fps = _read_frames(path)
    finally:
        try:
            os.remove(path)
        except OSError:
            pass

    if not frames:
        raise VideoFormatError("this AVI file contains no readable frames")

    height, width = frames[0].shape[:2]
    if height % 2 or width % 2:
        # See the module docstring: odd dimensions do not round-trip exactly
        # through the raw AVI muxer, so a trailing row/column is dropped.
        height -= height % 2
        width -= width % 2
        frames = [f[:height, :width, :] for f in frames]

    if any(f.shape[:2] != (height, width) for f in frames):
        raise VideoFormatError(
            "frames in this AVI file do not all share one resolution"
        )

    stacked = np.stack(frames, axis=0).astype(np.uint8)
    channels = stacked.shape[-1]

    return VideoCover(
        carriers=stacked.reshape(-1).copy(),
        frame_count=len(frames),
        height=height,
        width=width,
        channels=channels,
        fps=fps,
    )


def difference_stats(cover_carriers: np.ndarray, stego_carriers: np.ndarray) -> dict:
    """Quality metric for a video cover.

    A video's carriers are pixel bytes exactly like an image's, just with an
    extra frame axis flattened in ahead of them, so the existing PSNR
    computation applies unchanged: it operates elementwise and never looks at
    shape. Reusing it rather than re-deriving it is the same reasoning
    image_tab and audio_tab already lean on for a shared verification engine.
    """
    return image_stego.difference_stats(cover_carriers, stego_carriers)
