"""WAV/PCM cover objects.

Carriers are individual audio samples, interleaved across channels exactly as
they are stored in the file. A 3-second 44.1 kHz stereo clip offers roughly
264,600 carriers.

Design decisions worth defending in the demo:

  Uncompressed PCM only. MP3, AAC and Opus are perceptual codecs: they discard
  information the ear is unlikely to notice, and the LSB of a sample is
  precisely the sort of information they discard. A payload embedded before
  MP3 encoding does not survive it.

  16-bit is the working baseline, 8-bit is accepted. These differ in more than
  width: 16-bit PCM samples are signed, 8-bit PCM samples are unsigned with a
  silent midpoint of 128. Reading 8-bit data as signed produces samples that
  are wrong by 128 and audio that sounds broken, so the two are handled
  separately rather than assumed identical.

  Samples are manipulated as unsigned integers. Bit masking on a signed type
  is ambiguous around the sign bit, so 16-bit samples are viewed as uint16 for
  the duration of the embedding and viewed straight back afterwards. The
  underlying bits never move; only their interpretation does.

  Perceptual note: at high LSB depths audio degrades audibly long before an
  image looks wrong, because the ear is sensitive to broadband noise. This is
  a real finding to demonstrate, not a bug.
"""

from dataclasses import dataclass
import io
import wave

import numpy as np

from . import bitops

RIFF_MAGIC = b"RIFF"
WAVE_MAGIC = b"WAVE"
SUPPORTED_SAMPLE_WIDTHS = (1, 2)


class AudioFormatError(Exception):
    """Raised when the uploaded bytes are not a usable WAV/PCM file."""


@dataclass
class AudioCover:
    """A WAV file loaded and flattened into sample carriers."""

    carriers: np.ndarray   # 1-D uint8 or uint16
    n_channels: int
    sample_width: int      # bytes per sample
    frame_rate: int
    n_frames: int

    @property
    def num_carriers(self) -> int:
        return int(self.carriers.size)

    @property
    def duration_seconds(self) -> float:
        return self.n_frames / self.frame_rate if self.frame_rate else 0.0

    @property
    def bit_depth(self) -> int:
        return self.sample_width * 8

    def describe(self) -> dict:
        """Human-readable summary for the GUI."""
        return {
            "Duration": f"{self.duration_seconds:.2f} s",
            "Sample rate": f"{self.frame_rate:,} Hz",
            "Channels": self.n_channels,
            "Bit depth": f"{self.bit_depth}-bit PCM",
            "Carriers": f"{self.num_carriers:,} samples",
        }

    def to_wav_bytes(self, carriers: np.ndarray | None = None) -> bytes:
        """Render carriers back into WAV file bytes with the original params."""
        source = self.carriers if carriers is None else carriers
        if self.sample_width == 2:
            frames = source.astype(np.uint16).view(np.int16).tobytes()
        else:
            frames = source.astype(np.uint8).tobytes()

        buf = io.BytesIO()
        with wave.open(buf, "wb") as out:
            out.setnchannels(self.n_channels)
            out.setsampwidth(self.sample_width)
            out.setframerate(self.frame_rate)
            out.writeframes(frames)
        return buf.getvalue()

    def stable_hash_input(self, n_lsb: int, carriers: np.ndarray | None = None) -> bytes:
        """Bytes to hash: sample data with the embedding planes zeroed."""
        source = self.carriers if carriers is None else carriers
        masked = bitops.clear_lsb_planes(source, n_lsb)
        header = (
            f"audio|{self.n_channels}|{self.sample_width}|"
            f"{self.frame_rate}|{self.n_frames}|"
        ).encode("ascii")
        return header + masked.tobytes()

    def to_float_waveform(self, carriers: np.ndarray | None = None) -> np.ndarray:
        """Samples as floats in roughly [-1, 1], for plotting only."""
        source = self.carriers if carriers is None else carriers
        if self.sample_width == 2:
            signed = source.astype(np.uint16).view(np.int16).astype(np.float32)
            return signed / 32768.0
        return (source.astype(np.float32) - 128.0) / 128.0


def load_audio(data: bytes) -> AudioCover:
    """Load WAV bytes into an AudioCover, checking the RIFF header directly."""
    if not data:
        raise AudioFormatError("no audio data was provided")
    if len(data) < 12 or data[:4] != RIFF_MAGIC or data[8:12] != WAVE_MAGIC:
        raise AudioFormatError(
            "this file is not a RIFF/WAVE container. Compressed formats such "
            "as MP3 are not usable here: their encoders discard exactly the "
            "low-order detail the payload lives in."
        )

    try:
        with wave.open(io.BytesIO(data), "rb") as src:
            n_channels = src.getnchannels()
            sample_width = src.getsampwidth()
            frame_rate = src.getframerate()
            n_frames = src.getnframes()
            frames = src.readframes(n_frames)
    except wave.Error as exc:
        raise AudioFormatError(f"the WAV file could not be read: {exc}") from exc

    if sample_width not in SUPPORTED_SAMPLE_WIDTHS:
        raise AudioFormatError(
            f"{sample_width * 8}-bit WAV is not supported. Use 8-bit or 16-bit "
            "PCM. 24-bit samples have no native numpy integer width and 32-bit "
            "float WAV has no meaningful least significant bit."
        )

    if sample_width == 2:
        carriers = np.frombuffer(frames, dtype=np.int16).view(np.uint16).copy()
    else:
        carriers = np.frombuffer(frames, dtype=np.uint8).copy()

    if carriers.size == 0:
        raise AudioFormatError("this WAV file contains no audio samples")

    return AudioCover(
        carriers=carriers,
        n_channels=n_channels,
        sample_width=sample_width,
        frame_rate=frame_rate,
        n_frames=n_frames,
    )


def difference_stats(cover: AudioCover, stego_carriers: np.ndarray) -> dict:
    """Quantify the audible drift introduced by embedding.

    SNR is reported instead of PSNR because audio quality is conventionally
    described relative to signal power, not to a fixed peak.
    """
    a = cover.to_float_waveform().astype(np.float64)
    b = cover.to_float_waveform(stego_carriers).astype(np.float64)
    noise = b - a

    changed = int(np.count_nonzero(cover.carriers != stego_carriers))
    signal_power = float(np.mean(a ** 2))
    noise_power = float(np.mean(noise ** 2))
    snr = float("inf") if noise_power == 0 else 10.0 * np.log10(signal_power / noise_power)

    # Compare in the signed domain. For 16-bit PCM a raw unsigned subtraction
    # would misreport any sample that sits near the sign boundary.
    if cover.sample_width == 2:
        sa = cover.carriers.astype(np.uint16).view(np.int16).astype(np.int64)
        sb = stego_carriers.astype(np.uint16).view(np.int16).astype(np.int64)
    else:
        sa = cover.carriers.astype(np.int64)
        sb = stego_carriers.astype(np.int64)
    raw_diff = np.abs(sa - sb)
    return {
        "changed": changed,
        "total": int(cover.carriers.size),
        "changed_pct": (changed / cover.carriers.size * 100.0) if cover.carriers.size else 0.0,
        "max_delta": int(raw_diff.max()) if raw_diff.size else 0,
        "snr_db": snr,
    }
