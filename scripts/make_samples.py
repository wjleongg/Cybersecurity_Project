"""Generate the sample files and the test evidence for the submission.

Run from the project root:

    python -m scripts.make_samples

Produces, under samples/ and test_evidence/:

  - a cover PNG and a cover WAV
  - a protected (stego) version of each
  - a tampered version of each
  - the demo keypair
  - a markdown evidence log recording every case and the verdict it produced

Everything is deterministic apart from the keypair, the nonce and the AES
salt, so re-running gives the same files and the same verdicts. That matters
because the evidence log is a submission item: a marker should be able to run
this and get what the log says they will.
"""

import io
import json
import pathlib
import sys
import wave

import numpy as np
from PIL import Image

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from core import attacks, audio_stego, crypto_utils, engine, image_stego  # noqa: E402
from core import payload as pm  # noqa: E402
from ui import messages  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"
EVIDENCE = ROOT / "test_evidence"
KEYS = ROOT / "keys"

STEGO_KEY = "inf2005-p1-4-shared-stego-key"
WRONG_STEGO_KEY = "an-attacker-guess"
MSG_PASSPHRASE = "confidential-demo-passphrase"
ISSUER = "Team P1-4"


# --------------------------------------------------------------------------
# Cover generation
# --------------------------------------------------------------------------

def make_cover_image(width=800, height=600) -> bytes:
    """A synthetic but photograph-like image.

    Deliberately built from smooth gradients with a little fine grain, rather
    than random noise. Noise would hide LSB changes trivially and make the
    before/after comparison meaningless. Large flat and softly graded areas
    are the hardest case for LSB embedding, so if artefacts were going to be
    visible anywhere, they would be visible here.

    Substitute a real photograph for the demo if you have one. This exists so
    the repository is runnable out of the box, not because a synthetic image
    is preferable.
    """
    xs = np.linspace(0, 1, width, dtype=np.float32)
    ys = np.linspace(0, 1, height, dtype=np.float32)
    gx, gy = np.meshgrid(xs, ys)

    # A muted sky-to-ground gradient with a soft horizon.
    horizon = 0.58
    sky = np.clip((horizon - gy) / horizon, 0, 1)
    ground = np.clip((gy - horizon) / (1 - horizon), 0, 1)

    r = 0.42 + 0.30 * sky * (0.5 + 0.5 * gx) + 0.24 * ground
    g = 0.50 + 0.26 * sky + 0.20 * ground * (0.7 + 0.3 * (1 - gx))
    b = 0.62 + 0.24 * sky - 0.16 * ground

    # Low hills along the horizon, so the frame has an edge in it.
    ridge = horizon + 0.035 * np.sin(7.0 * gx + 0.6) + 0.02 * np.sin(17.0 * gx)
    hill = (gy > ridge) & (gy < ridge + 0.16)
    r = np.where(hill, r * 0.74, r)
    g = np.where(hill, g * 0.80, g)
    b = np.where(hill, b * 0.72, b)

    # A low sun, and a couple of soft cloud masses.
    for cx, cy, rad, tint, power in [
        (0.72, 0.28, 0.13, (0.30, 0.20, 0.02), 2.0),
        (0.24, 0.20, 0.22, (0.10, 0.10, 0.12), 1.4),
        (0.55, 0.13, 0.16, (0.08, 0.08, 0.10), 1.4),
    ]:
        d = np.sqrt((gx - cx) ** 2 + ((gy - cy) * 1.5) ** 2)
        m = np.clip(1.0 - d / rad, 0.0, 1.0) ** power
        r = r + tint[0] * m
        g = g + tint[1] * m
        b = b + tint[2] * m

    # Faint deterministic grain, the way a real sensor would leave it.
    grain = np.sin(gx * 811.0) * np.cos(gy * 727.0) * 0.006
    stack = np.clip(np.stack([r, g, b], axis=-1) + grain[..., None], 0, 1)

    arr = (stack * 255).astype(np.uint8)
    buf = io.BytesIO()
    Image.fromarray(arr, "RGB").save(buf, format="PNG")
    return buf.getvalue()


def make_cover_audio(seconds=5.0, rate=44100, channels=2) -> bytes:
    """A short musical phrase in 16-bit stereo PCM.

    Tonal rather than noise, for the same reason the image is smooth: LSB
    noise is easiest to hear against a clean tone, so a clean tone is the
    honest test.
    """
    n = int(seconds * rate)
    t = np.arange(n, dtype=np.float32) / rate

    chords = [
        (0.0, 1.25, [261.63, 329.63, 392.00]),   # C major
        (1.25, 2.50, [293.66, 349.23, 440.00]),  # D minor
        (2.50, 3.75, [329.63, 392.00, 493.88]),  # E minor
        (3.75, 5.00, [261.63, 329.63, 392.00]),  # C major
    ]

    left = np.zeros(n, dtype=np.float32)
    right = np.zeros(n, dtype=np.float32)

    for begin, end, freqs in chords:
        i0, i1 = int(begin * rate), min(n, int(end * rate))
        seg_t = t[i0:i1] - begin
        env = np.exp(-1.6 * seg_t) * (1 - np.exp(-60.0 * seg_t))
        for k, f in enumerate(freqs):
            wave_l = np.sin(2 * np.pi * f * seg_t)
            wave_r = np.sin(2 * np.pi * f * seg_t + 0.06 * (k + 1))
            left[i0:i1] += env * wave_l / len(freqs)
            right[i0:i1] += env * wave_r / len(freqs)

    peak = max(float(np.abs(left).max()), float(np.abs(right).max()), 1e-6)
    left = (left / peak) * 0.72
    right = (right / peak) * 0.72

    interleaved = np.empty(n * channels, dtype=np.float32)
    interleaved[0::2] = left
    interleaved[1::2] = right
    pcm = (interleaved * 32767).astype(np.int16)

    buf = io.BytesIO()
    with wave.open(buf, "wb") as out:
        out.setnchannels(channels)
        out.setsampwidth(2)
        out.setframerate(rate)
        out.writeframes(pcm.tobytes())
    return buf.getvalue()


# --------------------------------------------------------------------------
# Case runner
# --------------------------------------------------------------------------

class Log:
    """Collects case results for the evidence file."""

    def __init__(self):
        self.rows = []

    def add(self, media, case, expected, result, note=""):
        actual = result.verdict.value
        self.rows.append(
            {
                "media": media,
                "case": case,
                "expected": expected,
                "actual": actual,
                "match": "yes" if actual == expected else "NO",
                "note": note or result.reason,
            }
        )
        flag = "ok " if actual == expected else "MISMATCH"
        print(f"  [{flag}] {media:5s} {case:42s} -> {actual}")


def run_media_cases(log, media_type, cover_bytes, load, rebuild_attr, attack_set, kp, other_kp):
    """Run every positive and negative case for one cover object."""
    print(f"\n{media_type.upper()} cases")
    cover = load(cover_bytes)
    prefix = "image" if media_type == "image" else "audio"
    written = {}

    # POSITIVE 1: short message, derived location
    r1 = engine.encode(
        cover, media_type, messages.SHORT_MESSAGE.encode(), ISSUER, 2, STEGO_KEY, kp.private_key
    )
    stego1 = getattr(cover, rebuild_attr)(r1.stego_carriers)
    written[f"stego_{prefix}.png" if media_type == "image" else f"stego_{prefix}.wav"] = stego1
    v = engine.verify(load(stego1), media_type, 2, STEGO_KEY, kp.public_key)
    log.add(media_type, "P1 short payload, derived location", "Authentic", v)

    # POSITIVE 2: large message, higher LSB depth
    r2 = engine.encode(
        cover, media_type, messages.LARGE_MESSAGE.encode(), ISSUER, 3, STEGO_KEY, kp.private_key
    )
    stego2 = getattr(cover, rebuild_attr)(r2.stego_carriers)
    v = engine.verify(load(stego2), media_type, 3, STEGO_KEY, kp.public_key)
    log.add(media_type, "P2 large payload at 3 LSB", "Authentic", v)

    # POSITIVE 3: encrypted custom payload
    r3 = engine.encode(
        cover, media_type, messages.CUSTOM_DEFAULT.encode(), ISSUER, 2, STEGO_KEY,
        kp.private_key, passphrase=MSG_PASSPHRASE,
    )
    stego3 = getattr(cover, rebuild_attr)(r3.stego_carriers)
    key = f"stego_{prefix}_encrypted.png" if media_type == "image" else f"stego_{prefix}_encrypted.wav"
    written[key] = stego3
    v = engine.verify(
        load(stego3), media_type, 2, STEGO_KEY, kp.public_key, passphrase=MSG_PASSPHRASE
    )
    ok = v.payload is not None and v.payload.as_text() == messages.CUSTOM_DEFAULT
    log.add(
        media_type, "P3 encrypted custom payload", "Authentic", v,
        note=f"message recovered: {ok}",
    )

    # POSITIVE 4: a file payload, played or displayed rather than read
    thumb = make_cover_image(120, 90)
    r4f = engine.encode(
        cover, media_type, thumb, ISSUER, 3, STEGO_KEY, kp.private_key,
        kind=pm.KIND_FILE, filename="thumbnail.png",
    )
    stego4f = getattr(cover, rebuild_attr)(r4f.stego_carriers)
    key = (
        f"stego_{prefix}_filepayload.png" if media_type == "image"
        else f"stego_{prefix}_filepayload.wav"
    )
    written[key] = stego4f
    v = engine.verify(load(stego4f), media_type, 3, STEGO_KEY, kp.public_key)
    exact = v.payload is not None and v.payload.data == thumb
    log.add(
        media_type, "P4 hidden PNG file payload", "Authentic", v,
        note=f"{len(thumb):,} byte PNG embedded; bytes identical on extraction: {exact}",
    )

    # NEGATIVE 1: tampered media, payload planes preserved
    attacked, desc = list(attack_set.values())[0](r1.stego_carriers, {"start": r1.start_index, "n_lsb": 2})
    tampered = getattr(cover, rebuild_attr)(attacked)
    key = f"tampered_{prefix}.png" if media_type == "image" else f"tampered_{prefix}.wav"
    written[key] = tampered
    v = engine.verify(load(tampered), media_type, 2, STEGO_KEY, kp.public_key)
    log.add(media_type, "N1 media edited after signing", "Tampered", v, note=desc)

    # NEGATIVE 2: wrong public key
    v = engine.verify(load(stego1), media_type, 2, STEGO_KEY, other_kp.public_key)
    log.add(media_type, "N2 verified with a different public key", "Signature Invalid", v)

    # NEGATIVE 3: payload corrupted
    corrupted, desc = attacks.corrupt_payload_region(r1.stego_carriers, r1.start_index, 2)
    v = engine.verify(
        load(getattr(cover, rebuild_attr)(corrupted)), media_type, 2, STEGO_KEY, kp.public_key
    )
    log.add(media_type, "N3 embedded payload corrupted", "Signature Invalid", v, note=desc)

    # NEGATIVE 4: no payload present
    v = engine.verify(cover, media_type, 2, STEGO_KEY, kp.public_key)
    log.add(media_type, "N4 unprotected cover object", "Payload Missing", v)

    # NEGATIVE 5: wrong stego key
    v = engine.verify(load(stego1), media_type, 2, WRONG_STEGO_KEY, kp.public_key)
    log.add(media_type, "N5 wrong stego key", "Payload Missing", v)

    # NEGATIVE 6: wrong start location
    manual = min(50_000, cover.num_carriers - 1)
    r4 = engine.encode(
        cover, media_type, messages.SHORT_MESSAGE.encode(), ISSUER, 2, STEGO_KEY,
        kp.private_key, start_mode="manual", manual_offset=manual,
    )
    stego4 = getattr(cover, rebuild_attr)(r4.stego_carriers)
    v = engine.verify(load(stego4), media_type, 2, STEGO_KEY, kp.public_key)
    log.add(
        media_type, "N6 embedded manually, verified with derived offset",
        "Wrong Start Location", v, note=f"embedded at carrier {manual:,}",
    )

    # NEGATIVE 7: wrong LSB depth
    v = engine.verify(load(stego1), media_type, 5, STEGO_KEY, kp.public_key)
    log.add(media_type, "N7 wrong LSB depth at verification", "Payload Missing", v)

    # NEGATIVE 8: capacity refusal
    huge = "x" * (cover.num_carriers // 4)
    try:
        engine.encode(cover, media_type, huge.encode(), ISSUER, 1, STEGO_KEY, kp.private_key)
        print(f"  [MISMATCH] {media_type} N8 oversized payload was not refused")
        log.rows.append({
            "media": media_type, "case": "N8 payload larger than capacity",
            "expected": "refused", "actual": "accepted", "match": "NO", "note": "",
        })
    except engine.EncodeError as exc:
        print(f"  [ok ] {media_type:5s} {'N8 payload larger than capacity':42s} -> refused")
        log.rows.append({
            "media": media_type, "case": "N8 payload larger than capacity",
            "expected": "refused", "actual": "refused", "match": "yes", "note": str(exc),
        })

    # Quality numbers for the positive case
    if media_type == "image":
        stats = image_stego.difference_stats(cover.carriers, r1.stego_carriers)
        quality = f"PSNR {stats['psnr_db']:.1f} dB"
    else:
        stats = audio_stego.difference_stats(cover, r1.stego_carriers)
        quality = f"SNR {stats['snr_db']:.1f} dB"

    return written, {
        "carriers": cover.num_carriers,
        "changed": stats["changed"],
        "changed_pct": round(stats["changed_pct"], 3),
        "max_delta": stats["max_delta"],
        "quality": quality,
        "container_bytes": r1.container_bytes,
        "derived_start": r1.start_index,
    }


def main() -> int:
    for d in (SAMPLES, EVIDENCE, KEYS):
        d.mkdir(parents=True, exist_ok=True)

    print("Generating cover objects")
    cover_png = make_cover_image()
    cover_wav = make_cover_audio()
    (SAMPLES / "cover_image.png").write_bytes(cover_png)
    (SAMPLES / "cover_audio.wav").write_bytes(cover_wav)
    print(f"  cover_image.png  {len(cover_png):,} bytes")
    print(f"  cover_audio.wav  {len(cover_wav):,} bytes")

    kp = crypto_utils.generate_keypair()
    other_kp = crypto_utils.generate_keypair()
    (KEYS / "demo_private_key.pem").write_bytes(
        crypto_utils.serialize_private_key(kp.private_key)
    )
    (KEYS / "demo_public_key.pem").write_bytes(
        crypto_utils.serialize_public_key(kp.public_key)
    )
    (KEYS / "other_party_public_key.pem").write_bytes(
        crypto_utils.serialize_public_key(other_kp.public_key)
    )
    print(f"\nDemo keypair fingerprint     {kp.fingerprint}")
    print(f"Other party fingerprint      {other_kp.fingerprint}")

    log = Log()

    img_files, img_stats = run_media_cases(
        log, "image", cover_png, image_stego.load_image, "to_png_bytes",
        attacks.IMAGE_ATTACKS, kp, other_kp,
    )
    aud_files, aud_stats = run_media_cases(
        log, "audio", cover_wav, audio_stego.load_audio, "to_wav_bytes",
        attacks.AUDIO_ATTACKS, kp, other_kp,
    )

    for name, data in {**img_files, **aud_files}.items():
        (SAMPLES / name).write_bytes(data)

    _write_evidence(log, kp, other_kp, img_stats, aud_stats)

    mismatches = [r for r in log.rows if r["match"] != "yes"]
    print(f"\n{len(log.rows)} cases, {len(mismatches)} mismatches")
    return 1 if mismatches else 0


def _write_evidence(log, kp, other_kp, img_stats, aud_stats) -> None:
    """Write the markdown evidence log and a machine-readable copy."""
    lines = [
        "# Test evidence",
        "",
        "Generated by `python -m scripts.make_samples`. Every row below was produced",
        "by running the same engine the GUI calls.",
        "",
        f"- Stego key: `{STEGO_KEY}`",
        f"- Message passphrase (encrypted cases): `{MSG_PASSPHRASE}`",
        f"- Demo public key fingerprint: `{kp.fingerprint}`",
        f"- Other-party public key fingerprint: `{other_kp.fingerprint}`",
        "",
        "## Cover object statistics, positive case at 2 LSB",
        "",
        "| Measure | Image | Audio |",
        "| --- | --- | --- |",
        f"| Carriers | {img_stats['carriers']:,} | {aud_stats['carriers']:,} |",
        f"| Container size | {img_stats['container_bytes']:,} bytes | {aud_stats['container_bytes']:,} bytes |",
        f"| Derived start carrier | {img_stats['derived_start']:,} | {aud_stats['derived_start']:,} |",
        f"| Carriers changed | {img_stats['changed']:,} ({img_stats['changed_pct']}%) | {aud_stats['changed']:,} ({aud_stats['changed_pct']}%) |",
        f"| Max delta | {img_stats['max_delta']} | {aud_stats['max_delta']} |",
        f"| Quality | {img_stats['quality']} | {aud_stats['quality']} |",
        "",
        "## Cases",
        "",
        "| Media | Case | Expected | Actual | Match |",
        "| --- | --- | --- | --- | --- |",
    ]
    for r in log.rows:
        lines.append(
            f"| {r['media']} | {r['case']} | {r['expected']} | {r['actual']} | {r['match']} |"
        )

    lines += ["", "## Notes", ""]
    for r in log.rows:
        if r["note"]:
            lines.append(f"- **{r['media']} / {r['case']}** — {r['note']}")

    (EVIDENCE / "test_evidence.md").write_text("\n".join(lines) + "\n")
    (EVIDENCE / "test_evidence.json").write_text(json.dumps(log.rows, indent=2))
    print(f"\nWrote {EVIDENCE / 'test_evidence.md'}")


if __name__ == "__main__":
    sys.exit(main())