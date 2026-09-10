"""End-to-end checks over the core modules.

Run with:  python -m tests.test_core
"""

import io
import sys
import wave

import numpy as np
from PIL import Image

sys.path.insert(0, ".")

from core import attacks, audio_stego, crypto_utils, engine, image_stego, location
from core.engine import Verdict

PASSED = []
FAILED = []


def check(name, condition, detail=""):
    if condition:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  {detail}")


def make_png(w=160, h=120, seed=1) -> bytes:
    rng = np.random.default_rng(seed)
    arr = rng.integers(0, 256, size=(h, w, 3), dtype=np.uint8)
    buf = io.BytesIO()
    Image.fromarray(arr, "RGB").save(buf, format="PNG")
    return buf.getvalue()


def make_wav(seconds=1.0, rate=16000, channels=1, width=2, seed=2) -> bytes:
    rng = np.random.default_rng(seed)
    n = int(seconds * rate) * channels
    t = np.arange(n) / rate
    tone = (np.sin(2 * np.pi * 440 * t) * 12000).astype(np.int16)
    tone = (tone + rng.integers(-200, 200, size=n)).astype(np.int16)
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(channels)
        w.setsampwidth(width)
        w.setframerate(rate)
        w.writeframes(tone.tobytes())
    return buf.getvalue()


SHORT_MSG = "Explain how steganography can be used to embed hidden verification data."
LARGE_MSG = (
    "This undergraduate project requires student teams to design, implement and "
    "demonstrate a GUI-based LSB Replacement steganography program that protects "
    "and verifies both image and audio cover objects using steganography, hashing "
    "and digital signatures. " * 4
)

STEGO_KEY = "team-p1-4-shared-secret"
WRONG_STEGO_KEY = "not-the-right-key"


def run_media(label, load_fn, cover_bytes, rebuild_attr, media_type, attack_set):
    print(f"\n=== {label} ===")
    kp = crypto_utils.generate_keypair()
    other = crypto_utils.generate_keypair()
    cover = load_fn(cover_bytes)

    # --- positive: derived location, plaintext message
    res = engine.encode(
        cover, media_type, SHORT_MSG, "Team P1-4", 2, STEGO_KEY, kp.private_key
    )
    stego_bytes = getattr(cover, rebuild_attr)(res.stego_carriers)
    stego = load_fn(stego_bytes)
    v = engine.verify(stego, media_type, 2, STEGO_KEY, kp.public_key)
    check(f"{label}: authentic after round trip", v.verdict == Verdict.AUTHENTIC, v.reason)
    check(f"{label}: message recovered", v.message == SHORT_MSG)

    # --- carriers actually survive file rebuild
    check(
        f"{label}: carriers survive save/load",
        np.array_equal(stego.carriers, res.stego_carriers),
    )

    # --- positive: encrypted message
    res_e = engine.encode(
        cover, media_type, SHORT_MSG, "Team P1-4", 2, STEGO_KEY,
        kp.private_key, passphrase="demo-pass",
    )
    st_e = load_fn(getattr(cover, rebuild_attr)(res_e.stego_carriers))
    v_e = engine.verify(st_e, media_type, 2, STEGO_KEY, kp.public_key, passphrase="demo-pass")
    check(f"{label}: encrypted payload authentic", v_e.verdict == Verdict.AUTHENTIC, v_e.reason)
    check(f"{label}: encrypted message decrypted", v_e.message == SHORT_MSG)

    v_nopass = engine.verify(st_e, media_type, 2, STEGO_KEY, kp.public_key)
    check(
        f"{label}: authentic without passphrase, message withheld",
        v_nopass.verdict == Verdict.AUTHENTIC and v_nopass.message is None,
    )

    v_badpass = engine.verify(
        st_e, media_type, 2, STEGO_KEY, kp.public_key, passphrase="wrong"
    )
    check(
        f"{label}: wrong passphrase does not break verdict",
        v_badpass.verdict == Verdict.AUTHENTIC and v_badpass.message is None,
    )

    # --- all LSB depths
    for n in range(1, 9):
        r = engine.encode(
            cover, media_type, SHORT_MSG, "Team P1-4", n, STEGO_KEY, kp.private_key
        )
        s = load_fn(getattr(cover, rebuild_attr)(r.stego_carriers))
        vv = engine.verify(s, media_type, n, STEGO_KEY, kp.public_key)
        check(f"{label}: LSB depth {n} round trip", vv.verdict == Verdict.AUTHENTIC, vv.reason)

    # --- large payload
    r_big = engine.encode(
        cover, media_type, LARGE_MSG, "Team P1-4", 3, STEGO_KEY, kp.private_key
    )
    s_big = load_fn(getattr(cover, rebuild_attr)(r_big.stego_carriers))
    v_big = engine.verify(s_big, media_type, 3, STEGO_KEY, kp.public_key)
    check(f"{label}: large payload authentic", v_big.verdict == Verdict.AUTHENTIC, v_big.reason)
    check(f"{label}: large message intact", v_big.message == LARGE_MSG)

    # --- negative: wrong public key
    v_wrongkey = engine.verify(stego, media_type, 2, STEGO_KEY, other.public_key)
    check(
        f"{label}: wrong public key -> Signature Invalid",
        v_wrongkey.verdict == Verdict.SIGNATURE_INVALID,
        v_wrongkey.verdict,
    )

    # --- negative: wrong stego key
    v_wrongstego = engine.verify(stego, media_type, 2, WRONG_STEGO_KEY, kp.public_key)
    check(
        f"{label}: wrong stego key -> Payload Missing",
        v_wrongstego.verdict == Verdict.PAYLOAD_MISSING,
        v_wrongstego.verdict,
    )

    # --- negative: no payload at all
    v_clean = engine.verify(cover, media_type, 2, STEGO_KEY, kp.public_key)
    check(
        f"{label}: clean cover -> Payload Missing",
        v_clean.verdict == Verdict.PAYLOAD_MISSING,
        v_clean.verdict,
    )

    # --- negative: wrong start location
    manual = 5000 % cover.num_carriers
    r_manual = engine.encode(
        cover, media_type, SHORT_MSG, "Team P1-4", 2, STEGO_KEY, kp.private_key,
        start_mode="manual", manual_offset=manual,
    )
    s_manual = load_fn(getattr(cover, rebuild_attr)(r_manual.stego_carriers))
    v_manual = engine.verify(s_manual, media_type, 2, STEGO_KEY, kp.public_key)
    check(
        f"{label}: manual embed, derived verify -> Wrong Start Location",
        v_manual.verdict == Verdict.WRONG_START_LOCATION,
        v_manual.verdict,
    )
    check(
        f"{label}: scan reports the true offset",
        v_manual.found_at == manual,
        f"{v_manual.found_at} != {manual}",
    )

    v_manual_ok = engine.verify(
        s_manual, media_type, 2, STEGO_KEY, kp.public_key,
        start_mode="manual", manual_offset=manual,
    )
    check(
        f"{label}: manual verify at correct offset -> Authentic",
        v_manual_ok.verdict == Verdict.AUTHENTIC,
        v_manual_ok.reason,
    )

    # --- negative: wrong LSB depth at verify
    v_wrongn = engine.verify(stego, media_type, 4, STEGO_KEY, kp.public_key)
    check(
        f"{label}: wrong LSB depth -> Payload Missing",
        v_wrongn.verdict == Verdict.PAYLOAD_MISSING,
        v_wrongn.verdict,
    )

    # --- negative: tampering attacks
    ctx = {"start": res.start_index, "n_lsb": 2}
    for attack_name, fn in attack_set.items():
        attacked, desc = fn(res.stego_carriers, ctx)
        s_att = load_fn(getattr(cover, rebuild_attr)(attacked))
        v_att = engine.verify(s_att, media_type, 2, STEGO_KEY, kp.public_key)
        expected = {
            "Strip the LSB planes": {Verdict.PAYLOAD_MISSING},
            "Brighten carelessly (destroys payload)": {Verdict.PAYLOAD_MISSING},
            "Shift level carelessly (destroys payload)": {Verdict.PAYLOAD_MISSING},
            "Corrupt the embedded payload": {Verdict.SIGNATURE_INVALID, Verdict.PAYLOAD_MISSING,
                                             Verdict.CANNOT_VERIFY},
        }.get(attack_name, {Verdict.TAMPERED})
        check(
            f"{label}: attack '{attack_name}' -> {v_att.verdict.value}",
            v_att.verdict in expected,
            f"got {v_att.verdict}, expected one of {expected}",
        )

    # --- capacity refusal
    huge = "x" * (cover.num_carriers * 2)
    cap = engine.estimate_capacity(cover, 1, huge, False)
    check(f"{label}: capacity report says it will not fit", not cap.fits)
    try:
        engine.encode(cover, media_type, huge, "Team P1-4", 1, STEGO_KEY, kp.private_key)
        check(f"{label}: oversized payload refused", False, "no exception raised")
    except engine.EncodeError:
        check(f"{label}: oversized payload refused", True)


def main():
    print("Testing core modules")

    run_media(
        "IMAGE", image_stego.load_image, make_png(), "to_png_bytes", "image",
        attacks.IMAGE_ATTACKS,
    )
    run_media(
        "AUDIO", audio_stego.load_audio, make_wav(), "to_wav_bytes", "audio",
        attacks.AUDIO_ATTACKS,
    )

    print("\n=== format guards ===")
    try:
        image_stego.load_image(b"\xff\xd8\xff\xe0 fake jpeg")
        check("JPEG bytes rejected", False)
    except image_stego.ImageFormatError:
        check("JPEG bytes rejected", True)

    try:
        audio_stego.load_audio(b"ID3 fake mp3 data here")
        check("MP3 bytes rejected", False)
    except audio_stego.AudioFormatError:
        check("MP3 bytes rejected", True)

    try:
        audio_stego.load_audio(make_png())
        check("PNG-as-audio rejected", False)
    except audio_stego.AudioFormatError:
        check("PNG-as-audio rejected", True)

    print("\n=== start location determinism ===")
    a = location.derive_start(STEGO_KEY, "image", 100000, 2)
    b = location.derive_start(STEGO_KEY, "image", 100000, 2)
    c = location.derive_start(STEGO_KEY, "image", 100000, 3)
    d = location.derive_start(WRONG_STEGO_KEY, "image", 100000, 2)
    check("same inputs give same start", a == b)
    check("different LSB depth gives different start", a != c)
    check("different key gives different start", a != d)
    check(
        "different key gives different magic",
        location.derive_magic(STEGO_KEY) != location.derive_magic(WRONG_STEGO_KEY),
    )

    print(f"\n{len(PASSED)} passed, {len(FAILED)} failed")
    if FAILED:
        for name, detail in FAILED:
            print(f"  FAILED: {name}  {detail}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
