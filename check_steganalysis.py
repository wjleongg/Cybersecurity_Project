"""Targeted re-check, using the exact numbers from test_evidence.md.

The first check_steganalysis.py run used a 20,000-carrier default window,
which turned out to be far wider than the actual embedded region (1,562
carriers out of 1,440,000 for the image -- 0.1% of the file). A window that
wide averages the tiny embedded region away entirely. This script slices
right around the known start location instead, to answer one question: can
chi_square_scan see the signal at all, when looking at the right place?

If this test shows a real cover-vs-stego difference and the general scan in
check_steganalysis.py did not, the fix is choosing a much smaller
window_carriers (and probably scanning at several window sizes, since a real
detector does not get to read test_evidence.md).

    python check_steganalysis_targeted.py
"""

from pathlib import Path

from core import audio_stego, image_stego, steganalysis as sa

SAMPLES = Path("samples")


def targeted_slice(carriers, start: int, container_bytes: int, n_lsb: int, pad: int = 2000):
    """A window centred on the known embedded region, widened by `pad` on
    each side so the window still has enough samples for a valid chi-square
    test (see the >=5-per-bin rule in core/steganalysis.py).
    """
    span = (container_bytes * 8 + n_lsb - 1) // n_lsb  # carriers the container occupies
    lo = max(0, start - pad)
    hi = min(len(carriers), start + span + pad)
    return carriers[lo:hi], lo, hi


def run(label: str, cover_carriers, stego_carriers, start: int, container_bytes: int, n_lsb: int):
    print(f"\n{'=' * 70}\n{label}\n{'=' * 70}")

    cover_slice, lo, hi = targeted_slice(cover_carriers, start, container_bytes, n_lsb)
    stego_slice, _, _ = targeted_slice(stego_carriers, start, container_bytes, n_lsb)
    print(f"Targeted window: carriers {lo:,}-{hi:,} ({hi - lo:,} carriers, centred on known start {start:,})")

    c_chi2, c_dof = sa._pair_chi_square(cover_slice, n_lsb)
    s_chi2, s_dof = sa._pair_chi_square(stego_slice, n_lsb)

    if c_dof == 0 or s_dof == 0:
        print(f"Cover  window: chi2={c_chi2:.1f} dof={c_dof}")
        print(f"Stego  window: chi2={s_chi2:.1f} dof={s_dof}")
        print("At least one side had no group with enough samples to test "
              "(dof=0) -- widen `pad` or check MAX_GROUPS in core/steganalysis.py.")
    else:
        c_p, s_p = sa.chi2_sf(c_chi2, c_dof), sa.chi2_sf(s_chi2, s_dof)
        c_z, s_z = sa.chi_square_zscore(c_chi2, c_dof), sa.chi_square_zscore(s_chi2, s_dof)
        print(f"Cover  window: chi2={c_chi2:.1f} dof={c_dof} p={c_p:.6f} z={c_z:.3f}")
        print(f"Stego  window: chi2={s_chi2:.1f} dof={s_dof} p={s_p:.6f} z={s_z:.3f}")
        print(f"p shifted by {s_p - c_p:+.6f}  (often ~0 even when real -- p underflows on redundant images)")
        print(f"z shifted by {s_z - c_z:+.3f}  (this is the number that matters: more negative = more uniform after embedding)")

    # Also try a handful of window sizes over the whole file, to see which
    # scale actually catches this without foreknowledge of the start location.
    print("\nWhole-file scan at several window sizes (no foreknowledge of start location):")
    for wc in (1000, 2000, 5000, 10000, 20000):
        cover_scan = sa.chi_square_scan(cover_carriers, n_lsb=n_lsb, window_carriers=wc)
        stego_scan = sa.chi_square_scan(stego_carriers, n_lsb=n_lsb, window_carriers=wc)
        cmp = sa.compare_scans(cover_scan, stego_scan)
        caught = "CAUGHT" if "became markedly" in cmp else "missed"
        print(f"  window_carriers={wc:>6,}  ->  {caught}")


if __name__ == "__main__":
    # From test_evidence.md, "Cover object statistics, positive case at 2 LSB"
    IMAGE_START, IMAGE_CONTAINER, IMAGE_NLSB = 38_421, 524, 2
    AUDIO_START, AUDIO_CONTAINER, AUDIO_NLSB = 343_888, 524, 2

    cover_img = image_stego.load_image((SAMPLES / "cover_image.png").read_bytes())
    stego_img = image_stego.load_image((SAMPLES / "stego_image.png").read_bytes())
    run("IMAGE", cover_img.carriers, stego_img.carriers, IMAGE_START, IMAGE_CONTAINER, IMAGE_NLSB)

    cover_aud = audio_stego.load_audio((SAMPLES / "cover_audio.wav").read_bytes())
    stego_aud = audio_stego.load_audio((SAMPLES / "stego_audio.wav").read_bytes())
    run("AUDIO", cover_aud.carriers, stego_aud.carriers, AUDIO_START, AUDIO_CONTAINER, AUDIO_NLSB)