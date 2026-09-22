"""Statistical steganalysis for LSB-replacement cover objects.

Unlike core/engine.py, everything here works WITHOUT the stego key, the
signing keys or the payload. It only looks at the carrier values themselves
and asks whether their low-order bits look like they came from a natural
image/audio source, or from LSB replacement.

This module exists because the project's own README says as much under
Limitations: "the keyed marker resists scanning, but the payload's presence
may still be detectable statistically: the bit-plane histogram of an
LSB-embedded file differs measurably from a natural one." This is that claim,
made runnable, and it is the steganalysis optional challenge (brief, Section
8): "using known algorithms or methodologies, analyse a stego object and
convincingly infer the cover object is tampered or shows signs of hidden
payload."

Two independent techniques are provided:

  Chi-square pair-of-values attack (`chi_square_scan`) -- the classical
  Westfeld & Pfitzmann statistical test, generalised from single-bit LSB
  replacement to the n-LSB case this project supports. Produces a numeric
  "how uniform do the low bits look" curve across the file, in windows, so a
  detector without the key can still localise roughly where a payload sits.

  Bit-plane extraction (`bit_plane_image`, `bit_plane_waveform`) -- pulls out
  a single bit-plane as its own image or waveform. A plane carrying real
  payload data looks like noise; an unmodified plane keeps a visible trace of
  the cover content. This is the fast, visual complement to the numeric test,
  and the thing worth putting on screen first in a demo.

Both operate on the same NumPy carrier arrays that core/bitops.py and
core/image_stego.py / core/audio_stego.py already produce, so a result here
sits naturally next to engine.verify()'s key-based verdict: "no key needed,
and here is what an eavesdropper without the key could already tell."

No new dependency. The chi-square survival function is implemented directly
below (Numerical-Recipes-style incomplete gamma) rather than pulled in from
scipy, so requirements.txt does not need to change.
"""

from dataclasses import dataclass, field
from enum import Enum
import math

import numpy as np


# --------------------------------------------------------------------------
# Chi-square survival function, self-contained (no scipy dependency)
# --------------------------------------------------------------------------

def _gammln(x: float) -> float:
    return math.lgamma(x)


def _gser(a: float, x: float, itmax: int = 200, eps: float = 3e-9) -> float:
    """Series expansion for the regularised lower incomplete gamma P(a, x).

    Used when x < a + 1, where the series converges quickly.
    """
    if x <= 0:
        return 0.0
    gln = _gammln(a)
    ap = a
    summ = 1.0 / a
    delta = summ
    for _ in range(itmax):
        ap += 1.0
        delta *= x / ap
        summ += delta
        if abs(delta) < abs(summ) * eps:
            break
    return summ * math.exp(-x + a * math.log(x) - gln)


def _gcf(a: float, x: float, itmax: int = 200, eps: float = 3e-9, fpmin: float = 1e-300) -> float:
    """Continued fraction for the regularised upper incomplete gamma Q(a, x).

    Used when x >= a + 1, where the series above converges too slowly.
    """
    gln = _gammln(a)
    b = x + 1.0 - a
    c = 1.0 / fpmin
    d = 1.0 / b
    h = d
    for i in range(1, itmax + 1):
        an = -i * (i - a)
        b += 2.0
        d = an * d + b
        if abs(d) < fpmin:
            d = fpmin
        c = b + an / c
        if abs(c) < fpmin:
            c = fpmin
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < eps:
            break
    return math.exp(-x + a * math.log(x) - gln) * h


def chi2_sf(x: float, dof: float) -> float:
    """Upper-tail (survival) probability of the chi-square distribution.

    This is P(observed statistic >= x | dof), i.e. how compatible the data
    is with the null hypothesis being tested. Here the null hypothesis is
    "the low bits are uniformly distributed" -- so a HIGH value close to 1
    means the data looks like it was overwritten with an even mix of 0s and
    1s (consistent with LSB embedding), and a LOW value close to 0 means the
    low bits deviate from uniform far more than chance would explain
    (consistent with an untouched cover object).

    On real photographs this routinely underflows to exactly 0.0 on BOTH a
    cover and its stego counterpart -- a redundant, large-flat-region image
    can have a chi-square statistic so large that the true tail probability
    is far below double-precision's smallest representable value, even
    though embedding measurably shrank that statistic. When that underflow
    matters, use `chi_square_zscore` below instead: it stays informative
    exactly where this function saturates to 0.
    """
    if x <= 0 or dof <= 0:
        return 1.0
    a = dof / 2.0
    xx = x / 2.0
    if xx < a + 1.0:
        return 1.0 - _gser(a, xx)
    return _gcf(a, xx)


def chi_square_zscore(x: float, dof: float) -> float:
    """Wilson-Hilferty normal approximation for a chi-square statistic.

    Converts (chi2, dof) into an approximate z-score: how many standard
    deviations the statistic sits from what uniform low bits would produce.
    Unlike chi2_sf, this does not saturate for very large chi2 -- it stays a
    finite, orderable number well past the point where the true tail
    probability has underflowed to 0.0 in double precision. That makes it
    the right thing to DIFFERENCE (cover z-score vs stego z-score) when
    comparing two files that are both deep in the tail, which is the normal
    case for a real, high-detail cover image.

    Lower (more negative, or simply smaller) means closer to what uniform
    low bits would produce -- i.e. more consistent with LSB embedding.
    """
    if dof <= 0:
        return 0.0
    a = dof / 2.0
    xx = x / 2.0
    # (chi2 / dof) ** (1/3) is approximately normal with known mean/variance.
    ratio = xx / a
    mean = 1.0 - 2.0 / (9.0 * a)
    sd = math.sqrt(2.0 / (9.0 * a))
    return (ratio ** (1.0 / 3.0) - mean) / sd


# --------------------------------------------------------------------------
# Chi-square pair-of-values attack
# --------------------------------------------------------------------------

# A window whose p-value clears this is flagged "suspicious", following
# Westfeld & Pfitzmann's own convention of reading a high chi-square p-value
# as an estimated "probability of embedding".
#
# CALIBRATE THIS AGAINST YOUR OWN SAMPLES. In testing against synthetic cover
# data, single-window p-values were noisy and their absolute scale shifted
# with window size and with how close the untouched cover's own low bits
# already sit to uniform -- which varies a lot between images, and is a
# known, published limitation of this test, not specific to this
# implementation. 0.5 below is a reasonable starting point, not a validated
# constant. Once `scripts/make_samples.py` has produced real cover and
# stego pairs, run `chi_square_scan` on both, plot the p-value curves next
# to each other, and adjust SUSPICION_THRESHOLD and `window_carriers` to
# whatever actually separates them on this project's real files -- that
# comparison is also the strongest thing to put on screen during the demo,
# stronger than any single absolute number.
SUSPICION_THRESHOLD = 0.5

# Plain entropy of the low bits is intentionally NOT the primary signal.
# Tested against synthetic cover images, it saturated near its maximum on
# UNTOUCHED covers as often as on embedded ones -- consistent with the
# published observation that natural image and audio low bits already look
# close to random before anything is hidden in them. It is kept as a
# reported number because it is cheap and occasionally informative, but the
# chi-square pair test above is what carries the actual claim.


# Cap on the number of "high bits" groups _pair_chi_square will form. Real
# significance was never the reason for this -- validity is. An 8-bit image
# carrier at n_lsb=1 already only has up to 128 possible groups, well under
# this cap, so image behaviour is unaffected. A 16-bit audio sample at
# n_lsb=1 has up to 32,768 possible groups: in any realistically-sized
# window almost every group ends up with 0-2 members, which the >=5-per-bin
# validity rule then rejects almost entirely -- exactly the "dof=0, cannot
# test" failure seen when this was tried against real 16-bit WAV audio.
# Capping the group count trades location precision within a group (a group
# now spans several original "high bits" values instead of exactly one) for
# having enough samples per group to run a valid test at all, which for
# audio is the difference between a scoreable window and none.
MAX_GROUPS = 128


def _pair_chi_square(values: np.ndarray, n_lsb: int) -> tuple[float, int]:
    """One chi-square statistic for one window of carrier values.

    Groups values by their high bits (value >> n_lsb) -- the part embedding
    never touches -- and, within each group, tests whether the low n_lsb
    bits are uniformly distributed across all 2**n_lsb possibilities.

    This is the natural generalisation of Westfeld & Pfitzmann's original
    pair-of-values test. At n_lsb = 1 it reduces exactly to their test: each
    group is a pair of values (2k, 2k+1), and LSB replacement with an
    unbiased bitstream drives the two toward equal frequency. At higher
    depths the same reasoning extends to a full 2**n_lsb-way bucket:
    embedding fills every low-bit pattern equally, where untouched cover
    data usually does not.

    The high-bits value is right-shifted further, if needed, so no more
    than MAX_GROUPS distinct groups are ever formed -- see the note above
    MAX_GROUPS for why this matters for wide (e.g. 16-bit audio) carriers.

    Groups with fewer than 5 expected samples per bin are dropped, per the
    usual chi-square validity rule -- too few samples per bin makes the
    statistic unreliable regardless of what generated the data.

    Returns (chi_square_statistic, degrees_of_freedom). dof is 0 when no
    group had enough samples to test, which the caller treats as "this
    window cannot be scored".
    """
    bins = 1 << n_lsb
    width = values.dtype.itemsize * 8
    high_bits = max(0, width - n_lsb)
    extra_shift = max(0, high_bits - int(math.log2(MAX_GROUPS)))

    high = (values.astype(np.int64) >> n_lsb) >> extra_shift
    low = (values.astype(np.int64) & (bins - 1))

    group_ids, inverse = np.unique(high, return_inverse=True)
    counts = np.zeros((len(group_ids), bins), dtype=np.int64)
    np.add.at(counts, (inverse, low), 1)

    totals = counts.sum(axis=1)
    expected_per_bin = totals / bins
    valid = expected_per_bin >= 5
    if not np.any(valid):
        return 0.0, 0

    obs = counts[valid].astype(np.float64)
    exp = expected_per_bin[valid][:, None]
    chi2 = float(np.sum((obs - exp) ** 2 / exp))
    dof = int(valid.sum()) * (bins - 1)
    return chi2, dof


@dataclass
class WindowResult:
    """One scanned slice of the carrier array."""

    start: int
    end: int
    chi2: float
    dof: int
    p_value: float
    z_score: float = 0.0

    @property
    def suspicious(self) -> bool:
        return self.p_value >= SUSPICION_THRESHOLD


class Likelihood(str, Enum):
    """Headline verdict for a scan. Deliberately not merged into
    engine.Verdict -- that enum answers "does this pass the keyed check",
    this one answers a different question, "does this look embedded to a
    detector with no key at all", and the two can legitimately disagree.
    """

    LIKELY_CLEAN = "Likely clean"
    SUSPICIOUS = "Suspicious"
    LIKELY_STEGO = "Likely contains hidden data"
    INCONCLUSIVE = "Inconclusive"


@dataclass
class ScanResult:
    """Full output of a chi-square scan across a cover or stego object."""

    n_lsb: int
    window_carriers: int
    windows: list[WindowResult] = field(default_factory=list)
    suspicious_fraction: float = 0.0
    entropy_bits: float = 0.0
    max_entropy_bits: float = 0.0
    likelihood: Likelihood = Likelihood.INCONCLUSIVE
    summary: str = ""

    def curve(self) -> list[float]:
        """p-values in window order, for plotting (e.g. st.line_chart)."""
        return [w.p_value for w in self.windows]


def bit_plane_entropy(carriers: np.ndarray, n_lsb: int = 1) -> float:
    """Shannon entropy, in bits, of the low n_lsb bits across the whole array.

    Maximum possible is n_lsb (all 2**n_lsb values equally likely). Included
    as a fast, single-number headline. On its own it is a weak signal --
    natural image and audio LSBs often sit close to this maximum already,
    which is exactly why chi_square_scan (below) does the real discriminating
    work by testing pair structure rather than just overall spread.
    """
    bins = 1 << n_lsb
    low = (carriers.astype(np.int64) & (bins - 1))
    counts = np.bincount(low, minlength=bins).astype(np.float64)
    total = counts.sum()
    if total == 0:
        return 0.0
    probs = counts / total
    probs = probs[probs > 0]
    return float(-(probs * np.log2(probs)).sum())


def chi_square_scan(
    carriers: np.ndarray,
    n_lsb: int = 1,
    window_carriers: int = 20_000,
) -> ScanResult:
    """Scan the carrier array for statistical signs of LSB embedding.

    Two independent measurements feed the verdict:

      Entropy (whole array, one number) -- how close the low n_lsb bits sit
      to a uniform distribution overall. This held up as the more reliable
      signal in testing: it moved from clearly skewed on untouched synthetic
      covers to essentially maximal after embedding a fully random payload,
      consistently across trials.

      Chi-square pair-of-values (per window) -- tests uniformity within
      windows of `window_carriers` consecutive carriers, so a payload that
      only occupies part of the file (the normal case here, since the start
      location is keyed rather than fixed at zero) shows up as a run of
      suspicious windows rather than a uniform smear across the whole file.
      This is the weaker signal of the two: a single window's p-value has
      real variance and is not, on its own, a safe basis for a verdict (see
      the note on SUSPICION_THRESHOLD above) -- it is kept mainly so a result
      can be localised and shown on screen, e.g. as a curve alongside a
      bit-plane image.

    `window_carriers` defaults large (20,000) because chi-square power
    depends on carrier count: too small a window and even a fully-embedded
    region fails to read as suspicious, which is a known limitation of this
    test in the literature, not a bug in a specific implementation. For a
    small cover object, pass a smaller value and treat the result with more
    caution; for a large one, a larger value gives cleaner localisation.
    """
    total = len(carriers)
    if total == 0:
        return ScanResult(n_lsb, window_carriers, summary="No carriers to analyse.")

    window_carriers = max(window_carriers, (1 << n_lsb) * 5)
    entropy = bit_plane_entropy(carriers, n_lsb)
    entropy_ratio = entropy / n_lsb if n_lsb else 0.0

    windows: list[WindowResult] = []
    for start in range(0, total, window_carriers):
        end = min(start + window_carriers, total)
        chi2, dof = _pair_chi_square(carriers[start:end], n_lsb)
        if dof == 0:
            continue
        p = chi2_sf(chi2, dof)
        z = chi_square_zscore(chi2, dof)
        windows.append(WindowResult(start, end, chi2, dof, p, z))

    if not windows:
        return ScanResult(
            n_lsb, window_carriers, entropy_bits=entropy, max_entropy_bits=float(n_lsb),
            summary=(
                "Too few carriers per bin to run a valid chi-square test at "
                f"{n_lsb}-bit depth on this file. Entropy of the low bits is "
                f"{entropy:.3f} of {n_lsb} max bits, on its own inconclusive "
                "without the windowed test to corroborate it."
            ),
        )

    suspicious = [w for w in windows if w.suspicious]
    fraction = len(suspicious) / len(windows)

    # The chi-square windowed fraction is the primary signal (see the note
    # on SUSPICION_THRESHOLD above for why the cutoff needs calibrating on
    # this project's real samples). Entropy is reported alongside as extra
    # context, never as the deciding number.
    if fraction >= 0.5:
        likelihood = Likelihood.LIKELY_STEGO
        summary = (
            f"{fraction:.0%} of scanned windows test as statistically "
            f"uniform at {n_lsb}-bit depth (low-bit entropy "
            f"{entropy:.3f} of {n_lsb} max bits). Consistent with LSB "
            "embedding across most of the file."
        )
    elif fraction >= 0.15:
        likelihood = Likelihood.SUSPICIOUS
        first = suspicious[0]
        last = suspicious[-1]
        summary = (
            f"{fraction:.0%} of scanned windows test as statistically "
            f"uniform, concentrated around carriers {first.start:,}-"
            f"{last.end:,} rather than spread file-wide (low-bit entropy "
            f"{entropy:.3f} of {n_lsb} max bits). Consistent with a payload "
            "occupying only part of the file, which is what a keyed start "
            "location produces -- worth checking that region specifically."
        )
    else:
        likelihood = Likelihood.LIKELY_CLEAN
        summary = (
            f"Only {fraction:.0%} of scanned windows test as statistically "
            f"uniform (low-bit entropy {entropy:.3f} of {n_lsb} max bits). "
            "No strong evidence of LSB embedding at this depth."
        )

    return ScanResult(
        n_lsb=n_lsb,
        window_carriers=window_carriers,
        windows=windows,
        suspicious_fraction=fraction,
        entropy_bits=entropy,
        max_entropy_bits=float(n_lsb),
        likelihood=likelihood,
        summary=summary,
    )


# --------------------------------------------------------------------------
# Bit-plane extraction
# --------------------------------------------------------------------------

def extract_bit_plane(carriers: np.ndarray, bit_index: int = 0) -> np.ndarray:
    """The single bit at `bit_index` (0 = least significant) across every
    carrier. Returns 0/1 uint8, same length and order as `carriers`.
    """
    return ((carriers.astype(np.int64) >> bit_index) & 1).astype(np.uint8)


def bit_plane_image(cover, bit_index: int = 0, carriers: np.ndarray | None = None) -> np.ndarray:
    """The chosen bit-plane rendered as a black/white (H, W, C) uint8 image.

    `cover` supplies height/width/channels (an ImageCover). Pass a different
    `carriers` array -- e.g. a verified stego file's, loaded separately --
    to visualise that instead of the cover's own; the two should look
    visibly different if a payload sits in this plane.
    """
    source = cover.carriers if carriers is None else carriers
    plane = extract_bit_plane(source, bit_index) * 255
    return cover.to_array(plane.astype(np.uint8))


def bit_plane_waveform(cover, bit_index: int = 0, carriers: np.ndarray | None = None) -> np.ndarray:
    """The chosen bit-plane as a float waveform in {-1, 1}, for plotting.

    Centred on zero rather than left at {0, 1} so it renders as visible
    noise around a baseline instead of a solid block pinned to the top of
    the chart.
    """
    source = cover.carriers if carriers is None else carriers
    plane = extract_bit_plane(source, bit_index)
    return plane.astype(np.float32) * 2.0 - 1.0


# --------------------------------------------------------------------------
# One-call entry point
# --------------------------------------------------------------------------

def compare_scans(cover_scan: ScanResult, subject_scan: ScanResult) -> str:
    """Describe how a subject file's chi-square curve differs from a cover's.

    A real detector, by definition, only ever sees the suspect file and has
    no cover to compare against -- that is the actual steganalysis problem,
    and `chi_square_scan` on its own addresses it. This function is a
    demo/validation aid for when the cover IS available (which, for this
    project, it always is: encode and verify sit in the same app). A rise in
    p-value in specific windows after embedding is a clean, honest, visual
    claim -- much stronger to put on screen than any single absolute
    threshold, and the natural next thing to show right after the existing
    cover/stego comparison already in each media tab.

    The comparison is done on `z_score`, not `p_value`. Tested against a
    real photograph, both the cover's and the stego's chi-square statistics
    were so large that their true tail probabilities underflowed to exactly
    0.0 in double precision -- even though the underlying chi-square
    statistic itself dropped by roughly half after embedding, a large, real
    effect. Comparing p-values would have reported "no difference" on a file
    where a difference plainly exists; z_score (see chi_square_zscore)
    stays a finite, orderable number in that same regime, so the comparison
    below still finds the shift.

    Both scans should use the same n_lsb and window_carriers, or the window
    boundaries will not line up and the comparison will be meaningless.
    """
    if cover_scan.n_lsb != subject_scan.n_lsb:
        return "Cover and subject were scanned at different LSB depths; re-scan both at the same depth to compare."
    if cover_scan.window_carriers != subject_scan.window_carriers:
        return "Cover and subject were scanned with different window sizes; re-scan both with the same window_carriers to compare."

    n = min(len(cover_scan.windows), len(subject_scan.windows))
    if n == 0:
        return "Not enough carriers in one of the two scans to compare."

    # A drop in z-score means the subject's low bits sit closer to uniform
    # than the cover's did in that same window -- the signature of
    # embedding, regardless of whether either z-score's true p-value has
    # underflowed. 1.0 is a moderate, not extreme, shift on the z scale.
    shifted = []
    for i in range(n):
        c, s = cover_scan.windows[i], subject_scan.windows[i]
        if c.z_score - s.z_score >= 1.0:
            shifted.append(s)

    if not shifted:
        return (
            "No window became noticeably more statistically uniform between "
            "cover and subject. No evidence from this test that embedding "
            "happened in a way this scan would catch."
        )

    first, last = shifted[0], shifted[-1]
    return (
        f"{len(shifted)} of {n} windows became markedly more statistically "
        f"uniform after encoding (carriers {first.start:,}-{last.end:,} the "
        "affected span). This localises where the embedding most likely "
        "sits, using only the statistical shift -- no stego key needed."
    )


def analyze(
    cover,
    n_lsb: int = 1,
    carriers: np.ndarray | None = None,
    window_carriers: int = 20_000,
) -> ScanResult:
    """Run chi_square_scan over a cover object's own carriers, or a supplied
    array (e.g. a stego or tampered file's carriers loaded independently).

    Kept separate from the bit-plane functions deliberately: a caller often
    wants to scan at the suspected embedding depth while always *displaying*
    the plane at 1 LSB, which is the noisiest and most visually obvious
    regardless of the true embedding depth.
    """
    source = cover.carriers if carriers is None else carriers
    return chi_square_scan(source, n_lsb=n_lsb, window_carriers=window_carriers)