"""
spoof_detection.py — frequency-domain screen/print recapture heuristic.

The liveness model (check_liveness in app.py / slap_core.py) is a MobileNetV2
classifier and, per bug.md, was never trained against screen-replay or print
spoofs specifically — it fails to catch someone holding up a photo of a finger
on a phone or monitor. This module is a second, independent signal aimed at
exactly that gap: it does not touch or retrain the liveness model, it adds a
cheap frequency-domain check that can run alongside it.

Two independent signals feed the verdict, OR'd together (either one can flag
a capture; that only ever makes rejection stricter, never looser):

1. Peak-count (peak_count / MOIRE_PEAK_COUNT_FLAG): fir.estimate_ridge_period()
   already relies on a real fingertip photo having one dominant, quasi-periodic
   ridge frequency. A screen's own pixel/subpixel raster, being closer to a
   repeating grid than a smooth sinusoid, should in principle add a second
   sharp peak. In practice, checked against a first small real-photo set
   (5 real fingertip photos, 5 screen-recapture attempts, run through the
   actual YOLO crop the production pipeline uses): real photos never showed
   more than 1 peak, but neither did 4 of the 5 spoof photos -- real JPEG
   photos, blurred or compressed, mostly don't produce the crisp isolated
   comb a synthetic square-wave test pattern does. This signal is weak on its
   own against anything but a very sharp, high-quality recapture. Kept
   because it did catch the one sharp spoof sample outright, and because
   MOIRE_PEAK_COUNT_FLAG can't safely be lowered to 1 -- a clean, well-focused
   REAL capture legitimately produces exactly 1 peak too (see
   tests/test_spoof_detection.py), so a threshold of 1 would start rejecting
   good captures, not just catching spoofs.

2. Chromatic spectral divergence (chroma_diff / CHROMA_DIFF_THRESH): a real
   finger's ridge shading is structurally the same across R/G/B (same shape,
   different channel brightness from skin tone and lighting), so the radial
   spectra of its color channels should have very similar shape. A screen
   recapture's Bayer-sensor / display-subpixel interaction differs by channel
   in a way skin doesn't, so the channel spectra diverge more. On that same
   5-real/5-spoof set this was the strongest signal measured: real photos
   clustered at 0.06-0.11, four of five spoof photos at 0.14-0.17 (one spoof
   overlapped the real cluster at 0.093 and is simply not caught by this
   signal). CHROMA_DIFF_THRESH=0.12 sits in the gap between those clusters.

Both numbers above come from n=5+5 -- nowhere near enough to trust as a
calibrated threshold, but real measured data beats the pure synthetic-pattern
guess this module started from. Treat "is_screen" as one more input to
combine with the liveness model, the same way matching.py's MATCH_THRESH is
flagged as needing real-data calibration before being trusted alone -- this
needs the same treatment with a much larger real dataset before production.
"""

import cv2
import numpy as np
from scipy.ndimage import median_filter
from scipy.signal import find_peaks

# A peak must sit this far above its local neighbourhood (as a fraction of the
# neighbourhood's own magnitude) to count as "sharp" rather than natural texture.
MOIRE_REL_THRESH = 0.6

# >= this many sharp peaks in the radial spectrum reads as a comb (screen/print
# raster) rather than the single ridge-frequency peak a real fingertip produces.
MOIRE_PEAK_COUNT_FLAG = 2

# Width (in radial bins) of the running-median baseline each candidate peak is
# compared against.
MOIRE_BASELINE_WINDOW = 9

# Innermost fraction of the spectrum excluded as DC / gross illumination —
# not ridge or grid content either way.
MOIRE_DC_EXCLUDE_FRAC = 0.02

# A candidate peak must also reach this fraction of the strongest bin in the
# band, not just clear its local baseline — near the noise floor, even a real
# fingerprint's pure ridge tone leaves faint uint8-quantization harmonics that
# are relatively huge (baseline there is close to zero) but absolutely
# negligible. Without this floor those get counted as a second "peak".
MOIRE_MIN_ABS_FRAC = 0.02

# Above this L1 distance between the R and B channel radial spectra (each
# normalised to sum to 1), the color channels' frequency content is
# considered too different to be ordinary skin shading. See module docstring
# for where this number came from -- provisional, n=5+5.
CHROMA_DIFF_THRESH = 0.12

_INSUFFICIENT_SIGNAL = {
    "is_screen": False,
    "peak_count": 0,
    "strongest_peak_ratio": 0.0,
    "chroma_diff": None,
    "score": 0.0,
    "note": "insufficient_signal",
}


def _radial_spectrum(gray):
    """
    Windowed, isotropic radial magnitude spectrum of a square center crop.

    Same technique as fir.estimate_ridge_period (Hann window, fftshift, bincount
    radial average) so a real fingerprint's ridge frequency behaves the same way
    here as it does there: one dominant bump, not several. Returns None when the
    crop is too small or too flat to say anything.
    """
    img = gray.astype(np.float32)
    n = min(img.shape[0], img.shape[1])
    if n < 32 or float(img.std()) < 1e-6:
        return None

    y0 = (img.shape[0] - n) // 2
    x0 = (img.shape[1] - n) // 2
    patch = img[y0:y0 + n, x0:x0 + n]
    patch = patch - patch.mean()
    window = np.outer(np.hanning(n), np.hanning(n))
    spectrum = np.abs(np.fft.fftshift(np.fft.fft2(patch * window)))

    cy = cx = n // 2
    yy, xx = np.mgrid[0:n, 0:n]
    radius = np.sqrt((yy - cy) ** 2 + (xx - cx) ** 2).astype(np.int32)
    radial = np.bincount(radius.ravel(), weights=spectrum.ravel())
    counts = np.bincount(radius.ravel())
    return radial / np.maximum(counts, 1)


def _channel_chroma_diff(image_bgr):
    """
    L1 distance between the R and B channels' normalised radial spectra.

    Both channels go through the exact same _radial_spectrum used for the
    grayscale analysis, then both get the same DC/low-frequency exclusion
    analyze_spectrum applies to its band before normalising each to sum to
    1 -- so only the *shape* of the higher-frequency spectrum is compared,
    not gross low-frequency illumination (which differs between channels for
    entirely mundane reasons -- shading, white balance -- that have nothing
    to do with spoofing, and is large enough to swamp everything else if
    left in: an earlier version of this function skipped the exclusion and
    got real-photo numbers 5-10x too high, dominated by that illumination
    mismatch rather than the actual ridge-shape signal). Returns None when
    either channel has insufficient signal, same convention as
    _radial_spectrum itself.
    """
    if image_bgr is None or image_bgr.ndim != 3 or image_bgr.shape[2] < 3:
        return None
    b, _, r = cv2.split(image_bgr)[:3]
    r_radial = _radial_spectrum(r)
    b_radial = _radial_spectrum(b)
    if r_radial is None or b_radial is None:
        return None
    n = min(len(r_radial), len(b_radial))
    lo = max(2, int(n * MOIRE_DC_EXCLUDE_FRAC))
    if n - lo < 1:
        return None
    r_band = r_radial[lo:n]
    b_band = b_radial[lo:n]
    r_norm = r_band / (r_band.sum() + 1e-9)
    b_norm = b_band / (b_band.sum() + 1e-9)
    return float(np.abs(r_norm - b_norm).sum())


def analyze_spectrum(image_bgr):
    """
    Full diagnostic behind detect_screen_replay: the summary verdict plus the
    raw radial band, its local baseline and which bins were flagged as peaks.

    Exists as its own function (rather than inlined in detect_screen_replay) so
    a debugging/calibration tool can plot exactly what the detector saw instead
    of re-deriving the same FFT/baseline/peak-finding logic a second time and
    risking it drifting out of sync with the real thing. detect_screen_replay
    is just this, minus the arrays.

    band/baseline/peaks/band_start_radius are only present when there was
    enough signal to compute them — absent (not None) on insufficient_signal,
    so callers that only want the verdict can ignore them entirely.
    """
    if image_bgr is None or image_bgr.size == 0:
        return dict(_INSUFFICIENT_SIGNAL)

    gray = cv2.cvtColor(image_bgr, cv2.COLOR_BGR2GRAY) if image_bgr.ndim == 3 else image_bgr
    radial = _radial_spectrum(gray)
    if radial is None:
        return dict(_INSUFFICIENT_SIGNAL)

    n = len(radial)
    lo = max(2, int(n * MOIRE_DC_EXCLUDE_FRAC))
    band = radial[lo:]
    if len(band) < MOIRE_BASELINE_WINDOW:
        return dict(_INSUFFICIENT_SIGNAL)

    baseline = median_filter(band, size=MOIRE_BASELINE_WINDOW, mode="nearest")
    eps = 1e-6
    ratio = (band - baseline) / (baseline + eps)

    min_height = np.maximum(baseline * (1 + MOIRE_REL_THRESH), band.max() * MOIRE_MIN_ABS_FRAC)
    peaks, _ = find_peaks(
        band,
        height=min_height,
        distance=max(2, n // 64),
    )
    peak_count = int(len(peaks))
    strongest_ratio = float(ratio[peaks].max()) if peak_count else 0.0

    chroma_diff = _channel_chroma_diff(image_bgr)
    chroma_flagged = chroma_diff is not None and chroma_diff > CHROMA_DIFF_THRESH
    is_screen = peak_count >= MOIRE_PEAK_COUNT_FLAG or chroma_flagged

    return {
        "is_screen": bool(is_screen),
        "peak_count": peak_count,
        "strongest_peak_ratio": round(strongest_ratio, 3),
        "chroma_diff": round(chroma_diff, 4) if chroma_diff is not None else None,
        "score": round(peak_count + min(strongest_ratio, 5.0) / 5.0
                        + (chroma_diff or 0.0), 3),
        "note": "uncalibrated_heuristic",
        "band": band,
        "baseline": baseline,
        "peaks": peaks,
        "band_start_radius": lo,
    }


_SUMMARY_KEYS = ("is_screen", "peak_count", "strongest_peak_ratio", "chroma_diff", "score", "note")


def detect_screen_replay(image_bgr):
    """
    Flag likely screen/print recapture from two independent signals: the
    radial FFT peak count and the chromatic spectral divergence between
    color channels (see module docstring for both).

    Returns a dict with is_screen (bool), peak_count, strongest_peak_ratio,
    chroma_diff (None when it couldn't be computed, e.g. a grayscale input),
    score and a note. Never raises on a degenerate crop — insufficient signal
    reads as "not screen" (this is one signal among several gating a
    request; check_liveness stays the primary fail-closed check, this only
    ever makes rejection stricter, never looser).
    """
    full = analyze_spectrum(image_bgr)
    return {k: full[k] for k in _SUMMARY_KEYS}
