"""
ISO/IEC 19794-4 Finger Image Record (FIR) generation.

FP-06 requires templates "in ISO/IEC standard FIR format". A FIR wraps the fingerprint
*image*, not minutiae — the record that used to be produced by export_iso_template was a
minutiae record, which is a different standard entirely (19794-2) and was not conformant
to that one either.

Uncompressed records are conformant, so no JPEG2000 dependency is needed here. The
compression-algorithm field is set accordingly and the pixel data follows the headers
verbatim.

Record layout implemented
-------------------------
General record header, 32 bytes:

    offset  size  field
    0       4     format identifier, b"FIR\\0"
    4       4     version, b"010\\0"
    8       4     total record length, uint32
    12      4     CBEFF product identifier
    16      2     capture device ID
    18      2     image acquisition level
    20      1     number of fingers
    21      1     scale units (1 = pixels/inch, 2 = pixels/cm)
    22      2     scan resolution, horizontal
    24      2     scan resolution, vertical
    26      2     image resolution, horizontal
    28      2     image resolution, vertical
    30      1     pixel depth, bits
    31      1     image compression algorithm (0 = uncompressed)

Note on editions: this implements the 32-byte general header of ISO/IEC 19794-4:2005.
The 2011 revision reorganises the header and adds fields. Confirm which edition UIDAI
expects before submission — the format identifier and version bytes are what a verifier
will check first, and they differ between editions.

Finger image header, 14 bytes, one per view:

    0       4     length of this finger data block, uint32
    4       1     finger position code
    5       1     count of views
    6       1     view number
    7       1     image quality
    8       1     impression type
    9       2     horizontal line length (width)
    11      2     vertical line length (height)
    13      1     reserved

Then width x height bytes of 8-bit grayscale.

All multi-byte integers are big-endian, per the standard.
"""

import struct

import cv2
import numpy as np

# ── Constants ────────────────────────────────────────────────────────────────
FORMAT_IDENTIFIER = b"FIR\x00"
VERSION           = b"010\x00"

GENERAL_HEADER_LEN = 32
FINGER_HEADER_LEN  = 14

SCALE_UNITS_PPI = 1
SCALE_UNITS_PPCM = 2

COMPRESSION_UNCOMPRESSED = 0

TARGET_DPI = 500

# At 500 dpi a fingerprint ridge period is about 9-12 pixels: ridges sit roughly
# 0.5 mm apart and 500 dpi is 19.7 px/mm. Normalisation resamples so the measured
# period lands here, which is what makes records from different phone cameras
# comparable.
TARGET_RIDGE_PERIOD_PX = 10.0
MIN_RIDGE_PERIOD_PX    = 3.0
MAX_RIDGE_PERIOD_PX    = 30.0

# ISO/IEC 19794-4 finger position codes.
FINGER_POSITIONS = {
    "unknown": 0,
    "right_thumb": 1, "right_index": 2, "right_middle": 3,
    "right_ring": 4, "right_little": 5,
    "left_thumb": 6, "left_index": 7, "left_middle": 8,
    "left_ring": 9, "left_little": 10,
}


class FIRError(ValueError):
    """Raised when a record cannot be encoded or decoded."""


# ══════════════════════════════════════════════════════════════════════════════
# 500 DPI NORMALISATION
# ══════════════════════════════════════════════════════════════════════════════

def estimate_ridge_period(image_gray):
    """
    Estimate ridge spacing in pixels from the image's radial frequency spectrum.

    Ridges are quasi-periodic, so their spacing shows up as an annulus in the 2D FFT
    magnitude. Collapsing that to a radial profile and taking the strongest bin inside
    a plausible band gives the dominant period.

    Returns None when no clear periodicity is present — a blank or badly out-of-focus
    frame — so callers can decline to resample rather than resample by a wild factor.
    """
    img = image_gray.astype(np.float32)
    if img.size == 0 or float(img.std()) < 1e-6:
        return None

    # Square, windowed crop keeps the radial profile isotropic and suppresses the
    # spectral cross that edge discontinuities would otherwise produce.
    n = min(img.shape[0], img.shape[1])
    if n < 32:
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
    radial = radial / np.maximum(counts, 1)

    lo = max(1, int(n / MAX_RIDGE_PERIOD_PX))
    hi = min(len(radial) - 1, int(n / MIN_RIDGE_PERIOD_PX))
    if hi <= lo:
        return None

    band = radial[lo:hi]
    if band.size == 0 or not np.isfinite(band).any():
        return None
    peak = int(np.argmax(band)) + lo
    if peak <= 0:
        return None
    return float(n) / peak


def normalize_to_500dpi(image, source_dpi=None):
    """
    Resample so the image is at 500 dpi equivalent.

    With source_dpi given the scale factor is exact. Without it the factor is derived
    from measured ridge spacing, which is what makes the output comparable across phone
    cameras whose sensor resolutions differ.

    Returns (image, info). If ridge frequency cannot be measured the image is passed
    through unchanged and info["method"] says so — silently resampling by a guessed
    factor would corrupt the record.
    """
    if image is None or image.size == 0:
        raise FIRError("cannot normalise an empty image")

    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY) if image.ndim == 3 else image

    if source_dpi:
        factor = float(TARGET_DPI) / float(source_dpi)
        method = "source_dpi"
        period = None
    else:
        period = estimate_ridge_period(gray)
        if period is None:
            return gray, {"method": "passthrough", "scale_factor": 1.0,
                          "ridge_period_px": None,
                          "note": "no measurable ridge frequency; not resampled"}
        factor = TARGET_RIDGE_PERIOD_PX / period
        method = "ridge_frequency"

    if not np.isfinite(factor) or factor <= 0:
        raise FIRError("computed a non-positive scale factor")

    # Clamp: a factor outside this range means the estimate is unreliable, and
    # resampling by it would do more harm than leaving the image alone.
    factor = float(np.clip(factor, 0.2, 5.0))

    h = max(1, int(round(gray.shape[0] * factor)))
    w = max(1, int(round(gray.shape[1] * factor)))
    interp = cv2.INTER_AREA if factor < 1.0 else cv2.INTER_CUBIC
    out = cv2.resize(gray, (w, h), interpolation=interp)

    return out, {"method": method, "scale_factor": factor,
                 "ridge_period_px": period,
                 "output_size": (w, h)}


# ══════════════════════════════════════════════════════════════════════════════
# ENCODE
# ══════════════════════════════════════════════════════════════════════════════

def encode_fir(image, finger_position=0, image_quality=0, impression_type=0,
               capture_device_id=0, acquisition_level=31, view_number=0,
               count_of_views=1, cbeff_product_id=0, resolution_dpi=TARGET_DPI):
    """
    Encode one 8-bit grayscale image as an uncompressed ISO/IEC 19794-4 record.

    finger_position uses the standard codes — see FINGER_POSITIONS.

    impression_type defaults to 0 (live-scan plain). The 2011 revision of the standard
    adds contactless-specific impression codes; confirm which value UIDAI expects for
    contactless capture before submission rather than assuming this default is right.
    """
    if image is None or image.size == 0:
        raise FIRError("cannot encode an empty image")

    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY) if image.ndim == 3 else image
    gray = np.ascontiguousarray(gray.astype(np.uint8))
    height, width = gray.shape[:2]

    if not (0 <= finger_position <= 10):
        raise FIRError("finger position %r outside the standard's 0-10 range"
                       % (finger_position,))
    if width > 0xFFFF or height > 0xFFFF:
        raise FIRError("image %dx%d exceeds the 16-bit dimension fields"
                       % (width, height))

    pixels = gray.tobytes()
    finger_block_len = FINGER_HEADER_LEN + len(pixels)
    total_len = GENERAL_HEADER_LEN + finger_block_len

    general = b"".join([
        FORMAT_IDENTIFIER,
        VERSION,
        struct.pack(">I", total_len),
        struct.pack(">I", cbeff_product_id),
        struct.pack(">H", capture_device_id),
        struct.pack(">H", acquisition_level),
        struct.pack(">B", 1),                     # number of fingers in this record
        struct.pack(">B", SCALE_UNITS_PPI),
        struct.pack(">H", resolution_dpi),        # scan resolution, horizontal
        struct.pack(">H", resolution_dpi),        # scan resolution, vertical
        struct.pack(">H", resolution_dpi),        # image resolution, horizontal
        struct.pack(">H", resolution_dpi),        # image resolution, vertical
        struct.pack(">B", 8),                     # pixel depth, bits
        struct.pack(">B", COMPRESSION_UNCOMPRESSED),
    ])
    if len(general) != GENERAL_HEADER_LEN:
        raise FIRError("general header is %d bytes, expected %d"
                       % (len(general), GENERAL_HEADER_LEN))

    finger = b"".join([
        struct.pack(">I", finger_block_len),
        struct.pack(">B", finger_position),
        struct.pack(">B", count_of_views),
        struct.pack(">B", view_number),
        struct.pack(">B", image_quality),
        struct.pack(">B", impression_type),
        struct.pack(">H", width),
        struct.pack(">H", height),
        struct.pack(">B", 0),                     # reserved
    ])
    if len(finger) != FINGER_HEADER_LEN:
        raise FIRError("finger header is %d bytes, expected %d"
                       % (len(finger), FINGER_HEADER_LEN))

    return general + finger + pixels


# ══════════════════════════════════════════════════════════════════════════════
# DECODE
# ══════════════════════════════════════════════════════════════════════════════

def decode_fir(data):
    """
    Parse a record back into its fields and image.

    Exists so conformance can be demonstrated by round-tripping rather than asserted.
    Encoding without a decoder is self-certification.
    """
    if len(data) < GENERAL_HEADER_LEN + FINGER_HEADER_LEN:
        raise FIRError("record is %d bytes, too short to hold the headers" % len(data))
    if data[0:4] != FORMAT_IDENTIFIER:
        raise FIRError("bad format identifier %r, expected %r"
                       % (data[0:4], FORMAT_IDENTIFIER))
    if data[4:8] != VERSION:
        raise FIRError("bad version %r, expected %r" % (data[4:8], VERSION))

    total_len, = struct.unpack(">I", data[8:12])
    if total_len != len(data):
        raise FIRError("record length field says %d, actual length is %d"
                       % (total_len, len(data)))

    header = {
        "cbeff_product_id":    struct.unpack(">I", data[12:16])[0],
        "capture_device_id":   struct.unpack(">H", data[16:18])[0],
        "acquisition_level":   struct.unpack(">H", data[18:20])[0],
        "number_of_fingers":   data[20],
        "scale_units":         data[21],
        "scan_resolution_x":   struct.unpack(">H", data[22:24])[0],
        "scan_resolution_y":   struct.unpack(">H", data[24:26])[0],
        "image_resolution_x":  struct.unpack(">H", data[26:28])[0],
        "image_resolution_y":  struct.unpack(">H", data[28:30])[0],
        "pixel_depth":         data[30],
        "compression":         data[31],
    }

    off = GENERAL_HEADER_LEN
    block_len, = struct.unpack(">I", data[off:off + 4])
    finger = {
        "block_length":    block_len,
        "finger_position": data[off + 4],
        "count_of_views":  data[off + 5],
        "view_number":     data[off + 6],
        "image_quality":   data[off + 7],
        "impression_type": data[off + 8],
        "width":           struct.unpack(">H", data[off + 9:off + 11])[0],
        "height":          struct.unpack(">H", data[off + 11:off + 13])[0],
    }

    if header["compression"] != COMPRESSION_UNCOMPRESSED:
        raise FIRError("compression algorithm %d is not supported by this decoder"
                       % header["compression"])

    expected = finger["width"] * finger["height"]
    start = off + FINGER_HEADER_LEN
    pixels = data[start:start + expected]
    if len(pixels) != expected:
        raise FIRError("expected %d pixel bytes, found %d" % (expected, len(pixels)))

    image = np.frombuffer(pixels, dtype=np.uint8).reshape(
        finger["height"], finger["width"])

    return {"header": header, "finger": finger, "image": image}
