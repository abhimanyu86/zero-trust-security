"""
Synthetic biometric data for the PoC.

The generators are the ones the UIDAI contactless-fingerprint SDK's own test suite uses
(backend/tests/test_matching.py, test_spoof_detection.py), so the zero-trust layer is
exercised against the same assumptions the biometric engine was validated under.

`recapture` is deliberately harsh: two real captures never yield the same minutiae set,
so it drops genuine minutiae, adds spurious ones and rotates the finger.
"""

import math
import random

import numpy as np


def make_template(n=40, width=200, height=250, seed=0):
    rng = random.Random(seed)
    return [{"x": rng.uniform(0, width), "y": rng.uniform(0, height),
             "direction": rng.uniform(0, 2 * math.pi),
             "type": "BIF" if rng.random() > 0.5 else "RIG"} for _ in range(n)]


def _rotate(tmpl, degrees):
    th = math.radians(degrees)
    c, s = math.cos(th), math.sin(th)
    return [{**m, "x": m["x"] * c - m["y"] * s, "y": m["x"] * s + m["y"] * c,
             "direction": (m["direction"] + th) % (2 * math.pi)} for m in tmpl]


def _jitter(tmpl, px, rad, seed):
    rng = random.Random(seed)
    return [{**m, "x": m["x"] + rng.uniform(-px, px), "y": m["y"] + rng.uniform(-px, px),
             "direction": (m["direction"] + rng.uniform(-rad, rad)) % (2 * math.pi)}
            for m in tmpl]


def recapture(t, drop=0.3, spurious=0.2, rotation=20, seed=0):
    rng = random.Random(seed)
    kept = [m for m in t if rng.random() > drop]
    xs, ys = [m["x"] for m in t], [m["y"] for m in t]
    for _ in range(int(len(t) * spurious)):
        kept.append({"x": rng.uniform(min(xs), max(xs)), "y": rng.uniform(min(ys), max(ys)),
                     "direction": rng.uniform(0, 2 * math.pi),
                     "type": "BIF" if rng.random() > 0.5 else "RIG"})
    return _rotate(_jitter(kept, 3.0, 0.10, seed), rotation)


def ridge_image(period=10.0, size=256, angle=0.0, noise=6.0, seed=0):
    """Live-finger stand-in: one dominant ridge frequency. Returns BGR uint8."""
    yy, xx = np.mgrid[0:size, 0:size].astype(np.float32)
    proj = xx * math.cos(angle) + yy * math.sin(angle)
    img = (np.sin(2 * math.pi * proj / period) * 0.5 + 0.5) * 255
    if noise:
        img = img + np.random.RandomState(seed).normal(0, noise, size=img.shape)
    g = np.clip(img, 0, 255).astype(np.uint8)
    return np.dstack([g] * 3)


def screen_recapture_image(ridge_period=10.0, grid_period=8.0, size=256, angle=0.0):
    """A finger photo held up on a phone screen: ridges plus the display's pixel grid."""
    base = ridge_image(period=ridge_period, size=size, angle=angle, noise=0)[..., 0].astype(np.float32)
    yy, xx = np.mgrid[0:size, 0:size].astype(np.float32)
    grid = (np.sign(np.sin(2 * math.pi * xx / grid_period)) +
            np.sign(np.sin(2 * math.pi * yy / grid_period)))
    g = np.clip(base + grid * 18, 0, 255).astype(np.uint8)
    return np.dstack([g] * 3)
