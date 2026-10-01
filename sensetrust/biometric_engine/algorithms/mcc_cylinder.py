"""
Minutia Cylinder-Code (MCC) — the real algorithm.

Cappelli, R., Ferrara, M., & Maltoni, D. (2010). "Minutia Cylinder-Code: A New
Representation and Matching Technique for Fingerprint Recognition." IEEE Transactions on
Pattern Analysis and Machine Intelligence, 32(12), 2128-2141.

matching.py's `modern`/`legacy` algorithms were historically described as "MCC-style" in
this codebase despite building no cylinder structures at all — they are a k-NN graph with
relaxation labeling, closer to Ratha/Jain local-structure matching (see matching.py's
module docstring and MATCHING_ALGORITHMS.md, where this mislabeling is called out
directly). This module is the thing the name actually refers to: every minutia gets a
discretized cylinder built around it — a disc of spatial cells crossed with a full circle
of angular cells — and two templates are compared cylinder-to-cylinder, consolidated by
Local Similarity Sort (LSS), exactly as the paper's title describes.

Deviations from the paper, made deliberately and documented rather than silently:

  - The paper binarizes each cell (bit-vector cylinders, matched by a bit-count formula
    equivalent to Tanimoto/Jaccard similarity). This implementation keeps cell values
    continuous (summed Gaussian contributions) and compares cylinders with cosine
    similarity. Cosine similarity over non-negative Gaussian-weighted vectors reduces to
    the same "how much do these two local neighbourhoods agree" question the bit-vector
    formula answers, without the information loss of a hard 0.5 threshold, and without
    needing the paper's separate validity/reliability bit-masks (this codebase has no
    ridge-map/ROI data to compute those from — see the data contract below).
  - LSS here is the paper's actual consolidation idea (sort all local similarities, average
    the top ones) but without the paper's second-stage global consistency check
    (relaxation over the selected pairs). That refinement is what matching.py's `modern`
    algorithm already does in a different structural form; keeping this module to LSS
    alone is what makes it a clean, distinct comparison point in the bake-off rather than
    a second copy of the same idea.
  - Cylinder radius R is not a fixed pixel constant (the paper uses one because it always
    operates at a fixed sensor DPI). This codebase's minutiae are in arbitrary pixel-ish
    units — see the data contract in MATCHING_ALGORITHMS.md — so R is instead derived from
    each template's own median nearest-neighbour distance (see `_median_nn_distance`),
    the same scale-normalisation idea matching.py's `modern` path uses for its own reasons.
    Rescale a whole template uniformly and R rescales with it; the cylinders — and hence
    the score — do not change.

Rotation invariance — read this before touching the geometry
---------------------------------------------------------------
This is the one property this codebase has already gotten wrong once (matching.py's
`legacy` path measured edge bearings in absolute image space, so a rotated capture shifted
every angle and the matcher scored ~0% TAR on real phone photos — see matching.py's module
docstring and `test_legacy_collapses_under_rotation`). MCC is rotation invariant by
construction, but only if the *relative frame* step below is implemented exactly right:

For a cylinder centred on minutia m, every other minutia's contribution is expressed in
m's own reference frame, not in image space:

    rel = R(-m.direction) @ (other.xy - m.xy)          # position, rotated into m's frame
    rel_direction = (other.direction - m.direction) mod 2*pi   # direction, relative to m's

`R(-m.direction)` is the standard 2D rotation matrix by angle `-m.direction`. Under a rigid
rotation of the whole template by theta (every position rotates by theta AND every stored
`direction` increases by theta mod 2*pi — the convention this codebase uses throughout, see
`tests/test_matching.py`'s `rotate()` helper), both `m.direction` and `other.direction`
shift by the same theta, so:

    new_rel = R(-(m.direction + theta)) @ (R(theta) @ (other.xy - m.xy))
            = R(-m.direction) @ (other.xy - m.xy)      # theta cancels exactly
    new_rel_direction = (other.direction + theta) - (m.direction + theta)  (mod 2*pi)
                       = other.direction - m.direction  (mod 2*pi)         # theta cancels

Both quantities that get binned into the cylinder are unchanged by a global rotation, so
the cylinder itself — and every downstream similarity score — is unchanged. Skipping the
`R(-m.direction)` step (binning `other.xy - m.xy` directly, in image-space coordinates) is
exactly the bug `legacy` had; it would silently make this module just as rotation-fragile.
"""

import math

import numpy as np
from scipy.spatial import cKDTree

# ── Parameters ───────────────────────────────────────────────────────────────
# Minimum count ratio between two templates before matching is attempted at all — the
# same gate every algorithm in this codebase applies before doing any geometry.
MIN_COUNT_RATIO = 0.45

# Fewer than this many minutiae isn't enough to build a meaningful cylinder (no
# neighbourhood to describe) or even to compute a median nearest-neighbour distance
# reliably. Matching degrades to noise below this, so bail out instead of returning a
# number that looks meaningful but isn't.
MIN_MINUTIAE = 3

NS = 8              # spatial grid resolution (NS x NS cells span the cylinder's disc)
ND = 5               # angular cells, covering the full [0, 2*pi) range
R_FACTOR = 3.0       # cylinder radius = R_FACTOR * median nearest-neighbour distance

# Gaussian falloff widths, both expressed relative to the grid's own cell size rather
# than as absolute constants — this is what keeps the whole thing scale-independent
# alongside R itself. sigma_s of one spatial cell width gives each minutia's contribution
# a smooth footprint over roughly its own cell and its immediate neighbours, rather than
# either a hard bin edge or a blur across the whole disc. sigma_d of half an angular cell
# width does the equivalent for direction.
SPATIAL_SIGMA_CELLS = 1.0
ANGULAR_SIGMA_FRACTION = 0.5


# ══════════════════════════════════════════════════════════════════════════════
# PRIMITIVES
# ══════════════════════════════════════════════════════════════════════════════

def _median_nn_distance(points):
    """
    Median nearest-neighbour distance of a point cloud, via a KD-tree.

    Self-contained re-implementation of the same idea matching.py's `_scale` uses (median
    rather than mean/bbox-span for outlier robustness) — deliberately not imported, per
    this package's independence rule; see backend/algorithms/__init__.py.
    """
    if len(points) < 2:
        return None
    tree = cKDTree(points)
    nn = tree.query(points, k=2)[0][:, 1]     # distance to nearest *other* point
    med = float(np.median(nn))
    return med if med > 1e-9 else None


def _circular_diff(a, b):
    """Smallest angular difference between a and b (broadcastable), result in [0, pi]."""
    d = np.abs(a - b) % (2 * math.pi)
    return np.minimum(d, 2 * math.pi - d)


def _build_cell_grid(radius, ns):
    """
    NS x NS spatial cell centres, keeping only those that fall inside the disc of the
    given radius (the cylinder's actual cross-section is a circle, not a square — corner
    cells of the bounding square are dropped). The centre-of-mass grid position is the
    standard MCC cell-centre formula: cells indexed 0..ns-1, each cell_size wide, centred
    at -R + (index + 0.5) * cell_size.

    This mask depends only on `radius` and `ns`, so it is identical for every cylinder
    built at a given R within one match() call — including cylinders from both templates
    — which is what makes the resulting flattened vectors directly comparable.
    """
    cell_size = 2.0 * radius / ns
    coords = -radius + (np.arange(ns) + 0.5) * cell_size
    xx, yy = np.meshgrid(coords, coords, indexing="ij")
    centres = np.stack([xx.ravel(), yy.ravel()], axis=1)
    dist = np.linalg.norm(centres, axis=1)
    return centres[dist <= radius]


def _angle_centres(nd):
    step = 2 * math.pi / nd
    return (np.arange(nd) + 0.5) * step


def _build_cylinders(tmpl, radius, cell_centres, angle_centres, sigma_s, sigma_d):
    """
    One flattened cylinder vector per minutia in `tmpl`.

    For minutia i, every *other* minutia within `radius` contributes a Gaussian blob to
    every (spatial cell, angular cell) pair: a spatial term from its distance to the cell
    centre once expressed in minutia i's own reference frame (see the module docstring —
    this is the step that makes the whole thing rotation invariant), and an angular term
    from how far its direction, relative to minutia i's direction, sits from the cell's
    angle. Cell value = sum of these contributions over all qualifying minutiae — this
    module keeps values continuous rather than binarizing at 0.5 (see module docstring).

    Returns (vectors, types): vectors is an (n, P*ND) float array (P = number of valid
    spatial cells), types is the parallel list of minutia types for the type-gate in
    match().
    """
    n = len(tmpl)
    pts = np.array([[m["x"], m["y"]] for m in tmpl], dtype=float)
    dirs = np.array([m["direction"] for m in tmpl], dtype=float)
    types = [m["type"] for m in tmpl]

    p = cell_centres.shape[0]
    vectors = np.zeros((n, p * len(angle_centres)), dtype=float)

    for i in range(n):
        theta = dirs[i]
        c, s = math.cos(-theta), math.sin(-theta)
        delta = pts - pts[i]
        # Rotate every other minutia's offset into minutia i's own reference frame.
        rel = np.stack([
            delta[:, 0] * c - delta[:, 1] * s,
            delta[:, 0] * s + delta[:, 1] * c,
        ], axis=1)
        rel = np.delete(rel, i, axis=0)
        rel_dirs = (np.delete(dirs, i) - theta) % (2 * math.pi)

        dist = np.linalg.norm(rel, axis=1)
        keep = dist <= radius
        if not np.any(keep):
            continue                          # nothing nearby -> cylinder stays all-zero
        rel = rel[keep]
        rel_dirs = rel_dirs[keep]

        # Spatial weights: (P, k) — distance from every cell centre to every contributing
        # minutia's (rotated) position.
        diff = cell_centres[:, None, :] - rel[None, :, :]
        spatial_dist2 = np.sum(diff ** 2, axis=-1)
        spatial_w = np.exp(-spatial_dist2 / (2 * sigma_s ** 2))

        # Angular weights: (ND, k) — circular distance from every angular cell to every
        # contributing minutia's direction, relative to minutia i's own direction.
        ang_diff = _circular_diff(angle_centres[:, None], rel_dirs[None, :])
        angular_w = np.exp(-ang_diff ** 2 / (2 * sigma_d ** 2))

        # Outer combination over the shared "k contributing minutiae" axis: cell (p, d)
        # gets sum_k spatial_w[p, k] * angular_w[d, k].
        cylinder = spatial_w.dot(angular_w.T)      # (P, ND)
        vectors[i] = cylinder.ravel()

    return vectors, types


# ══════════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ══════════════════════════════════════════════════════════════════════════════

def match(t1, t2):
    """
    Similarity of two minutiae templates via Minutia Cylinder-Code, in [0, 1].

    See the module docstring for the algorithm, its deliberate deviations from the 2010
    paper, and a worked proof of why the relative-frame step makes this rotation
    invariant. Same data contract as matching.match_templates: each minutia is a dict
    with x, y, direction (radians) and type ("RIG" or "BIF"); t1/t2 are non-empty lists
    (the empty/None case is the caller's responsibility, not this function's).
    """
    ratio = min(len(t1), len(t2)) / max(len(t1), len(t2))
    if ratio < MIN_COUNT_RATIO:
        return 0.0
    if len(t1) < MIN_MINUTIAE or len(t2) < MIN_MINUTIAE:
        return 0.0

    pts1 = np.array([[m["x"], m["y"]] for m in t1], dtype=float)
    pts2 = np.array([[m["x"], m["y"]] for m in t2], dtype=float)
    r1 = _median_nn_distance(pts1)
    r2 = _median_nn_distance(pts2)
    if r1 is None or r2 is None:
        return 0.0

    # A single shared radius, derived from both templates' own density, is what keeps
    # the two sets of cylinders directly comparable — see module docstring.
    radius = R_FACTOR * ((r1 + r2) / 2.0)
    if radius <= 1e-9:
        return 0.0

    cell_centres = _build_cell_grid(radius, NS)
    if cell_centres.shape[0] == 0:
        return 0.0
    angle_centres = _angle_centres(ND)

    cell_size = 2.0 * radius / NS
    sigma_s = SPATIAL_SIGMA_CELLS * cell_size
    sigma_d = ANGULAR_SIGMA_FRACTION * (2 * math.pi / ND)

    vecs1, types1 = _build_cylinders(t1, radius, cell_centres, angle_centres, sigma_s, sigma_d)
    vecs2, types2 = _build_cylinders(t2, radius, cell_centres, angle_centres, sigma_s, sigma_d)

    # Local similarity: cosine similarity between cylinder vectors. Values are
    # non-negative sums of Gaussian contributions, so cosine similarity naturally lands
    # in [0, 1] (clipped below purely against floating-point noise).
    norms1 = np.linalg.norm(vecs1, axis=1)
    norms2 = np.linalg.norm(vecs2, axis=1)
    denom = np.outer(norms1, norms2)
    dot = vecs1.dot(vecs2.T)
    sim = np.zeros_like(dot)
    usable = denom > 1e-12
    sim[usable] = dot[usable] / denom[usable]
    sim = np.clip(sim, 0.0, 1.0)

    # Only compare cylinders whose centre minutiae share a type — a ridge-ending
    # cylinder and a bifurcation cylinder are never the same local structure regardless
    # of how their cell values happen to line up numerically.
    type_mask = np.array([[a == b for b in types2] for a in types1], dtype=bool)
    if not np.any(type_mask):
        return 0.0
    candidates = sim[type_mask]

    # Local Similarity Sort: consolidate into one score by averaging the top-K local
    # similarities across the whole (type-filtered) i x j matrix — the paper's actual
    # consolidation technique, deliberately simpler than matching.py's relaxation
    # labeling (see module docstring).
    k = min(min(len(t1), len(t2)), candidates.size)
    if k <= 0:
        return 0.0
    top = np.partition(candidates, -k)[-k:] if k < candidates.size else candidates

    score = float(np.mean(top))
    return float(max(0.0, min(1.0, score)))
