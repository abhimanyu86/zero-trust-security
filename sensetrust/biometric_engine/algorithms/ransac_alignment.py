"""
Minutiae matching via RANSAC (RANdom SAmple Consensus) rigid registration.

Fischler & Bolles, "Random Sample Consensus: A Paradigm for Model Fitting with
Applications to Image Analysis and Automated Cartography", CACM 1981. The general
recipe: repeatedly fit a model from a minimal sample of the data, count how many of
the remaining points agree with it ("inliers"), and keep the model with the most
agreement. Here the model is a 2D rigid transform (rotation + translation, no scale)
that aligns t1 onto t2, and "agreement" is minutiae that land on top of one another
after the transform.

KEY INSIGHT — why the minimal sample here is ONE point, not two
-----------------------------------------------------------------
Generic point-cloud RANSAC (e.g. aligning two LIDAR scans) has no notion of a point's
own orientation, so a single correspondence only pins down a translation — recovering
rotation needs a *second* correspondence to fix the angle between them. That forces an
O(n^2 * m^2) hypothesis space: every pair of points in cloud 1 against every pair in
cloud 2.

A fingerprint minutia is richer than a bare point: it carries a position AND a ridge
direction. Ridge direction rotates rigidly with the finger exactly like position does,
so a single correctly-matched pair (m1 in t1, m2 in t2, same type) already tells us the
whole rotation:

    theta = m2["direction"] - m1["direction"]

and once theta is known, translating m1's rotated position onto m2's position pins
down the rest:

    translation = m2.xy - R(theta) @ m1.xy

That's a complete rigid transform from ONE pair, which shrinks the hypothesis space
from O(n^2 * m^2) pair-of-pairs down to O(n * m) single-pair seeds — the same reason
this trick works for the "one-point RANSAC" used in some SLAM front ends, but applied
here to fingerprint minutiae instead of visual features.

ROTATION INVARIANCE — how this implementation actually achieves it
--------------------------------------------------------------------
This is the property that a previous matcher in this codebase (matching.py's original
"legacy" path) got wrong: it measured edge bearings in absolute image space, so
rotating the finger between enrol and authenticate shifted every descriptor and the
score collapsed to 0% TAR. This module never measures anything in absolute image
space at all — every hypothesis IS a rotation, generated directly from a candidate
pair's own directions (theta above), and every point in t1 is explicitly re-expressed
in t2's frame before comparison. There is no absolute-orientation gate anywhere in
this file. Concretely:

  - The seed step reads only the *difference* of two directions (theta), never an
    absolute bearing.
  - Inlier direction agreement compares `m1.direction + theta` against the matched
    t2 point's direction — again a relative comparison, invariant to how either
    capture happened to be rotated when it was taken.
  - Distance tolerance is scaled by each template's own median nearest-neighbour
    spacing (see `_median_nn_spacing`), not a fixed pixel radius, so the algorithm is
    resolution-independent too: a capture at higher zoom or DPI doesn't need a
    different tolerance constant.

Net effect: this algorithm is rotation invariant by construction, not by a gate that
happens to survive rotation — there was never an absolute frame to begin with. It is
NOT scale invariant by construction (no "no scale" transform can be, since scale
isn't part of the model), but the distance tolerance being spacing-relative means
that a modest scale difference degrades gracefully rather than falling off a cliff.

MECHANISM
---------
1. Build a bounded, deterministic list of candidate seed pairs: every same-type
   (m1, m2) across t1 x t2, ranked by a cheap density heuristic (minutiae with more
   same-type neighbours nearby are more likely to be genuine, well-conditioned
   landmarks) with a fixed index-order tie-break, then capped at SEED_BUDGET. No
   unseeded randomness anywhere — same two inputs always walk the same seed order.
2. For each seed, estimate the rigid transform (theta, translation) as above, apply
   it to every point in t1, and count inliers: t2 points within a spacing-relative
   distance tolerance of some transformed t1 point, of the SAME TYPE, whose predicted
   direction (m1.direction + theta) is also within an angular tolerance of the
   matched t2 point's actual direction. The direction check is what rejects
   coincidental distance-only agreement — two unrelated minutiae can easily land near
   each other under some rotation hypothesis by chance, but agreeing in direction too
   is far less likely by chance.
3. Matches within a hypothesis are deduplicated greedily (closest distance first,
   each t1/t2 index used at most once) so a single popular t2 minutia can't be
   double-counted as an inlier for multiple t1 points.
4. Keep the hypothesis with the most inliers; score is coverage against the smaller
   template, gated by the same count-ratio used everywhere else in this codebase.
"""

import math

import numpy as np
from scipy.spatial import cKDTree

# ── Parameters ───────────────────────────────────────────────────────────────

# Minimum count ratio between two templates before matching is attempted — identical
# gate and threshold to matching.py, for consistency across the bake-off.
MIN_COUNT_RATIO = 0.45

# Deterministic cap on the number of single-pair seed hypotheses tried. Candidate
# pairs are ranked by density before this cap is applied, so the pairs most likely to
# be genuine, well-supported landmarks are the ones spent on first.
SEED_BUDGET = 300

# Inlier distance tolerance, as a fraction of the template's own median
# nearest-neighbour spacing rather than a fixed pixel value — keeps the algorithm
# resolution-independent (a capture at higher zoom/DPI just has a larger spacing, and
# the tolerance scales with it automatically).
DIST_TOL_FACTOR = 0.6

# Inlier direction tolerance. Minutiae direction estimation is noisy (encoder /
# extractor error of a few degrees is typical); this is intentionally more forgiving
# than that noise floor while still rejecting coincidental distance-only agreement.
ANGLE_TOL = math.radians(20)

# Radius (as a multiple of median NN spacing) used only to rank candidate seeds by
# local same-type density — this is a priority heuristic, not a filter, so it never
# rejects a pair outright.
DENSITY_RADIUS_FACTOR = 3.0


# ══════════════════════════════════════════════════════════════════════════════
# PRIMITIVES
# ══════════════════════════════════════════════════════════════════════════════

def _median_nn_spacing(pts):
    """Median distance from each point to its nearest other point, or None if the
    template is degenerate (fewer than 2 distinct points)."""
    if len(pts) < 2:
        return None
    tree = cKDTree(pts)
    dists, _ = tree.query(pts, k=2)
    nn = dists[:, 1]
    med = float(np.median(nn))
    return med if med > 1e-9 else None


def _density_feature(pts, types, radius):
    """
    Number of same-type neighbours within `radius`, per point.

    Used only to order candidate seed pairs so well-supported minutiae are tried
    first within the hypothesis budget — a coincidental or spurious minutia tends to
    sit apart from same-type structure and so sorts to the back, but nothing is ever
    excluded on this basis alone.
    """
    n = len(pts)
    counts = np.zeros(n, dtype=int)
    if n < 2 or radius is None:
        return counts
    for t in set(types):
        idxs = [i for i in range(n) if types[i] == t]
        if len(idxs) < 2:
            continue
        sub_pts = pts[idxs]
        sub_tree = cKDTree(sub_pts)
        neigh = sub_tree.query_ball_tree(sub_tree, r=radius)
        for local_i, global_i in enumerate(idxs):
            counts[global_i] = len(neigh[local_i]) - 1  # exclude self
    return counts


def _rotation_matrix(theta):
    c, s = math.cos(theta), math.sin(theta)
    return np.array([[c, -s], [s, c]])


# ══════════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ══════════════════════════════════════════════════════════════════════════════

def match(t1, t2):
    """
    Similarity of two minutiae sets, in [0, 1], via single-pair RANSAC rigid
    registration. See the module docstring for the algorithm and why one matched
    minutia pair (not two) is enough to hypothesise a full rigid transform here.
    """
    ratio = min(len(t1), len(t2)) / max(len(t1), len(t2))
    if ratio < MIN_COUNT_RATIO:
        return 0.0

    n1, n2 = len(t1), len(t2)
    # Not enough structure to hypothesise or verify a transform from — a single point
    # has no meaningful "neighbourhood" to check agreement against.
    if n1 < 2 or n2 < 2:
        return 0.0

    pts1 = np.array([[m["x"], m["y"]] for m in t1], dtype=float)
    pts2 = np.array([[m["x"], m["y"]] for m in t2], dtype=float)
    dir1 = np.array([m["direction"] for m in t1], dtype=float)
    dir2 = np.array([m["direction"] for m in t2], dtype=float)
    type1 = [m["type"] for m in t1]
    type2 = [m["type"] for m in t2]

    spacing1 = _median_nn_spacing(pts1)
    spacing2 = _median_nn_spacing(pts2)
    spacings = [s for s in (spacing1, spacing2) if s is not None]
    if not spacings:
        return 0.0                                   # both templates degenerate
    spacing = sum(spacings) / len(spacings)
    dist_tol = DIST_TOL_FACTOR * spacing

    density1 = _density_feature(pts1, type1, DENSITY_RADIUS_FACTOR * spacing)
    density2 = _density_feature(pts2, type2, DENSITY_RADIUS_FACTOR * spacing)

    # Every same-type (i, j) pair is a candidate seed. Ranked by combined density,
    # ties broken by index — fully deterministic, no RNG involved anywhere in this
    # module.
    candidates = []
    for i in range(n1):
        for j in range(n2):
            if type1[i] != type2[j]:
                continue
            candidates.append((int(density1[i]) + int(density2[j]), i, j))
    if not candidates:
        return 0.0

    candidates.sort(key=lambda c: (-c[0], c[1], c[2]))
    candidates = candidates[:SEED_BUDGET]

    # Precompute, once, what the inner loop needs on every hypothesis: for each
    # type, which t1 rows have it, and a KD-tree over the matching t2 points.
    rows_by_type = {t: np.array([k for k in range(n1) if type1[k] == t])
                     for t in set(type1)}
    type_trees = {}
    for t in set(type2):
        idxs = np.array([j for j in range(n2) if type2[j] == t])
        type_trees[t] = (idxs, cKDTree(pts2[idxs]))

    two_pi = 2 * math.pi
    best_inliers = 0
    best_n = min(n1, n2)

    for _, si, sj in candidates:
        theta = dir2[sj] - dir1[si]
        R = _rotation_matrix(theta)

        transformed = pts1 @ R.T
        translation = pts2[sj] - transformed[si]
        transformed = transformed + translation
        pred_dir = (dir1 + theta) % two_pi

        raw_matches = []                             # (distance, t1_idx, t2_idx)
        for t, rows1 in rows_by_type.items():
            tree_entry = type_trees.get(t)
            if tree_entry is None or len(rows1) == 0:
                continue
            idxs2, tree2 = tree_entry
            dists, nn_local = tree2.query(transformed[rows1], k=1)
            dists = np.atleast_1d(dists)
            nn_local = np.atleast_1d(nn_local)
            for row, d, nn in zip(rows1, dists, nn_local):
                if d > dist_tol:
                    continue
                t2_idx = int(idxs2[nn])
                dd = abs((pred_dir[row] - dir2[t2_idx] + math.pi) % two_pi - math.pi)
                if dd > ANGLE_TOL:
                    continue
                raw_matches.append((d, int(row), t2_idx))

        # Greedy one-to-one dedup: closest agreement wins, each index used once —
        # keeps a single popular t2 minutia from being counted as several inliers.
        raw_matches.sort(key=lambda m: m[0])
        used1, used2, inliers = set(), set(), 0
        for d, a, b in raw_matches:
            if a in used1 or b in used2:
                continue
            used1.add(a)
            used2.add(b)
            inliers += 1

        if inliers > best_inliers:
            best_inliers = inliers
            if best_inliers >= best_n:
                break                                 # can't beat a full match

    score = (best_inliers / best_n) * ratio
    return float(max(0.0, min(1.0, score)))
