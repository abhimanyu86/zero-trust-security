"""
Minutiae matching via RANSAC rigid registration — v2 of `ransac_alignment.py`.

Same core idea as the original (see that file's docstring for the full "why one point
is enough" argument, which is unchanged here): a minutia carries both position and
direction, so a single matched pair fully determines a rigid transform, collapsing the
hypothesis space to O(n*m) single-pair seeds instead of O(n^2*m^2) pair-of-pairs.

This module exists because testing `ransac_alignment` surfaced three concrete, narrowly
scoped weaknesses, each fixed independently and kept separate from the original so the
bake-off shows a direct before/after rather than a silent replacement:

1. NO SCALE INVARIANCE. The original's transform model is rotation+translation only —
   there is no "rotation+translation+scale, no scale" version of a transform, since
   scale isn't part of the model at all. It failed `test_scale_invariance` outright
   (score dropped to ~0.20-0.45x baseline at 0.85x-1.5x rescale, well below the 0.8x
   bar). Fix: normalise both templates independently to a canonical median-nearest-
   neighbour spacing *before* the RANSAC search ever runs — the same technique
   `matching.py`'s `_scale` and `mcc_cylinder.py`'s cylinder-radius normalisation
   already use. For two templates that are already the same scale this is close to a
   no-op (both get ~the same rescale factor, so their *relative* geometry is
   unchanged) — it only helps the case that was failing, it can't regress the case
   that already worked.

2. NO REFIT. The original scores a hypothesis using only the raw transform derived
   from its single seed pair — even after finding the best-supported hypothesis, the
   final answer is still that one pair's transform, never re-estimated from the full
   inlier set it collected. Fix: once the best seed is found, re-estimate the
   rotation+translation via a proper 2D Kabsch/Procrustes least-squares fit over every
   inlier it collected (not just the seed pair), then recount inliers under the
   refined transform. Standard "RANSAC then refit" practice — a transform derived from
   several points is generally more accurate than one derived from a single pair.

3. CONFIDENCE IGNORED. `detect_minutiae` attaches a per-minutia `confidence`
   (`app.py:862`, the network's own location-heatmap value) that no algorithm in this
   codebase reads, this one included. Fix: fold confidence into how candidate seeds
   are *ordered* — high-confidence pairs are tried first, so the right transform is
   more likely to be found within the same hypothesis budget. This changes search
   order only, never the accept/reject decision or the score formula itself: whether
   `confidence` is a reliable, well-calibrated signal is not independently verified
   (see PIPELINE_ALGORITHMS.md), so it's used to search faster, not to decide what
   counts as a match. `confidence` is read via `.get(..., 1.0)` throughout, since
   synthetic test data (`tests/test_matching.py`'s `make_template`) doesn't include
   the field at all — every minutia is treated as maximally confident by default.

Rotation invariance is unaffected by any of this — everything the original docstring
says about never measuring an absolute bearing still holds verbatim here; scale
normalisation and the refit both operate entirely in relative/derived space.
"""

import math

import numpy as np
from scipy.spatial import cKDTree

# ── Parameters ───────────────────────────────────────────────────────────────

MIN_COUNT_RATIO = 0.45
SEED_BUDGET = 300
DIST_TOL_FACTOR = 0.6
ANGLE_TOL = math.radians(20)
DENSITY_RADIUS_FACTOR = 3.0

# New in this version.
TARGET_SPACING = 20.0       # canonical median-NN spacing after normalisation —
                             # matches matching.py's SCALE_TARGET_NN for consistency
CONFIDENCE_WEIGHT = 5.0     # how much a pair's combined confidence (each in ~[0,1])
                             # counts against combined density (integer neighbour
                             # counts) when ranking candidate seeds — density and
                             # confidence are both priority heuristics, so this only
                             # changes search order, never correctness
MIN_INLIERS_FOR_REFIT = 3   # below this a least-squares fit is underdetermined/
                             # noise-dominated; fall back to the raw seed transform


# ══════════════════════════════════════════════════════════════════════════════
# PRIMITIVES
# ══════════════════════════════════════════════════════════════════════════════

def _median_nn_spacing(pts):
    if len(pts) < 2:
        return None
    tree = cKDTree(pts)
    dists, _ = tree.query(pts, k=2)
    med = float(np.median(dists[:, 1]))
    return med if med > 1e-9 else None


def _normalize_scale(pts, target=TARGET_SPACING):
    """Rescale so the template's own median nearest-neighbour spacing hits `target`."""
    spacing = _median_nn_spacing(pts)
    if spacing is None:
        return pts
    return pts * (target / spacing)


def _density_feature(pts, types, radius):
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
            counts[global_i] = len(neigh[local_i]) - 1
    return counts


def _rotation_matrix(theta):
    c, s = math.cos(theta), math.sin(theta)
    return np.array([[c, -s], [s, c]])


def _kabsch_2d(src_pts, dst_pts):
    """
    Optimal rotation + translation (least squares, no scale) mapping src onto dst.

    Standard Kabsch/orthogonal-Procrustes solution via SVD of the cross-covariance
    matrix, with a reflection guard (det check) so the result is always a proper
    rotation, never a mirror flip — a real risk with only 2-3 near-collinear points.
    """
    src_c = src_pts.mean(axis=0)
    dst_c = dst_pts.mean(axis=0)
    H = (src_pts - src_c).T @ (dst_pts - dst_c)
    U, _, Vt = np.linalg.svd(H)
    d = np.sign(np.linalg.det(Vt.T @ U.T)) or 1.0
    R = Vt.T @ np.diag([1.0, d]) @ U.T
    t = dst_c - R @ src_c
    return R, t


def _count_inliers(transformed, pred_dir, pts2_by_type, rows_by_type, dist_tol):
    """
    Shared inlier-counting step, used both for the raw seed hypothesis and again for
    the refit. Returns the deduplicated (distance, t1_idx, t2_idx) inlier list.
    """
    raw_matches = []
    for t, rows1 in rows_by_type.items():
        entry = pts2_by_type.get(t)
        if entry is None or len(rows1) == 0:
            continue
        idxs2, tree2, dirs2 = entry
        dists, nn_local = tree2.query(transformed[rows1], k=1)
        dists = np.atleast_1d(dists)
        nn_local = np.atleast_1d(nn_local)
        for row, d, nn in zip(rows1, dists, nn_local):
            if d > dist_tol:
                continue
            t2_idx = int(idxs2[nn])
            dd = abs((pred_dir[row] - dirs2[nn] + math.pi) % (2 * math.pi) - math.pi)
            if dd > ANGLE_TOL:
                continue
            raw_matches.append((d, int(row), t2_idx))

    raw_matches.sort(key=lambda m: m[0])
    used1, used2, inliers = set(), set(), []
    for d, a, b in raw_matches:
        if a in used1 or b in used2:
            continue
        used1.add(a)
        used2.add(b)
        inliers.append((a, b))
    return inliers


# ══════════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ══════════════════════════════════════════════════════════════════════════════

def match(t1, t2):
    """Similarity of two minutiae sets, in [0, 1]. See the module docstring for what
    changed relative to `ransac_alignment.match` and why."""
    ratio = min(len(t1), len(t2)) / max(len(t1), len(t2))
    if ratio < MIN_COUNT_RATIO:
        return 0.0

    n1, n2 = len(t1), len(t2)
    if n1 < 2 or n2 < 2:
        return 0.0

    pts1_raw = np.array([[m["x"], m["y"]] for m in t1], dtype=float)
    pts2_raw = np.array([[m["x"], m["y"]] for m in t2], dtype=float)
    dir1 = np.array([m["direction"] for m in t1], dtype=float)
    dir2 = np.array([m["direction"] for m in t2], dtype=float)
    type1 = [m["type"] for m in t1]
    type2 = [m["type"] for m in t2]
    conf1 = np.array([float(m.get("confidence", 1.0)) for m in t1], dtype=float)
    conf2 = np.array([float(m.get("confidence", 1.0)) for m in t2], dtype=float)

    # Fix 1: normalise scale independently, before anything else runs.
    pts1 = _normalize_scale(pts1_raw)
    pts2 = _normalize_scale(pts2_raw)

    dist_tol = DIST_TOL_FACTOR * TARGET_SPACING
    density_radius = DENSITY_RADIUS_FACTOR * TARGET_SPACING

    density1 = _density_feature(pts1, type1, density_radius)
    density2 = _density_feature(pts2, type2, density_radius)

    # Fix 3: rank candidate seeds by density AND confidence, not density alone.
    candidates = []
    for i in range(n1):
        for j in range(n2):
            if type1[i] != type2[j]:
                continue
            rank = (density1[i] + density2[j]) + CONFIDENCE_WEIGHT * (conf1[i] + conf2[j])
            candidates.append((rank, i, j))
    if not candidates:
        return 0.0

    candidates.sort(key=lambda c: (-c[0], c[1], c[2]))
    candidates = candidates[:SEED_BUDGET]

    rows_by_type = {t: np.array([k for k in range(n1) if type1[k] == t])
                     for t in set(type1)}
    pts2_by_type = {}
    for t in set(type2):
        idxs = np.array([j for j in range(n2) if type2[j] == t])
        pts2_by_type[t] = (idxs, cKDTree(pts2[idxs]), dir2[idxs])

    two_pi = 2 * math.pi
    best_inliers = []
    best_n = min(n1, n2)

    for _, si, sj in candidates:
        theta = dir2[sj] - dir1[si]
        R = _rotation_matrix(theta)
        transformed = pts1 @ R.T
        translation = pts2[sj] - transformed[si]
        transformed = transformed + translation
        pred_dir = (dir1 + theta) % two_pi

        inliers = _count_inliers(transformed, pred_dir, pts2_by_type, rows_by_type, dist_tol)
        if len(inliers) > len(best_inliers):
            best_inliers = inliers
            if len(best_inliers) >= best_n:
                break

    # Fix 2: refit over every inlier the winning hypothesis collected, not just its
    # seed pair, then recount under the refined transform. Only worth it with enough
    # points for an over-determined fit; below that the raw single-pair transform
    # already IS the best available estimate.
    if len(best_inliers) >= MIN_INLIERS_FOR_REFIT:
        rows1 = np.array([a for a, _ in best_inliers])
        rows2 = np.array([b for _, b in best_inliers])
        R, t = _kabsch_2d(pts1[rows1], pts2[rows2])
        transformed = pts1 @ R.T + t
        theta = math.atan2(R[1, 0], R[0, 0])
        pred_dir = (dir1 + theta) % two_pi

        refined = _count_inliers(transformed, pred_dir, pts2_by_type, rows_by_type, dist_tol)
        if len(refined) > len(best_inliers):
            best_inliers = refined

    score = (len(best_inliers) / best_n) * ratio
    return float(max(0.0, min(1.0, score)))
