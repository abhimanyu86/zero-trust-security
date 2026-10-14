"""
Delaunay triangulation matching (candidate 3 in the bake-off, MATCHING_ALGORITHMS.md).

A structural-matching technique going back to fingerprint-recognition literature of the
early 2000s (e.g. Parziale & Niel's use of Delaunay triangulation for topology-based
minutiae matching): triangulate each minutiae set, describe every triangle with features
that survive a rigid motion, find triangles that agree between the two templates, and let
those agreements vote for individual minutia correspondences.

This is a genuinely different structural primitive from `matching.py`'s k-NN graph (and
from candidate 1's Hungarian-assignment variant of it): instead of describing a minutia
by its nearest neighbours, it describes it by the triangles a global triangulation of the
*whole point set* happens to put it in. `scipy.spatial.Delaunay` is deterministic given a
point set (ties aside, which do not occur with our floating-point coordinates), so the
triangulation itself is not something we tune — only the per-triangle feature comparison
and the voting/assignment on top of it are.

Rotation and translation invariance
------------------------------------
The triangulation is computed independently on each template's raw (x, y) — no shared
frame is needed. What makes matching between the two triangulations rotation- and
translation-invariant is the choice of *triangle features*, not the triangulation step:

  - The three interior angles of a triangle are unchanged by translating or rotating its
    vertices — they depend only on the shape, not on where or how it is oriented in the
    plane. That is the entire mechanism this module relies on for rotation invariance:
    angles computed from (x, y) after any rigid motion are identical to the angles before
    it, up to floating-point noise. No coordinate is ever compared to another coordinate
    across templates — only angle-to-angle and (optionally) ratio-to-ratio.
  - Side-length *ratios* (each side divided by the triangle's longest side) add scale
    robustness on top: they are invariant to uniform scaling as well as rotation and
    translation, which plain side lengths are not. This module uses them as a secondary,
    coarser filter alongside angles, not as a replacement for them.

This mirrors, at the triangle level, the same fix `matching.py` had to make at the edge
level: the original single-finger matcher (`_match_legacy`) measured edge bearings in
absolute image space, which made a rotated finger score 0% TAR, because an absolute
bearing is not preserved by rotation. Interior angles and side-ratios are preserved by
rotation (and, for ratios, by scale) by construction, so this module never needs an
alignment step before comparing two triangles from different templates.

What is NOT invariant here, deliberately: minutia *direction* (ridge orientation) is
never used as a triangle feature, and reflection (mirroring) is not handled — a mirrored
finger would still pass the angle test (a triangle and its mirror image have the same
three interior angles), but that is not a capture scenario this codebase needs to guard
against (a phone camera does not mirror a finger between enrol and authenticate), so it
is left alone rather than adding vertex-winding checks that would only cost discrimination
power for a threat that doesn't occur.

Mechanism
---------
1. Delaunay-triangulate each template's points (`scipy.spatial.Delaunay`). Fewer than 3
   points, or points that are exactly collinear (`QhullError`), have no triangulation —
   return 0.0 rather than crash.
2. For every triangle, build a signature: its three interior angles, sorted ascending and
   quantized into bins, plus (for the coarse filter) its two smaller side-length ratios,
   plus the sorted multiset of its three minutiae's types ("RIG"/"BIF"). Two triangles
   are only a candidate correspondence if the type multiset matches exactly and the
   quantized angle signature matches within tolerance.
3. Vertices within each triangle are ordered by their *own* interior angle (smallest
   first), which is itself rotation/translation-invariant, so "vertex 0" means the same
   thing — geometrically, not by array index — on both sides of a matched triangle pair.
   Matching triangles vertex-by-vertex in that order proposes 3 minutia-to-minutia
   correspondences per matched triangle pair.
4. Votes across all matched triangle pairs accumulate into a per-(i, j) minutia-pair
   score. Candidate triangle pairs are looked up through a (type-multiset, quantized
   angle-signature) hash bucket rather than compared all-against-all, so step 3 stays
   near-linear in triangle count instead of O(|tris1| * |tris2|).
5. A greedy pass (highest-voted pair first, skipping anything already used) turns the
   vote table into a 1:1 correspondence — a simple, non-optimal assignment on purpose;
   the interesting part of this candidate is the triangulation-based local structure it
   proposes, not the final assignment step (candidate 1 in the bake-off covers assignment
   quality directly).
6. Score blends coverage (matched minutiae over the smaller template's count) with mean
   vote strength of the accepted pairs, scaled into [0, 1] and multiplied by the same
   count-ratio term every algorithm in this bake-off applies, so scores stay comparable.
"""

import math
from collections import defaultdict

import numpy as np
from scipy.spatial import Delaunay, QhullError

# ── Parameters ───────────────────────────────────────────────────────────────

# Minimum count ratio between two templates before matching is attempted at all —
# same gate every algorithm in this bake-off applies (see MATCHING_ALGORITHMS.md).
MIN_COUNT_RATIO = 0.45

ANGLE_BINS = 36            # 5-degree bins for the quantized angle signature
ANGLE_TOL_BINS = 0         # candidate triangles must land in the same angle bin. Looser
                           # values (tried: 1 bin either side) let chance triangle-shape
                           # agreement between two *unrelated* 35-point random templates
                           # push the impostor score above 0.5 — tight enough to require
                           # near-exact shape agreement is what keeps genuine-vs-impostor
                           # separation meaningful for this candidate.
RATIO_TOL = 0.05           # tolerance on the two side-length ratios (coarse pre-filter)

MIN_VOTE = 1.0              # a pair needs at least one triangle vote to be considered
COVERAGE_WEIGHT = 0.6        # blend of coverage vs confidence in the final score


# ══════════════════════════════════════════════════════════════════════════════
# TRIANGLE FEATURES
# ══════════════════════════════════════════════════════════════════════════════

def _triangle_angles(pts):
    """
    Interior angles at each of a triangle's three vertices, in the SAME vertex order
    as `pts` (not sorted). Translation/rotation invariant by construction — computed
    purely from side lengths via the law of cosines, no absolute position or bearing
    involved.
    """
    a = math.dist(pts[1], pts[2])
    b = math.dist(pts[0], pts[2])
    c = math.dist(pts[0], pts[1])
    angles = []
    for opp, s1, s2 in ((a, b, c), (b, a, c), (c, a, b)):
        # angle opposite side `opp`, between the other two sides s1, s2
        denom = 2 * s1 * s2
        if denom < 1e-9:
            angles.append(0.0)
            continue
        cos_v = (s1 * s1 + s2 * s2 - opp * opp) / denom
        cos_v = max(-1.0, min(1.0, cos_v))
        angles.append(math.acos(cos_v))
    return angles


def _side_ratios(pts):
    """Two smaller side lengths divided by the longest — scale invariant."""
    sides = sorted([math.dist(pts[0], pts[1]),
                     math.dist(pts[1], pts[2]),
                     math.dist(pts[0], pts[2])])
    longest = sides[2]
    if longest < 1e-9:
        return (0.0, 0.0)
    return (sides[0] / longest, sides[1] / longest)


def _angle_signature(angles_sorted):
    """Quantized bins of the three angles, sorted ascending — the candidate filter key."""
    return tuple(int(a / math.pi * ANGLE_BINS) for a in angles_sorted)


def _triangles_of(tmpl):
    """
    Build every triangle of tmpl's Delaunay triangulation, described in an order-
    independent way: vertices reordered by their own interior angle (ascending), so
    "position 0" is a geometric identity (the sharpest corner), not an artefact of how
    scipy happened to list a triangle's indices.

    Returns a list of dicts: {verts: (i0, i1, i2) sorted by angle, angles: sorted list,
    ratios: (r1, r2), types: sorted type tuple}.
    """
    n = len(tmpl)
    if n < 3:
        return []
    pts = np.array([[m["x"], m["y"]] for m in tmpl], dtype=float)
    try:
        tri = Delaunay(pts)
    except QhullError:
        return []
    except Exception:
        # Any other degenerate-geometry failure from qhull — treat the same way.
        return []

    out = []
    for simplex in tri.simplices:
        idx = [int(k) for k in simplex]
        p = [pts[k] for k in idx]
        angles = _triangle_angles(p)
        # Reorder vertices by their own angle, ascending — geometric, not index-based.
        order = sorted(range(3), key=lambda k: angles[k])
        verts = tuple(idx[k] for k in order)
        angles_sorted = [angles[k] for k in order]
        ratios = _side_ratios(p)
        types = tuple(sorted(tmpl[k]["type"] for k in idx))
        out.append({
            "verts": verts,
            "angles": angles_sorted,
            "sig": _angle_signature(angles_sorted),
            "ratios": ratios,
            "types": types,
        })
    return out


# ══════════════════════════════════════════════════════════════════════════════
# CANDIDATE TRIANGLE CORRESPONDENCE
# ══════════════════════════════════════════════════════════════════════════════

def _index_triangles(tris):
    """Bucket triangles by (type-multiset, angle-signature) for fast candidate lookup."""
    index = defaultdict(list)
    for t in tris:
        index[(t["types"], t["sig"])].append(t)
    return index


def _angle_sig_neighbours(sig):
    """Every signature within +/-ANGLE_TOL_BINS per bin, to catch quantization edge cases."""
    ranges = [range(b - ANGLE_TOL_BINS, b + ANGLE_TOL_BINS + 1) for b in sig]
    for b0 in ranges[0]:
        for b1 in ranges[1]:
            for b2 in ranges[2]:
                yield (b0, b1, b2)


def _match_triangles(tris1, tris2):
    """
    Yield (tri_a, tri_b) candidate correspondences: same type multiset, angle signature
    within tolerance, and side-ratios within RATIO_TOL. Indexed by (types, sig) bucket
    so this stays near-linear in triangle count instead of O(|tris1| * |tris2|).
    """
    index2 = _index_triangles(tris2)
    for ta in tris1:
        seen = set()
        for sig in _angle_sig_neighbours(ta["sig"]):
            key = (ta["types"], sig)
            if key in seen or key not in index2:
                continue
            seen.add(key)
            for tb in index2[key]:
                if (abs(ta["ratios"][0] - tb["ratios"][0]) > RATIO_TOL
                        or abs(ta["ratios"][1] - tb["ratios"][1]) > RATIO_TOL):
                    continue
                yield ta, tb


# ══════════════════════════════════════════════════════════════════════════════
# VOTING AND ASSIGNMENT
# ══════════════════════════════════════════════════════════════════════════════

def _vote_strength(ta, tb):
    """Higher when the two triangles' angles agree more closely, in [0, 1]."""
    diff = sum(abs(x - y) for x, y in zip(ta["angles"], tb["angles"]))
    return math.exp(-diff)


def _accumulate_votes(tris1, tris2):
    votes = defaultdict(float)
    for ta, tb in _match_triangles(tris1, tris2):
        w = _vote_strength(ta, tb)
        if w <= 0:
            continue
        for i, j in zip(ta["verts"], tb["verts"]):
            votes[(i, j)] += w
    return votes


def _greedy_assign(votes):
    """Highest-voted pair first, skip if either side already used. Not globally optimal
    on purpose — see module docstring, point 5."""
    used_i, used_j, assigned = set(), set(), []
    for (i, j), v in sorted(votes.items(), key=lambda kv: -kv[1]):
        if v < MIN_VOTE:
            break
        if i in used_i or j in used_j:
            continue
        assigned.append(v)
        used_i.add(i)
        used_j.add(j)
    return assigned


# ══════════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ══════════════════════════════════════════════════════════════════════════════

def match(t1, t2):
    """
    Similarity of two minutiae sets via Delaunay-triangulation structural matching, in
    [0, 1]. See the module docstring for the algorithm and its invariance properties.
    """
    ratio = min(len(t1), len(t2)) / max(len(t1), len(t2))
    if ratio < MIN_COUNT_RATIO:
        return 0.0

    if len(t1) < 3 or len(t2) < 3:
        return 0.0

    tris1 = _triangles_of(t1)
    tris2 = _triangles_of(t2)
    if not tris1 or not tris2:
        return 0.0

    votes = _accumulate_votes(tris1, tris2)
    if not votes:
        return 0.0

    assigned = _greedy_assign(votes)
    if not assigned:
        return 0.0

    coverage = len(assigned) / min(len(t1), len(t2))
    # Vote strength is unbounded above (many triangles can vote for the same true
    # correspondence); squash it into a 0..1 confidence via a soft cap rather than a
    # hard clip, so a pair confirmed by many triangles still reads as "very confident"
    # instead of saturating at the first triangle.
    confidence = sum(1.0 - math.exp(-v) for v in assigned) / len(assigned)

    score = (COVERAGE_WEIGHT * coverage + (1 - COVERAGE_WEIGHT) * confidence) * ratio
    return float(max(0.0, min(1.0, score)))
