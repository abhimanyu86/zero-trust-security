"""
Jiang & Yau — "Fingerprint Minutiae Matching Based on the Local and Global Structures",
Proc. 15th International Conference on Pattern Recognition (ICPR), 2000.

Two stages, and it is the interplay between them — not either one alone — that makes
this "the Jiang & Yau algorithm" rather than a generic graph-relaxation matcher (see
matching.py's "modern" path, which is a different family: kNN graph + iterative
relaxation labeling over all candidate pairs at once, no seeding step at all):

  Stage 1 (local).  Every minutia is described by its k nearest neighbours, each
  neighbour contributing a (distance, bearing, relative-direction, type) tuple. Local
  structures are cheap to compare and are compared for every (i, j) pair across the two
  templates — this is what makes the algorithm tractable without exhaustive global
  search.

  Stage 2 (global, seeded by stage 1's ranking).  The top-K locally-best pairs become
  candidate seed correspondences. Each seed, on its own, is enough to estimate a rigid
  transform (rotation from the direction delta, translation from the position delta).
  Applying that one transform to the whole of t1 and counting how many other minutiae
  land on a same-type, same-direction minutia in t2 tests the seed's global consistency.
  The seed that explains the most other pairs wins, and its support count is the score.

Seeding by local-match rank (not random sampling, not trying every pair as a seed) is
the paper's actual contribution — it turns an O(n^2) x-transform-per-pair search into
an O(K) one, K small, while still finding the correct alignment because a genuinely
matching minutia pair almost always has a high stage-1 local similarity.

ROTATION INVARIANCE — how this module actually achieves it (see matching.py's docstring
for the cautionary tale: an earlier version of the default matcher in this codebase
measured minutiae bearings in absolute image-space and silently produced 0% TAR on any
rotated capture; a different earlier algorithm here was labelled "MCC-style" despite not
implementing the cited MCC paper at all — this module tries not to repeat either
mistake):

  - Stage 1's neighbour descriptor never touches absolute image-space angles. The
    bearing from a minutia m to its neighbour n is stored as
    atan2(dy, dx) - m["direction"] — i.e. relative to m's own ridge direction — and the
    neighbour's direction is stored as n["direction"] - m["direction"]. Both quantities
    are invariant to a rigid rotation of the whole template, because rotating the
    template by theta shifts every direction (including m's own) by theta, and the
    theta cancels out of the subtraction. Distance is invariant by construction.

  - Stage 2's transform is *estimated*, not assumed to be identity. Because a genuine
    seed pair's direction delta equals the finger's actual rotation between the two
    captures, the rigid transform built from theta = dir2 - dir1 correctly un-rotates
    (and un-translates) t1 onto t2's frame before the global consistency count runs —
    so a rotated capture of the same finger produces the same seed, the same estimated
    theta, and the same global support count as an unrotated one. See
    self-check in the module's test snippet (not committed) for measured before/after.

  - Uniform scale is normalised out up front (median nearest-neighbour distance is
    rescaled to a fixed target, independently for each template) so that the fixed
    distance tolerance used in stage 2 means the same thing for both templates. This is
    a small self-contained reimplementation of the same idea matching.py uses for its
    own scale normalisation (median NN distance, not bounding-box span) — not an import
    from it; see the INDEPENDENCE note in this package's __init__.py.

WHAT ISN'T INVARIANT: reflections (mirrored captures) are not handled — the rigid
transform estimated in stage 2 is a rotation+translation only, never a reflection, which
matches how a real finger can be rotated in front of a camera but not mirrored.
"""

import math

import numpy as np
from scipy.optimize import linear_sum_assignment
from scipy.spatial import cKDTree

# ── Parameters ───────────────────────────────────────────────────────────────

# The original paper uses k=2 nearest neighbours per minutia. We use 3: with only two
# neighbours a single missed/spurious minutia (routine between two real captures, see
# matching.py's recapture() test helper) can wipe out half of a minutia's descriptor:
# 3 gives the local-similarity assignment (below) something to work with even when one
# neighbour doesn't correspond, at negligible extra cost since k stays tiny.
K_NEIGHBORS = 3

# How many of the best stage-1 local matches are tried as stage-2 seeds. This is the
# paper's efficiency trick: only the top-ranked local matches are worth promoting to a
# full global-transform test, not every candidate pair and not a random sample of them.
TOP_K_SEEDS = 10

# Minimum count ratio between two templates before matching is attempted. Mirrors
# matching.py's MIN_COUNT_RATIO — same value, independently defined per the
# no-cross-imports rule for this package.
MIN_COUNT_RATIO = 0.45

# Need at least this many minutiae in each template to have any neighbours to describe
# a local structure with. Below this, return 0.0 rather than operate on an empty or
# near-empty neighbourhood.
MIN_POINTS = 3

# Median nearest-neighbour distance is rescaled to this value, independently per
# template, before any distance is compared or thresholded. Keeps DIST_TOL (below)
# meaningful regardless of the capture's absolute pixel scale.
SCALE_TARGET_NN = 20.0

# Stage-2 global consistency test: after applying a seed's estimated rigid transform to
# all of t1, a transformed point and a t2 point are considered the same physical
# minutia if they land within this distance (in SCALE_TARGET_NN units) ...
DIST_TOL = 25.0
# ... and within this direction difference (post-rotation) ...
DIR_TOL = math.radians(25.0)
# Both were picked generously relative to SCALE_TARGET_NN and typical capture-to-capture
# jitter (matching.py's tests jitter by ~0.05-0.1 rad and a few pixels) so that a
# genuine recapture survives, while a random impostor transform — which aligns nothing
# in particular — still only picks up incidental matches.

# Stage-1 local-structure similarity: weights for the three per-neighbour terms
# (distance, bearing-from-m, neighbour's-direction-relative-to-m). Distance and the two
# angular terms are weighted roughly evenly; not tuned beyond "roughly balanced", since
# stage 1 only has to rank candidates well enough to get a genuine pair into the
# top-TOP_K_SEEDS, not to score precisely on its own.
W_DIST = 0.4
W_BEARING = 0.3
W_DIRECTION = 0.3

# Per-neighbour-pair cost above which two neighbours are not really the same neighbour
# (used to discard entries the assignment step was forced to pair up only because the
# two neighbour lists have different lengths).
MAX_NEIGHBOR_COST = 1.5


# ══════════════════════════════════════════════════════════════════════════════
# PRIMITIVES
# ══════════════════════════════════════════════════════════════════════════════

def _wrap(angle):
    """Wrap an angle (radians) to (-pi, pi]."""
    return (angle + math.pi) % (2 * math.pi) - math.pi


def _circ_diff_rad(a, b):
    """Smallest absolute angular difference between two radian angles, in [0, pi]."""
    return abs(_wrap(a - b))


def _scale_to_target(tmpl, target=SCALE_TARGET_NN):
    """
    Rescale x/y so the median nearest-neighbour distance equals `target`.

    Self-contained reimplementation of the same idea matching.py's _scale() uses
    (median NN distance, robust to a single outlier point) — not imported from it, per
    this package's no-cross-imports rule. Direction and type are untouched; uniform
    scale doesn't affect either.
    """
    if len(tmpl) < 2:
        return tmpl
    pts = np.array([[m["x"], m["y"]] for m in tmpl], dtype=float)
    tree = cKDTree(pts)
    nn = tree.query(pts, k=2)[0][:, 1]
    med = float(np.median(nn))
    if med <= 1e-9:
        return tmpl
    f = target / med
    return [{**m, "x": m["x"] * f, "y": m["y"] * f} for m in tmpl]


# ══════════════════════════════════════════════════════════════════════════════
# STAGE 1 — local structure matching
# ══════════════════════════════════════════════════════════════════════════════

def _build_local_structures(tmpl, k=K_NEIGHBORS):
    """
    For every minutia, the (distance, bearing, relative-direction, type) tuple of each
    of its k nearest neighbours, nearest first.

    bearing and relative-direction are both measured relative to the minutia's own
    ridge direction (see the module docstring's ROTATION INVARIANCE section) — this is
    the one property that must survive verbatim for the whole algorithm to be rotation
    invariant.
    """
    n = len(tmpl)
    pts = np.array([[m["x"], m["y"]] for m in tmpl], dtype=float)
    tree = cKDTree(pts)
    kk = min(k + 1, n)          # +1 because query() includes the point itself
    dists, idxs = tree.query(pts, k=kk)
    if kk == 1:                 # only one point queried against itself, no neighbours
        dists = dists.reshape(n, 1)
        idxs = idxs.reshape(n, 1)

    structures = []
    for i in range(n):
        neighbours = []
        for rank in range(1, kk):               # skip rank 0: the point itself
            j = int(idxs[i][rank])
            dx = tmpl[j]["x"] - tmpl[i]["x"]
            dy = tmpl[j]["y"] - tmpl[i]["y"]
            neighbours.append({
                "dist": float(dists[i][rank]),
                "bearing": _wrap(math.atan2(dy, dx) - tmpl[i]["direction"]),
                "reldir": _wrap(tmpl[j]["direction"] - tmpl[i]["direction"]),
                "type": tmpl[j]["type"],
            })
        structures.append(neighbours)
    return structures


def _local_similarity(loc_i, loc_j):
    """
    Similarity in [0, 1] between two minutiae's local structures.

    Neighbour lists aren't assumed to line up by rank (a real second capture can find
    its k nearest neighbours in a different order, or miss one entirely), so neighbours
    are matched to each other via a small optimal assignment (k is at most K_NEIGHBORS,
    so this costs nothing) rather than compared position-by-position.
    """
    n1, n2 = len(loc_i), len(loc_j)
    if n1 == 0 or n2 == 0:
        return 0.0

    cost = np.empty((n1, n2), dtype=float)
    for a in range(n1):
        for b in range(n2):
            if loc_i[a]["type"] != loc_j[b]["type"]:
                cost[a, b] = MAX_NEIGHBOR_COST * 4       # clearly not a real pairing
                continue
            d_term = min(abs(loc_i[a]["dist"] - loc_j[b]["dist"]) / SCALE_TARGET_NN, 1.0)
            bearing_term = _circ_diff_rad(loc_i[a]["bearing"], loc_j[b]["bearing"]) / math.pi
            dir_term = _circ_diff_rad(loc_i[a]["reldir"], loc_j[b]["reldir"]) / math.pi
            cost[a, b] = W_DIST * d_term + W_BEARING * bearing_term + W_DIRECTION * dir_term

    rows, cols = linear_sum_assignment(cost)
    paired = cost[rows, cols]
    valid = paired < MAX_NEIGHBOR_COST
    if not np.any(valid):
        return 0.0

    mean_cost = float(paired[valid].mean())
    coverage = float(np.sum(valid)) / max(n1, n2)
    # exp(-2 * cost): a perfect match (cost 0) scores 1.0, the worst admissible match
    # (cost just under MAX_NEIGHBOR_COST=1.5) scores ~exp(-3) =~ 0.05 — a smooth, bounded
    # decay rather than a hard cutoff, so stage 1's ranking (all that matters for
    # seeding) stays informative near the margin.
    return float(math.exp(-2.0 * mean_cost) * coverage)


def _rank_candidate_seeds(t1, t2):
    """All (i, j, local_similarity) triples with matching minutia type, best first."""
    loc1 = _build_local_structures(t1)
    loc2 = _build_local_structures(t2)

    candidates = []
    for i, m1 in enumerate(t1):
        for j, m2 in enumerate(t2):
            if m1["type"] != m2["type"]:
                continue
            sim = _local_similarity(loc1[i], loc2[j])
            if sim > 0.0:
                candidates.append((sim, i, j))
    candidates.sort(key=lambda c: -c[0])
    return candidates


# ══════════════════════════════════════════════════════════════════════════════
# STAGE 2 — global structure matching, seeded by stage 1
# ══════════════════════════════════════════════════════════════════════════════

def _rigid_transform_from_pair(p1, p2):
    """
    Rotation + translation that maps p1 onto p2, using only that single pair's
    position and direction — exactly what "estimate a transform for a matched pair"
    means: the rotation is the direction delta, the translation is whatever is left
    over once that rotation is applied to p1's position.
    """
    theta = p2["direction"] - p1["direction"]
    c, s = math.cos(theta), math.sin(theta)
    tx = p2["x"] - (c * p1["x"] - s * p1["y"])
    ty = p2["y"] - (s * p1["x"] + c * p1["y"])
    return theta, c, s, tx, ty


def _apply_transform(tmpl, theta, c, s, tx, ty):
    return [{
        "x": c * m["x"] - s * m["y"] + tx,
        "y": s * m["x"] + c * m["y"] + ty,
        "direction": (m["direction"] + theta) % (2 * math.pi),
        "type": m["type"],
    } for m in tmpl]


def _global_support(t1, t2, seed_i, seed_j, tree2):
    """
    Apply the rigid transform estimated from (seed_i, seed_j) to all of t1, then count
    how many minutiae (other than the seed pair itself) land within tolerance of a
    same-type minutia in t2, one-to-one.

    Returns the total globally-consistent pair count, seed included.
    """
    theta, c, s, tx, ty = _rigid_transform_from_pair(t1[seed_i], t2[seed_j])
    transformed = _apply_transform(t1, theta, c, s, tx, ty)

    candidates = []
    for k, pk in enumerate(transformed):
        if k == seed_i:
            continue                                     # counted separately, below
        for l in tree2.query_ball_point([pk["x"], pk["y"]], DIST_TOL):
            if l == seed_j:
                continue
            if t2[l]["type"] != pk["type"]:
                continue
            if _circ_diff_rad(pk["direction"], t2[l]["direction"]) > DIR_TOL:
                continue
            dx = pk["x"] - t2[l]["x"]
            dy = pk["y"] - t2[l]["y"]
            candidates.append((dx * dx + dy * dy, k, l))

    # Greedy one-to-one assignment, closest pairs first — with DIST_TOL/DIR_TOL this
    # small a neighbourhood, a full optimal assignment would not change the count
    # meaningfully and greedy is cheaper.
    candidates.sort(key=lambda c: c[0])
    used_k, used_l = set(), {seed_j}
    support = 1                                          # the seed pair itself
    for _, k, l in candidates:
        if k in used_k or l in used_l:
            continue
        used_k.add(k)
        used_l.add(l)
        support += 1
    return support


# ══════════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ══════════════════════════════════════════════════════════════════════════════

def match(t1, t2):
    """
    Jiang & Yau local-then-global minutiae similarity, in [0, 1].

    t1, t2: lists of {"x", "y", "direction" (radians), "type" ("RIG"|"BIF")}. Assumed
    non-empty (the caller guards that); small counts are handled by returning 0.0
    rather than raising.
    """
    ratio = min(len(t1), len(t2)) / max(len(t1), len(t2))
    if ratio < MIN_COUNT_RATIO:
        return 0.0
    if len(t1) < MIN_POINTS or len(t2) < MIN_POINTS:
        return 0.0

    a = _scale_to_target(t1)
    b = _scale_to_target(t2)

    seeds = _rank_candidate_seeds(a, b)
    if not seeds:
        return 0.0

    tree_b = cKDTree(np.array([[m["x"], m["y"]] for m in b], dtype=float))

    best_support = 0
    for _, i, j in seeds[:TOP_K_SEEDS]:
        support = _global_support(a, b, i, j, tree_b)
        if support > best_support:
            best_support = support

    score = (best_support / min(len(a), len(b))) * ratio
    return float(max(0.0, min(1.0, score)))
