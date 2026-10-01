"""
Fingerprint minutiae matching — kNN graph matching with relaxation labeling.

Single source of truth. Previously this algorithm existed as three separate copies
(app.py, slap_app.py, benchmark.py) which had already begun to drift apart.

Despite past references to this as "MCC-style", it is not the Minutia Cylinder-Code
algorithm (Cappelli, Ferrara & Maltoni, 2010) — no cylinder structures are built. It's
a k-nearest-neighbour graph with relaxation labeling, closer in spirit to Ratha/Jain-
style local-structure matching. See MATCHING_ALGORITHMS.md for a real MCC candidate
and other alternatives under evaluation.

match_templates(t1, t2, algorithm=...) dispatches by name through the _ALGORITHMS
registry at the bottom of this file. Two algorithms are registered today:

  "legacy"   Byte-for-byte behaviour of the original app.py matcher. Kept so that
             before/after numbers can be measured on identical data.

  "modern"   Default. Fixes the defect that made the original score 0% TAR on real
             phone captures: the edge descriptor was measured in absolute image
             space, so rotating the finger between enrol and authenticate shifted
             every edge angle and destroyed the match.

What changed in the default path
--------------------------------
1. Rotation-invariant edges. `_compute_edge` stored atan2(dy,dx) in image coordinates.
   It now stores that angle relative to p1's own ridge direction. Distance and relative
   orientation were already invariant; this was the one component that was not.

2. Node compatibility no longer gates on absolute position or absolute orientation.
   The original required two minutiae to sit within 25 units of the same place after
   centroid alignment, which cannot survive rotation. Candidate pairs are now filtered
   by minutia type plus a rotation-invariant neighbourhood distance signature, and the
   graph does the discriminating.

3. Robust scaling. The original divided by the bounding-box span, so a single spurious
   minutia at the edge rescaled the whole template. Now uses median nearest-neighbour
   distance.

4. Score reflects match quality, not just match count. The original returned a Dice
   coefficient over the number of surviving pairs and discarded everything the
   relaxation step computed. The score now blends coverage with the mean confidence of
   the assigned pairs.
"""

import math

import numpy as np
from scipy.spatial import cKDTree

# ── Shared parameters ────────────────────────────────────────────────────────
K_NEIGHBORS   = 6
DIST_BIN_SIZE = 15
ANGLE_BINS    = 16
ORIENT_BINS   = 16
DIST_THRESH   = 1
ANGLE_THRESH  = 1
ORIENT_THRESH = 1
RELAX_ITER    = 10

# Minimum count ratio between two templates before matching is attempted.
MIN_COUNT_RATIO = 0.45

# Default path only.
SCALE_TARGET_NN = 20.0   # median nearest-neighbour distance is normalised to this
COVERAGE_WEIGHT = 0.65   # blend of coverage vs confidence in the final score
TOP_N_FRACTION  = 0.5    # fraction of assigned pairs averaged for the confidence term
MIN_TOP_N       = 4

# A pair is only accepted if its relaxation probability reaches this fraction of the
# strongest pair's. Measured on simulated recaptures: without a gate the greedy
# assignment accepts nearly every minutia in the smaller template regardless of whether
# the neighbourhood agrees, which pushes impostor scores up to ~0.60 and destroys
# separation. 0.05 was the best of {0, 0.05, 0.1, 0.2, 0.3}.
ASSIGN_MIN_PROB = 0.05


# ══════════════════════════════════════════════════════════════════════════════
# PRIMITIVES
# ══════════════════════════════════════════════════════════════════════════════

def _angle_to_bin(theta, bins):
    return int((theta % (2 * math.pi)) / (2 * math.pi) * bins)


def _circ_diff(a, b, bins):
    d = abs(a - b) % bins
    return min(d, bins - d)


def _euclidean(p1, p2):
    return math.sqrt((p1["x"] - p2["x"]) ** 2 + (p1["y"] - p2["y"]) ** 2)


def _edge_compat(e1, e2):
    """Compatibility of two edge descriptors in [0, 1]. Identical in both modes."""
    d1, a1, o1 = e1
    d2, a2, o2 = e2
    if abs(d1 - d2) > DIST_THRESH:
        return 0.0
    if _circ_diff(a1, a2, ANGLE_BINS) > ANGLE_THRESH:
        return 0.0
    if _circ_diff(o1, o2, ORIENT_BINS) > ORIENT_THRESH:
        return 0.0
    return math.exp(-(abs(d1 - d2)
                      + _circ_diff(a1, a2, ANGLE_BINS)
                      + _circ_diff(o1, o2, ORIENT_BINS)))


def _normalize(tmpl):
    """Translate so the centroid sits at the origin."""
    if not tmpl:
        return tmpl
    mx = sum(m["x"] for m in tmpl) / len(tmpl)
    my = sum(m["y"] for m in tmpl) / len(tmpl)
    return [{**m, "x": m["x"] - mx, "y": m["y"] - my} for m in tmpl]


# ══════════════════════════════════════════════════════════════════════════════
# LEGACY PATH — reproduces the original app.py matcher exactly
# ══════════════════════════════════════════════════════════════════════════════

def _legacy_compute_edge(p1, p2):
    dx = p2["x"] - p1["x"]
    dy = p2["y"] - p1["y"]
    dist = math.sqrt(dx * dx + dy * dy)
    return (int(dist / DIST_BIN_SIZE),
            _angle_to_bin(math.atan2(dy, dx), ANGLE_BINS),
            (_angle_to_bin(p2["direction"], ORIENT_BINS)
             - _angle_to_bin(p1["direction"], ORIENT_BINS)) % ORIENT_BINS)


def _legacy_build_graph(tmpl):
    edges = {}
    for i in range(len(tmpl)):
        dists = sorted([(_euclidean(tmpl[i], tmpl[j]), j)
                        for j in range(len(tmpl)) if j != i])
        for _, j in dists[:K_NEIGHBORS]:
            edges[(i, j)] = _legacy_compute_edge(tmpl[i], tmpl[j])
    return edges


def _legacy_node_compat(n1, n2):
    if n1["type"] != n2["type"]:
        return False
    if _circ_diff(_angle_to_bin(n1["direction"], ORIENT_BINS),
                  _angle_to_bin(n2["direction"], ORIENT_BINS), ORIENT_BINS) > ORIENT_THRESH:
        return False
    if math.sqrt((n1["x"] - n2["x"]) ** 2 + (n1["y"] - n2["y"]) ** 2) > 25:
        return False
    return True


def _legacy_scale(tmpl, target=200):
    if not tmpl:
        return tmpl
    xs = [m["x"] for m in tmpl]
    ys = [m["y"] for m in tmpl]
    span = max(max(xs) - min(xs), max(ys) - min(ys), 1)
    f = target / span
    return [{**m, "x": m["x"] * f, "y": m["y"] * f} for m in tmpl]


def _match_legacy(t1, t2):
    ratio = min(len(t1), len(t2)) / max(len(t1), len(t2))
    if ratio < MIN_COUNT_RATIO:
        return 0.0

    t1 = _legacy_scale(_normalize(t1))
    t2 = _legacy_scale(_normalize(t2))
    e1 = _legacy_build_graph(t1)
    e2 = _legacy_build_graph(t2)

    cands = [(i, j)
             for i, n1 in enumerate(t1)
             for j, n2 in enumerate(t2)
             if _legacy_node_compat(n1, n2)]
    if len(cands) < max(4, int(0.15 * min(len(t1), len(t2)))):
        return 0.0

    P = {c: 1.0 for c in cands}
    for _ in range(RELAX_ITER):
        Pn = {}
        for (i, j) in cands:
            Pn[(i, j)] = sum(P[(k, l)] * _edge_compat(e1[(i, k)], e2[(j, l)])
                             for (k, l) in cands
                             if k != i and l != j and (i, k) in e1 and (j, l) in e2)
        norm = sum(Pn.values()) + 1e-6
        P = {k: v / norm for k, v in Pn.items()}

    used_i, used_j, matches = set(), set(), []
    for (i, j), s in sorted(P.items(), key=lambda x: -x[1]):
        if s < 0.001:
            continue
        if i not in used_i and j not in used_j:
            matches.append((i, j, s))
            used_i.add(i)
            used_j.add(j)
    if not matches:
        return 0.0

    score = 2 * len(matches) / (len(t1) + len(t2)) * ratio
    return float(max(0.0, min(1.0, score)))


# ══════════════════════════════════════════════════════════════════════════════
# DEFAULT PATH — rotation invariant
# ══════════════════════════════════════════════════════════════════════════════

def _compute_edge(p1, p2):
    """
    Edge descriptor measured in p1's own reference frame.

    All three components are invariant to rotation of the whole template:
      - distance bin                      (invariant by construction)
      - edge bearing minus p1's direction (this is the fix; was absolute before)
      - p2's direction minus p1's         (already invariant)
    """
    dx = p2["x"] - p1["x"]
    dy = p2["y"] - p1["y"]
    dist = math.sqrt(dx * dx + dy * dy)
    bearing = math.atan2(dy, dx) - p1["direction"]
    return (int(dist / DIST_BIN_SIZE),
            _angle_to_bin(bearing, ANGLE_BINS),
            _angle_to_bin(p2["direction"] - p1["direction"], ORIENT_BINS))


def _scale(tmpl):
    """
    Normalise by median nearest-neighbour distance.

    Robust where the original bounding-box span was not: one spurious minutia at the
    edge of the frame used to rescale the entire template.
    """
    if len(tmpl) < 2:
        return tmpl
    pts = np.array([[m["x"], m["y"]] for m in tmpl], dtype=float)
    tree = cKDTree(pts)
    nn = tree.query(pts, k=2)[0][:, 1]          # distance to nearest other point
    med = float(np.median(nn))
    if med <= 1e-9:
        return tmpl
    f = SCALE_TARGET_NN / med
    return [{**m, "x": m["x"] * f, "y": m["y"] * f} for m in tmpl]


def _build_graph(tmpl):
    """k-nearest-neighbour graph via KD-tree."""
    n = len(tmpl)
    if n < 2:
        return {}, [[] for _ in range(n)]

    pts = np.array([[m["x"], m["y"]] for m in tmpl], dtype=float)
    tree = cKDTree(pts)
    k = min(K_NEIGHBORS + 1, n)
    idxs = tree.query(pts, k=k)[1]

    edges = {}
    neighbours = [[] for _ in range(n)]
    for i in range(n):
        # Drop self by index, not by assuming rank-0 is always self: when
        # another minutia shares i's exact coordinates, cKDTree can return
        # that duplicate at rank 0 instead, and slicing [1:] would silently
        # drop the real duplicate neighbor while leaving i as its own
        # neighbor (a self-loop edge). Filtering by index handles both the
        # normal case and the duplicate-coordinate case correctly.
        for j in idxs[i]:
            j = int(j)
            if j == i:
                continue
            edges[(i, j)] = _compute_edge(tmpl[i], tmpl[j])
            neighbours[i].append(j)
    return edges, neighbours


def _match_modern(t1, t2):
    ratio = min(len(t1), len(t2)) / max(len(t1), len(t2))
    if ratio < MIN_COUNT_RATIO:
        return 0.0

    a = _scale(_normalize(t1))
    b = _scale(_normalize(t2))
    e1, nb1 = _build_graph(a)
    e2, nb2 = _build_graph(b)

    # Candidate pairs are filtered on minutia type alone. Deliberately no absolute
    # position or absolute orientation test — both break under rotation, which is what
    # the original got wrong. Any geometric prefilter that depends on which minutiae
    # were detected also rejects genuine pairs when the two captures find different
    # subsets, so the structural agreement below does all the discriminating.
    candidates = []
    index = {}
    for i, n1 in enumerate(a):
        for j, n2 in enumerate(b):
            if n1["type"] != n2["type"]:
                continue
            index[(i, j)] = len(candidates)
            candidates.append((i, j))

    if len(candidates) < max(4, int(0.15 * min(len(a), len(b)))):
        return 0.0

    # Precompute the support links once rather than rescanning every iteration.
    links = [[] for _ in candidates]
    for idx, (i, j) in enumerate(candidates):
        for k in nb1[i]:
            edge_a = e1.get((i, k))
            if edge_a is None:
                continue
            for l in nb2[j]:
                target = index.get((k, l))
                if target is None:
                    continue
                w = _edge_compat(edge_a, e2.get((j, l)))
                if w:
                    links[idx].append((target, w))

    # Relaxation labeling. Normalising by the maximum (not the sum) keeps the values
    # on a stable 0..1 scale regardless of how many candidates there are — the
    # original divided by the sum and then applied a fixed 0.001 cut-off, so its
    # behaviour drifted with candidate count.
    probs = [1.0] * len(candidates)
    for _ in range(RELAX_ITER):
        updated = [0.0] * len(candidates)
        for idx, src in enumerate(links):
            updated[idx] = sum(probs[t] * w for t, w in src)
        peak = max(updated)
        if peak <= 1e-9:
            return 0.0
        probs = [v / peak for v in updated]

    used_i, used_j, assigned = set(), set(), []
    for score, (i, j) in sorted(zip(probs, candidates), key=lambda x: -x[0]):
        if score < ASSIGN_MIN_PROB:
            break                                    # sorted, so nothing below qualifies
        if i not in used_i and j not in used_j:
            assigned.append(score)
            used_i.add(i)
            used_j.add(j)
    if not assigned:
        return 0.0

    # Normalise coverage against the smaller template. Dice over the sum over-penalises
    # the common real-world case where the two captures detect different numbers of
    # minutiae, which is exactly when the matcher needs to stay reliable.
    coverage = len(assigned) / min(len(a), len(b))
    top_n = max(MIN_TOP_N, int(TOP_N_FRACTION * len(assigned)))
    confidence = sum(assigned[:top_n]) / min(top_n, len(assigned))

    score = (COVERAGE_WEIGHT * coverage + (1 - COVERAGE_WEIGHT) * confidence) * ratio
    return float(max(0.0, min(1.0, score)))


# ══════════════════════════════════════════════════════════════════════════════
# ALGORITHM CANDIDATE — Hungarian / optimal assignment (algorithm002)
#
# Identical front end to _match_modern: same normalisation, same rotation-invariant
# scaling, same k-NN graph, same relaxation labeling. The only thing that changes is
# the last step — _match_modern assigns pairs greedily (highest relaxation probability
# first, skip anything whose row or column is already taken); this instead poses it as
# a proper assignment problem and solves it exactly with the Hungarian algorithm
# (scipy.optimize.linear_sum_assignment), so a locally-attractive greedy pick can no
# longer block a globally better configuration. Isolating this one change is the
# point — everything downstream (the coverage/confidence score) is left identical to
# _match_modern so any score difference between the two is attributable to the
# assignment step alone, not to a different scoring formula too.
# ══════════════════════════════════════════════════════════════════════════════

def _match_hungarian(t1, t2):
    from scipy.optimize import linear_sum_assignment

    ratio = min(len(t1), len(t2)) / max(len(t1), len(t2))
    if ratio < MIN_COUNT_RATIO:
        return 0.0

    a = _scale(_normalize(t1))
    b = _scale(_normalize(t2))
    e1, nb1 = _build_graph(a)
    e2, nb2 = _build_graph(b)

    candidates = []
    index = {}
    for i, n1 in enumerate(a):
        for j, n2 in enumerate(b):
            if n1["type"] != n2["type"]:
                continue
            index[(i, j)] = len(candidates)
            candidates.append((i, j))

    if len(candidates) < max(4, int(0.15 * min(len(a), len(b)))):
        return 0.0

    links = [[] for _ in candidates]
    for idx, (i, j) in enumerate(candidates):
        for k in nb1[i]:
            edge_a = e1.get((i, k))
            if edge_a is None:
                continue
            for l in nb2[j]:
                target = index.get((k, l))
                if target is None:
                    continue
                w = _edge_compat(edge_a, e2.get((j, l)))
                if w:
                    links[idx].append((target, w))

    probs = [1.0] * len(candidates)
    for _ in range(RELAX_ITER):
        updated = [0.0] * len(candidates)
        for idx, src in enumerate(links):
            updated[idx] = sum(probs[t] * w for t, w in src)
        peak = max(updated)
        if peak <= 1e-9:
            return 0.0
        probs = [v / peak for v in updated]

    # Dense reward matrix over every (i, j) slot, not just type-matching candidates —
    # linear_sum_assignment requires a complete matrix and will otherwise have nothing
    # to assign a row to. Non-candidate cells default to 0 reward, so the solver only
    # ever prefers them when a row genuinely has no better option; the ASSIGN_MIN_PROB
    # filter below then drops anything it was forced into rather than actually matched.
    reward = np.zeros((len(a), len(b)), dtype=float)
    for (i, j), prob in zip(candidates, probs):
        reward[i, j] = prob

    row_idx, col_idx = linear_sum_assignment(reward, maximize=True)
    assigned = sorted(
        (reward[i, j] for i, j in zip(row_idx, col_idx) if reward[i, j] >= ASSIGN_MIN_PROB),
        reverse=True,
    )
    if not assigned:
        return 0.0

    coverage = len(assigned) / min(len(a), len(b))
    top_n = max(MIN_TOP_N, int(TOP_N_FRACTION * len(assigned)))
    confidence = sum(assigned[:top_n]) / min(top_n, len(assigned))

    score = (COVERAGE_WEIGHT * coverage + (1 - COVERAGE_WEIGHT) * confidence) * ratio
    return float(max(0.0, min(1.0, score)))


from algorithms import (  # noqa: E402
    mcc_cylinder, delaunay, ransac_alignment, jiang_yau, bozorth3_style, networkx_graph,
    ransac_similarity,
)

# ══════════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ══════════════════════════════════════════════════════════════════════════════

# Name -> scoring function. Every algorithm branch in the matching-algorithm bake-off
# adds one function above (or one backend/algorithms/<name>.py module) and one line
# here — nothing else in this file changes, and callers select it by name instead of
# by editing an ever-growing chain of booleans.
_ALGORITHMS = {
    "legacy": _match_legacy,
    "modern": _match_modern,
    "hungarian_assignment": _match_hungarian,
    "mcc_cylinder": mcc_cylinder.match,
    "delaunay": delaunay.match,
    "ransac_alignment": ransac_alignment.match,
    "jiang_yau": jiang_yau.match,
    "bozorth3_style": bozorth3_style.match,
    "networkx_graph": networkx_graph.match,
    "ransac_similarity": ransac_similarity.match,
}

# Sequential codes + human labels for the bake-off (see MATCHING_ALGORITHMS.md).
# algorithm000 is the pre-rotation-fix historical baseline; algorithm001 is what's
# actually in production today; algorithm002+ are the candidates under evaluation.
# This is a *display* layer only — the dict keys above stay descriptive so the code
# itself stays readable; UIs and reports should read through algorithm_display_name()
# rather than showing raw keys.
ALGORITHM_INFO = {
    "legacy":               {"code": "algorithm000", "label": "Legacy (pre-rotation-fix baseline)"},
    "modern":                {"code": "algorithm001", "label": "Modern (current production default)"},
    "hungarian_assignment":  {"code": "algorithm002", "label": "Hungarian / optimal assignment"},
    "mcc_cylinder":          {"code": "algorithm003", "label": "Minutia Cylinder-Code (MCC)"},
    "delaunay":              {"code": "algorithm004", "label": "Delaunay triangulation matching"},
    "ransac_alignment":      {"code": "algorithm005", "label": "RANSAC rigid alignment"},
    "jiang_yau":             {"code": "algorithm006", "label": "Jiang & Yau local/global structure"},
    "bozorth3_style":        {"code": "algorithm007", "label": "Bozorth3-style graph consistency"},
    "networkx_graph":        {"code": "algorithm008", "label": "NetworkX graph/spectral matching"},
    "ransac_similarity":     {"code": "algorithm009", "label": "RANSAC v2 (scale-normalised + refit + confidence-ordered)"},
}


def match_templates(t1, t2, algorithm="modern"):
    """
    Similarity of two minutiae sets, in [0, 1].

    Each minutia is a dict with x, y, direction (radians) and type ("RIG" or "BIF").
    `algorithm` selects which scorer runs — see list_algorithms() for the registered
    names. "legacy" reproduces the original pre-rotation-invariant algorithm exactly,
    kept so before/after can be measured on identical data.
    """
    if not t1 or not t2:
        return 0.0
    fn = _ALGORITHMS.get(algorithm)
    if fn is None:
        raise ValueError("unknown matching algorithm %r; choices: %s"
                         % (algorithm, sorted(_ALGORITHMS)))
    return fn(t1, t2)


def list_algorithms():
    """Registered algorithm names, for UIs and CLIs to build a selector from."""
    return sorted(_ALGORITHMS)


def algorithm_display_name(algorithm):
    """'algorithm003 — Minutia Cylinder-Code (MCC)', for UIs. Falls back to the raw key."""
    info = ALGORITHM_INFO.get(algorithm)
    if not info:
        return algorithm
    return "%s — %s" % (info["code"], info["label"])
