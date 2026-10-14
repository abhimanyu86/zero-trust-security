"""
Bozorth3-style pairwise-compatibility matching (candidate in the bake-off,
MATCHING_ALGORITHMS.md).

Reimplements the core mechanism of NIST NBIS's Bozorth3 — C. Watson et al., "User's Guide
to NIST Biometric Image Software (NBIS)" (NIST, 2004-2015); the algorithm itself traces
back to the FBI's original Bozorth matcher and has been the reference minutiae matcher
bundled with US government AFIS toolchains for decades. This is a from-scratch pure
Python/numpy/scipy reimplementation of its mechanism, not a wrapper around the `bozorth3`
binary — there is no NBIS dependency anywhere in this file.

Bozorth3's central idea, kept faithfully here: never compare a minutia to another minutia
directly. Compare *inter-minutia relationships* — one from each template — and only let
two relationships corroborate each other when they agree closely enough on shape. A single
agreeing pair of relationships is cheap coincidence; a large mutually-consistent cluster of
them is a fingerprint match. Rotation invariance and translation invariance both fall out
of using relationships (distances and self-referenced bearings) as the unit of comparison,
never an absolute coordinate.

Rotation invariance — how, specifically
----------------------------------------
Within one template, every ordered pair of minutiae (i, k) gets a descriptor:

    dist    = euclidean distance between i and k               (rigid-motion invariant)
    beta_i  = bearing(i -> k) - direction(i)                    (i's own frame)
    beta_k  = bearing(k -> i) - direction(k)                    (k's own frame)

`beta_i` and `beta_k` are each the angle between a minutia's own ridge direction and the
line to its partner, measured *relative to that minutia*, not in image space. Under a
rigid rotation by theta, every position rotates by theta AND — per this codebase's
convention (see backend/tests/test_matching.py's `rotate()` helper) — every minutia's
`direction` also increases by theta. So bearing(i -> k) shifts by +theta and direction(i)
shifts by +theta; beta_i = bearing - direction is their *difference*, and the two thetas
cancel exactly. Distance is unaffected by rotation or translation by construction (it never
touches direction or absolute position, only a coordinate difference). No centroid
alignment, no global rotation search, no absolute bearing is used anywhere in this file —
which is precisely the bug `matching.py` had to fix in its original (legacy) matcher, where
edge bearings were stored in absolute image space and a rotated finger scored 0% TAR. Here
that failure mode cannot occur because absolute bearing is never computed, let alone
compared.

Translation invariance is automatic and needs no explicit step: `dist`, `beta_i` and
`beta_k` are all built from coordinate *differences*, so shifting an entire template by any
offset changes no descriptor at all.

Scale is a partial exception. Real Bozorth3 assumes both fingerprints were captured at the
same fixed DPI and does not normalize scale at all. This codebase's captures come from a
phone camera at variable distance, so — matching the spirit of `matching.py`'s own
`_scale()` (reimplemented independently here per this module's no-cross-import rule, not
imported) — each template is rescaled so its median nearest-neighbour distance lands on a
fixed target before any pairwise table is built. This is an addition on top of the
original Bozorth3 mechanism, not part of it.

Mechanism
---------
1. Within each template independently, build a table of ALL pairwise minutia relationships
   (`_pairwise_table`), optionally capped by `MAX_PAIR_DIST` to keep the far-apart, rarely-
   useful pairs out of the table entirely.
2. Cross-compare every within-template pair of t1 against every within-template pair of t2
   (`_build_correspondence_graph`). Two pairs (i, k) from t1 and (j, l) from t2 are
   compatible when their distances agree within tolerance, and either:
     - type(i)==type(j) and type(k)==type(l), with beta_i~=beta_j and beta_k~=beta_l, or
     - type(i)==type(l) and type(k)==type(j) (the reversed pairing), with beta_i~=beta_l
       and beta_k~=beta_j
   A compatible pair-pair simultaneously proposes two minutia correspondences at once
   (i<->j and k<->l, or i<->l and k<->j) and links those two correspondences by an edge —
   this is the "mutual corroboration" step that gives Bozorth3 its robustness to a captures
   pair that share only a subset of minutiae.
   Performance: raw O(n^2) x O(m^2) cross-comparison is too slow at this codebase's scale
   (40-70 minutiae => ~1500-2400 pairs per side => several million raw comparisons). Pairs
   are first bucketed by `floor(dist / DIST_BUCKET)`; only pairs in the same or an adjacent
   bucket are ever cross-compared, and each bucket-vs-bucket block is compared with numpy
   broadcasting rather than nested Python loops. Bucket width equals the distance tolerance
   and buckets are floor-based (not round-based), which guarantees any two distances within
   tolerance always land in the same or an adjacent bucket — the pruning drops no pair that
   the exact `DIST_TOL` check downstream would have accepted.
3. Build a compatibility graph: nodes are candidate correspondences (i, j) that appeared in
   at least one compatible pair-pair match; edges connect two correspondences whenever a
   pair-pair comparison linked them. The largest connected component (found with
   `scipy.sparse.csgraph.connected_components`) is this implementation's tractable stand-in
   for Bozorth3's actual clique search — true maximum-clique is NP-hard, and requiring
   mutual pairwise consistency to chain correspondences into one connected blob is a
   reasonable, fast approximation of it.
4. Within that component, correspondences are still filtered down to a clean 1:1 mapping:
   on any conflict (two correspondences sharing an i or a j), keep only the one with the
   higher degree (most corroborating edges) and drop the rest.
5. Score = (size of the final 1:1 set) / min(len(t1), len(t2)) * ratio, where `ratio` is the
   same min/max count-ratio gate value used everywhere else in this codebase's matchers.
"""

import math

import numpy as np
from scipy.sparse import coo_matrix
from scipy.sparse.csgraph import connected_components
from scipy.spatial import cKDTree

# ── Parameters ───────────────────────────────────────────────────────────────

# Minimum count ratio between two templates before matching is attempted at all — same
# gate every algorithm in this bake-off applies (see MATCHING_ALGORITHMS.md).
MIN_COUNT_RATIO = 0.45

# Each template is rescaled so its median nearest-neighbour distance lands here before any
# pairwise table is built. An addition over stock Bozorth3 (see module docstring) to cope
# with phone captures taken at variable distance rather than a fixed-DPI scanner.
SCALE_TARGET_NN = 20.0

# Pairs farther apart than this (in post-scaling units) are dropped from the pairwise table
# entirely — the "optionally capped by a max distance" tractability knob from the spec.
# Generous relative to SCALE_TARGET_NN so it only excludes genuinely far-flung pairs, not
# ordinary finger-sized relationships.
MAX_PAIR_DIST = 400.0

# Distance tolerance for two candidate pairs to be considered the "same" relationship, and
# also the bucket width used to prune the cross-comparison (see module docstring point 2 —
# floor-based bucketing at this width is what makes the pruning lossless).
DIST_TOL = 15.0
DIST_BUCKET = DIST_TOL

# Tolerance, in radians, for the two beta angles to be considered in agreement (~20 degrees).
ANGLE_TOL = 0.35

_TYPE_CODE = {"RIG": 0, "BIF": 1}


# ══════════════════════════════════════════════════════════════════════════════
# PRIMITIVES
# ══════════════════════════════════════════════════════════════════════════════

def _circ_diff(a, b):
    """
    Smallest absolute angular difference between a and b, in [0, pi], robust to wrap-
    around and vectorised over numpy arrays of any shape. Works for any real-valued input
    (no pre-wrapping of beta angles is needed before calling this).
    """
    return np.abs(np.angle(np.exp(1j * (a - b))))


def _scale_by_median_nn(tmpl, target=SCALE_TARGET_NN):
    """
    Rescale so the median nearest-neighbour distance lands on `target`. Robust to a single
    spurious minutia the way a bounding-box normalisation would not be. Deliberately
    self-contained — matching.py has an equivalent `_scale()`, but this module does not
    import from matching.py or any other backend/algorithms/*.py module (see package
    docstring), so the handful of lines are reimplemented here rather than shared.
    """
    if len(tmpl) < 2:
        return tmpl
    pts = np.array([[m["x"], m["y"]] for m in tmpl], dtype=float)
    tree = cKDTree(pts)
    nn = tree.query(pts, k=2)[0][:, 1]              # distance to nearest other point
    med = float(np.median(nn))
    if med <= 1e-9:
        return tmpl
    f = target / med
    return [{**m, "x": m["x"] * f, "y": m["y"] * f} for m in tmpl]


# ══════════════════════════════════════════════════════════════════════════════
# WITHIN-TEMPLATE PAIR TABLE
# ══════════════════════════════════════════════════════════════════════════════

def _pairwise_table(tmpl):
    """
    Every unordered pair (a, b) of a template's minutiae (a index < b index), described by
    a distance and the two self-referenced beta angles defined in the module docstring.
    Returns None if the template has fewer than 2 minutiae or every pair exceeds
    MAX_PAIR_DIST.

    Fields, all numpy arrays of equal length (one row per pair):
      a, b         point indices into `tmpl`
      dist         euclidean distance between a and b
      beta_a       angle from a's own direction to the bearing a -> b
      beta_b       angle from b's own direction to the bearing b -> a
      type_a, type_b   0 ("RIG") or 1 ("BIF")
      bucket       floor(dist / DIST_BUCKET), used to prune cross-comparison
    """
    n = len(tmpl)
    if n < 2:
        return None

    xs = np.array([m["x"] for m in tmpl], dtype=float)
    ys = np.array([m["y"] for m in tmpl], dtype=float)
    dirs = np.array([m["direction"] for m in tmpl], dtype=float)
    types = np.array([_TYPE_CODE.get(m["type"], -1) for m in tmpl], dtype=np.int8)

    ia, ib = np.triu_indices(n, k=1)
    dx = xs[ib] - xs[ia]
    dy = ys[ib] - ys[ia]
    dist = np.hypot(dx, dy)

    keep = dist <= MAX_PAIR_DIST
    if not np.any(keep):
        return None
    ia, ib, dx, dy, dist = ia[keep], ib[keep], dx[keep], dy[keep], dist[keep]

    bearing_ab = np.arctan2(dy, dx)
    bearing_ba = bearing_ab + math.pi
    beta_a = bearing_ab - dirs[ia]
    beta_b = bearing_ba - dirs[ib]

    bucket = np.floor(dist / DIST_BUCKET).astype(np.int64)

    return {
        "a": ia, "b": ib,
        "dist": dist,
        "beta_a": beta_a, "beta_b": beta_b,
        "type_a": types[ia], "type_b": types[ib],
        "bucket": bucket,
    }


def _bucket_groups(bucket_arr):
    """int bucket value -> array of row indices sharing it, built without a Python loop
    over individual rows."""
    order = np.argsort(bucket_arr, kind="stable")
    sorted_b = bucket_arr[order]
    uniq, starts = np.unique(sorted_b, return_index=True)
    ends = list(starts[1:]) + [len(order)]
    return {int(u): order[s:e] for u, s, e in zip(uniq, starts, ends)}


# ══════════════════════════════════════════════════════════════════════════════
# CROSS-TEMPLATE COMPATIBILITY GRAPH
# ══════════════════════════════════════════════════════════════════════════════

def _get_node(index_map, node_list, pair):
    idx = index_map.get(pair)
    if idx is None:
        idx = len(node_list)
        index_map[pair] = idx
        node_list.append(pair)
    return idx


def _build_correspondence_graph(t1, t2):
    """
    Cross-compare every within-template pair of t1 against every within-template pair of
    t2, bucketed on distance for tractability (see module docstring point 2).

    Returns (nodes, edges_u, edges_v):
      nodes    list of (i, j) candidate minutia correspondences, index == node id
      edges_u, edges_v   parallel lists of node ids — one entry per corroborating
                         pair-pair match, may contain duplicates (multiplicity is a
                         legitimate strength signal, used later for degree tie-breaking)
    """
    groups1 = _bucket_groups(t1["bucket"])
    groups2 = _bucket_groups(t2["bucket"])

    node_index = {}
    nodes = []
    edges_u, edges_v = [], []

    for b, q_idx in groups2.items():
        cand_parts = [groups1[bb] for bb in (b - 1, b, b + 1) if bb in groups1]
        if not cand_parts:
            continue
        p_idx = np.concatenate(cand_parts)
        if p_idx.size == 0 or q_idx.size == 0:
            continue

        d1 = t1["dist"][p_idx]
        d2 = t2["dist"][q_idx]
        mask_dist = np.abs(d1[:, None] - d2[None, :]) <= DIST_TOL
        if not np.any(mask_dist):
            continue

        ta1, tb1 = t1["type_a"][p_idx], t1["type_b"][p_idx]
        ta2, tb2 = t2["type_a"][q_idx], t2["type_b"][q_idx]
        beta_a1, beta_b1 = t1["beta_a"][p_idx], t1["beta_b"][p_idx]
        beta_a2, beta_b2 = t2["beta_a"][q_idx], t2["beta_b"][q_idx]

        # Orientation A: i<->j, k<->l  (t1's a<->t2's a, t1's b<->t2's b)
        mask_a = (mask_dist
                  & (ta1[:, None] == ta2[None, :])
                  & (tb1[:, None] == tb2[None, :])
                  & (_circ_diff(beta_a1[:, None], beta_a2[None, :]) <= ANGLE_TOL)
                  & (_circ_diff(beta_b1[:, None], beta_b2[None, :]) <= ANGLE_TOL))

        # Orientation B (reversed pairing): i<->l, k<->j
        mask_b = (mask_dist
                  & (ta1[:, None] == tb2[None, :])
                  & (tb1[:, None] == ta2[None, :])
                  & (_circ_diff(beta_a1[:, None], beta_b2[None, :]) <= ANGLE_TOL)
                  & (_circ_diff(beta_b1[:, None], beta_a2[None, :]) <= ANGLE_TOL))

        pa1, pb1 = t1["a"][p_idx], t1["b"][p_idx]
        pa2, pb2 = t2["a"][q_idx], t2["b"][q_idx]

        pp, qq = np.nonzero(mask_a)
        for pi_, qi_ in zip(pp.tolist(), qq.tolist()):
            u = _get_node(node_index, nodes, (int(pa1[pi_]), int(pa2[qi_])))
            v = _get_node(node_index, nodes, (int(pb1[pi_]), int(pb2[qi_])))
            edges_u.append(u)
            edges_v.append(v)

        pp, qq = np.nonzero(mask_b)
        for pi_, qi_ in zip(pp.tolist(), qq.tolist()):
            u = _get_node(node_index, nodes, (int(pa1[pi_]), int(pb2[qi_])))
            v = _get_node(node_index, nodes, (int(pb1[pi_]), int(pa2[qi_])))
            edges_u.append(u)
            edges_v.append(v)

    return nodes, edges_u, edges_v


# ══════════════════════════════════════════════════════════════════════════════
# LARGEST CONSISTENT COMPONENT -> 1:1 ASSIGNMENT
# ══════════════════════════════════════════════════════════════════════════════

def _largest_component_1to1(nodes, edges_u, edges_v):
    """
    Find the largest connected component of the correspondence graph, then reduce it to a
    clean 1:1 mapping by resolving any conflicts (a repeated i or j) in favour of the
    higher-degree (more corroborated) correspondence. Returns the final list of (i, j)
    pairs, or [] if there is no usable structure.
    """
    if not edges_u:
        return []

    n_nodes = len(nodes)
    eu = np.array(edges_u, dtype=np.int64)
    ev = np.array(edges_v, dtype=np.int64)

    graph = coo_matrix((np.ones(len(eu)), (eu, ev)), shape=(n_nodes, n_nodes))
    n_components, labels = connected_components(graph, directed=False)

    sizes = np.bincount(labels, minlength=n_components)
    best_label = int(np.argmax(sizes))
    if sizes[best_label] < 2:
        return []                                    # no corroborated component at all

    degree = np.bincount(np.concatenate([eu, ev]), minlength=n_nodes)

    component_ids = np.where(labels == best_label)[0]
    ranked = sorted(
        ((nodes[nid][0], nodes[nid][1], int(degree[nid])) for nid in component_ids),
        key=lambda row: -row[2],
    )

    used_i, used_j = set(), set()
    final = []
    for i, j, _ in ranked:
        if i in used_i or j in used_j:
            continue
        used_i.add(i)
        used_j.add(j)
        final.append((i, j))
    return final


# ══════════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ══════════════════════════════════════════════════════════════════════════════

def match(t1, t2):
    """
    Similarity of two minutiae sets via Bozorth3-style pairwise-relationship matching, in
    [0, 1]. See the module docstring for the algorithm and its rotation-invariance
    guarantee.
    """
    ratio = min(len(t1), len(t2)) / max(len(t1), len(t2))
    if ratio < MIN_COUNT_RATIO:
        return 0.0

    if len(t1) < 2 or len(t2) < 2:
        return 0.0

    a = _scale_by_median_nn(t1)
    b = _scale_by_median_nn(t2)

    table1 = _pairwise_table(a)
    table2 = _pairwise_table(b)
    if table1 is None or table2 is None:
        return 0.0

    nodes, edges_u, edges_v = _build_correspondence_graph(table1, table2)
    final = _largest_component_1to1(nodes, edges_u, edges_v)
    if not final:
        return 0.0

    score = (len(final) / min(len(t1), len(t2))) * ratio
    return float(max(0.0, min(1.0, score)))
