"""
NetworkX graph / spectral minutiae matching (candidate 7, `algo/networkx-graph`).

Deliberately the odd one out in this bake-off: every other candidate hand-rolls its own
kNN-graph bookkeeping (adjacency dicts, neighbour lists) on top of numpy/scipy. This one
instead builds a real `networkx.Graph` per template and leans on the library for the
graph plumbing, to see whether a heavier, general-purpose graph-algorithms toolkit buys
anything over the bespoke KD-tree/relaxation-labeling code in matching.py.

Mechanism
---------
1. One node per minutia, attributed with `type` ("RIG"/"BIF") and `direction` (radians).
   Edges to each minutia's k=6 nearest neighbours (`scipy.spatial.cKDTree`, same
   neighbourhood size as the rest of the codebase), each edge attributed with a
   `(distance, relative_bearing)` descriptor — see "Rotation invariance" below.

2. A coarse **global** structural signal: the graph Laplacian's eigenvalue spectrum
   (`networkx.laplacian_spectrum`), compared between the two graphs over their top-K
   eigenvalues (K = the smaller node count). Two graphs with similar Laplacian spectra
   have similar overall connectivity structure — this is the classic spectral-graph-
   theory notion of "graphs that look alike", and it's cheap: no correspondence between
   individual nodes is needed to compute it.

   Deliberately NOT using `nx.graph_edit_distance` / `nx.optimize_graph_edit_distance`
   here. Graph edit distance is NP-hard in general and its NetworkX implementation is a
   search over node mappings — fine for graphs with a handful of nodes, unusable at
   40-70 nodes within this codebase's sub-second budget. The spectrum is an O(n^3)
   eigendecomposition (dominated by building the n x n Laplacian, n <= ~70 here), not a
   combinatorial search, so it stays fast at this scale.

3. Because two structurally-similar-looking graphs are not the same as two fingers
   actually lining up minutia-for-minutia, the spectral number alone is only a coarse
   prior. It is blended with an actual per-minutia correspondence: candidate node pairs
   are formed from matching type plus similar *local* edge-descriptor neighbourhoods
   (cosine similarity between each node's sorted list of outgoing edge descriptors —
   see `_local_feature_vector`'s docstring for how distance and bearing are normalised
   before the cosine comparison, and why that normalisation turned out to matter), then
   resolved with a simple greedy 1:1 assignment (highest compatibility first, skip
   anything whose row or column is already taken — the same greedy discipline
   matching.py's default algorithm uses, no Hungarian solver here since the point of
   this candidate is the graph/spectral machinery, not the assignment step).

4. Final score = weighted blend of (assigned-pair coverage fraction) and (global spectral
   similarity), multiplied by the count-ratio gate value, clamped to [0, 1].

Known limits (measured, not assumed — see `_local_feature_vector`'s "Tuning notes"):
rotation invariance holds cleanly; discrimination against a wholly unrelated template is
reasonable; discrimination under a partial-overlap, jittered recapture (the realistic
case) is comparatively weak versus matching.py's relaxation-labeling default, since this
candidate's correspondence step only looks one hop out and never propagates evidence
across the graph the way relaxation labeling does.

Rotation invariance
--------------------
This is the exact defect that made matching.py's original algorithm score 0% TAR on
real, rotated phone captures (see matching.py's module docstring), so it is worth being
explicit and correct about it here rather than just asserting it.

Every geometric quantity this module computes is measured **relative to a minutia's own
ridge direction**, never in absolute image-space coordinates:

  - Edge descriptor: `bearing = atan2(dy, dx) - p1["direction"]`. Under a rigid rotation
    by theta, both `atan2(dy, dx)` and `p1["direction"]` increase by theta, so their
    difference is unchanged. Distance is a norm of a translation-covariant vector, also
    unchanged by rotation. Neither node's absolute (x, y) nor absolute `direction` ever
    appears in a graph attribute or a compatibility score — only distance and this
    relative bearing do.
  - Node attributes carry `direction` for reference, but node compatibility for
    candidate correspondences is gated on `type` only, exactly like matching.py's
    default path — an absolute-direction or absolute-position gate is what broke the
    original matcher under rotation, so this module does not reintroduce one.
  - The Laplacian spectrum depends only on graph *topology* (which nodes are connected
    to which, i.e. the kNN adjacency structure), not on node positions or edge weights
    unless weights are attached to the Laplacian. This implementation deliberately uses
    the *unweighted* Laplacian, so the spectral term is rotation-invariant by
    construction — it does not even see the (already rotation-invariant) edge
    descriptors, only which kNN edges exist.

Net effect: rotating a template's positions and directions together (matching this
codebase's convention — see test_matching.py's `rotate()` helper) changes neither the
kNN topology (kNN is itself rotation-invariant — nearest neighbours by Euclidean
distance don't change under a rigid rotation) nor any edge/node attribute this module
reads. The self-check in the algorithm's development notes confirmed the rotated score
tracks the unrotated one closely.
"""

import math

import networkx as nx
import numpy as np
from scipy.spatial import cKDTree

# ── Shared parameters (same neighbourhood-size convention as matching.py) ──────
K_NEIGHBORS = 6

# Minimum count ratio between two templates before matching is attempted at all.
MIN_COUNT_RATIO = 0.45

# Spectral comparison is capped at this many eigenvalues even when both graphs are
# larger, to keep the O(K) distance computation trivial and to focus the comparison on
# the coarse, low-frequency structure (small eigenvalues) rather than noisy high-order
# detail that differs node-by-node.
MAX_SPECTRAL_K = 40

# Local edge-descriptor neighbourhood used for the cosine-similarity local feature is
# capped at this many outgoing edges per node (== K_NEIGHBORS in practice, since the
# kNN graph gives every node at most K_NEIGHBORS outgoing edges — kept as an explicit
# constant rather than reusing K_NEIGHBORS so the cap is legible on its own).
MAX_LOCAL_EDGES = K_NEIGHBORS

# A correspondence candidate is only kept if its local-neighbourhood cosine similarity
# reaches this much. Below this, two nodes just happen to share a type and contribute
# noise to the greedy assignment rather than signal. Tuned empirically (see module
# docstring's "Tuning notes") against synthetic uniform-random templates, where two
# *unrelated* nodes' raw distance lists already resemble each other closely (an artefact
# of drawing many points from the same distribution, not of them corresponding) — 0.6
# was the smallest threshold that kept the random-impostor mean score comfortably below
# a same-template match without also rejecting genuine rotated correspondences.
MIN_LOCAL_SIM = 0.6

# Final score = SPECTRAL_WEIGHT * spectral_similarity + (1 - SPECTRAL_WEIGHT) * coverage
SPECTRAL_WEIGHT = 0.25


# ══════════════════════════════════════════════════════════════════════════════
# GRAPH CONSTRUCTION
# ══════════════════════════════════════════════════════════════════════════════

def _build_graph(tmpl):
    """
    One networkx.Graph per template: node per minutia (type, direction attributes),
    edges to each minutia's k=6 nearest neighbours, edge attribute `descriptor` =
    (distance, relative_bearing) measured in the source node's own reference frame.

    Returns (graph, descriptors) where `descriptors[i]` is the sorted list of outgoing
    edge descriptors for node i — precomputed once here since both the local-similarity
    step and nothing else needs to rebuild it.
    """
    n = len(tmpl)
    g = nx.Graph()
    for i, m in enumerate(tmpl):
        g.add_node(i, type=m["type"], direction=m["direction"])

    if n < 2:
        return g, [[] for _ in range(n)]

    pts = np.array([[m["x"], m["y"]] for m in tmpl], dtype=float)
    tree = cKDTree(pts)
    k = min(K_NEIGHBORS + 1, n)
    idxs = tree.query(pts, k=k)[1]

    descriptors = [[] for _ in range(n)]
    for i in range(n):
        neighbours = idxs[i] if k > 1 else [idxs[i]]
        for j in np.atleast_1d(neighbours):
            j = int(j)
            if j == i:
                continue
            dx = tmpl[j]["x"] - tmpl[i]["x"]
            dy = tmpl[j]["y"] - tmpl[i]["y"]
            dist = math.hypot(dx, dy)
            bearing = (math.atan2(dy, dx) - tmpl[i]["direction"]) % (2 * math.pi)
            descriptor = (dist, bearing)
            descriptors[i].append(descriptor)
            # Undirected graph edge for the spectral/topological view; the directed
            # per-node descriptor list above is what the local-similarity step uses,
            # since a-relative-to-b and b-relative-to-a are genuinely different vectors.
            if not g.has_edge(i, j):
                g.add_edge(i, j)

    for i in range(n):
        descriptors[i].sort()

    return g, descriptors


# ══════════════════════════════════════════════════════════════════════════════
# GLOBAL SIGNAL — Laplacian spectral similarity
# ══════════════════════════════════════════════════════════════════════════════

def _spectral_similarity(g1, g2):
    """
    Normalised similarity in [0, 1] between two graphs' Laplacian eigenvalue spectra,
    compared over their top-K eigenvalues (K = min node count, capped at
    MAX_SPECTRAL_K). Purely topological — does not depend on node/edge attributes.
    """
    n1, n2 = g1.number_of_nodes(), g2.number_of_nodes()
    if n1 == 0 or n2 == 0:
        return 0.0

    k = min(n1, n2, MAX_SPECTRAL_K)
    if k == 0:
        return 0.0

    spec1 = np.sort(nx.laplacian_spectrum(g1))[::-1][:k]
    spec2 = np.sort(nx.laplacian_spectrum(g2))[::-1][:k]

    denom = max(float(np.linalg.norm(spec1)), float(np.linalg.norm(spec2)), 1e-9)
    dist = float(np.linalg.norm(spec1 - spec2)) / denom
    return float(max(0.0, 1.0 - dist))


# ══════════════════════════════════════════════════════════════════════════════
# LOCAL SIGNAL — per-node correspondence via local edge-descriptor similarity
# ══════════════════════════════════════════════════════════════════════════════

DIST_COMPONENT_WEIGHT = 0.4  # see _local_feature_vector docstring


def _local_feature_vector(descriptors_i):
    """
    Flatten a node's (capped, sorted) outgoing (distance, bearing) descriptors into a
    fixed-ish-length numeric vector so two nodes' local neighbourhoods can be compared
    with cosine similarity.

    Two normalisations matter here, both found necessary empirically (see "Tuning
    notes" below), not just for tidiness:

    - Bearing is projected onto the unit circle (cos, sin) rather than compared as a
      raw radian value, so the wraparound at 2*pi doesn't produce a spurious large
      difference between two nearly-identical bearings either side of 0.
    - Distance is z-scored *within this node's own neighbour list* (subtract this
      list's mean, divide by its std) rather than used raw, and down-weighted by
      DIST_COMPONENT_WEIGHT relative to the unit-norm bearing terms. Raw pixel
      distances turned out to be a poor cosine-similarity feature here: k-NN distances
      drawn from similarly-dense point sets are strongly correlated by construction
      (an order-statistics effect — the k nearest-neighbour distances of *any* two
      points sampled from a similar-density layout tend to look alike), so an unweighted
      raw-distance component made unrelated nodes look deceptively similar and collapsed
      genuine/impostor separation. Z-scoring compares each node's *relative* near/far
      neighbour shape instead of absolute spacing, which carries real signal without
      that artefact.

    Tuning notes: MIN_LOCAL_SIM and SPECTRAL_WEIGHT above were picked by measuring this
    function against synthetic uniform-random templates (self-match, rotated self-match,
    unrelated "impostor" templates, and partial-overlap recaptures with jitter) — see the
    algorithm's self-check script. Rotation invariance holds cleanly (self and rotated-
    self both score 1.0). Discrimination against a wholly unrelated random template is
    reasonable but not sharp; discrimination under a *partial-overlap, jittered* recapture
    — the harder, more realistic case — is weak on this synthetic generator, sometimes on
    par with the unrelated-template case. This is a genuine, honestly-reported limitation
    of a one-hop local-cosine correspondence step, not a bug: relaxation labeling (as
    matching.py's default algorithm uses) propagates evidence across multiple hops before
    committing to a correspondence, which this candidate deliberately does not do, in
    keeping with this being the "how much does a heavier general-purpose graph toolkit
    buy you" comparison point rather than a reimplementation of the relaxation approach.
    """
    capped = descriptors_i[:MAX_LOCAL_EDGES]
    if not capped:
        return np.array([])
    dists = np.array([d for d, _ in capped], dtype=float)
    mu = float(dists.mean())
    sd = float(dists.std())
    if sd < 1e-6:
        sd = 1.0
    vec = []
    for dist, bearing in capped:
        vec.append(DIST_COMPONENT_WEIGHT * (dist - mu) / sd)
        vec.append(math.cos(bearing))
        vec.append(math.sin(bearing))
    return np.array(vec, dtype=float)


def _cosine_sim(v1, v2):
    if v1.size == 0 or v2.size == 0:
        return 0.0
    n = min(v1.size, v2.size)
    v1, v2 = v1[:n], v2[:n]
    denom = np.linalg.norm(v1) * np.linalg.norm(v2)
    if denom <= 1e-9:
        return 0.0
    return float(np.clip(np.dot(v1, v2) / denom, -1.0, 1.0))


def _match_correspondence(a, b, desc_a, desc_b):
    """
    Candidate node pairs: same minutia type, then ranked by cosine similarity between
    local edge-descriptor feature vectors. Greedy 1:1 assignment, highest similarity
    first — same discipline matching.py's default algorithm uses for its final
    assignment step, kept deliberately simple since this candidate's point is the
    graph/spectral machinery upstream of it, not a fancier assignment solver.

    Returns the list of accepted per-pair similarity scores.
    """
    feats_a = [_local_feature_vector(d) for d in desc_a]
    feats_b = [_local_feature_vector(d) for d in desc_b]

    scored = []
    for i, m1 in enumerate(a):
        for j, m2 in enumerate(b):
            if m1["type"] != m2["type"]:
                continue
            sim = _cosine_sim(feats_a[i], feats_b[j])
            if sim >= MIN_LOCAL_SIM:
                scored.append((sim, i, j))

    scored.sort(key=lambda x: -x[0])
    used_i, used_j, assigned = set(), set(), []
    for sim, i, j in scored:
        if i in used_i or j in used_j:
            continue
        used_i.add(i)
        used_j.add(j)
        assigned.append(sim)
    return assigned


# ══════════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ══════════════════════════════════════════════════════════════════════════════

def match(t1, t2):
    """
    Similarity of two minutiae sets, in [0, 1]. See module docstring for mechanism and
    the rotation-invariance argument.
    """
    ratio = min(len(t1), len(t2)) / max(len(t1), len(t2))
    if ratio < MIN_COUNT_RATIO:
        return 0.0

    # Not enough structure to build a meaningful kNN graph or a 2-eigenvalue spectrum.
    if len(t1) < 3 or len(t2) < 3:
        return 0.0

    g1, desc1 = _build_graph(t1)
    g2, desc2 = _build_graph(t2)

    spectral = _spectral_similarity(g1, g2)
    assigned = _match_correspondence(t1, t2, desc1, desc2)

    coverage = len(assigned) / min(len(t1), len(t2))

    score = (SPECTRAL_WEIGHT * spectral + (1 - SPECTRAL_WEIGHT) * coverage) * ratio
    return float(max(0.0, min(1.0, score)))
