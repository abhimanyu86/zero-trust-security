"""
Independent matching-algorithm candidates for the bake-off (see MATCHING_ALGORITHMS.md
at the repo root for what each one is, why it's here, and the running results table).

Every module in this package exports one function:

    match(t1, t2) -> float

with the exact same contract as matching.match_templates: t1/t2 are list[dict] minutiae
(x, y, direction radians, type "RIG"|"BIF"), the return value is a similarity in [0, 1].
Each module is self-contained — no imports between algorithm modules, no imports from
matching.py — so building one doesn't risk breaking another. matching.py's _ALGORITHMS
registry imports from here and is the only place that wires them together.

The one exception is the Hungarian/optimal-assignment variant, which lives directly in
matching.py instead of here: it deliberately reuses matching.py's private graph-building
and relaxation-labeling helpers (same front end as the modern algorithm, different final
assignment step), so keeping it in the same file avoids a fragile cross-module import of
underscore-prefixed internals.
"""
