import math
import numpy as np
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from simulator.cells import CellNetwork


@dataclass
class DivergenceReport:
    divergence_detected: bool
    divergence_score: float  # 0.0 to 1.0
    heading_discrepancy_deg: float
    invalidated_candidate: Optional[str]
    emerging_candidate: Optional[str]
    reason: str


class RouteDivergenceDetector:
    """Detects when real-world UE trajectory deviates from previously predicted path."""

    def __init__(
        self,
        network: CellNetwork,
        heading_deviation_th_deg: float = 35.0,
        candidate_signal_drop_th_db: float = 4.0,
        divergence_score_th: float = 0.55,
    ):
        self.network = network
        self.heading_th = heading_deviation_th_deg
        self.signal_drop_th = candidate_signal_drop_th_db
        self.divergence_th = divergence_score_th

    def detect(
        self,
        current_telemetry: Dict[str, Any],
        active_candidate_cell: Optional[str],
        prior_telemetry: Optional[Dict[str, Any]] = None,
    ) -> DivergenceReport:
        if not active_candidate_cell or active_candidate_cell not in self.network.cells:
            return DivergenceReport(
                divergence_detected=False,
                divergence_score=0.0,
                heading_discrepancy_deg=0.0,
                invalidated_candidate=None,
                emerging_candidate=None,
                reason="No active proactive candidate to evaluate.",
            )

        ue_x = current_telemetry.get("x", 0.0)
        ue_y = current_telemetry.get("y", 0.0)
        heading = current_telemetry.get("heading_deg", 0.0)

        # 1. Kinematic Vector Check: Direction from UE to candidate cell
        cand_cell = self.network.get_cell(active_candidate_cell)
        dx = cand_cell.x - ue_x
        dy = cand_cell.y - ue_y
        bearing_to_candidate = math.degrees(math.atan2(dy, dx)) % 360.0

        # Angular difference between current travel heading and direction to candidate cell
        angle_diff = abs((heading - bearing_to_candidate + 180.0) % 360.0 - 180.0)

        # 2. RF Differential Check: Candidate RSRP vs Alternative Neighbour RSRP trends
        curr_cand_rsrp = current_telemetry.get(f"neighbor_{active_candidate_cell}_rsrp", -130.0)
        prior_cand_rsrp = (
            prior_telemetry.get(f"neighbor_{active_candidate_cell}_rsrp", curr_cand_rsrp)
            if prior_telemetry
            else curr_cand_rsrp
        )
        cand_rsrp_delta = curr_cand_rsrp - prior_cand_rsrp  # Negative means signal is weakening

        # Check for rising alternative cell
        emerging_cell = None
        max_emerging_gain = 0.0
        for cid in self.network.get_cell_ids():
            if cid == active_candidate_cell or cid == current_telemetry.get("current_cell"):
                continue
            curr_rsrp = current_telemetry.get(f"neighbor_{cid}_rsrp", -130.0)
            prior_rsrp = (
                prior_telemetry.get(f"neighbor_{cid}_rsrp", curr_rsrp) if prior_telemetry else curr_rsrp
            )
            gain = curr_rsrp - prior_rsrp
            if gain > max_emerging_gain and curr_rsrp > curr_cand_rsrp:
                max_emerging_gain = gain
                emerging_cell = cid

        # 3. Calculate Divergence Score (0.0 to 1.0)
        kinematic_score = min(1.0, angle_diff / 90.0) if angle_diff > self.heading_th else 0.0
        rf_score = min(1.0, max_emerging_gain / 6.0) if cand_rsrp_delta <= -1.0 or emerging_cell else 0.0
        
        divergence_score = 0.6 * kinematic_score + 0.4 * rf_score

        is_divergent = divergence_score >= self.divergence_th or (angle_diff > self.heading_th and emerging_cell is not None)

        if is_divergent:
            reason = (
                f"Trajectory heading deviated by {angle_diff:.1f}° from {active_candidate_cell} corridor. "
            )
            if emerging_cell:
                reason += f"Alternative {emerging_cell} signal is emerging (+{max_emerging_gain:.1f} dBm/s)."
        else:
            reason = f"Trajectory consistent with {active_candidate_cell} corridor (Deviation: {angle_diff:.1f}°)."

        return DivergenceReport(
            divergence_detected=is_divergent,
            divergence_score=round(divergence_score, 3),
            heading_discrepancy_deg=round(angle_diff, 1),
            invalidated_candidate=active_candidate_cell if is_divergent else None,
            emerging_candidate=emerging_cell if is_divergent else None,
            reason=reason,
        )
