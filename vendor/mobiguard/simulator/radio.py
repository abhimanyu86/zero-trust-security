import math
import numpy as np
from typing import Dict, List, Tuple, Optional
from .cells import CellNetwork


class RadioEnvironment:
    """Simulates realistic 5G radio telemetry: RSRP, SINR, correlated shadowing & handover."""

    def __init__(
        self,
        network: CellNetwork,
        noise_std_db: float = 1.5,
        temporal_correlation_alpha: float = 0.75,
        hysteresis_db: float = 3.0,
        thermal_noise_dbm: float = -104.0,
        seed: int = 42,
    ):
        self.network = network
        self.noise_std_db = noise_std_db
        self.alpha = temporal_correlation_alpha
        self.hysteresis_db = hysteresis_db
        self.thermal_noise_dbm = thermal_noise_dbm

        self.rng = np.random.default_rng(seed)
        self.cell_ids = self.network.get_cell_ids()

        # AR(1) correlated shadowing state per cell
        self.shadowing: Dict[str, float] = {cid: 0.0 for cid in self.cell_ids}

        # Current serving state
        self.current_serving_cell: str = self.cell_ids[0]
        self.previous_cell_1: str = "NONE"
        self.previous_cell_2: str = "NONE"
        self.current_dwell_s: float = 0.0

    def reset_ue_state(self, initial_serving: Optional[str] = None):
        """Reset state for a new trajectory."""
        self.shadowing = {cid: 0.0 for cid in self.cell_ids}
        self.current_serving_cell = initial_serving or self.cell_ids[0]
        self.previous_cell_1 = "NONE"
        self.previous_cell_2 = "NONE"
        self.current_dwell_s = 0.0

    def compute_telemetry(
        self,
        x: float,
        y: float,
        dt: float = 1.0,
        noise_multiplier: float = 1.0,
    ) -> Dict[str, any]:
        """Calculates instantaneous RSRP, SINR, neighbours, and updates serving cell."""
        std = self.noise_std_db * noise_multiplier

        # 1. Update correlated shadowing per cell: S(t) = alpha*S(t-1) + sqrt(1-alpha^2)*e(t)
        for cid in self.cell_ids:
            innov = self.rng.normal(0.0, std)
            self.shadowing[cid] = self.alpha * self.shadowing[cid] + math.sqrt(1.0 - self.alpha ** 2) * innov

        # 2. Compute raw RSRP for all cells: RSRP = Ptx - PL(d) + Shadowing
        rsrp_dict: Dict[str, float] = {}
        for cid, cell in self.network.cells.items():
            dist = cell.distance_to(x, y)
            pl = cell.path_loss_db(dist, exponent=self.network.exponent, ref_loss_d0=self.network.ref_loss_d0)
            raw_rsrp = cell.tx_power_dbm - pl + self.shadowing[cid]
            # Clip between physical receiver bounds (-135 dBm to -40 dBm)
            rsrp_dict[cid] = round(float(np.clip(raw_rsrp, -135.0, -40.0)), 2)

        # 3. Determine serving cell using hysteresis (3GPP A3 Handover Event)
        # Serving cell must be exceeded by at least hysteresis_db to trigger handover
        best_cell = max(rsrp_dict, key=rsrp_dict.get)
        current_serving_rsrp = rsrp_dict.get(self.current_serving_cell, -140.0)
        best_rsrp = rsrp_dict[best_cell]

        if best_cell != self.current_serving_cell:
            if best_rsrp > current_serving_rsrp + self.hysteresis_db:
                # Handover triggered
                self.previous_cell_2 = self.previous_cell_1
                self.previous_cell_1 = self.current_serving_cell
                self.current_serving_cell = best_cell
                self.current_dwell_s = 0.0
            else:
                self.current_dwell_s += dt
        else:
            self.current_dwell_s += dt

        # 4. Compute SINR for serving cell and neighbours
        # SINR = 10 * log10( P_rx / (N_0 + sum(Interference)) )
        thermal_mw = 10.0 ** (self.thermal_noise_dbm / 10.0)
        total_mw = thermal_mw + sum(10.0 ** (p / 10.0) for p in rsrp_dict.values())

        sinr_dict: Dict[str, float] = {}
        for cid, p_dbm in rsrp_dict.items():
            p_mw = 10.0 ** (p_dbm / 10.0)
            interf_mw = max(1e-15, total_mw - p_mw)
            sinr = 10.0 * math.log10(p_mw / interf_mw)
            sinr_dict[cid] = round(float(np.clip(sinr, -15.0, 35.0)), 2)

        # 5. Build standard telemetry payload
        result = {
            "current_cell": self.current_serving_cell,
            "current_rsrp_dbm": rsrp_dict[self.current_serving_cell],
            "current_sinr_db": sinr_dict[self.current_serving_cell],
            "previous_cell_1": self.previous_cell_1,
            "previous_cell_2": self.previous_cell_2,
            "current_dwell_s": round(self.current_dwell_s, 1),
        }

        # Add neighbour metrics (e.g. neighbor_Cell_B_rsrp, neighbor_Cell_B_sinr)
        for cid in self.cell_ids:
            result[f"neighbor_{cid}_rsrp"] = rsrp_dict[cid]
            result[f"neighbor_{cid}_sinr"] = sinr_dict[cid]

        return result
