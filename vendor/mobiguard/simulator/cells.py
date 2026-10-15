import math
from typing import Dict, List, Tuple
from dataclasses import dataclass


@dataclass
class Cell:
    id: str
    x: float
    y: float
    tx_power_dbm: float = 43.0
    frequency_ghz: float = 3.5
    label: str = ""
    color: str = "#3B82F6"

    def distance_to(self, x: float, y: float) -> float:
        """Euclidean distance in meters (with 5m minimum to prevent log singularity)."""
        dist = math.hypot(self.x - x, self.y - y)
        return max(dist, 5.0)

    def path_loss_db(self, distance_m: float, exponent: float = 3.4, ref_loss_d0: float = 38.5) -> float:
        """3GPP Urban / Sub-6 GHz logarithmic path loss formulation."""
        d = max(distance_m, 1.0)
        pl = ref_loss_d0 + 10.0 * exponent * math.log10(d)
        return pl


class CellNetwork:
    """Manages the network topology of 5G gNB cells."""

    def __init__(self, cell_configs: Dict[str, dict], default_exponent: float = 3.4, ref_loss_d0: float = 38.5):
        self.cells: Dict[str, Cell] = {}
        self.exponent = default_exponent
        self.ref_loss_d0 = ref_loss_d0

        for cell_id, cfg in cell_configs.items():
            self.cells[cell_id] = Cell(
                id=cell_id,
                x=float(cfg.get("x", 0.0)),
                y=float(cfg.get("y", 0.0)),
                tx_power_dbm=float(cfg.get("tx_power_dbm", 43.0)),
                frequency_ghz=float(cfg.get("frequency_ghz", 3.5)),
                label=cfg.get("label", cell_id),
                color=cfg.get("color", "#3B82F6"),
            )

    @classmethod
    def default_6_cell_network(cls) -> "CellNetwork":
        configs = {
            "Cell_A": {"x": 0.0, "y": 0.0, "label": "Sector A (West Hub)", "color": "#3B82F6"},
            "Cell_B": {"x": 2000.0, "y": 0.0, "label": "Sector B (East Corridor)", "color": "#10B981"},
            "Cell_C": {"x": 1600.0, "y": 1100.0, "label": "Sector C (North-East Branch)", "color": "#F59E0B"},
            "Cell_D": {"x": 0.0, "y": 1800.0, "label": "Sector D (North Urban)", "color": "#8B5CF6"},
            "Cell_E": {"x": 3600.0, "y": 0.0, "label": "Sector E (Far East Expressway)", "color": "#EC4899"},
            "Cell_F": {"x": 2800.0, "y": 1600.0, "label": "Sector F (Outer Orbital)", "color": "#06B6D4"},
        }
        return cls(configs)

    def get_cell_ids(self) -> List[str]:
        return sorted(list(self.cells.keys()))

    def get_cell(self, cell_id: str) -> Cell:
        return self.cells[cell_id]

    def get_distances(self, x: float, y: float) -> Dict[str, float]:
        return {cid: cell.distance_to(x, y) for cid, cell in self.cells.items()}
