import math
import numpy as np
from typing import List, Tuple, Dict


class RouteGenerator:
    """Generates kinematic waypoints and trajectories for different mobility scenarios."""

    @staticmethod
    def get_available_scenarios() -> List[str]:
        return [
            "highway_straight",
            "highway_exit",
            "urban_grid",
            "rail_corridor",
            "station_approach",
            "noisy_measurement",
            "sparse_telemetry",
        ]

    @classmethod
    def generate_waypoints(
        cls,
        scenario: str,
        seed: int = 42,
        traj_index: int = 0,
        lateral_offset: float = 0.0,
    ) -> List[Tuple[float, float, float]]:
        """
        Returns a list of (x, y, target_speed_mps) waypoints.
        """
        rng = np.random.default_rng(seed + traj_index * 13)
        y_jitter = lateral_offset + float(rng.uniform(-15.0, 15.0))

        if scenario in ["highway_straight", "noisy_measurement", "sparse_telemetry"]:
            speed = float(rng.uniform(26.0, 32.0))
            if scenario == "noisy_measurement":
                speed = float(rng.uniform(18.0, 24.0))
            return [
                (-200.0, y_jitter, speed),
                (500.0, y_jitter, speed),
                (1500.0, y_jitter, speed),
                (2200.0, y_jitter, speed),
                (3200.0, y_jitter, speed),
                (4200.0, y_jitter, speed),
            ]

        elif scenario == "highway_exit":
            # Primary story: Starts East towards Cell B (2000, 0), then diverges at X=1000m towards Cell C (1600, 1100)
            base_speed = float(rng.uniform(25.0, 30.0))
            return [
                (-200.0, y_jitter, base_speed),
                (400.0, y_jitter, base_speed),
                (950.0, y_jitter, base_speed * 0.95),
                (1250.0, 350.0 + y_jitter, base_speed * 0.85),  # Exit ramp curve
                (1550.0, 850.0 + y_jitter, base_speed * 0.80),  # Entering Cell C coverage
                (1800.0, 1300.0 + y_jitter, base_speed * 0.75), # Approaching Cell C
                (2200.0, 1550.0 + y_jitter, base_speed * 0.75), # Continuing past Cell C
            ]

        elif scenario == "urban_grid":
            spd = float(rng.uniform(10.0, 14.0))
            return [
                (-100.0, -100.0 + y_jitter, spd),
                (0.0, 600.0 + y_jitter, spd),
                (0.0, 1200.0 + y_jitter, spd * 0.8),
                (600.0, 1200.0 + y_jitter, spd),
                (1200.0, 1200.0 + y_jitter, spd),
                (1600.0, 1600.0 + y_jitter, spd * 0.9),
                (2200.0, 1600.0 + y_jitter, spd),
            ]

        elif scenario == "rail_corridor":
            spd = float(rng.uniform(42.0, 48.0))
            return [
                (-300.0, 50.0 + y_jitter, spd),
                (800.0, 50.0 + y_jitter, spd),
                (2000.0, 50.0 + y_jitter, spd),
                (3200.0, 50.0 + y_jitter, spd),
                (4400.0, 50.0 + y_jitter, spd),
            ]

        elif scenario == "station_approach":
            return [
                (-100.0, 200.0 + y_jitter, 28.0),
                (500.0, 500.0 + y_jitter, 22.0),
                (1000.0, 800.0 + y_jitter, 15.0),
                (1400.0, 1050.0 + y_jitter, 6.0),
                (1600.0, 1100.0 + y_jitter, 0.0),
            ]

        else:
            return [
                (0.0, 0.0, 20.0),
                (1000.0, 500.0, 20.0),
                (2000.0, 1000.0, 20.0),
            ]
