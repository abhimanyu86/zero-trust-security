import math
import numpy as np
import pandas as pd
from typing import Dict, List, Optional
from .cells import CellNetwork
from .routes import RouteGenerator
from .mobility import MobilitySimulator
from .radio import RadioEnvironment


class SyntheticDatasetGenerator:
    """Generates synthetic mobility & radio telemetry datasets with future ground-truth labels."""

    def __init__(self, config: dict):
        self.config = config
        self.seed = config.get("seed", 42)
        self.sim_cfg = config.get("simulator", {})
        self.dt = self.sim_cfg.get("dt_seconds", 1.0)
        self.horizon_steps = self.sim_cfg.get("prediction_horizon_steps", 3)
        self.weakening_rsrp_th = config.get("features", {}).get("weakening_rsrp_threshold_dbm", -95.0)
        self.weakening_delta_th = config.get("features", {}).get("weakening_delta_drop_db", 4.0)

        cell_configs = config.get("cells", {})
        self.network = CellNetwork(
            cell_configs,
            default_exponent=self.sim_cfg.get("path_loss_exponent", 3.4),
            ref_loss_d0=self.sim_cfg.get("reference_loss_d0", 38.5),
        )

    def generate_single_trajectory(
        self,
        scenario: str,
        trajectory_id: str,
        ue_id: str,
        seed: int,
        traj_index: int = 0,
        noise_multiplier: float = 1.0,
        sample_drop_rate: float = 0.0,
    ) -> pd.DataFrame:
        """Simulate a single end-to-end trajectory and record timesteps."""
        waypoints = RouteGenerator.generate_waypoints(
            scenario=scenario,
            seed=seed,
            traj_index=traj_index,
        )

        mobility = MobilitySimulator(waypoints, dt=self.dt)
        radio = RadioEnvironment(
            network=self.network,
            noise_std_db=self.sim_cfg.get("noise_std_db", 1.5),
            temporal_correlation_alpha=self.sim_cfg.get("temporal_correlation_alpha", 0.75),
            hysteresis_db=self.sim_cfg.get("hysteresis_db", 3.0),
            thermal_noise_dbm=self.sim_cfg.get("thermal_noise_dbm", -104.0),
            seed=seed + traj_index * 17,
        )

        # Initial radio state
        initial_telemetry = radio.compute_telemetry(mobility.x, mobility.y, dt=self.dt)
        radio.reset_ue_state(initial_serving=initial_telemetry["current_cell"])

        records: List[Dict[str, any]] = []
        step_idx = 0
        t = 0.0

        rng = np.random.default_rng(seed + traj_index * 29)

        while True:
            # 1. Advance kinematics
            kin = mobility.step()
            x = kin["x"]
            y = kin["y"]
            speed = kin["speed_mps"]
            heading = kin["heading_deg"]
            heading_change = kin["heading_change_deg"]

            # 2. Compute radio measurements
            rad = radio.compute_telemetry(x, y, dt=self.dt, noise_multiplier=noise_multiplier)

            # Drop sample if sparse scenario is active
            if sample_drop_rate > 0.0 and rng.uniform(0.0, 1.0) < sample_drop_rate and step_idx > 2:
                t += self.dt
                step_idx += 1
                if kin["is_finished"]:
                    break
                continue

            row = {
                "trajectory_id": trajectory_id,
                "ue_id": ue_id,
                "scenario": scenario,
                "step_index": step_idx,
                "timestamp": round(t, 2),
                "x": x,
                "y": y,
                "speed_mps": speed,
                "heading_deg": heading,
                "heading_change_deg": heading_change,
                **rad,
            }
            records.append(row)

            t += self.dt
            step_idx += 1

            if kin["is_finished"]:
                break

        df = pd.DataFrame(records)
        if len(df) == 0:
            return df

        # 3. Future Next-Cell Target (Look ahead by H steps)
        df["target_next_cell"] = df["current_cell"].shift(-self.horizon_steps).bfill().ffill()

        # 4. Serving-Cell Weakening Ground Truth Label
        # Evaluates whether the cell serving AT STEP t will undergo severe attenuation or lose serving status over horizon H
        weakening_labels = []
        n_rows = len(df)
        for i in range(n_rows):
            curr_c = df.loc[i, "current_cell"]
            curr_rsrp = df.loc[i, "current_rsrp_dbm"]
            fut_idx = min(n_rows - 1, i + self.horizon_steps)
            
            # Future signal of the SAME cell serving at time t
            n_col = f"neighbor_{curr_c}_rsrp"
            fut_c_rsrp = df.loc[fut_idx, n_col] if n_col in df.columns else curr_rsrp
            fut_serving = df.loc[fut_idx, "current_cell"]

            drop = curr_rsrp - fut_c_rsrp
            is_weak = (
                (fut_c_rsrp < self.weakening_rsrp_th) or 
                (drop >= self.weakening_delta_th) or 
                (fut_serving != curr_c and drop >= 2.0)
            )
            weakening_labels.append(int(is_weak))

        df["current_weakening_label"] = weakening_labels
        return df

    def generate_full_dataset(self) -> pd.DataFrame:
        """Generates the full multi-scenario synthetic dataset partitioned by trajectory."""
        scenarios_cfg = self.config.get("scenarios", {})
        all_dfs: List[pd.DataFrame] = []

        global_traj_id = 0
        for scenario_key, sc_info in scenarios_cfg.items():
            num_trajs = sc_info.get("num_trajectories", 20)
            noise_mult = sc_info.get("noise_multiplier", 1.0)
            drop_rate = sc_info.get("sample_drop_rate", 0.0)

            for i in range(num_trajs):
                traj_id = f"{scenario_key}_traj_{i:03d}"
                ue_id = f"UE_{global_traj_id:04d}"
                df_traj = self.generate_single_trajectory(
                    scenario=scenario_key,
                    trajectory_id=traj_id,
                    ue_id=ue_id,
                    seed=self.seed + global_traj_id * 31,
                    traj_index=i,
                    noise_multiplier=noise_mult,
                    sample_drop_rate=drop_rate,
                )
                if not df_traj.empty:
                    all_dfs.append(df_traj)
                global_traj_id += 1

        master_df = pd.concat(all_dfs, ignore_index=True)
        return master_df
