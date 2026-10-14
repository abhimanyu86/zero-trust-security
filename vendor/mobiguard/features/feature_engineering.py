import math
import numpy as np
import pandas as pd
from typing import List, Dict, Any, Optional, Tuple


class FeaturePipeline:
    """Reusable feature transformation pipeline for both offline training and online streaming inference."""

    CELL_LIST = ["Cell_A", "Cell_B", "Cell_C", "Cell_D", "Cell_E", "Cell_F"]

    def __init__(self, cell_list: Optional[List[str]] = None, window_size: int = 3):
        self.cells = cell_list or self.CELL_LIST
        self.window_size = window_size
        self.cell_to_idx = {c: i for i, c in enumerate(self.cells)}

    @property
    def feature_columns(self) -> List[str]:
        cols = [
            "current_rsrp_dbm",
            "current_sinr_db",
            "delta_rsrp",
            "delta_sinr",
            "rolling_rsrp_slope",
            "rolling_sinr_slope",
            "speed_mps",
            "speed_bucket",
            "sin_heading",
            "cos_heading",
            "heading_change_deg",
            "current_dwell_s",
            "current_cell_idx",
            "prev_cell_1_idx",
        ]
        # Relative metrics per candidate cell
        for cid in self.cells:
            cols.append(f"rel_rsrp_{cid}")
            cols.append(f"rel_sinr_{cid}")
            cols.append(f"is_top_neigh_{cid}")

        return cols

    def _encode_cell(self, cell_name: str) -> int:
        return self.cell_to_idx.get(cell_name, -1)

    def extract_batch_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Transforms an entire trajectory DataFrame with grouped rolling calculations."""
        df = df.copy()

        # Sort values chronologically per trajectory
        if "trajectory_id" in df.columns:
            df = df.sort_values(by=["trajectory_id", "step_index"]).reset_index(drop=True)
            grouped = df.groupby("trajectory_id")
            
            # Lag & Rolling features within trajectory
            df["prev_rsrp"] = grouped["current_rsrp_dbm"].shift(1)
            df["prev_sinr"] = grouped["current_sinr_db"].shift(1)
            df["delta_rsrp"] = (df["current_rsrp_dbm"] - df["prev_rsrp"]).fillna(0.0)
            df["delta_sinr"] = (df["current_sinr_db"] - df["prev_sinr"]).fillna(0.0)

            # Rolling slopes over window
            df["rolling_rsrp_slope"] = (
                grouped["current_rsrp_dbm"].diff(self.window_size).fillna(0.0) / float(self.window_size)
            )
            df["rolling_sinr_slope"] = (
                grouped["current_sinr_db"].diff(self.window_size).fillna(0.0) / float(self.window_size)
            )
        else:
            df["prev_rsrp"] = df["current_rsrp_dbm"].shift(1)
            df["prev_sinr"] = df["current_sinr_db"].shift(1)
            df["delta_rsrp"] = (df["current_rsrp_dbm"] - df["prev_rsrp"]).fillna(0.0)
            df["delta_sinr"] = (df["current_sinr_db"] - df["prev_sinr"]).fillna(0.0)
            df["rolling_rsrp_slope"] = df["current_rsrp_dbm"].diff(self.window_size).fillna(0.0) / float(self.window_size)
            df["rolling_sinr_slope"] = df["current_sinr_db"].diff(self.window_size).fillna(0.0) / float(self.window_size)

        # Speed bucket
        # 0: < 10 m/s (pedestrian/slow urban), 1: 10-25 m/s (suburban/arterial), 2: > 25 m/s (highway/rail)
        df["speed_bucket"] = pd.cut(
            df["speed_mps"],
            bins=[-np.inf, 10.0, 25.0, np.inf],
            labels=[0, 1, 2],
        ).astype(int)

        # Circular trigonometry for heading
        rads = np.radians(df["heading_deg"])
        df["sin_heading"] = np.sin(rads)
        df["cos_heading"] = np.cos(rads)
        df["heading_change_deg"] = df["heading_change_deg"].fillna(0.0)

        # Cell index encodings
        df["current_cell_idx"] = df["current_cell"].map(self._encode_cell)
        df["prev_cell_1_idx"] = df["previous_cell_1"].map(self._encode_cell)

        # Relative candidate neighbour features
        neigh_rsrp_cols = [f"neighbor_{c}_rsrp" for c in self.cells if f"neighbor_{c}_rsrp" in df.columns]
        
        for cid in self.cells:
            n_rsrp_col = f"neighbor_{cid}_rsrp"
            n_sinr_col = f"neighbor_{cid}_sinr"

            if n_rsrp_col in df.columns:
                df[f"rel_rsrp_{cid}"] = df[n_rsrp_col] - df["current_rsrp_dbm"]
            else:
                df[f"rel_rsrp_{cid}"] = -50.0

            if n_sinr_col in df.columns:
                df[f"rel_sinr_{cid}"] = df[n_sinr_col] - df["current_sinr_db"]
            else:
                df[f"rel_sinr_{cid}"] = -20.0

            # Rank / strongest flag
            if neigh_rsrp_cols:
                is_max = df[n_rsrp_col] == df[neigh_rsrp_cols].max(axis=1)
                df[f"is_top_neigh_{cid}"] = is_max.astype(int)
            else:
                df[f"is_top_neigh_{cid}"] = 0

        # Fill any remaining NaNs cleanly
        return df

    def extract_single_step(
        self,
        current_telemetry: Dict[str, Any],
        recent_history: Optional[List[Dict[str, Any]]] = None,
    ) -> pd.DataFrame:
        """Transforms a single real-time streaming telemetry packet using recent rolling history."""
        hist = recent_history or []
        combined_records = list(hist) + [current_telemetry]
        temp_df = pd.DataFrame(combined_records)
        feat_df = self.extract_batch_features(temp_df)
        
        # Return the feature row corresponding to the latest timestamp
        latest_row = feat_df.iloc[[-1]][self.feature_columns]
        return latest_row
