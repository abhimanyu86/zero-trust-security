from dataclasses import dataclass
from typing import Dict, List, Any, Optional
import pandas as pd
import numpy as np


@dataclass
class TelemetryQualityReport:
    is_valid: bool
    quality_score: float  # 0.0 (unusable) to 1.0 (perfect)
    status: str           # "HEALTHY", "DEGRADED", "CRITICAL"
    issues: List[str]


class TelemetryValidator:
    """Validates real-time and batched telemetry against telecom physical guardrails."""

    def __init__(
        self,
        min_sinr_db: float = -5.0,
        max_stale_seconds: float = 4.0,
        max_speed_mps: float = 70.0,
    ):
        self.min_sinr_db = min_sinr_db
        self.max_stale_seconds = max_stale_seconds
        self.max_speed_mps = max_speed_mps

    def validate_record(self, record: Dict[str, Any], last_timestamp: Optional[float] = None) -> TelemetryQualityReport:
        issues = []
        score = 1.0

        # 1. RSRP check
        rsrp = record.get("current_rsrp_dbm", None)
        if rsrp is None or pd.isna(rsrp):
            issues.append("Missing serving RSRP")
            score -= 0.4
        elif rsrp < -135.0 or rsrp > -40.0:
            issues.append(f"Unphysical RSRP value: {rsrp} dBm")
            score -= 0.3

        # 2. SINR check
        sinr = record.get("current_sinr_db", None)
        if sinr is None or pd.isna(sinr):
            issues.append("Missing serving SINR")
            score -= 0.3
        elif sinr < self.min_sinr_db:
            issues.append(f"Low SINR near noise floor: {sinr} dB")
            score -= 0.2

        # 3. Speed bounds
        speed = record.get("speed_mps", None)
        if speed is None or pd.isna(speed):
            issues.append("Missing speed telemetry")
            score -= 0.2
        elif speed < 0.0 or speed > self.max_speed_mps:
            issues.append(f"Abnormal speed reading: {speed} m/s")
            score -= 0.4

        # 4. Telemetry staleness
        ts = record.get("timestamp", None)
        if ts is not None and last_timestamp is not None:
            delta_t = ts - last_timestamp
            if delta_t < 0:
                issues.append("Out-of-order timestamp detected")
                score -= 0.5
            elif delta_t > self.max_stale_seconds:
                issues.append(f"Stale telemetry gap: {delta_t:.1f}s")
                score -= 0.35

        score = max(0.0, min(1.0, score))
        if score >= 0.8:
            status = "HEALTHY"
            is_valid = True
        elif score >= 0.4:
            status = "DEGRADED"
            is_valid = True
        else:
            status = "CRITICAL"
            is_valid = False

        return TelemetryQualityReport(
            is_valid=is_valid,
            quality_score=round(score, 2),
            status=status,
            issues=issues,
        )

    def validate_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """Adds data quality audit columns to training or validation DataFrame."""
        validated_df = df.copy()
        
        # Check nulls
        validated_df["is_rsrp_valid"] = ~validated_df["current_rsrp_dbm"].isna() & (validated_df["current_rsrp_dbm"] >= -135.0)
        validated_df["is_speed_valid"] = ~validated_df["speed_mps"].isna() & (validated_df["speed_mps"] >= 0.0) & (validated_df["speed_mps"] <= self.max_speed_mps)
        
        # Overall quality flag
        validated_df["telemetry_quality_ok"] = validated_df["is_rsrp_valid"] & validated_df["is_speed_valid"]
        return validated_df
