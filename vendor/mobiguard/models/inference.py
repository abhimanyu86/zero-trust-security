import time
import pandas as pd
from typing import Dict, Any, Optional, List, Tuple
from features.feature_engineering import FeaturePipeline
from features.validation import TelemetryValidator, TelemetryQualityReport
from .next_cell_model import NextCellPredictor
from .weakness_model import WeaknessPredictor


class MobilityInferenceEngine:
    """End-to-end inference coordinator for real-time mobility intelligence."""

    def __init__(
        self,
        next_cell_model: NextCellPredictor,
        weakness_model: WeaknessPredictor,
        feature_pipeline: Optional[FeaturePipeline] = None,
        validator: Optional[TelemetryValidator] = None,
    ):
        self.next_cell_model = next_cell_model
        self.weakness_model = weakness_model
        self.feature_pipeline = feature_pipeline or FeaturePipeline()
        self.validator = validator or TelemetryValidator()

    def run_inference(
        self,
        current_telemetry: Dict[str, Any],
        recent_history: Optional[List[Dict[str, Any]]] = None,
        last_timestamp: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Executes full inference pipeline on single telemetry observation."""
        t_start = time.perf_counter()

        # 1. Telemetry Quality Gate
        quality_report = self.validator.validate_record(current_telemetry, last_timestamp=last_timestamp)

        # 2. Extract Features
        feat_df = self.feature_pipeline.extract_single_step(current_telemetry, recent_history)

        # 3. Predict Next Cell Probabilities
        prob_dict = self.next_cell_model.predict_probabilities(feat_df)
        predicted_cell = max(prob_dict, key=prob_dict.get)

        # 4. Predict Current Cell Weakening Risk
        weakness_risk = self.weakness_model.predict_weakness_risk(feat_df)

        latency_ms = (time.perf_counter() - t_start) * 1000.0

        return {
            "predicted_next_cell": predicted_cell,
            "probabilities": prob_dict,
            "weakness_risk": round(weakness_risk, 4),
            "telemetry_quality": {
                "is_valid": quality_report.is_valid,
                "score": quality_report.quality_score,
                "status": quality_report.status,
                "issues": quality_report.issues,
            },
            "latency_ms": round(latency_ms, 2),
        }
