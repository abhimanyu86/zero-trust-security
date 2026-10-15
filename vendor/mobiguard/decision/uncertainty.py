import math
import numpy as np
from typing import Dict, List, Any
from dataclasses import dataclass


@dataclass
class UncertaintyResult:
    predicted_cell: str
    confidence: float            # Max calibrated probability (0.0 to 1.0)
    confidence_percentage: float # 0 to 100%
    entropy: float               # Shannon entropy (bits)
    normalized_entropy: float    # 0.0 (certain) to 1.0 (uniform random)
    uncertainty_level: str       # "LOW", "MEDIUM", "HIGH"
    margin: float                # Top-1 prob - Top-2 prob
    top_candidates: List[Dict[str, Any]]


class UncertaintyEstimator:
    """Calculates rigorous uncertainty and confidence metrics from calibrated model probabilities."""

    def __init__(self, high_uncertainty_entropy_th: float = 0.65, low_uncertainty_entropy_th: float = 0.35):
        self.high_entropy_th = high_uncertainty_entropy_th
        self.low_entropy_th = low_uncertainty_entropy_th

    def evaluate(self, probabilities: Dict[str, float]) -> UncertaintyResult:
        if not probabilities:
            return UncertaintyResult(
                predicted_cell="UNKNOWN",
                confidence=0.0,
                confidence_percentage=0.0,
                entropy=0.0,
                normalized_entropy=1.0,
                uncertainty_level="HIGH",
                margin=0.0,
                top_candidates=[],
            )

        probs = list(probabilities.values())
        k = len(probs)
        max_possible_entropy = math.log2(k) if k > 1 else 1.0

        # Calculate Shannon entropy: H = -sum(p * log2(p))
        entropy = 0.0
        for p in probs:
            if p > 1e-12:
                entropy -= p * math.log2(p)

        normalized_entropy = entropy / max_possible_entropy if max_possible_entropy > 0 else 0.0
        normalized_entropy = float(np.clip(normalized_entropy, 0.0, 1.0))

        # Sort candidate cells by probability
        sorted_candidates = sorted(probabilities.items(), key=lambda x: x[1], reverse=True)
        top_cell, top_prob = sorted_candidates[0]
        second_prob = sorted_candidates[1][1] if len(sorted_candidates) > 1 else 0.0
        margin = top_prob - second_prob

        # Uncertainty Level Categorization
        if normalized_entropy < self.low_entropy_th and top_prob >= 0.75:
            uncertainty_level = "LOW"
        elif normalized_entropy >= self.high_entropy_th or top_prob < 0.60:
            uncertainty_level = "HIGH"
        else:
            uncertainty_level = "MEDIUM"

        top_candidates_list = [
            {"cell": cell, "probability": round(prob, 4), "pct": round(prob * 100, 1)}
            for cell, prob in sorted_candidates
        ]

        return UncertaintyResult(
            predicted_cell=top_cell,
            confidence=round(top_prob, 4),
            confidence_percentage=round(top_prob * 100, 1),
            entropy=round(entropy, 4),
            normalized_entropy=round(normalized_entropy, 4),
            uncertainty_level=uncertainty_level,
            margin=round(margin, 4),
            top_candidates=top_candidates_list,
        )
