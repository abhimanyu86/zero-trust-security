from enum import Enum
from typing import Dict, Any, Optional, List
from dataclasses import dataclass

from .uncertainty import UncertaintyResult
from .divergence import DivergenceReport, RouteDivergenceDetector
from .guardrails import PolicyGuardrails


class MobilityState(str, Enum):
    NORMAL = "NORMAL"
    PREDICTING = "PREDICTING"
    PROACTIVE_CANDIDATE = "PROACTIVE_CANDIDATE"
    MONITOR_RECHECK = "MONITOR_RECHECK"
    HOLD_RECHECK = "HOLD_RECHECK"
    ROUTE_DIVERGENCE = "ROUTE_DIVERGENCE"
    RE_EVALUATING = "RE_EVALUATING"
    UPDATED_CANDIDATE = "UPDATED_CANDIDATE"
    OBSERVED = "OBSERVED"
    COMPLETED = "COMPLETED"


@dataclass
class PolicyDecision:
    action: str                  # "PROACTIVE_CANDIDATE", "MONITOR_RECHECK", "HOLD_RECHECK", "RE_EVALUATING"
    candidate_cell: Optional[str]
    state: MobilityState
    reason: str
    confidence: float
    uncertainty_level: str
    weakness_risk: float
    divergence_detected: bool
    is_proactive_candidate_selected: bool


class MobilityPolicyEngine:
    """Decoupled policy engine translating predictions, uncertainty, risk, and divergence into safe network actions."""

    def __init__(
        self,
        divergence_detector: RouteDivergenceDetector,
        guardrails: Optional[PolicyGuardrails] = None,
        conf_high_th: float = 0.80,
        conf_med_th: float = 0.60,
        weakness_risk_th: float = 0.55,
    ):
        self.divergence_detector = divergence_detector
        self.guardrails = guardrails or PolicyGuardrails()
        self.conf_high_th = conf_high_th
        self.conf_med_th = conf_med_th
        self.weakness_risk_th = weakness_risk_th

        # Policy session state
        self.active_proactive_candidate: Optional[str] = None
        self.current_state = MobilityState.NORMAL
        self.prior_telemetry: Optional[Dict[str, Any]] = None

    def reset(self):
        self.active_proactive_candidate = None
        self.current_state = MobilityState.NORMAL
        self.prior_telemetry = None
        self.guardrails.reset()

    def evaluate(
        self,
        current_telemetry: Dict[str, Any],
        inference_result: Dict[str, Any],
        uncertainty_result: UncertaintyResult,
        step_index: int = 0,
    ) -> PolicyDecision:
        current_cell = current_telemetry.get("current_cell", "UNKNOWN")
        predicted_cell = uncertainty_result.predicted_cell
        confidence = uncertainty_result.confidence
        weakness_risk = inference_result.get("weakness_risk", 0.0)
        quality = inference_result.get("telemetry_quality", {})
        timestamp = current_telemetry.get("timestamp", 0.0)

        # 1. Check Route Divergence against active proactive candidate
        divergence_report = self.divergence_detector.detect(
            current_telemetry=current_telemetry,
            active_candidate_cell=self.active_proactive_candidate,
            prior_telemetry=self.prior_telemetry,
        )

        # Save telemetry for next step's differential calculation
        self.prior_telemetry = current_telemetry.copy()

        # Route Divergence Adaptation Handler
        if divergence_report.divergence_detected:
            self.current_state = MobilityState.ROUTE_DIVERGENCE
            old_cand = self.active_proactive_candidate
            self.active_proactive_candidate = None  # Invalidate old candidate

            # When route divergence occurs, re-evaluate with current top candidate
            new_target = predicted_cell
            if divergence_report.emerging_candidate:
                new_target = divergence_report.emerging_candidate

            self.current_state = MobilityState.UPDATED_CANDIDATE
            self.active_proactive_candidate = new_target

            reason = (
                f"ROUTE DIVERGENCE DETECTED: {divergence_report.reason} "
                f"Prediction of {old_cand} invalidated. Re-evaluating -> Updated candidate: {new_target} "
                f"(Conf: {uncertainty_result.confidence_percentage}%)."
            )

            return PolicyDecision(
                action="RE_EVALUATING",
                candidate_cell=new_target,
                state=MobilityState.UPDATED_CANDIDATE,
                reason=reason,
                confidence=confidence,
                uncertainty_level=uncertainty_result.uncertainty_level,
                weakness_risk=weakness_risk,
                divergence_detected=True,
                is_proactive_candidate_selected=True,
            )

        # 2. Telemetry Quality Gate Check
        telemetry_ok, quality_msg = self.guardrails.check_telemetry_gate(quality)
        if not telemetry_ok:
            self.current_state = MobilityState.HOLD_RECHECK
            return PolicyDecision(
                action="HOLD_RECHECK",
                candidate_cell=None,
                state=MobilityState.HOLD_RECHECK,
                reason=quality_msg,
                confidence=confidence,
                uncertainty_level=uncertainty_result.uncertainty_level,
                weakness_risk=weakness_risk,
                divergence_detected=False,
                is_proactive_candidate_selected=False,
            )

        # 3. If predicted cell is the SAME as current serving cell, no proactive handover needed
        if predicted_cell == current_cell:
            self.current_state = MobilityState.MONITOR_RECHECK
            self.active_proactive_candidate = None
            return PolicyDecision(
                action="MONITOR_RECHECK",
                candidate_cell=current_cell,
                state=MobilityState.MONITOR_RECHECK,
                reason=f"Continuing in current {current_cell} coverage (Confidence: {uncertainty_result.confidence_percentage}%).",
                confidence=confidence,
                uncertainty_level=uncertainty_result.uncertainty_level,
                weakness_risk=weakness_risk,
                divergence_detected=False,
                is_proactive_candidate_selected=False,
            )

        # 4. Standard Decision Rules based on Confidence, Weakening Risk, and Uncertainty
        if confidence >= self.conf_high_th and weakness_risk >= self.weakness_risk_th:
            # Check guardrails: cooldown & budget
            cooldown_ok, cool_msg = self.guardrails.check_cooldown(step_index, predicted_cell)
            budget_ok, budg_msg = self.guardrails.check_action_budget(timestamp)

            if cooldown_ok and budget_ok:
                self.current_state = MobilityState.PROACTIVE_CANDIDATE
                self.active_proactive_candidate = predicted_cell
                self.guardrails.record_proactive_action(step_index, timestamp, predicted_cell)
                
                reason = (
                    f"PROACTIVE CANDIDATE: High-confidence next cell {predicted_cell} ({uncertainty_result.confidence_percentage}%) "
                    f"with imminent serving-cell weakening risk ({weakness_risk * 100:.1f}%). Uncertainty: {uncertainty_result.uncertainty_level}."
                )
                return PolicyDecision(
                    action="PROACTIVE_CANDIDATE",
                    candidate_cell=predicted_cell,
                    state=MobilityState.PROACTIVE_CANDIDATE,
                    reason=reason,
                    confidence=confidence,
                    uncertainty_level=uncertainty_result.uncertainty_level,
                    weakness_risk=weakness_risk,
                    divergence_detected=False,
                    is_proactive_candidate_selected=True,
                )
            else:
                guard_reason = cool_msg if not cooldown_ok else budg_msg
                self.current_state = MobilityState.MONITOR_RECHECK
                return PolicyDecision(
                    action="MONITOR_RECHECK",
                    candidate_cell=predicted_cell,
                    state=MobilityState.MONITOR_RECHECK,
                    reason=f"Proactive preparation gated by guardrail: {guard_reason}",
                    confidence=confidence,
                    uncertainty_level=uncertainty_result.uncertainty_level,
                    weakness_risk=weakness_risk,
                    divergence_detected=False,
                    is_proactive_candidate_selected=False,
                )

        elif confidence >= self.conf_med_th or (confidence >= self.conf_high_th and weakness_risk < self.weakness_risk_th):
            self.current_state = MobilityState.MONITOR_RECHECK
            if weakness_risk < self.weakness_risk_th:
                reason = (
                    f"MONITOR_RECHECK: Next cell candidate {predicted_cell} identified ({uncertainty_result.confidence_percentage}%), "
                    f"but serving {current_cell} signal is still stable (Weakening risk: {weakness_risk * 100:.1f}%). No urgent handover."
                )
            else:
                reason = (
                    f"MONITOR_RECHECK: Moderate confidence ({uncertainty_result.confidence_percentage}%). "
                    f"Monitoring radio trends before committing resources."
                )

            return PolicyDecision(
                action="MONITOR_RECHECK",
                candidate_cell=predicted_cell,
                state=MobilityState.MONITOR_RECHECK,
                reason=reason,
                confidence=confidence,
                uncertainty_level=uncertainty_result.uncertainty_level,
                weakness_risk=weakness_risk,
                divergence_detected=False,
                is_proactive_candidate_selected=False,
            )

        else:
            # Low confidence or High Entropy
            self.current_state = MobilityState.HOLD_RECHECK
            self.active_proactive_candidate = None
            reason = (
                f"HOLD_RECHECK: High uncertainty detected (Confidence: {uncertainty_result.confidence_percentage}%, "
                f"Entropy: {uncertainty_result.normalized_entropy:.2f}). Holding proactive allocation to prevent ping-pong."
            )
            return PolicyDecision(
                action="HOLD_RECHECK",
                candidate_cell=None,
                state=MobilityState.HOLD_RECHECK,
                reason=reason,
                confidence=confidence,
                uncertainty_level=uncertainty_result.uncertainty_level,
                weakness_risk=weakness_risk,
                divergence_detected=False,
                is_proactive_candidate_selected=False,
            )
