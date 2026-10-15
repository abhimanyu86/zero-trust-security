from typing import List, Dict, Any, Optional, Tuple
from collections import deque


class PolicyGuardrails:
    """Enforces operational safety constraints, telemetry quality gates, and action budgeting."""

    def __init__(
        self,
        hysteresis_steps: int = 2,
        max_actions_per_window: int = 4,
        action_window_seconds: float = 60.0,
        advisory_mode_only: bool = True,
    ):
        self.hysteresis_steps = hysteresis_steps
        self.max_actions = max_actions_per_window
        self.window_seconds = action_window_seconds
        self.advisory_mode = advisory_mode_only

        # State tracking
        self.last_action_step = -999
        self.last_proactive_candidate: Optional[str] = None
        self.action_timestamps: deque = deque()

    def reset(self):
        self.last_action_step = -999
        self.last_proactive_candidate = None
        self.action_timestamps.clear()

    def check_telemetry_gate(self, quality_report_dict: Dict[str, Any]) -> Tuple[bool, str]:
        if not quality_report_dict.get("is_valid", True):
            issues = quality_report_dict.get("issues", ["Critical telemetry flaw"])
            return False, f"Telemetry Gate Blocked: {', '.join(issues)}"
        return True, "Telemetry Gate Passed (Quality OK)"

    def check_cooldown(self, current_step: int, candidate_cell: str) -> Tuple[bool, str]:
        if candidate_cell != self.last_proactive_candidate:
            steps_since = current_step - self.last_action_step
            if steps_since < self.hysteresis_steps:
                return False, f"Cooldown Active: Candidate change suppressed for {self.hysteresis_steps - steps_since} more steps."
        return True, "Cooldown Cleared"

    def check_action_budget(self, current_timestamp: float) -> Tuple[bool, str]:
        # Purge timestamps older than window
        while self.action_timestamps and (current_timestamp - self.action_timestamps[0] > self.window_seconds):
            self.action_timestamps.popleft()

        if len(self.action_timestamps) >= self.max_actions:
            return False, f"Action Budget Exceeded ({self.max_actions} actions in {self.window_seconds}s window)."
        return True, "Action Budget Available"

    def record_proactive_action(self, current_step: int, current_timestamp: float, candidate_cell: str):
        self.last_action_step = current_step
        self.last_proactive_candidate = candidate_cell
        self.action_timestamps.append(current_timestamp)
