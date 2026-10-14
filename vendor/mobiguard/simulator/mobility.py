import math
import numpy as np
from typing import List, Tuple, Dict, Any


class MobilitySimulator:
    """Simulates realistic kinematic movement of a User Equipment (UE) along waypoints."""

    def __init__(
        self,
        waypoints: List[Tuple[float, float, float]],
        dt: float = 1.0,
        acceleration_limit_mps2: float = 3.5,
    ):
        self.waypoints = waypoints
        self.dt = dt
        self.accel_limit = acceleration_limit_mps2

        # State variables
        self.current_idx = 0
        self.x = waypoints[0][0]
        self.y = waypoints[0][1]
        self.speed = waypoints[0][2]
        self.heading_deg = 0.0
        self.total_distance = 0.0
        self.time = 0.0
        self.step_count = 0

        if len(waypoints) > 1:
            dx = waypoints[1][0] - waypoints[0][0]
            dy = waypoints[1][1] - waypoints[0][1]
            self.heading_deg = math.degrees(math.atan2(dy, dx)) % 360.0

    def step(self) -> Dict[str, float]:
        """Advance the kinematic simulation by dt seconds."""
        self.step_count += 1
        if self.current_idx >= len(self.waypoints) - 1 or self.step_count > 300:
            # End of trajectory reached
            return {
                "x": round(self.x, 2),
                "y": round(self.y, 2),
                "speed_mps": 0.0,
                "heading_deg": round(self.heading_deg, 2),
                "heading_change_deg": 0.0,
                "is_finished": True,
            }

        target_wp = self.waypoints[self.current_idx + 1]
        tx, ty, target_speed = target_wp

        dx = tx - self.x
        dy = ty - self.y
        dist_to_target = math.hypot(dx, dy)

        # Desired heading
        desired_heading = math.degrees(math.atan2(dy, dx)) % 360.0
        heading_diff = (desired_heading - self.heading_deg + 180.0) % 360.0 - 180.0

        # Smooth turn rate
        max_turn_deg_per_sec = 25.0 * self.dt
        actual_turn = np.clip(heading_diff, -max_turn_deg_per_sec, max_turn_deg_per_sec)
        new_heading = (self.heading_deg + actual_turn) % 360.0

        # Smooth speed adaptation
        speed_diff = target_speed - self.speed
        actual_accel = np.clip(speed_diff / self.dt, -self.accel_limit, self.accel_limit)
        new_speed = max(1.0 if dist_to_target > 20.0 else 0.0, self.speed + actual_accel * self.dt)

        step_distance = max(new_speed * self.dt, 1.0 if dist_to_target > 10.0 else 0.0)

        if dist_to_target <= max(step_distance, 15.0):
            # Reached waypoint
            self.x = tx
            self.y = ty
            self.current_idx += 1
            self.speed = target_speed
            self.heading_deg = desired_heading
            heading_change = float(actual_turn)
        else:
            # Move along current direction
            rad = math.radians(new_heading)
            self.x += step_distance * math.cos(rad)
            self.y += step_distance * math.sin(rad)
            heading_change = float(new_heading - self.heading_deg)
            self.heading_deg = new_heading
            self.speed = new_speed

        self.total_distance += step_distance
        self.time += self.dt

        return {
            "x": round(self.x, 2),
            "y": round(self.y, 2),
            "speed_mps": round(self.speed, 2),
            "heading_deg": round(self.heading_deg, 2),
            "heading_change_deg": round(heading_change, 2),
            "is_finished": False,
        }
