"""Synthetic User Activity and Natural Input Simulation Engine.

Generates realistic human-like mouse movements using Cubic Bézier curves,
keystroke jitter, window focus switching, and scroll events to deceive
malware performing human-interaction and mouse-dwell evasion checks.
"""

from __future__ import annotations
import dataclasses
import math
import random
from typing import List, Tuple


@dataclasses.dataclass
class MouseTrajectoryPoint:
    x: int
    y: int
    timestamp_offset_ms: int
    action: str  # MOVE, CLICK_LEFT, CLICK_RIGHT, DWELL, SCROLL


class UserSimulator:
    """Simulates natural user behavior within the guest virtual machine."""

    def __init__(self, screen_width: int = 1920, screen_height: int = 1080, seed: int = 42) -> None:
        self.screen_width = screen_width
        self.screen_height = screen_height
        self.rng = random.Random(seed)
        self.current_x = self.screen_width // 2
        self.current_y = self.screen_height // 2

    def generate_bezier_trajectory(
        self,
        start: Tuple[int, int],
        end: Tuple[int, int],
        duration_ms: int = 600,
        steps: int = 30,
    ) -> List[MouseTrajectoryPoint]:
        """Calculates a smooth cubic Bézier trajectory between two screen coordinates."""
        x0, y0 = start
        x3, y3 = end

        # Generate control points with human-like jitter
        ctrl_dist = math.hypot(x3 - x0, y3 - y0) / 3.0
        angle = math.atan2(y3 - y0, x3 - x0)

        jitter_angle1 = angle + self.rng.uniform(-0.5, 0.5)
        x1 = int(x0 + math.cos(jitter_angle1) * ctrl_dist)
        y1 = int(y0 + math.sin(jitter_angle1) * ctrl_dist)

        jitter_angle2 = angle + self.rng.uniform(-0.5, 0.5)
        x2 = int(x3 - math.cos(jitter_angle2) * ctrl_dist)
        y2 = int(y3 - math.sin(jitter_angle2) * ctrl_dist)

        trajectory: List[MouseTrajectoryPoint] = []
        for i in range(steps + 1):
            t = i / float(steps)
            # Cubic Bézier formula
            cx = (1 - t)**3 * x0 + 3 * (1 - t)**2 * t * x1 + 3 * (1 - t) * t**2 * x2 + t**3 * x3
            cy = (1 - t)**3 * y0 + 3 * (1 - t)**2 * t * y1 + 3 * (1 - t) * t**2 * y2 + t**3 * y3
            time_ms = int(t * duration_ms)

            action = "MOVE"
            if i == steps:
                action = "CLICK_LEFT" if self.rng.random() > 0.3 else "DWELL"

            trajectory.append(
                MouseTrajectoryPoint(
                    x=max(0, min(self.screen_width, int(cx))),
                    y=max(0, min(self.screen_height, int(cy))),
                    timestamp_offset_ms=time_ms,
                    action=action,
                )
            )

        self.current_x = trajectory[-1].x
        self.current_y = trajectory[-1].y
        return trajectory

    def generate_random_user_session(self, duration_seconds: int = 10) -> List[MouseTrajectoryPoint]:
        """Generates a continuous sequence of realistic user activity points."""
        total_points: List[MouseTrajectoryPoint] = []
        accumulated_time_ms = 0

        while accumulated_time_ms < (duration_seconds * 1000):
            target_x = self.rng.randint(50, self.screen_width - 50)
            target_y = self.rng.randint(50, self.screen_height - 50)
            move_duration = self.rng.randint(300, 900)

            traj = self.generate_bezier_trajectory(
                (self.current_x, self.current_y), (target_x, target_y), duration_ms=move_duration
            )
            for pt in traj:
                total_points.append(
                    MouseTrajectoryPoint(
                        x=pt.x,
                        y=pt.y,
                        timestamp_offset_ms=accumulated_time_ms + pt.timestamp_offset_ms,
                        action=pt.action,
                    )
                )

            accumulated_time_ms += move_duration
            # Add small dwell time
            dwell_ms = self.rng.randint(100, 400)
            accumulated_time_ms += dwell_ms

        return total_points
