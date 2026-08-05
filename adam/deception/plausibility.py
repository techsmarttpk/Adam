"""
Plausibility scoring — every mutation must self-report how likely it is
to be detected as synthetic (ARCHITECTURE.md §2.4). This is not decoration:
hiding a detectable mutation would invalidate the paper's results, so the
report is required to surface low-plausibility mutations rather than bury
them in a success count.

Keep these as small, composable, pure functions — plausibility.py has no
business logic of its own, just shared arithmetic that primitives call into.
"""

from __future__ import annotations

# Below this, session_metrics should flag the mutation for the report
# (config: deception.plausibility_warn_below in default.toml, §12.2).
WARN_BELOW = 0.50


def score_timestamp_consistency(is_post_boot_write: bool) -> float:
    """A registry/file timestamp written mid-session, after boot, is a tell."""
    return 0.6 if is_post_boot_write else 0.95


def score_naming_consistency(matches_locale_convention: bool) -> float:
    return 0.9 if matches_locale_convention else 0.4


def combine(*scores: float) -> float:
    """Conservative combination: plausibility is only as good as the weakest tell."""
    if not scores:
        return 1.0
    return min(scores)
