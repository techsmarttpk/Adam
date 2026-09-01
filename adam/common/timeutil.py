from datetime import datetime, timezone

def now_utc() -> datetime:
    """Returns current datetime with explicit UTC timezone."""
    return datetime.now(timezone.utc)

def to_iso(dt: datetime) -> str:
    """Serializes datetime to ISO-8601 string representation."""
    return dt.isoformat()

def parse_iso(s: str) -> datetime:
    """Parses ISO-8601 string, correcting Zulu 'Z' designations to UTC offset."""
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return datetime.fromisoformat(s)
