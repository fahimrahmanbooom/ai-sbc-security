"""Time helpers — replace deprecated datetime.utcnow()."""
from datetime import datetime, timezone


def utcnow() -> datetime:
    """
    Drop-in replacement for the deprecated datetime.utcnow().

    Returns a *naive* datetime in UTC (tzinfo=None) to remain compatible
    with SQLAlchemy DateTime columns that don't accept aware datetimes,
    and with the rest of the codebase which assumes naive UTC throughout.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)
