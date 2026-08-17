"""Source-independent advisory filters.

Every upstream API has slightly different query semantics.  These helpers are
the final, local gate applied to normalized records so one UI query means the
same thing regardless of the source that produced a record.
"""

from __future__ import annotations

import re
from datetime import datetime, time, timedelta, timezone


_DATE_FILTER_RE = re.compile(
    r"^(?:(>=|>|<=|<))?(\d{4}-\d{2}-\d{2})(?:\.\.(\d{4}-\d{2}-\d{2}))?$"
)


def parse_timestamp(value: str | None) -> datetime | None:
    """Parse an ISO-8601 timestamp, accepting a plain YYYY-MM-DD date."""
    if not value:
        return None
    value = str(value).strip()
    try:
        if len(value) == 10:
            return datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except (TypeError, ValueError, OverflowError):
        return None


def valid_published_filter(value: str | None) -> bool:
    if value is None or value == "":
        return True
    if not isinstance(value, str):
        return False
    try:
        published_bounds(value)
    except (TypeError, ValueError):
        return False
    return True


def published_bounds(value: str | None) -> tuple[datetime | None, datetime | None]:
    """Return inclusive UTC bounds for the supported date-filter syntax."""
    if value is None or value == "":
        return None, None
    if not isinstance(value, str):
        raise ValueError(f"invalid published filter: {value}")
    match = _DATE_FILTER_RE.fullmatch(value.strip())
    if not match:
        raise ValueError(f"invalid published filter: {value}")

    op, first, second = match.groups()
    first_dt = parse_timestamp(first)
    second_dt = parse_timestamp(second) if second else None
    if first_dt is None or (second and second_dt is None):
        raise ValueError(f"invalid published filter: {value}")
    if op and second:
        raise ValueError(f"invalid published filter: {value}")
    if second_dt is not None and first_dt > second_dt:
        raise ValueError(f"invalid published filter: {value}")

    first_end = datetime.combine(first_dt.date(), time.max, tzinfo=timezone.utc)

    if second_dt is not None:
        return first_dt, datetime.combine(second_dt.date(), time.max, tzinfo=timezone.utc)
    if op == ">=":
        return first_dt, None
    if op == ">":
        if first_dt.date() == datetime.max.date():
            raise ValueError(f"published filter is outside the supported range: {value}")
        return first_end + timedelta(microseconds=1), None
    if op == "<=":
        return None, first_end
    if op == "<":
        if first_dt.date() == datetime.min.date():
            raise ValueError(f"published filter is outside the supported range: {value}")
        return None, first_dt - timedelta(microseconds=1)
    return first_dt, first_end


def matches_published(record: dict, value: str | None) -> bool:
    if not value:
        return True
    published = parse_timestamp(record.get("published_at"))
    if published is None:
        return False
    start, end = published_bounds(value)
    return (start is None or published >= start) and (end is None or published <= end)


def matches_package(record: dict, affects: str | None) -> bool:
    """Match the normalized, canonical package name exactly, case-insensitively."""
    if not affects:
        return True
    wanted = affects.strip().casefold()
    return any(
        str(package.get("name") or "").strip().casefold() == wanted
        for package in (record.get("packages") or [])
    )


def matches_severity(record: dict, severity: str | None) -> bool:
    return not severity or severity == "any" or record.get("severity") == severity


def matches_common_filters(
    record: dict,
    *,
    published: str | None = None,
    affects: str | None = None,
    severity: str | None = None,
) -> bool:
    return (
        matches_published(record, published)
        and matches_package(record, affects)
        and matches_severity(record, severity)
    )
