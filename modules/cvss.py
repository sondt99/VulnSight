"""CVSS v3.x base-score computation and v4.0 rough estimation.

OSV records usually carry only a CVSS vector string (no numeric score), so we
compute the v3.0/3.1 base score ourselves from the vector's base metrics and
derive a qualitative severity from it.

For CVSS v4.0, the scoring algorithm uses a complex ~200-line lookup table
that is impractical to reimplement.  ``base_score_v4()`` provides a simplified
approximation from attack-surface and impact metrics; callers should always
prefer a pre-computed score (e.g. from NVD) when one is available.

Rounding uses the Roundup() algorithm from the CVSS v3.1 specification
(Appendix A) rather than a naive `math.ceil(x * 10) / 10`: the naive form is
sensitive to floating-point artifacts (e.g. a score computed as
4.000000000000001 would round up to 4.1 instead of 4.0), while the spec
algorithm works on an integer scaled by 10**5 and is exact.

Severity thresholds follow the CVSS qualitative rating scale: >=9.0 critical,
>=7.0 high, >=4.0 medium, >0 low, else (or no score) unknown.  CVSS v4.0 uses
the same thresholds.
"""

from __future__ import annotations

_CVSS_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_CVSS_PR = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.5},
}


def _roundup(x: float) -> float:
    """Roundup() as defined by the CVSS v3.1 spec, Appendix A."""
    i = int(round(x * 100000))
    if i % 10000 == 0:
        return i / 100000.0
    return (i // 10000 + 1) / 10.0


def base_score(vector: str) -> float | None:
    """Compute CVSS v3.0/3.1 base score from a vector string, else None."""
    if not vector or "CVSS:3" not in vector:
        return None
    m = dict(kv.split(":", 1) for kv in vector.split("/") if ":" in kv and not kv.startswith("CVSS"))
    try:
        scope = m["S"]
        av, ac, ui = _CVSS_W["AV"][m["AV"]], _CVSS_W["AC"][m["AC"]], _CVSS_W["UI"][m["UI"]]
        pr = _CVSS_PR[scope][m["PR"]]
        c, i, a = _CVSS_W["C"][m["C"]], _CVSS_W["I"][m["I"]], _CVSS_W["A"][m["A"]]
    except KeyError:
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    if impact <= 0:
        return 0.0
    expl = 8.22 * av * ac * pr * ui
    raw = (impact + expl) if scope == "U" else 1.08 * (impact + expl)
    return _roundup(min(raw, 10.0))


# ---------------------------------------------------------------------------
# CVSS v4.0 rough estimation
# ---------------------------------------------------------------------------

# Exploitability lookup keyed by (Attack Vector, Attack Complexity).
# Values are calibrated so that the exploitability component plus the impact
# component land in the correct qualitative severity bucket for common cases.
_V4_EXPLOITABILITY: dict[tuple[str, str], float] = {
    ("N", "L"): 3.9,  ("N", "H"): 2.2,
    ("A", "L"): 2.8,  ("A", "H"): 1.5,
    ("L", "L"): 2.0,  ("L", "H"): 1.0,
    ("P", "L"): 1.0,  ("P", "H"): 0.5,
}
_V4_IMPACT: dict[str, float] = {"H": 1.0, "L": 0.5, "N": 0.0}


def base_score_v4(vector: str) -> float | None:
    """Rough CVSS v4.0 base-score estimate from AV, AC, and impact metrics.

    Full v4.0 scoring requires a complex lookup table; this function provides
    a simplified approximation for severity bucketing when no pre-computed
    score (e.g. from NVD) is available.  Always prefer the NVD-provided score
    when present.

    Returns ``None`` for non-v4 vectors or vectors missing required metrics.
    """
    if not vector or "CVSS:4.0/" not in vector:
        return None
    m: dict[str, str] = {}
    for kv in vector.split("/"):
        if ":" in kv and not kv.startswith("CVSS"):
            k, v = kv.split(":", 1)
            m[k] = v

    av = m.get("AV")
    ac = m.get("AC")
    if not av or not ac or (av, ac) not in _V4_EXPLOITABILITY:
        return None

    expl = _V4_EXPLOITABILITY[(av, ac)]

    # Highest severity across all six CIA sub-metrics (vulnerable + subsequent).
    impacts = [
        _V4_IMPACT.get(m.get(k, "N"), 0.0)
        for k in ("VC", "VI", "VA", "SC", "SI", "SA")
    ]
    impact = max(impacts)

    if impact == 0.0:
        return 0.0

    raw = min(expl + 6.1 * impact, 10.0)
    return round(raw, 1)


def severity_from_score(score: float | None) -> str:
    """Map a CVSS base score to its qualitative severity bucket."""
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "unknown"
