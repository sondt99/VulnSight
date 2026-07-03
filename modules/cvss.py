"""CVSS v3.x base-score computation.

OSV records usually carry only a CVSS vector string (no numeric score), so we
compute the v3.0/3.1 base score ourselves from the vector's base metrics and
derive a qualitative severity from it.

Rounding uses the Roundup() algorithm from the CVSS v3.1 specification
(Appendix A) rather than a naive `math.ceil(x * 10) / 10`: the naive form is
sensitive to floating-point artifacts (e.g. a score computed as
4.000000000000001 would round up to 4.1 instead of 4.0), while the spec
algorithm works on an integer scaled by 10**5 and is exact.

Severity thresholds follow the CVSS qualitative rating scale: >=9.0 critical,
>=7.0 high, >=4.0 medium, >0 low, else (or no score) unknown.
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
