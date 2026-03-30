from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any


_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


@dataclass(frozen=True)
class CVEData:
    cve_id: str
    title: str
    description: str
    cvss_score: float | None
    severity_label: str | None
    references: list[str]
    sources: list[str]


def _http_json(url: str, timeout_s: int = 12) -> dict[str, Any]:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "VulnReport/1.0 (edu project)",
            "Accept": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout_s) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
    return json.loads(raw)


def _severity_from_score(score: float | None) -> str | None:
    if score is None:
        return None
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"


def fetch_cve_data(cve_id: str) -> CVEData | None:
    """
    Best-effort CVE fetch.

    - Primary data: MITRE CVE Services (cveawg) JSON (CVERecord v5.x)
    - Always returns links to cve.org + cvedetails for traceability.
    """
    if not cve_id:
        return None
    cve_id = cve_id.strip().upper()
    if not _CVE_RE.match(cve_id):
        return None

    sources = [
        f"https://www.cve.org/CVERecord?id={cve_id}",
        f"https://www.cvedetails.com/cve/{cve_id}/",
        f"https://cveawg.mitre.org/api/cve/{cve_id}",
    ]

    try:
        record = _http_json(f"https://cveawg.mitre.org/api/cve/{cve_id}")
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return CVEData(
            cve_id=cve_id,
            title=cve_id,
            description="",
            cvss_score=None,
            severity_label=None,
            references=[],
            sources=sources[:2],
        )

    # Extract: title, description, cvss score, references
    title = cve_id
    description = ""
    cvss_score: float | None = None
    severity_label: str | None = None
    references: list[str] = []

    containers = (record or {}).get("containers") or {}
    cna = containers.get("cna") or {}

    title = (cna.get("title") or title).strip() or title

    descs = cna.get("descriptions") or []
    if isinstance(descs, list) and descs:
        # prefer en, else first
        preferred = next((d for d in descs if (d.get("lang") == "en")), descs[0])
        description = (preferred.get("value") or "").strip()

    metrics = cna.get("metrics") or []
    if isinstance(metrics, list):
        for m in metrics:
            cvss = m.get("cvssV3_1") or m.get("cvssV3_0") or None
            if cvss and isinstance(cvss, dict) and cvss.get("baseScore") is not None:
                try:
                    cvss_score = float(cvss["baseScore"])
                    severity_label = (cvss.get("baseSeverity") or _severity_from_score(cvss_score))
                    break
                except (TypeError, ValueError):
                    continue
            other = m.get("other") or {}
            content = (other.get("content") or {})
            value = content.get("value")
            if isinstance(value, str) and value.strip():
                severity_label = value.strip()

    refs = cna.get("references") or []
    if isinstance(refs, list):
        for r in refs:
            url = r.get("url")
            if isinstance(url, str) and url.startswith("http"):
                references.append(url)

    # Ensure the two requested sources are always present
    for u in sources[:2]:
        if u not in references:
            references.append(u)

    return CVEData(
        cve_id=cve_id,
        title=title,
        description=description,
        cvss_score=cvss_score,
        severity_label=severity_label,
        references=references[:50],
        sources=sources[:2],
    )

