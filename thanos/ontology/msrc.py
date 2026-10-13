"""Real Microsoft CVEs (MSRC CVRF) for the ontology catalog (RF-01).

Every month the public MSRC API publishes a CVRF document with all fixed
vulnerabilities, the affected products, severity, impact, CVSS and remediation
(KB, superseded KB and fixed build).

- :func:`fetch_cvrf` downloads a document (e.g. ``2026-Apr``); requires network.
- :func:`extract_cves` keeps the Windows Server 2022 CVEs.
- :func:`load_cves` reads the extract saved in ``fixtures/msrc/`` (offline).
- :func:`match_cves` proposes CANDIDATE CVEs for a changed binary.

Important: Microsoft does NOT publish the CVE-to-file mapping. Candidates are
HYPOTHESES based on the component name (confidence 'medium' or 'low', never 'high')
and are shown as such in the report and in the dashboard.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ..config import env, resolve_path

CVRF_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{doc}"
WS2022_PRODUCTS = ("Windows Server 2022", "Windows Server 2022 (Server Core installation)")
DEFAULT_FIXTURE = "fixtures/msrc/2026-Apr.ws2022.json"
TIMEOUT = 60

# Threat and remediation types of the MSRC CVRF format.
_THREAT_IMPACT, _THREAT_EXPLOIT, _THREAT_SEVERITY = 0, 1, 3
_REMEDIATION_VENDOR_FIX = 2

_IMPACT_SUFFIX_RE = re.compile(
    r"\s+(Remote Code Execution|Elevation of Privilege|Information Disclosure|Security Feature Bypass"
    r"|Denial of Service|Spoofing|Tampering)\s+Vulnerability$"
)
_FILE_IN_TITLE_RE = re.compile(r"\(([\w.-]+\.(?:dll|sys|exe))\)", re.IGNORECASE)

# Curated table: component (MSRC title) -> bundle binaries/packages.
# Each entry is justified by the component name; it is still a hypothesis.
CURATED: list[tuple[str, tuple[str, ...], tuple[str, ...], str]] = [
    ("Windows UPnP Device Host", ("upnphost.dll",), ("upnpdevicehost",),
     "the UPnP Device Host service is implemented in upnphost.dll (package upnpdevicehost)"),
    ("Windows Advanced Rasterization Platform", ("d3d10warp.dll",), ("directx-warp",),
     "WARP is the Direct3D software rasterizer (d3d10warp.dll, package directx-warp10)"),
    ("Desktop Window Manager", ("dwmscene.dll", "dwmcore.dll", "udwm.dll", "dwm.exe"), ("windowmanager",),
     "Desktop Window Manager component (package desktopwindowmanager)"),
    ("Windows BitLocker", ("fvecerts.dll", "fveapi.dll", "fvevol.sys", "bdesvc.dll"), (),
     "FVE (Full Volume Encryption) is the internal name of BitLocker"),
    ("Windows Sensor Data Service", ("mediafoundation.defaultperceptionprovider.dll",), ("sensordataservice",),
     "binary of the sensordataservice package"),
]

# Words too generic to support a match (e.g. "desktop" would link Remote Desktop
# with windows.cortana.desktop.dll; "access", Remote Access with userdataaccess).
_STOPWORDS = {
    "windows", "microsoft", "service", "services", "driver", "system", "server", "client",
    "filter", "remote", "local", "security", "subsystem", "manager", "core", "file",
    "desktop", "access", "management", "account", "accounts", "network", "networking",
    "application", "applicationmodel", "runtime", "platform", "provider", "devices", "device",
    "connected", "universal", "brokered", "experience", "settings", "interface", "media",
}


def fetch_cvrf(doc_id: str) -> dict[str, Any]:
    """Download the CVRF document ``doc_id`` (e.g. '2026-Apr') from the MSRC API."""
    import urllib.error
    import urllib.request

    req = urllib.request.Request(CVRF_URL.format(doc=doc_id), headers={"Accept": "application/json"})
    try:
        # Fixed https URL of the MSRC API (doc_id is only part of the path).
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:  # nosec B310
            return json.loads(r.read())
    except (OSError, urllib.error.URLError, ValueError) as exc:
        raise RuntimeError(f"could not download CVRF {doc_id} from MSRC: {exc}") from exc


def _value(obj: Any) -> str:
    return obj.get("Value", "") if isinstance(obj, dict) else ""


def extract_cves(cvrf: dict[str, Any], product_names: tuple[str, ...] = WS2022_PRODUCTS) -> list[dict[str, Any]]:
    """CVEs in the CVRF document that affect the given products (Windows Server 2022)."""
    products = {p["ProductID"] for p in cvrf.get("ProductTree", {}).get("FullProductName", [])
                if p.get("Value") in product_names}
    out = []
    for vuln in cvrf.get("Vulnerability", []):
        def ours(item: dict[str, Any]) -> bool:
            return bool(products.intersection(item.get("ProductID") or []))

        threats = vuln.get("Threats", [])
        impact = next((_value(t["Description"]) for t in threats if t.get("Type") == _THREAT_IMPACT and ours(t)), "")
        if not impact:
            continue
        severity = next(
            (_value(t["Description"]) for t in threats if t.get("Type") == _THREAT_SEVERITY and ours(t)), "")
        exploit = next((_value(t["Description"]) for t in threats if t.get("Type") == _THREAT_EXPLOIT), "")
        cvss = next((c for c in vuln.get("CVSSScoreSets", []) if ours(c)), {})
        fixes = [r for r in vuln.get("Remediations", []) if r.get("Type") == _REMEDIATION_VENDOR_FIX and ours(r)]
        out.append({
            "cve": vuln.get("CVE", ""),
            "title": _value(vuln.get("Title")),
            "severity": severity,
            "impact": impact,
            "cvss": cvss.get("BaseScore"),
            "vector": cvss.get("Vector", ""),
            "cwe": [c.get("ID", "") for c in vuln.get("CWE", []) if c.get("ID")],
            "exploited": "Exploited:Yes" in exploit,
            "kbs": sorted({f"KB{_value(r.get('Description'))}" for r in fixes if _value(r.get("Description"))}),
            "supersedes": sorted({f"KB{r['Supercedence']}" for r in fixes if r.get("Supercedence")}),
            "fixed_build": next((r.get("FixedBuild", "") for r in fixes if r.get("FixedBuild")), ""),
        })
    return sorted(out, key=lambda c: c["cve"])


def build_fixture(cvrf: dict[str, Any], doc_id: str, retrieved: str) -> dict[str, Any]:
    """Offline extract with provenance (what is saved in fixtures/msrc/)."""
    cves = extract_cves(cvrf)
    return {
        "source": CVRF_URL.format(doc=doc_id),
        "document": doc_id,
        "document_release": cvrf.get("DocumentTracking", {}).get("CurrentReleaseDate", ""),
        "retrieved": retrieved,
        "products": list(WS2022_PRODUCTS),
        "count": len(cves),
        "cves": cves,
    }


def load_cves(path: str | Path | None = None) -> list[dict[str, Any]]:
    """CVEs from the offline extract (THANOS_MSRC_CVES or fixtures/msrc/2026-Apr.ws2022.json)."""
    path = resolve_path(path or env("THANOS_MSRC_CVES", DEFAULT_FIXTURE))
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return data["cves"] if isinstance(data, dict) else data


def component(title: str) -> str:
    """'Windows UPnP Device Host Elevation of Privilege Vulnerability' -> 'Windows UPnP Device Host'."""
    return _IMPACT_SUFFIX_RE.sub("", title or "").strip()


def _tokens(text: str) -> set[str]:
    return {t for t in re.split(r"[^a-z0-9]+", text.lower()) if len(t) >= 5 and t not in _STOPWORDS}


def match_cves(
    logical_name: str, package_key: str = "", cves: list[dict[str, Any]] | None = None
) -> list[dict[str, Any]]:
    """Candidate CVEs for a binary: hypotheses based on the component name (never 'high')."""
    cves = load_cves() if cves is None else cves
    name, package = (logical_name or "").lower(), (package_key or "").lower()
    candidates = []
    for cve in cves:
        comp = component(cve["title"])
        confidence, reason = None, ""
        explicit = _FILE_IN_TITLE_RE.search(cve["title"])
        if explicit and explicit.group(1).lower() == name:
            confidence, reason = "medium", f"the MSRC title names the file {explicit.group(1)}"
        else:
            for comp_name, binaries, packages, why in CURATED:
                if comp == comp_name and (name in binaries or any(p in package for p in packages)):
                    confidence, reason = "medium", why
                    break
        if confidence is None and not explicit:
            shared = _tokens(comp) & (_tokens(name) | _tokens(package))
            if shared:
                confidence, reason = "low", f"component words match: {', '.join(sorted(shared))}"
        if confidence:
            candidates.append({
                "cve": cve["cve"], "title": cve["title"], "severity": cve.get("severity", ""),
                "impact": cve.get("impact", ""), "cvss": cve.get("cvss"), "exploited": cve.get("exploited", False),
                "confidence": confidence,
                "reason": f"Hypothesis based on the component name ({reason}); "
                          "Microsoft does not publish CVE-to-file mappings.",
            })
    order = {"medium": 0, "low": 1}
    return sorted(candidates, key=lambda c: (order[c["confidence"]], -(c["cvss"] or 0), c["cve"]))
