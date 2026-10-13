"""KB → GUID → MSU URL resolution in the Microsoft Update catalog.

Coordinator Phases 2 and 3 (RF-02, RF-03):

1. ``Search.aspx?q=<KB>`` returns an HTML table with one row per update
   (title, product, classification, date, size). :func:`parse_rows` turns it
   into data and :func:`select_cumulative` picks the Windows Server 2022 cumulative
   update row (in the catalog: "Microsoft server operating system version 21H2 for
   x64-based Systems"), discarding .NET, Dynamic and other OS versions.
2. ``DownloadDialog.aspx`` (POST with the updateID) returns the direct .msu URL
   (:func:`parse_msu_url`).
3. :func:`download_msu` downloads the MSU (optional; hundreds of MB) only from
   Microsoft domains and computes its SHA-256.

Verified live on 2026-10-13: KB5082142 → GUID fd522b7b-4adf-4335-a6fe-2ae3327e54cb
(the P1 report quoted it truncated, missing the last character) → windows10.0-kb5082142-x64_….msu.
The tests use that real HTML, saved in fixtures/catalog/.
"""

from __future__ import annotations

import hashlib
import html
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlsplit

SEARCH_URL = "https://www.catalog.update.microsoft.com/Search.aspx?q={q}"
DOWNLOAD_DIALOG_URL = "https://www.catalog.update.microsoft.com/DownloadDialog.aspx"
TIMEOUT = 30
MAX_MSU_BYTES = 2 * 1024**3          # 2 GB: a WS2022 cumulative update is around 500 MB
_ALLOWED_DOWNLOAD_DOMAINS = ("windowsupdate.com", "microsoft.com")

_GUID_RE = re.compile(r"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})")
_ROW_RE = re.compile(r'<tr id="([0-9a-fA-F-]{36})_R\d+"(.*?)</tr>', re.S)
_CELL_RE = re.compile(r"<td[^>]*>(.*?)</td>", re.S)
_TAG_RE = re.compile(r"<[^>]+>|\s+")
_MSU_URL_RE = re.compile(r"https?://[^\"'\s]+?\.msu")

# Title of the WS2022 cumulative update in the catalog (WS2022 = "server operating system 21H2").
_WS2022_TITLE = "cumulative update for microsoft server operating system version 21h2 for x64"
_EXCLUDED = (".net", "dynamic", "hotpatch", "servicing stack")


class CatalogError(RuntimeError):
    """Error resolving or downloading from the Microsoft Update catalog."""


def search_url(kb: str) -> str:
    """Catalog search URL for a KB (RF-02)."""
    return SEARCH_URL.format(q=kb)


def _text(cell: str) -> str:
    return html.unescape(_TAG_RE.sub(" ", cell)).strip()


def parse_rows(page: str) -> list[dict[str, str]]:
    """Catalog result rows: guid, title, product, classification, date, size."""
    rows, seen = [], set()
    for guid, body in _ROW_RE.findall(page or ""):
        guid = guid.lower()
        if guid in seen:
            continue
        seen.add(guid)
        cells = [_text(c) for c in _CELL_RE.findall(body)]
        if len(cells) < 4:
            continue
        rows.append({
            "guid": guid, "title": cells[1], "product": cells[2], "classification": cells[3],
            "date": cells[4] if len(cells) > 4 else "", "size": cells[6] if len(cells) > 6 else "",
        })
    return rows


def is_server_2022_cumulative(title: str) -> bool:
    """Is this the Windows Server 2022 x64 OS cumulative update (not .NET, Dynamic...)?"""
    t = (title or "").lower()
    return _WS2022_TITLE in t and not any(x in t for x in _EXCLUDED)


def select_cumulative(rows: list[dict[str, str]], kb: str | None = None) -> dict[str, str]:
    """Pick the single WS2022 cumulative update row (optionally, for that KB) (RF-03)."""
    kb_tag = f"({kb.upper()})" if kb else ""
    matches = [r for r in rows
               if is_server_2022_cumulative(r["title"]) and kb_tag in r["title"].upper()]
    if len(matches) > 1:   # e.g. "Security Updates" and "Updates" from the same month
        security = [r for r in matches if r["classification"].lower() == "security updates"]
        matches = security or matches
    if not matches:
        raise CatalogError(f"no Windows Server 2022 x64 cumulative update for {kb or 'the search'}")
    if len(matches) > 1:
        raise CatalogError(f"ambiguous result: {len(matches)} cumulative updates match {kb or 'the search'}")
    return matches[0]


def download_dialog_payload(update_ids: list[str]) -> dict[str, Any]:
    """Payload of the POST to DownloadDialog.aspx (RF-03)."""
    return {"updateIDs": [{"size": 0, "uidInfo": uid, "updateID": uid} for uid in update_ids]}


def download_dialog_body(update_ids: list[str]) -> bytes:
    """Form-encoded POST body (updateIDs=<json>)."""
    return urlencode({"updateIDs": json.dumps(download_dialog_payload(update_ids)["updateIDs"])}).encode()


def parse_msu_url(body: str) -> str | None:
    """Extract the .msu URL from the response body (RF-03)."""
    m = _MSU_URL_RE.search(body or "")
    return m.group(0) if m else None


def _http(url: str, data: bytes | None = None, *, session: Any = None) -> str:
    import urllib.error
    import urllib.request

    try:
        if session is not None:
            resp = session.post(url, data=data, timeout=TIMEOUT) if data else session.get(url, timeout=TIMEOUT)
            resp.raise_for_status()
            return resp.text
        headers = {"Content-Type": "application/x-www-form-urlencoded"} if data else {}
        req = urllib.request.Request(url, data=data, headers=headers, method="POST" if data else "GET")  # noqa: S310
        # Fixed Microsoft catalog URL (https); user-supplied schemes are not accepted.
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:  # nosec B310
            return r.read().decode("utf-8", "replace")
    except (OSError, urllib.error.URLError) as exc:
        raise CatalogError(f"could not reach the catalog ({url}): {exc}") from exc
    except Exception as exc:  # errors from the injected session (e.g. requests)
        raise CatalogError(f"HTTP error from the catalog ({url}): {exc}") from exc


def resolve_kb(kb: str, *, session: Any = None) -> dict[str, Any]:
    """Resolve KB → {kb, guid, title, msu_url} by querying the catalog (RF-02, RF-03)."""
    row = select_cumulative(parse_rows(_http(search_url(kb), session=session)), kb)
    body = _http(DOWNLOAD_DIALOG_URL, download_dialog_body([row["guid"]]), session=session)
    url = parse_msu_url(body)
    if not url:
        raise CatalogError(f"the catalog did not return the MSU URL for {kb} ({row['guid']})")
    return {"kb": kb, "guid": row["guid"], "title": row["title"], "msu_url": url}


def download_msu(url: str, dest_dir: str | Path, *, opener: Any = None) -> dict[str, Any]:
    """Stream the MSU into dest_dir and return {path, bytes, sha256} (RF-03).

    Only accepts https URLs on Microsoft domains and aborts above MAX_MSU_BYTES.
    """
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if parts.scheme != "https" or not any(host == d or host.endswith("." + d) for d in _ALLOWED_DOWNLOAD_DOMAINS):
        raise CatalogError(f"download URL not allowed: {url}")
    import urllib.request

    dest = Path(dest_dir) / Path(parts.path).name
    dest.parent.mkdir(parents=True, exist_ok=True)
    digest, total = hashlib.sha256(), 0
    try:
        # URL validated above: https and Microsoft domains only.
        with (opener or urllib.request.urlopen)(url, timeout=TIMEOUT) as resp, open(dest, "wb") as out:  # nosec B310
            for chunk in iter(lambda: resp.read(1 << 20), b""):
                total += len(chunk)
                if total > MAX_MSU_BYTES:
                    raise CatalogError("the MSU exceeds the maximum allowed size")
                digest.update(chunk)
                out.write(chunk)
    except CatalogError:
        dest.unlink(missing_ok=True)
        raise
    except OSError as exc:
        dest.unlink(missing_ok=True)
        raise CatalogError(f"failed to download the MSU: {exc}") from exc
    return {"path": str(dest), "bytes": total, "sha256": digest.hexdigest()}
