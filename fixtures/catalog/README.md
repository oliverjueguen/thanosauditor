# Microsoft Update catalog fixtures

**Real** HTML responses from the Microsoft Update catalog, saved on 2026-10-13
so the RF-02/RF-03 tests do not depend on the network:

| File | Request |
|---|---|
| `catalog-search-KB5082142.html` | `GET https://www.catalog.update.microsoft.com/Search.aspx?q=KB5082142` (1 row: the WS2022 cumulative update) |
| `catalog-search-broad.html` | Broad search for the 2026-04 cumulative update (12 rows: 21H2/23H2/24H2, .NET, "Updates" and "Security Updates") |
| `downloaddialog-KB5082142.html` | `POST https://www.catalog.update.microsoft.com/DownloadDialog.aspx` with updateID `fd522b7b-4adf-4335-a6fe-2ae3327e54cb` |

These are public Microsoft pages, with no personal data or credentials.
