# Traceability matrix (report section 9)

Format from the assignment brief (section 8): for each requirement, where it is implemented, how it was
tested (ID from `docs/05_tests.md`) and where it can be checked. Under **Evidence**, the video
minutes are the **planned** ones from the script (`docs/06_video_script.md`); they must be replaced by
the real minutes after recording.

| Requirement | Description | Final status | Implementation | Test | Evidence |
|---|---|---|---|---|---|
| RF-01 | Queryable catalog of KBs and CVEs | Modified: RDF ontology with MSRC CVEs | `thanos/ontology/store.py`, `thanos/ontology/msrc.py`, `thanos/ontology/thanos-schema.ttl`, `data/ontology/catalog.ttl`; consumed by `thanos/auditor/report.py::candidates_for` | PR-01 | Video 08:00 (planned) · `fixtures/msrc/2026-Apr.ws2022.json` |
| RF-02 | KB → GUID → MSU URL | Done | `thanos/coordinator/catalog.py` (`parse_rows`, `select_cumulative`, `resolve_kb`) | PR-02 | Video 04:30 (planned) · `fixtures/catalog/` |
| RF-03 | MSU download | Done | `thanos/coordinator/catalog.py::download_msu`, `coordinator resolve --download` | PR-03 | Video 04:30 (planned) |
| RF-04 | Baseline from ISO/WIM | Pending | Procedure in `docs/02_coordinator_executor.md` | PR-04 | Report sec. 10 (limitations) · Video 14:30 (planned) |
| RF-05 | PA30 reconstruction with msdelta | Done | `thanos/coordinator/reconstruct.py` | PR-05 | `docs/evidence/rf05_msdelta_windows.log` · Video 14:30 (planned) |
| RF-06 | Manifest diff | Done | `thanos/coordinator/diff_index.py`, `coordinator manifest/diff` | PR-06 | Video 05:00 (planned) |
| RF-07 | Round-Robin split | Done | `thanos/coordinator/split_workload.py`, `coordinator split` | PR-07 | Video 05:00 (planned) |
| RF-08 | ZIP per person | Done | `thanos/coordinator/package.py`, `coordinator package` | PR-08 | Video 05:00 (planned) |
| RF-09 | Validate ZIP and pairs | Done | `executor/run_diff.py` (`load_config`, `run`) | PR-09 | Video 06:00 (planned) |
| RF-10 | Executor bootstrap | Modified (no MCP); Windows test pending | `executor/bootstrap.ps1` | PR-12 | Video 07:30 (planned, if Windows is available) |
| RF-11 | Preconfigured `config.yaml` | Done | `executor/config.example.yaml`, `thanos/coordinator/package.py::executor_config`, `run_diff.load_config` | PR-10 | Video 05:00 (planned) |
| RF-12 | Pair and discard identical SHAs | Done | `thanos/executor/pair.py` | PR-11 | Video 06:00 (planned) |
| RF-13 | Ghidra headless → facts | Modified: `analyzeHeadless` + `ExportFacts.java` | `thanos/executor/ghidra.py`, `thanos/executor/ghidra_scripts/ExportFacts.java` | PR-13 | `docs/evidence/rf13_executor_ghidra_real.bundle.json` · Video 06:00 (planned) |
| RF-14 | Diff by names | Done (full list + noise filter) | `thanos/executor/changes.py`, `thanos/core/noise.py`, `thanos/core/bundles.py` | PR-14 | Video 09:00 (planned) |
| RF-15 | Executor bundle | Done | `thanos/executor/bundle.py`, `thanos/core/bundles.py::validate_bundle` | PR-15 | Video 06:00 (planned) |
| RF-16 | LLM auditor | Modified: Claude via Agent SDK | `thanos/auditor/backends.py`, `thanos/auditor/prompts.py` | PR-16 | `output/report-claude.json` (regenerated) · Video 10:00 (planned) |
| RF-17 | Auditor JSON report | Done | `thanos/auditor/report.py` | PR-17 | Video 09:00 (planned) |
| RF-18 | Upload bundles to the panel | Done | `thanos/panel/app.py::upload`, `thanos/panel/store.py` | PR-18 | Video 11:00 (planned) |
| RF-19 | List cycles | Done | `thanos/panel/store.py::cycles`, `thanos/panel/render.py::render_home` | PR-19 | Video 11:00 (planned) |
| RF-20 | Cycle view with criticality and provenance | Modified (score formula) | `thanos/core/scoring.py`, `thanos/core/aggregate.py`, `thanos/panel/render.py::render_cycle`, `thanos/panel/store.py::enrich` | PR-20 | Video 11:00 (planned) |
| RNF-01 | Reduce analysis time | Partial | Full pipeline | PR-21 | Report sec. 8 (timings) · Video 15:30 (planned) |
| RNF-02 | Avoid duplication | Done | `thanos/coordinator/split_workload.py` | PR-22 | Video 05:00 (planned) |
| RNF-03 | Lightweight catalog in GitHub | Done | `data/ontology/catalog.ttl` (~170 KB) | PR-23 | Video 08:00 (planned) |
| RNF-04 | Installable from scratch | Done | `README.md`, `requirements.txt`, `constraints.txt`, `Dockerfile`, `.github/workflows/ci.yml` | PR-24 | Video 03:30 (planned) |
| RNF-05 | Product security | Done | `docs/03_security.md`, `thanos/panel/app.py`, `thanos/auditor/backends.py`, `thanos/core/sanitize.py` | PR-25 | Video 13:00 (planned) |
| RNF-06 | Error handling | Done | `thanos/cliutil.py`, `thanos/panel/app.py`, `thanos/panel/store.py`, `thanos/core/bundles.py::validate_bundle` | PR-26 | Video 13:00 (planned) |
| RNF-07 | Role portability | Partial | `executor/`, `thanos/coordinator/reconstruct.py` | PR-27 | Video 14:30 (planned) |
| RNF-08 | Structured logging | Done | `thanos/log.py` | PR-28 | Video 13:00 (planned) |
| RNF-09 | Claude subscription with login | Done | `thanos/auditor/cli.py` (`login`, `status`) | PR-29 | Video 10:00 (planned) |

## How to verify it

```bash
pip install -e ".[dev,auditor]" -c constraints.txt
pytest -q          # the automated tests cited in docs/05_tests.md
```
