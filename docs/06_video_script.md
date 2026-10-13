# Demo video script (~16-17 min)

Assignment brief requirements (section 6): ≥ 10 min, MP4 1080p, real demo of the product
deployed **from the repository** (clone of the `v1.0-practica3` tag), cuts marked on
screen, errors and security in action, every member speaks.

**Preparation:** clone the tag into a clean folder and show `git describe --tags`; browser
at 125-150% zoom and terminal at 16-18 pt; `data/panel/` empty so the seeding is visible;
Claude session logged in (hide the email when showing `status`); Ghidra and the JDK installed
for the executor block. **Do not upload the synthetic bundle to the panel.**

Voices: **A**, **B**, **C**, **D** (one team member each; split them by who knows each
module best). After recording, replace the "planned" minutes in `docs/04_traceability.md` with the
real ones.

| Minute | Voice | Block | What is shown | Requirements |
|---|---|---|---|---|
| 00:00 | A | Introduction | Group, problem: thousands of binaries change every Patch Tuesday; what Thanos does | - |
| 01:00 | A | Requirements and changes | Slide: RF/RNF from P1, Neo4j → ontology, llama.cpp → Claude, improvements found with real data (`docs/01_requirements.md`) | - |
| 02:00 | B | Architecture | README diagram; the 4 levels; what is shown live and what is shown with evidence | - |
| 03:30 | B | Install from scratch | `git clone` + `git describe --tags`, venv, `pip install -r requirements.txt -c constraints.txt`, `pip install -e ".[dev,auditor]"`, `pytest -q` → 162 passed *(marked cut during pip install)* | RNF-04 |
| 04:30 | C | Coordinator: catalog | `python -m thanos.coordinator resolve KB5082142` → GUID `fd522b7b-…-2ae3327e54cb` and MSU URL (live) | RF-02, RF-03 |
| 05:00 | C | Coordinator: diff, split and ZIP | `manifest` + `diff` (85/85), `split --people …` (22/21/21/21), `package --from-bundle …`; open a ZIP and its `config.yaml` (quoted build) | RF-06, RF-07, RF-08, RNF-02, RF-11 |
| 06:00 | C | Executor with real Ghidra | `run_diff.py` on 3 real WinSxS pairs → bundle with `changes` *(marked cut during the analysis)*; repeat with a wrong `ghidra_support_dir` → clear error | RF-09, RF-12, RF-13, RF-14, RF-15 |
| 07:30 | C | bootstrap (if Windows is available) | `powershell -ExecutionPolicy Bypass -File .\bootstrap.ps1` inside the ZIP | RF-10 |
| 08:00 | D | Ontology + MSRC CVEs | `ontology ingest … --fresh`, `ingest-cvrf` (115 CVEs, 16 candidates), `stats`, `cves --binary upnphost.dll`; size of `catalog.ttl` and a SPARQL query | RF-01, RNF-03 |
| 09:00 | D | Heuristic auditor | `thanos-auditor analyze …` → summary; noise filter (260 names), `upnphost.dll` at P1, `fvecerts.dll` as a CRT change | RF-17, RF-14 |
| 10:00 | D | Auditor with Claude | `thanos-auditor status` → login with the subscription; `analyze --backend claude --no-fallback` *(marked cut of ~1.5 min)*; compare with the heuristic report | RF-16, RNF-09 |
| 11:00 | A | Panel | `python -m thanos.panel.app`; home page (2 seeded cycles); upload a bundle; cycle view: score, auditor report, candidate CVEs, P1 filter, "show names", wow64 label | RF-18, RF-19, RF-20 |
| 13:00 | B | Errors and security | Upload a malformed JSON → rejected and the panel stays up; `THANOS_PANEL_TOKEN` → 401 without token; `curl` with `Origin: https://evil.example` → 403; foreign Host → 400; `pytest tests/test_security.py`; CLI with a missing file → one-line error; panel JSON log; `pip-audit` | RNF-05, RNF-06, RNF-08 |
| 14:30 | B | Evidence that cannot be reproduced live | RF-05 on Windows (`docs/evidence/rf05_msdelta_windows.log`); cross-check of the real bundles (same SHA-256 in two runs); RF-04 pending | RF-05, RF-04, RNF-07 |
| 15:30 | A | Limitations and closing | RNF-01 without manual measurement; RF-04 pending; PA31; diff by names ≠ control-flow diff; CVE→binary links are hypotheses; future work (BinDiff/Diaphora) | RNF-01 |
