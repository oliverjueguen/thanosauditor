# Coordinator and executor: phases, commands and environment

Phases from the P1 report (Phases 1-6) and how they run in P3. Default paths are
relative to the project root.

## Coordinator

| P1 phase | P3 command | Req. | Environment | Status |
|---|---|---|---|---|
| 2. Identify the KB and resolve the MSU URL | `python -m thanos.coordinator resolve KB5082142` | RF-02, RF-03 | Network | Done; verified live |
| 3. Download the MSU | `… resolve KB5082142 --download downloads/msu` | RF-03 | Network, ~500 MB | Done (tested with a simulated network) |
| 3. Baseline from ISO/WIM | Manual (below) | RF-04 | **Windows Server 2022** with the ISO | Pending |
| 3. Rebuild DLLs (PA30 + msdelta) | `thanos.coordinator.reconstruct.apply_delta(delta, base)` | RF-05 | **Windows** (`msdelta.dll`) | Done; verified on Windows |
| 4. Compare manifests | `… diff before.json after.json` → `staging/changed_manifest.json` | RF-06 | Any | Done |
| 5. Split | `… split staging/changed_manifest.json --people ana luis marta pablo` | RF-07 | Any | Done |
| 5. ZIP per person | `… package --cycle "2026-04 Patch Tuesday" --target-build 20348.5020 --kb KB5078766 --kb KB5082142` | RF-08 | Any | Done |

**Reproducible demo without Windows:** `… manifest fixtures/bundles/2026-04-patch-tuesday-full.bundle.json`
generates the BEFORE/AFTER manifests from a real bundle (SXS package + SHA-256 of each
side), so `diff`, `split` and `package` can run on any machine.

### Manual procedure for RF-04 (baseline): Windows Server 2022

1. Mount the Windows Server 2022 ISO (RTM 20348.1) and locate `sources\install.wim`.
2. `dism /Mount-Wim /WimFile:X:\sources\install.wim /Index:<edition> /MountDir:C:\mnt /ReadOnly`
3. Copy the base DLLs from `C:\mnt\Windows\WinSxS\<package>\` to `baseline\<rtm>\` (same SXS
   package name as in the MSU).
4. `dism /Unmount-Wim /MountDir:C:\mnt /Discard`.

### Reconstruction (RF-05): Windows

The MSU expands in 4 layers (`expand.exe -F:*`: MSU → container CAB → `Cab_1/Cab_2_for_KB*.cab`
→ SXS tree with `n/` and `f/` deltas). For each delta:

```python
from thanos.coordinator.reconstruct import apply_delta, sha256
dll = apply_delta(delta_bytes, base_bytes)   # n/ deltas: base_bytes = b""
```

`apply_delta` strips the 4-byte CRC32 prefix, checks the `PA30` header and calls
`ApplyDeltaB`. Evidence on Windows 11: `docs/evidence/rf05_msdelta_windows.log` (identical
SHA-256 with and without the prefix; no memory leaks). Windows 11 24H2 **PA31** deltas are
not supported (they require `UpdateCompression.dll`); Windows Server 2022 uses PA30.

## Executor

Full manual and error table: `executor/README.md`. Summary:

| P1 phase | P3 | Req. | Status |
|---|---|---|---|
| Unzip and validate the ZIP | `run_diff.py` checks `config.yaml`, the Ghidra path and the pairs | RF-09, RF-11 | Done |
| bootstrap | `powershell -ExecutionPolicy Bypass -File .\bootstrap.ps1` (`.venv`, `pyyaml`, `rdflib`, `config.yaml`) | RF-10 | Modified; Windows test pending |
| Pair and discard identical files | `thanos/executor/pair.py` (case-insensitive) | RF-12 | Done |
| Ghidra headless | `thanos/executor/ghidra.py` + `ghidra_scripts/ExportFacts.java` | RF-13 | Done with real Ghidra 11.0.3 |
| Diff by names | `thanos/executor/changes.py` (full list) | RF-14 | Done |
| Bundle | `thanos/executor/bundle.py` (P1 schema, validated) | RF-15 | Done |

**Real verification (2026-10-13, Ghidra 11.0.3 + JDK 17):** `upnphost.dll` analyzed in 28 s
(1429 functions, 6 exports, 293 imports); `run_diff.py` on 3 real Windows Update pairs
from the development machine (`msasn1`, `cryptbase`, `nsi`, build 26100.8875 → 26100.9444) in 45 s,
valid bundle in `docs/evidence/rf13_executor_ghidra_real.bundle.json`. In those 3 binaries the
patch changes neither the number nor the names of the functions: the diff by names does not see changes
inside a function (stated limitation; a control-flow diff is future work).

## Environment requirements per role (RNF-07)

| Role | System | Software |
|---|---|---|
| Coordinator (catalog, diff, split, ZIP) | Any | Python 3.10+ |
| Coordinator (baseline and reconstruction) | Windows Server 2022 | Python 3.10+, `expand.exe`, `dism`, `msdelta.dll`, ~10 GB free |
| Executor | Windows (or Linux) | Python 3.10+, Ghidra 11.x, JDK 17+ |
| Auditor and panel | Any | Python 3.10+ (or Docker); for Claude, the `auditor` extra and a Claude account |
