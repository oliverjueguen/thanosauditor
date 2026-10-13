# Thanos executor: team member manual

Contents of the ZIP delivered by the coordinator (`python -m thanos.coordinator package`):

| File | Purpose |
|---|---|
| `bootstrap.ps1` | Creates `.venv`, installs `pyyaml` and `rdflib` and copies `config.yaml` if missing (RF-10) |
| `config.yaml` | Preconfigured by the coordinator: id, cycle, build and KBs. Only `ghidra_support_dir` needs to be set (RF-11) |
| `assignment.json` | Binaries assigned to you in the Round-Robin split (RF-07) |
| `input/before`, `input/after` | The rebuilt DLLs for each side of the pair |
| `run_diff.py` | Runner: pairs → Ghidra headless → diff by names → bundle (RF-12…RF-15) |
| `thanos/` | Library used by the runner |
| `CLAUDE.md` | Instructions if you use Claude Code to drive the run |

## Requirements

- Windows with **Python 3.10+**.
- **Ghidra** (tested with 11.0.3) and a **JDK 17+** (Ghidra does not work with a JRE).

## Steps

```powershell
powershell -ExecutionPolicy Bypass -File .\bootstrap.ps1
notepad config.yaml                       # set ghidra_support_dir (and java_home if needed)
.\.venv\Scripts\python.exe run_diff.py
```

The runner:

1. Validates `config.yaml` and checks that `analyzeHeadless.bat` exists **before** starting.
2. Pairs `input\before` ↔ `input\after` by name (case-insensitive) and
   discards pairs with the same SHA-256.
3. Analyzes each side with Ghidra headless and the `ExportFacts.java` script: number of
   functions, exports, imports, libraries and strings, and the **full list** of function
   and export names.
4. Computes the diff by names (`changes`, same schema as P1, without the P1 cut at 512
   functions).
5. Writes and validates `output\<run_id>.bundle.json`.

If Ghidra fails on a binary, the runner skips it, records it in `analyst_notes` and continues with the rest.

## Common errors (from P1 and P3)

| Message | Cause | Fix |
|---|---|---|
| `analyzeHeadless not found in …` | Wrong `ghidra_support_dir` | Point it to Ghidra's `support` folder, in single quotes |
| `Ghidra cannot find a JDK 17+` / `Unable to prompt user for JDK path` | The `java` on the PATH is a JRE or does not exist | Install a JDK 17+ and set `java_home` |
| `target_build must be quoted` | `target_build: 20348.5020` without quotes: YAML turns it into a number and drops the trailing zero (P1 bug) | `target_build: "20348.5020"` |
| `Found 0 pairs` | ZIP badly extracted or different names | Check `input\before` and `input\after` |
| `all have the same SHA-256` | Both sides are identical | Check that before and after come from different builds |
| Java/Ghidra hung | Blocked process | Close `java.exe` from Task Manager |
| *Long Path* errors | Long paths on Windows | Move the folder to a short path (e.g. `C:\thanos`) |
| PowerShell blocks `bootstrap.ps1` | ExecutionPolicy / downloaded file | `powershell -ExecutionPolicy Bypass -File .\bootstrap.ps1` or `Unblock-File` |
