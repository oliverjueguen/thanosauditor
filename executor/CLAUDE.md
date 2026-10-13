# Thanos executor: instructions for Claude Code

This directory is the package the coordinator delivers to each team member
(`thanos-<person>.zip`). Your task, if the team member asks you, is to **help them
run the analysis of their binaries** and deliver the bundle. This is defensive work
(patch diffing of public Windows Server 2022 updates) on binaries from the
team's own machine.

## Steps

1. Check that Python 3.10+ is available and run `bootstrap.ps1`
   (`powershell -ExecutionPolicy Bypass -File .\bootstrap.ps1`).
2. Review `config.yaml` with the team member. Usually only
   `ghidra_support_dir` needs to be set (Ghidra's `support` folder, in single quotes).
   Ghidra needs a **JDK 17+**; if the `java` on the PATH is not one, set `java_home`.
3. Verify that `input\before` and `input\after` contain the assigned DLLs (see
   `assignment.json`) with the same name in both folders.
4. Run `.\.venv\Scripts\python.exe run_diff.py` and watch its output: it shows which
   binary is being analyzed (`[i/n] Ghidra: name.dll`). Each DLL can take several
   minutes.
5. When it finishes, locate `output\<run_id>.bundle.json` and deliver it to the coordinator or
   upload it to the Thanos panel.

## Rules

- Do not modify `run_diff.py`, `config.yaml` (except `ghidra_support_dir`/`java_home`)
  or the content of the bundles: they are evidence of the analysis.
- Do not upload the DLLs, the Ghidra projects or the bundle to external services.
- If `run_diff.py` ends with an error, explain the message to the team member using the
  common errors table in `README.md`; do not try to "fix" the data.
