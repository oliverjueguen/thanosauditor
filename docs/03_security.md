# Product security (report section 7)

Thanos is a **defensive analysis** tool (patch diffing of public Windows Server 2022
updates). This document answers the six questions in the assignment brief about the
security of the **product itself**. Every control cited is implemented and, unless stated
otherwise, covered by an automated test (`docs/05_tests.md`, PR-25 and PR-26).

## 1. Assets, attackers and threat model (STRIDE)

**Assets:** the bundles and the auditor report (analysis results), the ontology
catalog, the user's Claude session (OAuth token managed by the Claude CLI), the
integrity of the coordinator → executor → panel chain, and the team members' machines.

**Attackers considered:** another website open in the user's browser (CSRF, DNS rebinding);
a process or user on the same machine; an analyzed binary with malicious names or strings
(prompt injection toward the LLM); anyone who tampers with a ZIP or bundle in transit; a
compromised dependency.

| STRIDE | Threat | Control in Thanos | Test |
|---|---|---|---|
| **S**poofing | An external website uploads bundles to the panel on behalf of the user (CSRF) | POST with a foreign `Origin`/`Referer` → 403; optional upload token (`THANOS_PANEL_TOKEN`) | `test_cross_origin_post_is_rejected`, `test_upload_token_required_when_configured` |
| **S**poofing | DNS rebinding against the panel on 127.0.0.1 | Only local `Host` headers or the configured one are accepted → 400 | `test_foreign_host_header_is_rejected` |
| **T**ampering | Bundle or report tampered with to fake the criticality | Strict `validate_bundle` / `validate_report` (types and values); binaries in the report must exist in the input; `.bak` copy on replace; ontology and fixtures versioned in git | `test_malformed_bundle_is_rejected_and_panel_survives`, `test_claude_invented_binary_is_rejected`, `test_replacement_keeps_backup` |
| **T**ampering | MSU downloaded from a fake source | Download only over https and from Microsoft domains; the SHA-256 is logged | `test_download_msu_rejects_foreign_domains` |
| **T**ampering | Coordinator ZIP altered before it reaches the executor | `run_diff.py` validates `config.yaml` and the generated bundle; `config.yaml` is created by the coordinator. *Residual:* the ZIP is not signed; delivering it over a team channel is recommended | `test_run_diff_errors` |
| **R**epudiation | Denying who uploaded or generated an analysis | Each bundle carries `person`, `run_id` and `created_at`; the panel logs each upload (person, cycle, SHA-256) as JSON-lines | `test_log_lines_are_json` |
| **I**nformation disclosure | Windows paths and user name in published bundles | `python -m thanos.core.sanitize` before publishing; a test prevents uploading unsanitized fixtures | `test_real_fixtures_have_no_local_paths` |
| **I**nformation disclosure | Internal traces in errors | Custom error pages and JSON, no traceback; CLI with one-line messages | `test_errors_have_no_traceback`, `test_cli_bad_input_is_one_line_rc2` |
| **I**nformation disclosure | Leak of the Claude OAuth token | The token is stored by the Claude CLI in the user's profile; Thanos never reads or writes it | Code review |
| **D**enial of service | Huge uploads or pathological JSON that bring down the panel | Per-file limit (`THANOS_PANEL_MAX_UPLOAD_MB`, 5 MB) and per-request limit (20 files); nested or non-UTF-8 JSON rejected; a corrupt file on disk is ignored | `test_size_limit`, `test_corrupt_file_on_disk_does_not_break_panel` |
| **E**levation of privilege | Prompt injection from function names in the binary that makes the LLM act | The auditor runs **without tools** (`tools=[]`), `permission_mode="dontAsk"`, no MCP or local configuration, a single answer; names are sanitized and marked as `<untrusted_data>`; the answer is validated | `test_claude_runs_without_any_tool`, `test_untrusted_names_are_sanitized` |
| **E**levation of privilege | XSS in the panel through binary or cycle names | All content is escaped; CSP `default-src 'none'`, `X-Frame-Options: DENY`, `nosniff` | `test_xss_is_escaped`, `test_security_headers_present` |
| **E**levation of privilege | Writing outside the store through `../` in `person` | The file name is generated with a slug | `test_path_traversal_is_contained` |

## 2. Credentials, keys and tokens

- **There are no secrets in the repository.** `.gitignore` excludes `.env`, `.env.*` (except
  `.env.example`), `config.yaml`, keys (`*.key`, `*.pem`, `*.pfx`), `.claude/` and `.mcp.json`. The
  exceptions under `fixtures/` are listed by file type so nothing is re-included.
- `.env.example` and `executor/config.example.yaml` only contain example values.
- **Claude:** the user's own session is used (`python -m thanos.auditor.cli login`, which calls
  `claude auth login --claudeai`). The token is stored by the Claude CLI; Thanos does not handle it. As
  an alternative, `ANTHROPIC_API_KEY` in `.env` (not versioned). `status` warns if that variable
  exists, because it takes priority over the subscription.
- **Panel token:** `THANOS_PANEL_TOKEN` (optional) lives in `.env`; it is compared in constant
  time (`hmac.compare_digest`).
- Before each push, the team reviews `git ls-files` and enables *Secret scanning* and *Push
  protection* on GitHub. If a secret reached the history, it would be revoked and the history cleaned.

## 3. Authentication and access control

| Component | Who uses it | Authentication | Access control |
|---|---|---|---|
| Web panel | The team, on their own machine | **No users by design**: listens only on `127.0.0.1` (in Docker, the port is published only on the host's `127.0.0.1`). For a shared deployment, `THANOS_PANEL_TOKEN` is enabled | Free read access on loopback; **writing** (`POST /upload`) requires the same origin and, if configured, the token (401 if missing). Non-local host → 400 |
| Auditor with Claude | Each team member | Their own Claude account (subscription) | The model has no tools: it can only return text |
| Coordinator, executor and ontology CLIs | Whoever has access to the machine | Those of the operating system | File system permissions; they open no ports |

**Decision and residual risk:** no user accounts are implemented because the product is
local and single-user per machine. If the panel were exposed on a network, real
authentication (e.g. a proxy with SSO) and HTTPS would be needed; this is left as future work.

## 4. Inputs and their validation

| Input | Validation |
|---|---|
| Bundles (panel, CLI, ontology) | `validate_bundle`: types and lengths of all fields; never raises; invalid ones are rejected with a reason |
| Auditor report (Claude answer or file) | `validate_report`: schema, allowed values (P1-P4, severity, confidence) and existing binaries |
| Panel uploads | Size, number of files, UTF-8 JSON, origin and token |
| Executor `config.yaml` | Required keys, `kb_ids` as a list, `target_build` as text, Ghidra path checked before starting |
| HTML and responses from the Microsoft catalog | Row parsing and strict filtering; clear error if there are 0 or several results |
| Names extracted from binaries sent to the LLM | Length cut, removal of control characters and of `<`/`>`, marked as untrusted |
| Panel URL parameters | `prio` limited to P1-P4; everything else is escaped on rendering |

## 5. Third-party dependencies

- Minimal set with lower bounds that avoid versions with known CVEs
  (`pyproject.toml`) and **exact tested versions** in `constraints.txt` (Python 3.10 to 3.14).
- Results on 2026-10-13:
  - `pip-audit -r requirements.txt`: **no known vulnerabilities**. With the full
    environment (`dev` and `auditor`) there are none either.
  - `bandit -r thanos executor`: **no findings**. The 7 initial warnings (B310, B104,
    B404/B603) were reviewed and annotated with `# nosec` and their justification in the code.
  - `ruff check .`: no warnings.
- CI runs `pip-audit` on every push and Dependabot proposes weekly updates.
- Reused third-party code: none copied. Ghidra (Apache
  2.0) and the Claude Agent SDK are used as tools; the HTML files in `fixtures/catalog/` and the MSRC extract are
  public Microsoft responses.

## 6. Personal data

- The product analyzes binaries from public Microsoft updates: **it does not process personal
  data of third parties**.
- The `person` field of the bundles contains the **first name of each team member** who generated
  the bundle. Purpose: knowing who analyzed what and replacing the right bundle. Basis: the
  team itself, which publishes it in its repository.
- **Not sent to Claude:** the prompt only includes the binaries' facts and the
  cycle metadata; the person is re-associated locally afterwards.
- **Retention:** bundles uploaded to the panel stay in `data/panel/` (not versioned) until
  the user deletes them (delete the folder or start with `THANOS_PANEL_SEED=0`). The published
  fixtures are sanitized (no user paths).
- Tests and the demo use the team's own real data and a marked **synthetic** bundle
  (`"synthetic": true`, person `synthetic`); no third-party data is used.

## Ethical and legal use

Analyses are run on binaries from public updates and on the team's own or lab
machines. The only external requests are **read-only** requests to public Microsoft APIs
(Microsoft Update catalog and MSRC CVRF). The goal is defensive: prioritizing which changes in a
patch are worth reviewing.
