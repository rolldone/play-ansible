# Target Milestone

Last updated: 2025-08-15

## Objective
- Implement dynamic configuration handling with clear precedence (Flags > JSON > YAML), robust host normalization, predictable private-key resolution inside containers, temporary inventories for Ansible runs, and a provenance artifact for debugging.

# Configuration Milestone
Last updated: 2025-08-15

## Objective
- Implement dynamic configuration handling with clear precedence (Flags > JSON > YAML), robust host normalization, predictable private-key resolution inside containers, temporary inventories for Ansible runs, and a provenance artifact for debugging.

## Priority Levels
1. Flags (highest)
2. JSON config file
3. Default YAML file

## Tasks & Status
1. Parse and validate CLI flags (`--config`, `--action`, `--working-dir`, `--private-key`, `--username`, `--hosts`, etc.) — Done
2. Load JSON configuration file dynamically based on `--config` flag — Done
3. Merge JSON into YAML with a controlled deep-merge (JSON overrides YAML only for provided fields) — Done
4. Ensure flags override both JSON and YAML and mark provenance (source) — Done
5. Handle missing/invalid values with fallbacks and clear error logging — Partial (basic fallbacks implemented; more granular error codes can be added)
6. Log the source of each value for debugging (produce `run_artifact.json`) — Done (artifact produced; sensitive values flagged for redaction as a follow-up)
7. Preserve `--hosts` flag and support multi-host parsing (IPv4/IPv6 and optional :port) — Done
8. Use a temporary inventory file per run for ansible-runner (avoid passing raw IP strings) — Done
9. Define private-key resolution semantics (config-relative vs flag-default-to-cwd, `source:` prefix to force source-dir) — Done
10. Add `--show-sources` dry-run to print merged config + provenance and exit — Done

## Deliverables (current)
- `src/main.py` — updated orchestrator with CLI, deep-merge, host normalization, provenance, temp inventory usage — Done
- `src/basic/playbooks/disk.yaml` — updated to run controller-local script and capture output — Done
- `README.md` — usage and semantics documentation — Done
- `LICENSE` (MIT) — Done
- `milestone/next_actions.md` — next small tasks and prioritization — Done

## Remaining / Next Actions (recommended priority)
1. Redact private-key and other secrets in `run_artifact.json` before writing to disk (high priority) — Not Done
2. Add `requirements.txt` (PyYAML, ansible-runner, pinned versions) and document the minimal Python environment — Not Done
3. Add unit tests (pytest) for `deep_merge()`, `parse_hosts_flag()`, and `resolve_private_key()` (medium priority) — Not Done
4. Add CI (lightweight lint + tests) — Not Done
5. Improve exit codes and error classification (distinguish validation vs runtime errors) — Deferred

## Notes / Rationale
- The implementation follows a strict precedence: Flags > JSON > YAML. Provenance entries are emitted per-field to help debugging and to show which layer provided each value.
- Private-key semantics were made explicit to avoid surprising behavior inside containers: config files (YAML/JSON) use paths relative to the `source_dir`; CLI `--private-key` defaults to resolving relative to the current working directory (host/container), but may be forced to `source_dir` with a `source:` prefix.
- `--show-sources` lets operators inspect the merged configuration and provenance without running Ansible.

## Quick status mapping
- Implemented: CLI parsing, JSON loading & merging, host parsing, temporary inventories, provenance artifact, logging, `--show-sources`.
- Partial: fallback/error reporting granularity.
- Pending: redact secrets, add requirements/tests, CI.

---

If you'd like, I can implement the highest-priority next action now: redact secrets in `run_artifact.json` and add a short unit test for the redaction function.
