# Next actions milestone

This milestone captures the next small, high-value tasks for the play-ansible project. Each item has a short description, priority, and acceptance criteria.

## 1) Redact private_key in `run_artifact.json` (priority: high)
- Description: Avoid storing absolute/private key paths in `run_artifact.json` for security. Replace the `private_key` value with either the basename or a masked path (e.g., `***redacted***`), while keeping provenance (`source`) intact.
- Acceptance criteria:
  - `run_artifact.json` contains `private_key` entries with redacted values (not full absolute paths).
  - `run_artifact.json` still shows `source: "flag"|"json"|...` for those entries.
  - The live run still uses the full path to execute (only the artifact is redacted).

## 2) Add `requirements.txt` (priority: high)
- Description: Add a minimal `requirements.txt` listing runtime dependencies so users can install quickly.
- Contents suggestion:
  - ansible-runner
  - PyYAML
- Acceptance criteria:
  - `requirements.txt` at repo root contains the two packages.
  - Running `python -m pip install -r requirements.txt` installs the dependencies (note: CI not run here).

## 3) Add unit tests for merge and hosts parsing (priority: medium)
- Description: Add small unit tests for `deep_merge()` and `parse_hosts_flag()` to avoid regressions.
- Approach: create tests under `tests/` using `pytest`.
- Acceptance criteria:
  - `tests/test_merge.py` verifies dict merging and list replacement behavior.
  - `tests/test_hosts.py` checks IPv4, IPv6, port parsing and repeated flags.
  - Run `pytest -q` locally passes (developer will run in their environment).

## 4) Optional: Improve list-merge behavior (priority: low)
- Description: Add configurable merge semantics for lists (append vs replace) or provide a CLI flag to choose merging strategy.
- Acceptance criteria:
  - New option documented and tested.

---

Next step: I can implement items 1-2 quickly in this repo. Tell me which to start with (I recommend 1 then 2).
