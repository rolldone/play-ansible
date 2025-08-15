# play-ansible

Lightweight, auditable Ansible runner and config merger.

play-ansible helps you run Ansible playbooks from a small, per-directory configuration while making provenance and overrides explicit. It merges a base YAML environment definition with optional JSON overrides and supports global CLI flags. The tool validates private-key paths, generates a masked provenance artifact (`run_artifact.json`), and can print a dry-run of the merged configuration before executing anything.

## Key features
- Merge semantics: JSON overrides > YAML. Dicts merge recursively; lists are replaced.
- Global CLI overrides (highest precedence): `--hosts`, `--username`, `--private-key`, `--password`, `--working-dir`, `--port`.
- Provenance: writes `run_artifact.json` showing where every value came from (`flag`, `json`, `env`, `host`, `parent`).
- Safe runs: creates a temporary inventory per-run, resolves private key paths (relative to the source directory or absolute), and warns if keys sit outside the play directory.
- Dry-run: `--show-sources` prints the merged provenance and exits.

## Requirements
- Python 3.8+ (or your environment's default Python 3)
- ansible-runner
- PyYAML

Install dependencies (recommended inside a virtualenv):

```bash
python -m pip install ansible-runner pyyaml
```

## Layout
- `src/main.py` — main runner script (CLI).
- `basic/play.yaml` — example YAML per-directory environment definitions.
- `src/dev.json` — example JSON override (optional).

Run the script from the repository root and point `source_dir` at the directory containing a `play.yaml`/`play.yml` (for example, `basic/`).

## Usage

Dry-run to inspect merged values and provenance:

```bash
python src/main.py basic/ --action dev --config src/dev.json --show-sources
```

Run (executes playbooks):

```bash
python src/main.py basic/ --action dev --config src/dev.json --hosts 127.0.0.1,172.0.0.1:2200 --username ciuser --private-key ssh/ci_key
```

The script writes a timestamped log file inside the `source_dir` and also creates `run_artifact.json` in the `source_dir` describing the resolved values and their sources.

## CLI flags (summary)
- `source_dir` (positional): directory holding `play.yaml`/`play.yml` and `playbooks/`.
- `--action ACTION` (required): environment/action to run (e.g., `dev`, `prod`).
- `--config PATH`: optional JSON file with overrides (higher precedence than YAML).
- `--hosts HOSTS`: repeatable; each value may be a comma-separated list of `IP` or `IP:PORT`. IPv6 with port must be provided as `[ipv6]:port`.
- `--username NAME`, `--private-key PATH`, `--password PWD`, `--working-dir PATH`, `--port N`: global overrides that act as highest precedence.
- `--show-sources`: print merged provenance (`run_artifact.json`) to stdout and exit.

Notes on `--hosts`:
- Accepts IPv4, IPv6 (bare or in brackets). To specify a port for IPv6 use the bracket form: `[2001:db8::1]:2222`.

## Provenance (`run_artifact.json`)

The tool writes `run_artifact.json` into your `source_dir`. Each host entry contains per-field `value` and `source` (one of `flag`, `json`, `env`, `host`, `parent`, or `null`). Passwords are redacted in the provenance output.

Example fragment:

```json
{
  "action": "dev",
  "hosts": [
    {
      "ip": {"value": "127.0.0.1", "source": "host"},
      "username": {"value": "ciuser", "source": "flag"},
      "private_key": {"value": "ssh/ci_key", "source": "flag"}
    }
  ],
  "playbooks": ["memory.yaml"]
}
```

## Troubleshooting
- If the tool warns that a private key is outside the `source_dir`, ensure the file is mounted into your container/environment at that absolute path.
- If a private key path does not exist the run will fail with an ERROR in the log. Use relative paths (they are resolved against `source_dir`) or absolute paths that exist inside your runtime.

## Contributing
- The code is intentionally small and easy to modify. Suggested next improvements: per-host CLI overrides, unit tests for merge behavior, and configurable list-merge semantics.

---

If you want, I can also add a short LICENSE file and a `requirements.txt` listing `ansible-runner` and `PyYAML`. Tell me which and I will add them.
