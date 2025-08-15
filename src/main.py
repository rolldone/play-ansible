import argparse
import yaml
import subprocess
import ansible_runner
import os
import datetime
import logging
import tempfile
import json
from copy import deepcopy

# Set umask to 002
os.umask(0o002)

# Parse arguments
def parse_args():
    parser = argparse.ArgumentParser(description="Simulate tasks based on play.yaml/play.yml")
    parser.add_argument("source_dir", help="Source directory that contains play.yaml/playbooks (e.g., basic/)")
    parser.add_argument("--action", required=True, help="Environment to simulate (e.g., dev, prod)")
    parser.add_argument("--config", help="Optional JSON config file that overrides YAML (higher precedence than YAML)")
    parser.add_argument("--hosts", action="append", help="Comma-separated list of hosts (IP or IP:PORT). Can be repeated.")
    parser.add_argument("--username", help="Override username for all hosts (highest precedence)")
    parser.add_argument("--private-key", dest="private_key", help="Override private key path for all hosts (relative resolved against source_dir)")
    parser.add_argument("--password", help="Override password for all hosts (redacted in provenance)")
    parser.add_argument("--working-dir", help="Override remote working directory for all hosts")
    parser.add_argument("--port", type=int, help="Override port for all hosts (applies where a host doesn't specify a port)")
    parser.add_argument("--show-sources", action="store_true", help="Print the merged provenance/run_artifact JSON and exit (dry-run)")
    return parser.parse_args()

# Load YAML configuration
def load_config(config_path):
    with open(config_path, "r") as f:
        return yaml.safe_load(f)


def resolve_private_key(path, base_dir):
    """Resolve a private key path: return absolute path if provided, or join with base_dir when relative."""
    if not path:
        return None
    return path if os.path.isabs(path) else os.path.join(base_dir, path)


def deep_merge(a, b):
    """Deep merge dict b into a and return result (new dict). Lists are replaced, not merged."""
    if a is None:
        return deepcopy(b)
    if b is None:
        return deepcopy(a)
    out = deepcopy(a)
    for k, v in b.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = deepcopy(v)
    return out


def parse_hosts_flag(hosts_flag_list):
    """Parse repeated --hosts values (each may be comma-separated). Supports IPv4, IPv6 (in brackets) and optional :port."""
    if not hosts_flag_list:
        return None
    results = []
    for entry in hosts_flag_list:
        parts = [p.strip() for p in entry.split(',') if p.strip()]
        for token in parts:
            # IPv6 may be provided in [..] to allow :port after
            ip = token
            port = None
            if token.startswith('['):
                # format: [ipv6]:port or [ipv6]
                if ']' in token:
                    ip_part, rest = token.split(']', 1)
                    ip = ip_part[1:]
                    if rest.startswith(':'):
                        port = rest[1:]
                else:
                    ip = token
            else:
                # IPv4 or hostname or ipv6 without brackets - split last ':' as port separator
                if ':' in token and token.count(':') == 1:
                    ip, port = token.rsplit(':', 1)
                else:
                    # multiple colons -> likely bare IPv6 without brackets; accept as ip
                    ip = token

            # coerce port to int when present
            if port is not None:
                try:
                    port = int(port)
                except Exception:
                    port = None

            results.append({"ip": ip, **({"port": port} if port is not None else {})})
    return results

# Simulate SSH connection
def simulate_ssh(host, username, private_key):
    # Use logging instead of manual file I/O
    logging.info("[SSH Connection] Connecting to %s as %s using %s", host, username, private_key)
    # Mock SSH command
    command = ["echo", f"Connected to {host} as {username}"]
    result = subprocess.run(command, capture_output=True, text=True)
    logging.info("[Command Executed] %s\n[Output]\n%s", " ".join(command), result.stdout)

# Update YAML with process stdout
def update_yaml_with_stdout(config_path, action, host, playbook, stdout):
    # Removed logic to update the YAML file with results
    pass

# Simulate playbook execution using ansible_runner
def simulate_playbook(playbook, host, base_dir):
    # playbooks are expected under the provided source/base directory
    playbook_path = os.path.join(base_dir, "playbooks", playbook)
    logging.info("[Playbook Execution] Running playbook %s on %s", playbook_path, host)

    # Build a tiny INI inventory file with the host and connection vars
    inventory_content = "[all]\n"
    host_ip = host.get("ip") if isinstance(host, dict) else host
    host_name = host_ip
    ansible_user = host.get("username")
    ansible_key = host.get("private_key")
    if ansible_key:
        ansible_key = resolve_private_key(ansible_key, base_dir)
        try:
            if os.path.isabs(ansible_key) and os.path.commonpath([os.path.abspath(base_dir), os.path.abspath(ansible_key)]) != os.path.abspath(base_dir):
                logging.warning("Ansible key %s is outside base_dir %s", ansible_key, base_dir)
        except Exception:
            logging.warning("Couldn't determine if ansible key %s is outside base_dir %s", ansible_key, base_dir)

    # Ensure the key file exists before creating inventory
    if ansible_key and not os.path.exists(ansible_key):
        logging.error("Private key for host %s does not exist: %s", host_name, ansible_key)
        return False
    ansible_port = host.get("port", 22)

    # Provide both legacy and newer variable names for private key
    inventory_content += (
        f"{host_name} ansible_host={host_ip} ansible_user={ansible_user} "
        f"ansible_ssh_private_key_file={ansible_key} ansible_private_key_file={ansible_key} ansible_port={ansible_port}\n"
    )

    tmp_inv = None
    try:
        tmp = tempfile.NamedTemporaryFile(mode="w", delete=False, prefix="inventory_", suffix=".ini")
        tmp.write(inventory_content)
        tmp.flush()
        tmp.close()
        tmp_inv = tmp.name
        logging.info("Writing temporary inventory %s with content:\n%s", tmp_inv, inventory_content)

        # Execute the playbook using ansible_runner with the inventory file
        try:
            runner = ansible_runner.run(
                private_data_dir=base_dir,
                playbook=playbook_path,
                inventory=tmp_inv,
                extravars={
                    "ansible_user": ansible_user,
                    "ansible_ssh_private_key_file": ansible_key,
                    "ansible_port": ansible_port,
                },
                quiet=False
            )
        except Exception as e:
            logging.exception("ansible_runner failed to start for %s on %s", playbook_path, host)
            return False

        # Log events safely
        for event in getattr(runner, "events", []) or []:
            try:
                logging.info(event.get("stdout", ""))
            except Exception:
                # defensive: some events may be non-dict
                logging.debug("Non-dict event: %s", repr(event))

        if getattr(runner, "status", None) != "successful":
            logging.error("Error executing playbook %s on %s, status=%s, rc=%s", playbook_path, host, getattr(runner, "status", None), getattr(runner, "rc", None))
            print(f"Error executing playbook {playbook_path} on {host}")
            return False

        return True
    finally:
        if tmp_inv and os.path.exists(tmp_inv):
            try:
                os.remove(tmp_inv)
            except Exception:
                logging.debug("Failed to remove temp inventory %s", tmp_inv)

def validate_config(config):
    for env in config:
        if not isinstance(env.get("hosts"), list):
            raise ValueError("Hosts should be a list of dictionaries")
        for host in env.get("hosts", []):
            if not isinstance(host, dict):
                raise ValueError("Each host should be a dictionary")
            if not host.get("username"):
                raise ValueError(f"Missing username for host {host.get('ip')}")
            if not host.get("private_key") and not host.get("password"):
                raise ValueError(f"Host {host.get('ip')} must have either a private_key or a password")
            if "port" in host and (not isinstance(host["port"], int) or not (1 <= host["port"] <= 65535)):
                raise ValueError(f"Invalid port for host {host.get('ip')}: {host.get('port')} (must be an integer between 1 and 65535)")

    return True

def create_log_file(base_dir):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    log_file = os.path.join(base_dir, f"{timestamp}_process.log")
    return log_file

# Main function
def main():
    args = parse_args()

    # Use the provided source_dir as the base directory for plays/keys/logs
    base_dir = os.path.abspath(args.source_dir)
    if not os.path.isdir(base_dir):
        print(f"Error: source_dir '{base_dir}' is not a directory")
        return

    # Prefer play.yaml, fallback to play.yml
    config_path = os.path.join(base_dir, "play.yaml")
    if not os.path.exists(config_path):
        config_path = os.path.join(base_dir, "play.yml")
        if not os.path.exists(config_path):
            print("Error: Configuration file not found (play.yaml or play.yml) in source_dir")
            return

    config = load_config(config_path)

    # If user provided a JSON config, load it and apply it as higher-precedence overrides
    json_overrides = None
    if args.config:
        json_path = os.path.abspath(args.config)
        if not os.path.exists(json_path):
            print(f"Error: JSON config file not found: {json_path}")
            return
        try:
            with open(json_path, 'r') as jf:
                json_overrides = json.load(jf)
        except Exception as e:
            print(f"Error: failed to load JSON config {json_path}: {e}")
            return

    # Find the environment configuration
    env_config = next((env for env in config if env["action"] == args.action), None)
    if not env_config:
        print(f"Error: No configuration found for action '{args.action}'")
        return

    # Apply JSON overrides targeted at this action if provided
    if json_overrides:
        # Expect the JSON to possibly contain a top-level mapping of actions -> overrides
        override_for_action = None
        if isinstance(json_overrides, dict) and args.action in json_overrides:
            override_for_action = json_overrides[args.action]
        else:
            # Otherwise, assume the JSON is a flat override for env_config
            override_for_action = json_overrides

        if override_for_action:
            try:
                env_config = deep_merge(env_config, override_for_action)
            except Exception:
                print("Error: failed to merge JSON overrides into YAML configuration")
                return

    # --- Apply CLI flag overrides (highest precedence) ---
    # --hosts: replace hosts list when provided
    flag_hosts = parse_hosts_flag(args.hosts)
    if flag_hosts is not None:
        env_config["hosts"] = flag_hosts

    # Global flag overrides (apply as env-level defaults)
    if args.username:
        env_config["username"] = args.username
    if args.private_key:
        # Resolve flagged private key: default resolve relative to cwd; allow explicit source: prefix
        pk_flag = args.private_key
        if isinstance(pk_flag, str) and pk_flag.startswith("source:"):
            # force resolution relative to source_dir
            pk_val = pk_flag.split(':', 1)[1]
            resolved_pk = resolve_private_key(pk_val, base_dir)
        else:
            # resolve relative to current working directory (cwd), unless absolute
            if os.path.isabs(pk_flag):
                resolved_pk = pk_flag
            else:
                resolved_pk = os.path.join(os.getcwd(), pk_flag)
        env_config["private_key"] = resolved_pk
    if args.password:
        env_config["password"] = args.password
    if args.working_dir:
        env_config["working_dir"] = args.working_dir
    if args.port:
        env_config["port"] = args.port

    # Transform env_config['hosts'] to ensure it is a list of dictionaries
    env_config["hosts"] = [
    {"ip": host, "username": env_config.get("username"), "private_key": env_config.get("private_key"), "port": env_config.get("port", 22)}
    if isinstance(host, str) else host
    for host in env_config["hosts"]
    ]

    # Note: validation of required per-host fields is performed after normalization

    # --- Host normalization & provenance (parent:true semantics) ---
    # Capture pre-merge defaults for provenance comparison
    env_defaults = {
        "username": env_config.get("username"),
        "private_key": env_config.get("private_key"),
        "password": env_config.get("password"),
        "working_dir": env_config.get("working_dir"),
        "port": env_config.get("port", 22),
    }

    # We'll detect JSON-origin values by checking if json_overrides provided a differing value
    json_values = {}
    if json_overrides:
        if isinstance(json_overrides, dict) and args.action in json_overrides:
            json_values = json_overrides[args.action] or {}
        elif isinstance(json_overrides, dict):
            json_values = json_overrides or {}

    # Build a quick map of flag-supplied values for provenance detection
    flag_values = {}
    if args.username:
        flag_values["username"] = args.username
    if args.private_key:
        flag_values["private_key"] = args.private_key
    if args.password:
        flag_values["password"] = args.password
    if args.working_dir:
        flag_values["working_dir"] = args.working_dir
    if args.port:
        flag_values["port"] = args.port

    normalized_hosts = []
    provenance_list = []
    # helper to detect if a particular field for this host was supplied by JSON overrides
    def is_field_from_flag(field, ip, host_entry=None):
        return field in flag_values

    def is_field_from_json(field, ip, host_entry=None):
        if not json_values:
            return False
        # check per-host overrides
        hv = json_values.get("hosts") if isinstance(json_values, dict) else None
        if isinstance(hv, list):
            for h in hv:
                if isinstance(h, dict) and h.get("ip") == ip and field in h:
                    return True
        # check top-level override
        if isinstance(json_values, dict) and field in json_values:
            return True
        return False
    for raw_host in env_config["hosts"]:
        host = dict(raw_host) if isinstance(raw_host, dict) else {"ip": raw_host}

        # ip must exist
        ip = host.get("ip")
        if not ip:
            print(f"Error: host entry missing 'ip': {host}")
            return

        # port: prefer host value, else env default, else 22
        port = host.get("port") if host.get("port") else env_defaults.get("port", 22)
        try:
            port = int(port)
        except Exception:
            print(f"Error: invalid port for host {ip}: {host.get('port')}")
            return

        # parent:true strict inheritance
        parent_flag = bool(host.get("parent", False))

        host_prov = {"ip": {"value": ip, "source": "host"}, "port": {"value": port, "source": "host"}}

        final_host = {"ip": ip, "port": port}

        # Fields to apply inheritance or force from parent
        for field in ("username", "private_key", "password", "working_dir"):
            host_val = host.get(field)
            # treat empty string as missing
            if isinstance(host_val, str) and host_val.strip() == "":
                host_val = None

            if parent_flag:
                # strict: force env default (but CLI flags would override; none here)
                value = env_defaults.get(field)
                # if JSON overrides supplied this env-level value, mark source as json
                if value is not None:
                    if is_field_from_flag(field, ip):
                        src = "flag"
                    else:
                        src = "json" if is_field_from_json(field, ip) else "parent"
                    final_host[field] = value
                    host_prov[field] = {"value": ("<redacted>" if field == "password" else value), "source": src}
                else:
                    host_prov[field] = {"value": None, "source": None}
            else:
                # implicit inheritance: host value wins, else env default
                if host_val is not None:
                    # flags override everything
                    if is_field_from_flag(field, ip, host):
                        src = "flag"
                    else:
                        # if a JSON per-host override supplied this value, attribute to json
                        src = "json" if is_field_from_json(field, ip, host) else "host"
                    final_host[field] = host_val
                    host_prov[field] = {"value": ("<redacted>" if field == "password" else host_val), "source": src}
                else:
                    value = env_defaults.get(field)
                    if value is not None:
                        if is_field_from_flag(field, ip):
                            src = "flag"
                        else:
                            src = "json" if is_field_from_json(field, ip) else "env"
                        final_host[field] = value
                        host_prov[field] = {"value": ("<redacted>" if field == "password" else value), "source": src}
                    else:
                        host_prov[field] = {"value": None, "source": None}

        # Resolve private_key path using helper
        pk = final_host.get("private_key")
        if pk:
            pk_abs = resolve_private_key(pk, base_dir)
            final_host["private_key"] = pk_abs
            # update provenance value to show resolved path
            if host_prov.get("private_key"):
                host_prov["private_key"]["value"] = pk_abs

            # ensure file exists
            # warn if the resolved key is outside the base_dir (likely not mounted)
            try:
                if os.path.isabs(pk_abs) and os.path.commonpath([os.path.abspath(base_dir), os.path.abspath(pk_abs)]) != os.path.abspath(base_dir):
                    logging.warning("Resolved private_key %s is outside base_dir %s", pk_abs, base_dir)
            except Exception:
                # In case commonpath raises (different drives), still warn
                logging.warning("Resolved private_key %s may be outside base_dir %s (could not compute commonpath)", pk_abs, base_dir)

            if not os.path.exists(pk_abs):
                logging.error("private_key not found for host %s: %s", ip, pk_abs)
                return

        # Ensure at least one auth method exists
        if not final_host.get("private_key") and not final_host.get("password"):
            print(f"Error: host {ip} missing authentication (private_key or password).")
            logging.error("Missing auth for host %s", ip)
            return

        normalized_hosts.append(final_host)
        provenance_list.append(host_prov)

    # attach normalized hosts back to env_config
    env_config["hosts"] = normalized_hosts

    # Normalize playbook(s) key: prefer 'playbooks' (plural), fall back to 'playbook' for compatibility
    playbooks_list = env_config.get("playbooks") if env_config.get("playbooks") is not None else env_config.get("playbook", [])

    # Generate run artifact (masked) for debugging provenance
    artifact = {"action": args.action, "hosts": provenance_list, "playbooks": playbooks_list}
    artifact_path = os.path.join(base_dir, "run_artifact.json")
    try:
        with open(artifact_path, "w") as af:
            json.dump(artifact, af, indent=2)
    except Exception:
        logging.debug("Failed to write run artifact %s", artifact_path)

    # If user only wants to inspect sources, print the artifact and exit
    if args.show_sources:
        try:
            print(json.dumps(artifact, indent=2))
        except Exception:
            print("(Failed to serialize artifact for display)")
        return

    # Post-normalization validation
    for h in env_config["hosts"]:
        if not h.get("username") and not h.get("password"):
            print(f"Configuration error: Missing username for host {h.get('ip')}")
            return
        if "port" in h and (not isinstance(h["port"], int) or not (1 <= h["port"] <= 65535)):
            print(f"Configuration error: Invalid port for host {h.get('ip')}: {h.get('port')}")
            return

    # Generate log file name with complete date format
    log_file = create_log_file(base_dir)

    # Configure basic logging to the created log file
    logging.basicConfig(filename=log_file, level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    # Also add a console handler that prints WARNING and above to stderr so users see important messages
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)
    console_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
    logging.getLogger().addHandler(console_handler)

    # Simulate tasks for the selected environment
    for host in env_config["hosts"]:
        simulate_ssh(host, host.get("username"), host.get("private_key"))
        for playbook in playbooks_list:
            if not simulate_playbook(playbook, host, base_dir):
                print("Task failed. Stopping execution.")
                return

if __name__ == "__main__":
    main()
