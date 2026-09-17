#!/usr/bin/env bash
# Deploy the versioned WAAP policy (policy as code). Invoked by the pipeline
# only after every security gate has passed. In this academic lab "deploy"
# validates the policy file and records a deployment marker instead of touching
# a production WAAP.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RULES="${ROOT}/waap/rules/waap_rules.yaml"
MARKER="${ROOT}/logs/waap_rules_deployed.json"

if [[ ! -f "${RULES}" ]]; then
  echo "[deploy] ERROR: no existe ${RULES}" >&2
  exit 1
fi

python3 - "${RULES}" "${MARKER}" <<'PY'
import datetime
import hashlib
import json
import pathlib
import sys

rules_path, marker_path = sys.argv[1], sys.argv[2]
data = pathlib.Path(rules_path).read_bytes()
version, rule_engine = "unknown", "unknown"

try:
    import yaml

    document = yaml.safe_load(data) or {}
    version = str(document.get("version", "unknown"))
    rule_engine = str((document.get("waf") or {}).get("rule_engine", "unknown"))
except Exception as error:  # noqa: BLE001 - PyYAML is optional
    sys.stderr.write(f"[deploy] aviso: validación YAML básica ({error})\n")
    for line in data.decode("utf-8", "replace").splitlines():
        if line.startswith("version:"):
            version = line.split(":", 1)[1].strip().strip('"')

marker = {
    "deployed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "rules_file": str(rules_path),
    "version": version,
    "waf_rule_engine": rule_engine,
    "sha256": hashlib.sha256(data).hexdigest(),
    "status": "deployed",
}
pathlib.Path(marker_path).parent.mkdir(parents=True, exist_ok=True)
pathlib.Path(marker_path).write_text(json.dumps(marker, indent=2, ensure_ascii=False), encoding="utf-8")
print(f"[deploy] reglas WAAP v{version} desplegadas -> {marker_path}")
PY
