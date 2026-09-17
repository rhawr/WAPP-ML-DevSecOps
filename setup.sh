#!/usr/bin/env bash
# Bootstrap of the WAAP lab: creates the virtual environments and installs the
# dependencies. The ML stack (scikit-learn/pandas/numpy) requires Python
# 3.10-3.12; newer interpreters do not ship compatible wheels yet.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="${ROOT}/.venv"
TOOLS_VENV="${ROOT}/.venv-tools"
REQUIREMENTS="${ROOT}/requirements.txt"
PYTHON_BIN="${PYTHON:-}"

if [[ -t 1 ]]; then
  C_OK=$'\033[32m'; C_WARN=$'\033[33m'; C_ERR=$'\033[31m'; C_OFF=$'\033[0m'
else
  C_OK=""; C_WARN=""; C_ERR=""; C_OFF=""
fi

info() { printf '  %s\n' "$*"; }
ok()   { printf '%s\n' "${C_OK}[OK]${C_OFF} $*"; }
warn() { printf '%s\n' "${C_WARN}[WARN]${C_OFF} $*" >&2; }
die()  { printf '%s\n' "${C_ERR}[ERR]${C_OFF} $*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Uso: ./setup.sh [opciones]

Opciones:
  --check        Solo verifica prerequisitos; no crea entornos ni instala.
  --no-tools     No crea .venv-tools (semgrep/pip-audit/checkov).
  --recreate     Borra y recrea los entornos virtuales.
  -h, --help     Muestra esta ayuda.

Variables:
  PYTHON=/ruta/a/python3.12   Interprete a usar (por defecto se autodetecta).
EOF
}

pick_python() {
  if [[ -n "${PYTHON_BIN}" ]]; then
    command -v "${PYTHON_BIN}" >/dev/null 2>&1 || die "PYTHON=${PYTHON_BIN} no encontrado"
    printf '%s' "${PYTHON_BIN}"
    return 0
  fi
  local candidate
  for candidate in python3.12 python3.11 python3.10 python3; do
    if command -v "${candidate}" >/dev/null 2>&1; then
      printf '%s' "${candidate}"
      return 0
    fi
  done
  return 1
}

validate_python() {
  "$1" - <<'PY'
import sys

version = sys.version_info
if version.major != 3 or version.minor < 10 or version.minor > 12:
    sys.exit(
        f"Python {version.major}.{version.minor}.{version.micro} no soportado; "
        "se requiere Python 3.10-3.12 para las wheels de scikit-learn/pandas/numpy"
    )
print(f"Python {version.major}.{version.minor}.{version.micro} compatible")
PY
}

CHECK_ONLY=false
NO_TOOLS=false
RECREATE=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --check) CHECK_ONLY=true ;;
    --no-tools) NO_TOOLS=true ;;
    --recreate) RECREATE=true ;;
    -h|--help) usage; exit 0 ;;
    *) die "opcion desconocida: $1" ;;
  esac
  shift
done

[[ -f "${REQUIREMENTS}" ]] || die "no existe ${REQUIREMENTS}"

printf '%s\n' "== Bootstrap laboratorio WAAP =="
printf '%s\n' "Raiz: ${ROOT}"

PY="$(pick_python)" || die "No se encontro Python 3.10-3.12. Instalalo o usa: PYTHON=/ruta/python3.12 ./setup.sh"
info "Interprete seleccionado: ${PY} ($(command -v "${PY}"))"
validate_python "${PY}" || die "Version de Python incompatible"
ok "Python compatible"

if command -v podman >/dev/null 2>&1; then
  if podman compose version >/dev/null 2>&1 || command -v podman-compose >/dev/null 2>&1; then
    ok "podman + podman compose presentes"
  else
    warn "podman presente, pero 'podman compose' no responde; instala podman-compose"
  fi
else
  warn "podman no instalado: el laboratorio (Fases 0-2, 6) y Trivy/ZAP no podran ejecutarse"
fi

if command -v trivy >/dev/null 2>&1; then
  ok "trivy presente"
else
  warn "trivy no instalado (opcional) -> https://trivy.dev/latest/docs/getting-started/installation/"
fi

if ${CHECK_ONLY}; then
  ok "Verificacion completada (--check); no se crearon entornos"
  exit 0
fi

if ${RECREATE}; then
  info "Eliminando entornos previos"
  rm -rf "${VENV}" "${TOOLS_VENV}"
fi

if [[ ! -d "${VENV}" ]]; then
  info "Creando entorno principal ${VENV}"
  "${PY}" -m venv "${VENV}"
fi
"${VENV}/bin/pip" install --quiet --upgrade pip
info "Instalando dependencias (Flask, requests, scikit-learn, pandas...)"
"${VENV}/bin/pip" install --quiet -r "${REQUIREMENTS}"
ok "Entorno principal listo: ${VENV}"

if ! ${NO_TOOLS}; then
  if [[ ! -d "${TOOLS_VENV}" ]]; then
    info "Creando entorno de herramientas ${TOOLS_VENV}"
    "${PY}" -m venv "${TOOLS_VENV}"
  fi
  "${TOOLS_VENV}/bin/pip" install --quiet --upgrade pip
  info "Instalando herramientas (semgrep, pip-audit, checkov)"
  "${TOOLS_VENV}/bin/pip" install --quiet semgrep pip-audit checkov
  ok "Entorno de herramientas listo: ${TOOLS_VENV}"
fi

cat <<'EOF'

Siguiente paso:
  make lab-up       # o: docker compose up -d
  make phase3

Activa el entorno principal:
  source .venv/bin/activate
EOF
