#!/usr/bin/env bash
# ============================================================================
#  setup.sh — Levanta TODO el laboratorio WAAP (Docker + entorno Python)
# ----------------------------------------------------------------------------
#  Qué hace:
#    1. Verifica prerequisitos (Docker, Python 3.10-3.13).
#    2. Crea el entorno virtual local .venv e instala TODAS las dependencias
#       (Fases 3-7) + herramientas del pipeline (semgrep, pip-audit).
#    3. Fija el WAF en modo bloqueo (MODSEC_RULE_ENGINE=On) vía .env.
#    4. Levanta los contenedores Juice Shop (3000) y WAAP-proxy (4000).
#    5. Verifica funcionalmente que el proxy bloquea (SQLi -> 403).
#
#  Uso:
#    ./setup.sh                 # levanta todo
#    ./setup.sh --no-docker     # solo el entorno Python (no toca contenedores)
#    ./setup.sh --recreate      # recrea .venv desde cero
#    ./setup.sh --checkov       # además instala checkov (IaC, opcional)
#    ./setup.sh -h | --help
#
#  Variables:
#    PYTHON=/ruta/a/python3.12  # fuerza un intérprete concreto
# ============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="${ROOT}/.venv"
REQUIREMENTS="${ROOT}/requirements.txt"
ENV_FILE="${ROOT}/.env"
PROXY_URL="http://localhost:4000"
DIRECT_URL="http://localhost:3000"

if [[ -t 1 ]]; then
  C_OK=$'\033[32m'; C_WARN=$'\033[33m'; C_ERR=$'\033[31m'; C_INF=$'\033[36m'; C_OFF=$'\033[0m'
else
  C_OK=""; C_WARN=""; C_ERR=""; C_INF=""; C_OFF=""
fi
info() { printf '%s\n' "${C_INF}[..]${C_OFF} $*"; }
ok()   { printf '%s\n' "${C_OK}[OK]${C_OFF} $*"; }
warn() { printf '%s\n' "${C_WARN}[WARN]${C_OFF} $*" >&2; }
die()  { printf '%s\n' "${C_ERR}[ERR]${C_OFF} $*" >&2; exit 1; }

usage() { sed -n '2,26p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

NO_DOCKER=false; RECREATE=false; WITH_CHECKOV=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-docker) NO_DOCKER=true ;;
    --recreate)  RECREATE=true ;;
    --checkov)   WITH_CHECKOV=true ;;
    -h|--help)   usage; exit 0 ;;
    *) die "opción desconocida: $1 (usa --help)" ;;
  esac
  shift
done

# --- detección del comando de compose --------------------------------------
detect_compose() {
  if docker compose version >/dev/null 2>&1; then echo "docker compose"; return 0; fi
  if command -v docker-compose >/dev/null 2>&1; then echo "docker-compose"; return 0; fi
  return 1
}

# --- selección y validación del intérprete de Python -----------------------
pick_python() {
  if [[ -n "${PYTHON:-}" ]]; then command -v "${PYTHON}" >/dev/null 2>&1 && { echo "${PYTHON}"; return 0; }; return 1; fi
  local c
  for c in python3.13 python3.12 python3.11 python3.10 python3; do
    command -v "$c" >/dev/null 2>&1 && { echo "$c"; return 0; }
  done
  return 1
}
validate_python() {
  "$1" - <<'PY'
import sys
v = sys.version_info
if v[:2] < (3, 10) or v[:2] > (3, 13):
    sys.exit(f"Python {v.major}.{v.minor} fuera de rango; se requiere 3.10-3.13")
print(f"Python {v.major}.{v.minor}.{v.micro} compatible")
PY
}

printf '%s\n' "== Bootstrap laboratorio WAAP =="
printf '%s\n' "Raíz: ${ROOT}"

# 1) Prerequisitos ------------------------------------------------------------
PY="$(pick_python)" || die "No se encontró Python 3.10-3.13. Instálalo o usa PYTHON=/ruta/python3.12 ./setup.sh"
info "Intérprete: ${PY} ($(command -v "${PY}"))"
validate_python "${PY}" || die "Versión de Python incompatible"
ok "Python compatible"

# 2) Entorno virtual + dependencias ------------------------------------------
if ${RECREATE}; then info "Eliminando .venv previo"; rm -rf "${VENV}"; fi
if [[ ! -d "${VENV}" ]]; then info "Creando ${VENV}"; "${PY}" -m venv "${VENV}"; fi
info "Actualizando pip"
"${VENV}/bin/pip" install --quiet --upgrade pip
info "Instalando dependencias del laboratorio (Fases 3-7)"
"${VENV}/bin/pip" install --quiet -r "${REQUIREMENTS}"
info "Instalando herramientas del pipeline (semgrep, pip-audit)"
"${VENV}/bin/pip" install --quiet semgrep pip-audit
if ${WITH_CHECKOV}; then
  info "Instalando checkov (IaC)"
  "${VENV}/bin/pip" install --quiet checkov
fi
ok "Entorno Python listo: ${VENV}"

# 3-5) Docker: WAF en modo bloqueo y contenedores arriba ----------------------
if ${NO_DOCKER}; then
  warn "--no-docker: se omite el arranque de contenedores"
else
  command -v docker >/dev/null 2>&1 || die "docker no está instalado"
  COMPOSE="$(detect_compose)" || die "no se encontró 'docker compose' ni 'docker-compose'"
  info "Usando: ${COMPOSE}"

  # Fija el WAF en modo bloqueo. .env está en .gitignore, no se sube al repo.
  info "Escribiendo ${ENV_FILE} con MODSEC_RULE_ENGINE=On"
  cat > "${ENV_FILE}" <<'EOF'
# Generado por setup.sh — configuración del laboratorio (WAF en modo bloqueo).
MODSEC_RULE_ENGINE=On
PARANOIA=1
ANOMALY_INBOUND=5
ANOMALY_OUTBOUND=4
EOF

  info "Levantando contenedores (juice-shop:3000, waap-proxy:4000)"
  ( cd "${ROOT}" && ${COMPOSE} up -d --force-recreate )

  info "Esperando a que Juice Shop responda (puede tardar ~20-40s)"
  ok_direct=false
  for _ in $(seq 1 40); do
    code="$(curl -s -o /dev/null -w '%{http_code}' "${DIRECT_URL}/" 2>/dev/null || true)"
    if [[ "${code}" == "200" ]]; then ok_direct=true; break; fi
    sleep 2
  done
  ${ok_direct} && ok "Juice Shop responde 200 en ${DIRECT_URL}" || warn "Juice Shop aún no responde 200 (revisa: docker logs mecanismos-juice-shop-1)"

  info "Verificando que el WAF bloquea (SQLi -> 403)"
  home_code="$(curl -s -o /dev/null -w '%{http_code}' "${PROXY_URL}/" 2>/dev/null || true)"
  sqli_code="$(curl -s -o /dev/null -w '%{http_code}' "${PROXY_URL}/rest/products/search?q=%27%20OR%20%271%27%3D%271" 2>/dev/null || true)"
  info "Proxy home=${home_code}  SQLi=${sqli_code}"
  if [[ "${sqli_code}" == "403" ]]; then
    ok "WAF activo: el ataque SQLi fue bloqueado (403)"
  else
    warn "El SQLi no devolvió 403 (obtuvo ${sqli_code}). Verifica el modo del proxy: docker exec mecanismos-waap-proxy-1 sh -c 'echo \$MODSEC_RULE_ENGINE'"
  fi
fi

cat <<EOF

${C_OK}== Laboratorio listo ==${C_OFF}
  Entorno Python : source .venv/bin/activate
  Juice Shop     : ${DIRECT_URL}
  Proxy WAAP     : ${PROXY_URL}  (WAF en modo On)

Ejecuta las fases con la guía en docs/guia-laboratorio-waap.md
Para bajar todo:  ./shutdown.sh
EOF
