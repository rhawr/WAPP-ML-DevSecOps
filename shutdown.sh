#!/usr/bin/env bash
# ============================================================================
#  shutdown.sh — Baja TODO el laboratorio WAAP y no deja rastro de ejecución
# ----------------------------------------------------------------------------
#  Qué elimina SIEMPRE:
#    - Contenedores del lab (juice-shop, waap-proxy) y su red (docker compose down).
#    - Entorno virtual local .venv.
#    - Cachés de Python (__pycache__, *.pyc) y el .env generado por setup.sh.
#    - Marcadores de despliegue del pipeline (logs/waap_rules_deployed.json).
#
#  Qué CONSERVA por defecto (son entregables, no basura):
#    - El código fuente y la documentación (docs/).
#    - Las evidencias regeneradas en logs/ (matriz, métricas, latencia, eventos).
#
#  Opciones:
#    --purge-evidence   Borra también las evidencias generadas en logs/ (deja
#                       el repo como recién clonado). ÚSALO con cuidado.
#    --images           Elimina también las imágenes Docker del lab (juice-shop,
#                       modsecurity-crs). Tendrás que re-descargarlas luego.
#    --keep-venv        No borra .venv (útil si solo quieres apagar Docker).
#    -h | --help
# ============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="${ROOT}/.venv"

if [[ -t 1 ]]; then
  C_OK=$'\033[32m'; C_WARN=$'\033[33m'; C_ERR=$'\033[31m'; C_INF=$'\033[36m'; C_OFF=$'\033[0m'
else
  C_OK=""; C_WARN=""; C_ERR=""; C_INF=""; C_OFF=""
fi
info() { printf '%s\n' "${C_INF}[..]${C_OFF} $*"; }
ok()   { printf '%s\n' "${C_OK}[OK]${C_OFF} $*"; }
warn() { printf '%s\n' "${C_WARN}[WARN]${C_OFF} $*" >&2; }

usage() { sed -n '2,25p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

PURGE_EVIDENCE=false; RM_IMAGES=false; KEEP_VENV=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --purge-evidence) PURGE_EVIDENCE=true ;;
    --images)         RM_IMAGES=true ;;
    --keep-venv)      KEEP_VENV=true ;;
    -h|--help)        usage; exit 0 ;;
    *) warn "opción desconocida: $1 (usa --help)"; exit 1 ;;
  esac
  shift
done

detect_compose() {
  if docker compose version >/dev/null 2>&1; then echo "docker compose"; return 0; fi
  if command -v docker-compose >/dev/null 2>&1; then echo "docker-compose"; return 0; fi
  return 1
}

printf '%s\n' "== Apagando laboratorio WAAP =="

# 1) Contenedores + red -------------------------------------------------------
if command -v docker >/dev/null 2>&1 && COMPOSE="$(detect_compose)"; then
  info "Deteniendo y eliminando contenedores + red (${COMPOSE} down)"
  down_args=""
  ${RM_IMAGES} && down_args="--rmi all"
  ( cd "${ROOT}" && ${COMPOSE} down ${down_args} ) || warn "compose down devolvió error (¿ya estaban abajo?)"
  ok "Contenedores del lab eliminados"
  ${RM_IMAGES} && ok "Imágenes del lab eliminadas"
else
  warn "docker/compose no disponible; se omite el apagado de contenedores"
fi

# 2) Entorno virtual ----------------------------------------------------------
if ${KEEP_VENV}; then
  info "--keep-venv: se conserva ${VENV}"
elif [[ -d "${VENV}" ]]; then
  info "Eliminando entorno virtual ${VENV}"
  rm -rf "${VENV}"
  ok ".venv eliminado"
fi

# 3) Cachés, .env y marcadores de ejecución ----------------------------------
info "Limpiando cachés de Python y artefactos de ejecución"
find "${ROOT}" -type d -name '__pycache__' -not -path '*/envTrafficAgent/*' -prune -exec rm -rf {} + 2>/dev/null || true
find "${ROOT}" -type f \( -name '*.pyc' -o -name '*.pyo' \) -not -path '*/envTrafficAgent/*' -delete 2>/dev/null || true
rm -f "${ROOT}/.env" "${ROOT}/logs/waap_rules_deployed.json"
ok "Cachés, .env y marcadores eliminados"

# 4) Evidencias (opcional) ----------------------------------------------------
if ${PURGE_EVIDENCE}; then
  warn "--purge-evidence: borrando evidencias regeneradas en logs/"
  rm -f "${ROOT}/logs/"evasion_matrix.{csv,json} \
        "${ROOT}/logs/"metrics_report.md \
        "${ROOT}/logs/"metrics_dashboard.json \
        "${ROOT}/logs/"rasp_latency.csv \
        "${ROOT}/logs/"rasp_test_results.json \
        "${ROOT}/logs/"waap_events.jsonl \
        "${ROOT}/logs/"pipeline_report.json \
        "${ROOT}/logs/"pipeline_verification.json 2>/dev/null || true
  rm -rf "${ROOT}/logs/sqlmap" "${ROOT}/logs/entrega" 2>/dev/null || true
  ok "Evidencias en logs/ eliminadas"
else
  info "Evidencias en logs/ conservadas (usa --purge-evidence para borrarlas)"
fi

cat <<EOF

${C_OK}== Laboratorio apagado ==${C_OFF}
  Contenedores : eliminados
  .venv        : $(${KEEP_VENV} && echo conservado || echo eliminado)
  Evidencias   : $(${PURGE_EVIDENCE} && echo eliminadas || echo conservadas en logs/)

Para volver a levantar todo:  ./setup.sh
EOF
