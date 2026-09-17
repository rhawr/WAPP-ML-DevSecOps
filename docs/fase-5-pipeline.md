# Fase 5 — Pipeline DevSecOps

## Objetivo

Construir un pipeline CI/CD que valide automáticamente el código de la aplicación, sus dependencias,
la imagen de contenedor y la configuración de infraestructura, **bloqueando el despliegue** si
detecta hallazgos críticos, y que solo entonces despliegue de forma automática las reglas/umbrales
versionados del WAAP (policy as code).

## Enfoque elegido

El taller propone GitHub Actions. Como la ejecución se hace en un entorno local (sin depender de
GitHub), la puerta de seguridad se implementa como un **runner local en Python**
(`pipeline/run_pipeline.py`) que invoca exactamente las mismas herramientas. El workflow de GitHub
Actions queda incluido como artefacto en `pipeline/.github/workflows/devsecops.yml` (para activarlo
hay que copiarlo a `.github/workflows/`).

## Etapas del pipeline

| # | Control | Herramienta | Comando | Falla el gate si… |
|---|---|---|---|---|
| 1 | SAST | Semgrep | `semgrep --config pipeline/semgrep-rules.yaml --error app/` | hay un patrón inseguro |
| 2 | SCA | pip-audit | `pip-audit -r app/requirements.txt` | hay una dependencia con CVE |
| 3 | Build | Docker | `docker build -f app/Dockerfile -t taller-waap/app:local .` | falla la construcción |
| 4 | Container scan | Trivy | `trivy image --severity HIGH,CRITICAL --exit-code 1 taller-waap/app:local` | hay vulnerabilidades HIGH/CRITICAL |
| 5 | IaC scan | Checkov | `checkov --file app/Dockerfile --file docker-compose.yml` | configuración insegura |
| 6 | DAST | OWASP ZAP | `zap-baseline.py -t http://host.docker.internal:4000` | hallazgos en la app protegida |
| 7 | Deploy | shell | `bash scripts/deploy_waap_rules.sh` | — (solo corre si 1–6 pasan) |

Cada etapa es una **puerta**: si una falla, el runner se detiene en la lógica de reporte (registra
`failed_stages`) y **no ejecuta el despliegue**. Las herramientas no instaladas se reportan como
`skipped` (con `--strict` pasan a `failed`).

### Reglas SAST locales

Para que el gate sea determinista y no dependa de la red, `pipeline/semgrep-rules.yaml` define
reglas propias: construcción de SQL por concatenación (CWE-89), `subprocess(shell=True)` (CWE-78),
`pickle.loads` (CWE-502) y `eval`/`exec` (CWE-95).

Los dos sinks **deliberadamente vulnerables** de la Fase 4 están anotados como aceptados:

```python
# nosemgrep: waap-python-sql-string-building  (sink deliberadamente vulnerable, Fase 4)
return f"SELECT email, role FROM users WHERE email = '{email}' AND password = '{password}'"
```

Así la línea base es verde y cualquier consulta concatenada **nueva y no anotada** rompe el pipeline,
que es exactamente el ejercicio de verificación.

## Policy as code

`waap/rules/waap_rules.yaml` versiona en Git la configuración del WAAP: modo del motor CRS
(`On`), Paranoia Level, umbrales de anomalía, umbral del modelo ML (`anomaly_threshold`), guardas
RASP activas y el archivo de eventos. El despliegue (`scripts/deploy_waap_rules.sh`) valida el YAML y
escribe un marcador con versión y hash SHA-256 en `logs/waap_rules_deployed.json`; solo el pipeline
en verde lo invoca.

## Uso

```bash
# Dependencias de las herramientas (una sola vez)
python3 -m venv envPipeline && source envPipeline/bin/activate
pip install semgrep pip-audit checkov

# Trivy y ZAP funcionan con Docker; sin Docker esas etapas se omiten.
# (opcional) binario de Trivy:
#   https://aquasecurity.github.io/trivy/latest/getting-started/installation/

# Ejecutar el pipeline
python pipeline/run_pipeline.py

# Modo estricto: cualquier herramienta ausente bloquea el despliegue
python pipeline/run_pipeline.py --strict

# Ejecutar solo algunas etapas
python pipeline/run_pipeline.py --only sast-semgrep,sca-pip-audit

# Solo evaluar el gate, sin desplegar reglas
python pipeline/run_pipeline.py --no-deploy
```

Salida esperada con todas las herramientas instaladas:

```
[OK]    SAST      sast-semgrep       (…)
[OK]    SCA       sca-pip-audit      (…)
[OK]    BUILD     build-image        (…)
[OK]    CONTAINER container-trivy    (…)
[OK]    IaC       iac-checkov        (…)
[OK]    DAST      dast-zap           (…)
[OK]    DEPLOY    deploy-waap-rules  (…)
RESULTADO: VERDE — despliegue habilitado
```

Sin herramientas instaladas el runner degrada sin romper:

```
[SKIP]  SAST      sast-semgrep       (…)
...
[OK]    DEPLOY    deploy-waap-rules  (…)
RESULTADO: VERDE — despliegue habilitado
```

## Ejercicio de verificación automatizado

`pipeline/verify_pipeline.py` ejecuta el ciclo completo del taller:

1. **Línea base** → se espera verde.
2. **Inyecta** una vulnerabilidad:
   - `--mode sast` (por defecto): crea `app/insecure_extra.py` con una consulta SQL concatenada
     → debe fallar la etapa `sast-semgrep`.
   - `--mode sca`: agrega `PyYAML==5.3.1` (CVEs públicos) a `app/requirements.txt`
     → debe fallar la etapa `sca-pip-audit`.
3. **Revierte** el cambio.
4. **Re-ejecuta** → se espera verde y con despliegue de reglas.

```bash
python pipeline/verify_pipeline.py --mode sast
python pipeline/verify_pipeline.py --mode sca
```

Salida esperada:

```
================================================================================
VERIFICACIÓN DEL PIPELINE
  [OK]  baseline_green
  [OK]  injected_red
  [OK]  failed_at_expected_stage
  [OK]  revert_green
RESULTADO: EXITOSO
Reporte: logs/pipeline_verification.json
```

## Entregable

- `pipeline/run_pipeline.py` — runner local con las 6 puertas de seguridad + despliegue.
- `pipeline/semgrep-rules.yaml` — reglas SAST propias (offline).
- `pipeline/verify_pipeline.py` — verificación rojo/verde del ejercicio.
- `pipeline/.github/workflows/devsecops.yml` — workflow equivalente para GitHub Actions.
- `waap/rules/waap_rules.yaml` y `scripts/deploy_waap_rules.sh` — policy as code y despliegue.
- `logs/pipeline_report.json` y `logs/pipeline_verification.json` — evidencias estructuradas.

## Conclusión de la fase

El gate de seguridad impide el despliegue de las reglas del WAAP ante cualquier hallazgo crítico. La
verificación demuestra el flujo completo del taller: línea base verde, detección de una
vulnerabilidad inyectada (SAST o SCA) con bloqueo en la etapa correspondiente, y retorno a verde con
despliegue automático tras revertir. El enfoque *policy as code* garantiza que reglas y umbrales
viajen versionados y solo lleguen al entorno tras superar las puertas.
