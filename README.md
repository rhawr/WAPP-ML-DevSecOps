# Taller WAAP — Web Application and API Protection

**Universidad Distrital Francisco José de Caldas**  
Facultad de Ingeniería — Ingeniería de Sistemas  
Materia: Mecanismos de Seguridad Informática  
Profesor: Octavio J. Salcedo Parra  

## Integrantes

| Nombre | Correo |
|---|---|
| Javier Alejandro Penagos Hernandez | 20221020028 |
| Laura Daniela Muñoz Ipus | 20221020022 |
| Jhonatan David Moreno Barragan | 20201020094 |

---

## Descripción

Prototipo funcional de plataforma **WAAP (Web Application and API Protection)** que integra cuatro capas de defensa en profundidad:

| Capa | Tecnología | Estado |
|---|---|---|
| Motor de reglas (WAF) | ModSecurity + OWASP CRS 3.3.10 | [+] Fase 2 completa |
| Detección por IA/ML | Isolation Forest (scikit-learn) | [+] Fase 3 completa |
| Protección en ejecución (RASP) | Middleware Python (Flask/WSGI) | [+] Fase 4 completa |
| Pipeline DevSecOps | GitHub Actions (Semgrep, pip-audit, Trivy, Checkov, ZAP) | [~] Fase 5 pendiente |

La aplicación objetivo es **OWASP Juice Shop**, desplegada en un entorno de laboratorio local completamente aislado. Todos los ataques se ejecutan únicamente contra esta instancia controlada.

---

## Arquitectura

```mermaid
flowchart TD
    Client(["Cliente / Atacante\ncurl · ZAP · scripts"])

    subgraph WAAP ["CAPA WAAP — localhost:4000"]
        direction LR
        WAF["Motor de reglas\nModSecurity + OWASP CRS 3.3.10"]
        ML["Módulo IA/ML\nIsolation Forest"]
        Orq{{"Orquestador\nallow / block / alert"}}
        WAF --> Orq
        ML --> Orq
    end

    subgraph Target ["Aplicación objetivo — localhost:3000"]
        JS["OWASP Juice Shop"]
        RASP["Agente RASP\nmiddleware runtime"]
        JS --> RASP
    end

    Logs[("Logging JSON\nObservabilidad")]

    subgraph Pipeline ["PIPELINE DEVSECOPS — CI/CD"]
        CI["Semgrep · pip-audit · Trivy · Checkov · ZAP"]
    end

    Client -->|"HTTP request"| WAAP
    Orq -->|"permitido"| Target
    Orq -->|"bloqueado 403"| Client
    RASP --> Logs
    Orq --> Logs
    Pipeline -.->|"valida antes del despliegue"| WAAP
```

Flujo de una petición:
1. El motor de reglas (ModSecurity + OWASP CRS) evalúa la petición contra firmas conocidas.
2. El módulo IA/ML calcula un score de anomalía con Isolation Forest.
3. El orquestador combina ambos resultados y decide: permitir, bloquear o alertar.
4. Si pasa, el agente RASP intercepta operaciones peligrosas en tiempo de ejecución.
5. Todos los eventos se registran en JSON estructurado para observabilidad (Fase 7).

---

## Requisitos

### Software

| Componente | Versión mínima |
|---|---|
| Docker + Docker Compose | Docker 24+ |
| Python | 3.10+ |
| curl | cualquiera |

### Hardware sugerido

- CPU: 4 núcleos (recomendado 8)
- RAM: 8 GB mínimo, 16 GB recomendado
- Disco: 20 GB libres

---

## Estructura del repositorio

```
.
├── docker-compose.yml              # Juice Shop + proxy WAAP
├── docs/                           # Documentación por fase
│   ├── fase-0-preparacion.md
│   ├── fase-1-app-vulnerable.md
│   ├── fase-2-waf-reglas.md
│   └── fase-3-ia-ml.md
├── traffic_agent/                  # Módulo IA/ML (Fase 3)
│   ├── agent.py                    # Genera tráfico etiquetado contra el proxy
│   ├── features.py                 # Extracción de 9 features por petición
│   ├── train_model.py              # Entrena Isolation Forest → model.pkl
│   ├── evaluate_model.py           # Evalúa el modelo con métricas completas
│   ├── model.pkl                   # Modelo serializado (entregable Fase 3)
│   ├── requirements.txt
│   ├── generators/
│   │   ├── normal.py               # Generador de tráfico legítimo
│   │   └── attack.py               # Generador de ataques con variantes de encoding
│   ├── loaders/
│   │   ├── csic_loader.py          # Cargador dataset CSIC 2010
│   │   └── params_loader.py        # Cargador dataset HTTP Params
│   └── logs/
│       ├── traffic_dataset.csv     # 500 peticiones etiquetadas
│       ├── features_normal_traffic.csv
│       ├── evaluation_predictions.csv
│       └── evaluation_metrics.json
├── observability/                  # Logging JSON unificado (base de Fase 7)
│   └── logger.py
├── app/                            # App instrumentada con RASP (Fase 4)
│   ├── vulnerable_app.py           # App Flask con operaciones sensibles
│   ├── rasp_agent.py               # Decoradores/guardas RASP
│   ├── run_rasp_tests.py           # Casos de prueba + latencia
│   ├── Dockerfile
│   └── requirements.txt
├── pipeline/                       # Pipeline DevSecOps (Fase 5 — pendiente)
│   └── .github/workflows/devsecops.yml
└── README.md
```

---

## Inicio rápido

### 1. Levantar el entorno Docker

```bash
# Clonar el repositorio y entrar al directorio
cd ~/Documents/UD/Mecanismos

# Levantar Juice Shop (puerto 3000) + proxy WAAP ModSecurity (puerto 4000)
docker compose up -d

# Verificar que ambos contenedores están corriendo
docker compose ps
```

| Servicio | URL | Descripción |
|---|---|---|
| Juice Shop (directo) | http://localhost:3000 | Sin WAF — para pruebas de explotación base |
| WAAP Proxy | http://localhost:4000 | Con ModSecurity + OWASP CRS |

> El puerto 8080 está reservado por Burp Suite, por eso el proxy usa el 4000.

### 2. Configurar el entorno Python (módulo IA/ML)

```bash
cd traffic_agent

# Crear el entorno virtual
python3 -m venv envTrafficAgent

# Activar el entorno
source envTrafficAgent/bin/activate

# Instalar dependencias (incluye scikit-learn, joblib, numpy)
pip install -r requirements.txt
```

### 3. Generar tráfico y entrenar el modelo

```bash
# Con el entorno activado y docker compose corriendo:

# Paso 1: Generar 200 peticiones normales + 300 ataques contra el proxy
python agent.py

# Paso 2: Entrenar Isolation Forest con el tráfico normal capturado
python train_model.py

# Paso 3: Evaluar el modelo contra el dataset completo
python evaluate_model.py
```

### 4. Ejecutar la Fase 4 (RASP)

La Fase 4 no requiere Docker ni el laboratorio de Juice Shop: la app vulnerable y el agente RASP
corren como un proceso Flask local.

```bash
# Opción A: entorno dedicado (recomendado)
python3 -m venv envRasp
source envRasp/bin/activate
pip install -r app/requirements.txt

# Opción B: instalar sobre el entorno actual
pip install -r app/requirements.txt

# Ejecutar los casos de prueba y la medición de latencia
python app/run_rasp_tests.py
```

Genera:

| Archivo | Contenido |
|---|---|
| `logs/rasp_test_results.json` | Casos (SQLi fragmentado, XSS doble-encode, path traversal, deserialización) + latencia |
| `logs/rasp_latency.csv` | Muestras individuales de latencia RASP on/off |
| `logs/waap_events.jsonl` | Flujo estructurado de eventos, con `verdict: block` y `guard_ms` |

Para levantar la app manualmente y atacarla con `curl`:

```bash
python app/vulnerable_app.py            # http://127.0.0.1:5000 con RASP activo
PORT=5050 RASP_ENABLED=false python app/vulnerable_app.py   # sin RASP
```

Ejemplo de bloqueo en tiempo de ejecución:

```bash
# RASP activo → 403
curl -i "http://127.0.0.1:5000/api/Products/search?q=%27%20OR%201&extra=%3D1--"
```

---

## Progreso por fases

### [+] Fase 0 — Preparación del entorno
- Contenedores `juice-shop` y `waap-proxy` corriendo.
- ModSecurity v3.0.16 + OWASP CRS 3.3.10 con 929 reglas cargadas.
- Acceso verificado en `localhost:3000` (directo) y `localhost:4000` (proxy).
- Documentación: [`docs/fase-0-preparacion.md`](docs/fase-0-preparacion.md)

### [+] Fase 1 — Aplicación vulnerable
Cinco vulnerabilidades identificadas y explotadas contra `localhost:3000`:

| # | Vulnerabilidad | OWASP Top 10 2021 | Endpoint |
|---|---|---|---|
| 1 | SQL Injection en login | A03 – Injection | `POST /rest/user/login` |
| 2 | XSS reflejado en búsqueda | A03 – Injection | `GET /rest/products/search?q=` |
| 3 | IDOR en pedidos | A01 – Broken Access Control | `GET /rest/basket/{id}` |
| 4 | API no documentada expuesta | A05 – Security Misconfiguration | `GET /api-docs`, `/api/Users` |
| 5 | Fuerza bruta sin límite | A07 – Auth Failures | `POST /rest/user/login` |

- Documentación: [`docs/fase-1-app-vulnerable.md`](docs/fase-1-app-vulnerable.md)

### [+] Fase 2 — WAF con motor de reglas
- Motor cambiado de `DetectionOnly` → `On` para bloqueo activo.
- SQLi `' OR 1=1--` bloqueado con `HTTP 403` (regla 942100, score anomalía = 5).
- XSS `<script>` directo bloqueado (regla 941100).
- **Caso de evasión:** XSS con doble URL encoding (`%2527...`) evade Paranoia Level 1 → `HTTP 200`.
- Documentación: [`docs/fase-2-waf-reglas.md`](docs/fase-2-waf-reglas.md)

### [+] Fase 3 — Detección por IA/ML

**Modelo:** Isolation Forest no supervisado entrenado sobre 200 peticiones normales reales.

**Features (9):** `status_code`, `response_time_ms`, `url_length`, `body_length`, `entropy`, `n_params`, `has_suspicious_chars`, `param_max_length`, `special_char_ratio`.

**Resultados sobre 500 peticiones (200 normales + 300 ataques):**

| Métrica | Valor |
|---|---|
| Accuracy | 86.00% |
| Recall (detección de ataques) | 83.33% |
| Precisión | 92.59% |
| F1 | 87.72% |
| Tasa de falsos positivos | 10.00% |
| ROC-AUC | 0.9217 |

- Artefacto: [`traffic_agent/model.pkl`](traffic_agent/model.pkl)
- Métricas: [`traffic_agent/logs/evaluation_metrics.json`](traffic_agent/logs/evaluation_metrics.json)
- Documentación: [`docs/fase-3-ia-ml.md`](docs/fase-3-ia-ml.md)

### [+] Fase 4 — Agente RASP

Agente en proceso (`app/rasp_agent.py`) con decoradores que inspeccionan el **valor final** antes de
ejecutarlo: consulta SQL concatenada, valor reflejado en HTML, ruta de archivo y blob serializado.
Bloquea con `HTTP 403` y registra cada decisión en JSON estructurado.

| Caso | RASP off | RASP on |
|---|---|---|
| SQLi fragmentado (`q=' OR 1` + `extra='=1--'`) | 200 — ejecuta `... OR 1=1--` | **403** |
| XSS doble-encode (evasión Fase 2) | 200 — `<script>alert(1)</script>` | **403** |
| Path traversal (`../outside_secret.txt`) | 200 — lee archivo externo | **403** |
| Deserialización (`__reduce__: os.system`) | 200 | **403** |

**Latencia** (150 muestras/escenario): RASP on 2.285 ms vs off 1.990 ms → **+0.294 ms (+14.8 %)**;
inspección interna del guard: **0.035 ms** de media. Tráfico legítimo sin falsos positivos.

- Artefactos: [`logs/rasp_test_results.json`](logs/rasp_test_results.json),
  [`logs/rasp_latency.csv`](logs/rasp_latency.csv), [`logs/waap_events.jsonl`](logs/waap_events.jsonl)
- Documentación: [`docs/fase-4-rasp.md`](docs/fase-4-rasp.md)

### [~] Fase 5 — Pipeline DevSecOps
GitHub Actions con: SAST (Semgrep), SCA (pip-audit), Container scan (Trivy), IaC scan (Checkov), DAST (OWASP ZAP).

### [~] Fase 6 — Pruebas de evasión
Matriz comparativa de efectividad por capa (reglas, IA/ML, RASP) frente a técnicas de evasión.

### [~] Fase 7 — Observabilidad y métricas
Panel de métricas centralizadas: tasa de detección, FP, MTTD y recomendación de ajuste de umbrales.

---

## Configuración Docker Compose

```yaml
services:
  juice-shop:
    image: bkimminich/juice-shop
    ports:
      - "3000:3000"

  waap-proxy:
    image: owasp/modsecurity-crs:nginx-alpine
    ports:
      - "4000:8080"
    environment:
      - BACKEND=http://juice-shop:3000
      - MODSEC_RULE_ENGINE=DetectionOnly   # Cambiar a "On" en Fase 2
      - PARANOIA=1
      - ANOMALY_INBOUND=5
      - ANOMALY_OUTBOUND=4
    depends_on:
      - juice-shop
```

---

## Marco normativo

- **OWASP Top 10 (2021)** — catálogo de riesgos para los casos de prueba.
- **MITRE ATT&CK T1190** — Exploit Public-Facing Application.
- **NIST SP 800-53** — controles SC-7 (Boundary Protection) y SI-4 (System Monitoring).
- **PCI DSS v4.0, requisito 6.4.2** — protección automatizada de aplicaciones web.
- **CIS Controls v8, control 16** — Application Software Security.

---

## Nota ética

Este laboratorio es de carácter exclusivamente académico y opera en un entorno aislado (red interna Docker). Todos los ataques se ejecutan únicamente contra OWASP Juice Shop desplegado localmente por el propio estudiante. Ninguna técnica documentada se aplica contra sistemas de terceros ni redes externas.

---

## Referencias

- OWASP Foundation. *OWASP Top 10:2021.* https://owasp.org/Top10/
- OWASP Foundation. *OWASP Core Rule Set (CRS).* https://coreruleset.org/
- OWASP Foundation. *OWASP Juice Shop.* https://owasp.org/www-project-juice-shop/
- MITRE. *ATT&CK Framework — T1190.* https://attack.mitre.org/
- scikit-learn developers. *Isolation Forest — User Guide.* https://scikit-learn.org/
- Gartner. *Market Guide for Cloud Web Application and API Protection.*
