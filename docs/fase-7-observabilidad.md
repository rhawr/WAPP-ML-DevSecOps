# Fase 7 — Observabilidad y métricas

## Objetivo

Cerrar el ciclo de defensa en profundidad con visibilidad centralizada de los eventos de seguridad y
con métricas que permitan justificar decisiones de *tuning* de las reglas y del modelo: tasa de
detección, falsos positivos, falsos negativos y un indicador de tiempo medio de detección (MTTD).

## Centralización de logs

Todas las capas escriben en un **único flujo JSON-lines** mediante `observability/logger.py`:

```json
{"timestamp": "...", "layer": "rasp", "verdict": "block", "event": "sql_injection",
 "request_id": "...", "target": "build_search_query", "matched_rule": "numeric_tautology",
 "matched_text": "OR 1=1", "inspected": "SELECT ...", "guard_ms": 0.0166}
```

| Campo | Descripción |
|---|---|
| `layer` | `waf` / `ml` / `rasp` / `orchestrator` / `pipeline` / `observability` |
| `verdict` | `allow` / `block` / `alert` |
| `event` | Tipo de evento (`sql_injection`, `xss`, `path_traversal`, `deserialization`, `security_gate`…) |
| `request_id` | Correlación de una misma petición entre capas |
| `guard_ms` | Latencia de inspección del guard (para MTTD) |

El archivo resultante es `logs/waap_events.jsonl`. Opcionalmente este flujo se puede enviar a
Wazuh/ELK añadiendo un *shipper* que lea el JSONL; aquí se mantiene en archivo estructurado.

## Cálculo de métricas

`observability/collect_metrics.py` consume:

| Fuente | Contenido |
|---|---|
| `logs/evasion_matrix.json` | Resultado por capa de la Fase 6 (casos maliciosos + controles benignos) |
| `logs/waap_events.jsonl` | Eventos RASP: bloqueos, tipos y `guard_ms` |
| `traffic_agent/logs/evaluation_metrics.json` | Métricas del modelo (accuracy, recall, ROC-AUC) |

y calcula por capa:

- `TP` (malicioso detectado), `FN` (malicioso evadido), `FP` (benigno bloqueado), `TN` (benigno permitido).
- `detection_rate = TP/(TP+FN)`, `FPR = FP/(FP+TN)`, `FNR = FN/(TP+FN)`, `precision = TP/(TP+FP)`.
- **MTTD simulado** = latencia desde la petición hasta la alerta registrada:
  - Reglas: latencia de la respuesta `403` del proxy.
  - IA/ML: latencia de inferencia del modelo (medida sobre las peticiones de la matriz).
  - RASP: `guard_ms` de los eventos de bloqueo (detección in-process).
  - Se puede añadir un retardo de ingesta simulado con `--ingest-delay-ms`.

```bash
python observability/collect_metrics.py
# o con retardo de SIEM simulado:
python observability/collect_metrics.py --ingest-delay-ms 25
```

## Resultado medido

> Captura local en la que el proxy estaba disponible pero en `DetectionOnly` (por eso la columna de
> reglas es todo `No`) y `scikit-learn` no estaba instalado (columna IA/ML `N/A`). Con
> `make lab-up` el WAF queda en `On` y `make phase7` produce las tres columnas completas.

| Capa | TP | FP | FN | TN | Tasa detección | FPR | FNR | Precisión | MTTD (ms) |
|---|---|---|---|---|---|---|---|---|---|
| Reglas (Fase 2) | 0 | 0 | 10 | 3 | 0.0% | 0.0% | 100.0% | N/A | N/A |
| IA/ML (Fase 3) | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | N/A |
| RASP (Fase 4) | 8 | 0 | 1 | 3 | 88.9% | 0.0% | 11.1% | 100.0% | 0.033 |
| **Combinada (∪)** | 8 | 0 | 2 | 3 | **80.0%** | 0.0% | — | — | — |

**Eventos RASP:** 44 bloqueos / 110 permisos; por tipo `{sql_injection: 21, xss: 16, path_traversal: 6, deserialization: 1}`; `guard_ms` medio 0.033 ms (p95 0.072).

**Métricas del modelo (Fase 3):** accuracy 0.86, recall 0.833, F1 0.877, ROC-AUC 0.922.

**Huecos de cobertura (sin detección por ninguna capa):**
- SQLi con comentarios en línea (`OR/**/1=1--`).
- Ráfaga de 20 peticiones (bot).

## Recomendación final de ajuste de umbrales

- **IA/ML:** ampliar el set de entrenamiento normal para estabilizar el umbral; si el FPR supera el
  5 %, bajar `contamination` de 0.10 a 0.05 y/o ajustar `anomaly_threshold`. Incorporar
  `req_per_minute` como feature para cubrir el caso de bot.
- **Reglas:** subir Paranoia Level a 2 y habilitar decodificación múltiple para cubrir
  doble URL-encoding y fragmentación (los dos falsos negativos de las reglas).
- **RASP:** normalizar comentarios SQL (`/**/`, `--`, `#`) antes de aplicar las firmas, o añadir
  `libinjection` a nivel de aplicación, para cerrar el hueco del SQLi con comentarios.
- **Gobernanza de datos:** no reentrenar el modelo directamente con tráfico de producción sin
  validación; aplicar un ciclo de cuarentena/revisión para evitar *data poisoning*.

## Entregable

- `logs/metrics_dashboard.json` — panel completo por capa, MTTD y recomendaciones.
- `logs/metrics_report.md` — reporte legible con las tablas anteriores.
- `observability/collect_metrics.py` — colector de métricas.
- `observability/logger.py` — logging JSON centralizado reutilizado por todas las capas.

## Conclusión de la fase

El logging centralizado y el colector convierten las evidencias dispersas de las fases anteriores en
un panel accionable. La capa RASP es la que más aporta (88.9 % de detección sin falsos positivos
sobre los controles), las reglas dependen del modo del motor y del Paranoia Level, y el modelo
aporta cobertura estadística con un coste de falsos positivos. Los huecos identificados —SQLi con
comentarios y abuso de volumen— no los cubre ninguna capa actual y orientan las recomendaciones de
tuning y la incorporación de rate limiting / features de frecuencia.
