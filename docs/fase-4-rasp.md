# Fase 4 — Integración RASP (Runtime Application Self-Protection)

## Objetivo

Instrumentar la aplicación objetivo con un agente embebido que intercepte operaciones sensibles
en tiempo de ejecución (construcción de consultas SQL, reflejo de HTML, resolución de rutas de
archivo y deserialización), demostrando que bloquea payloads que ya habían atravesado el WAF de
reglas (Fase 2) y el módulo IA/ML (Fase 3). Entregables: logs de al menos un bloqueo de un payload
que evadió las capas anteriores y una tabla comparativa de latencia con/sin RASP.

## Diseño del agente

A diferencia del WAF/WAAP perimetral, que analiza la petición HTTP antes de llegar a la aplicación,
el RASP vive **dentro del proceso** y observa el valor **final ya construido/decodificado**. Por eso
es indiferente al URL-encoding, a la fragmentación en varios parámetros o a la ofuscación del
payload: cuando el guard se ejecuta, el dato ya pasó por todas las capas de decodificación de la app.

El agente (`app/rasp_agent.py`) es agnóstico del framework: los decoradores no importan Flask, sino
que lanzan la excepción `RaspBlocked`, y la aplicación la traduce a `HTTP 403`.

| Decorador | Operación sensible | Valor inspeccionado |
|---|---|---|
| `rasp_guard_query` | Construcción de consulta SQL | La **consulta final** ya concatenada, antes de ejecutarla |
| `rasp_guard_output` | Reflejo de datos en HTML | El valor normalizado (multi-decode) antes de renderizar |
| `rasp_guard_path` | Apertura de archivos | La **ruta solicitada** antes de abrirla |
| `rasp_guard_deserialize` | Deserialización | El blob decodificado (base64) antes de deserializar |

La clave frente a la evasión de la Fase 2 (doble URL-encoding) es `decode_deep()`, que deshace
múltiples capas de `%`-encoding y entidades HTML antes de aplicar las firmas:

```python
def decode_deep(value: str, rounds: int = 3) -> str:
    current = html.unescape(value)
    for _ in range(rounds):
        decoded = html.unescape(unquote_plus(current))
        if decoded == current:
            break
        current = decoded
    return current
```

Las reglas se agrupan por tipo: `SQLI_RULES` (tautologías numéricas y de cadena, `UNION SELECT`,
comentarios SQL, stacked queries, time-based, sondeo de metadatos), `XSS_RULES` (`<script>`,
manejadores `on*=`, `javascript:`), `PATH_RULES` (`../`, rutas absolutas, null byte) y
`DESERIALIZE_RULES` (`__reduce__`, `os.system`, gadgets Java).

## Aplicación vulnerable instrumentada

`app/vulnerable_app.py` replica las superficies explotadas en la Fase 1 pero como proceso Python,
que es donde un RASP puede instrumentarse:

| Endpoint | Operación sensible | Vulnerabilidad |
|---|---|---|
| `POST /rest/user/login` | `build_login_query()` | SQLi por concatenación |
| `GET /api/Products/search?q=&extra=` | `build_search_query()` | SQLi fragmentado en 2 parámetros |
| `GET /rest/products/render?q=` | `render_search_term()` | XSS reflejado (doble decodificación) |
| `GET /api/files?name=` | `read_document()` | Path traversal |
| `POST /api/deserialize` | `load_object()` | Deserialización insegura (simulada) |

El login consulta una base SQLite en memoria con un usuario `admin@juice-sh.op`; con el RASP
desactivado, el payload `' OR 1=1--` autentica como administrador, igual que en la Fase 1.

## Casos de prueba

Runner: `app/run_rasp_tests.py`. Levanta la app dos veces en un puerto efímero (RASP `on` y `off`),
ejecuta los casos y mide latencia con 50 peticiones por escenario, 3 ciclos intercalados y 10
peticiones de calentamiento.

### Caso 1 — SQLi fragmentado en dos parámetros

Payload partido en `q="' OR 1"` y `extra="=1--"`. Cada fragmento por separado no constituye una
inyección; la consulta final sí:

```sql
SELECT name FROM products WHERE name LIKE '%' OR 1=1--%'
```

| Fragmento / combinación | RASP on | RASP off |
|---|---|---|
| `q="' OR 1"` solo | 400 (no bloqueado) | 400 |
| `extra="=1--"` solo | 200 (no bloqueado) | 200 |
| **combinado** | **403 (RASP)** | 200 — devuelve los 3 productos |

### Caso 2 — Evasión de la Fase 2 (XSS con doble URL-encoding)

Se reutiliza el payload de evasión documentado en Fase 2 (`%253Cscript%253E...`). El WAF lo dejó
pasar porque solo decodifica un nivel; el RASP lo detecta porque ve el valor post-decodificación.

| Escenario | Resultado |
|---|---|
| RASP off | `200` con `<h1>Resultados para: <script>alert(1)</script></h1>` (XSS ejecutable) |
| RASP on | `403` — evento `xss`, regla `script_tag` |

### Caso 3 (adicional) — Path traversal y deserialización

| Prueba | RASP off | RASP on |
|---|---|---|
| `GET /api/files?name=../outside_secret.txt` | `200` y devuelve el contenido externo | `403` (regla `path_traversal`) |
| `POST /api/deserialize` con `__reduce__: os.system` | `200` y deserializa el objeto | `403` (regla `python_pickle_opcode`) |

### Control — el tráfico legítimo no se ve afectado

`POST /rest/user/login` con credenciales válidas devuelve `200` con RASP on y off. No se observaron
falsos positivos en las peticiones benignas usadas para latencia.

## Tabla comparativa de latencia

Medición extremo a extremo (HTTP + Flask), 150 muestras por escenario:

| Escenario | Media (ms) | Mediana (ms) | p95 (ms) | Máx (ms) |
|---|---|---|---|---|
| RASP **on** | 2.285 | 2.199 | 3.577 | 5.621 |
| RASP **off** | 1.990 | 1.840 | 3.503 | 4.310 |
| **Overhead** | **+0.294 ms** | +0.359 ms | +0.074 ms | +1.311 ms |

Overhead extremo a extremo: **+0.294 ms (+14.8 %)**, muy por debajo del ruido típico de red.

El tiempo de inspección **interno** del guard (medido por el propio agente y registrado en cada
evento) es todavía menor y es la cifra que realmente caracteriza el costo del RASP:

| Métrica del guard | Valor |
|---|---|
| Muestras | 106 |
| Media | 0.035 ms |
| Mediana | 0.032 ms |
| p95 | 0.058 ms |
| Máx | 0.068 ms |

## Evidencias

### Eventos de bloqueo (`logs/waap_events.jsonl`)

```json
{"layer": "rasp", "verdict": "block", "event": "sql_injection", "target": "build_search_query",
 "matched_rule": "numeric_tautology", "matched_text": "OR 1=1",
 "inspected": "SELECT name FROM products WHERE name LIKE '%' OR 1=1--%'", "guard_ms": 0.0166}
{"layer": "rasp", "verdict": "block", "event": "xss", "target": "render_search_term",
 "matched_rule": "script_tag", "matched_text": "<script",
 "inspected": "<script>alert(1)</script>", "guard_ms": 0.0088}
{"layer": "rasp", "verdict": "block", "event": "path_traversal", "target": "read_document",
 "matched_rule": "path_traversal", "matched_text": "../", "guard_ms": 0.0169}
{"layer": "rasp", "verdict": "block", "event": "deserialization", "target": "load_object",
 "matched_rule": "python_pickle_opcode", "matched_text": "__reduce__", "guard_ms": 0.0154}
```

### Respuesta 403 de la aplicación

```json
{"error": "Operación bloqueada por RASP", "event": "sql_injection", "matched_rule": "numeric_tautology"}
```

### Artefactos

- `logs/rasp_test_results.json` — casos + resumen de latencia + tiempo de guarda.
- `logs/rasp_latency.csv` — 300 muestras individuales (`scenario`, `cycle`, `endpoint`, `latency_ms`).
- `logs/waap_events.jsonl` — flujo estructurado unificado de todos los eventos RASP.

## Nota de alcance

El taller propone un RASP como decorador/middleware (ejemplo Flask). Aquí se implementó un **RASP
propio sobre una app Python controlada**, porque la aplicación objetivo original (OWASP Juice Shop)
está escrita en Node.js y un agente Python no puede instrumentar su proceso. Esta decisión es
explícita y no altera los objetivos de la fase: se demuestra el bloqueo en tiempo de ejecución del
contexto real post-decodificación.

## Conclusión de la fase

El RASP bloqueó cuatro clases de operación peligrosa que las capas anteriores no cubren: la consulta
SQL final del payload fragmentado, el XSS doblemente codificado que evadió el WAF en la Fase 2, el
path traversal y la deserialización con `__reduce__`. El costo es despreciable (+0.29 ms extremo a
extremo; 0.035 ms de inspección media), lo que confirma que la protección en tiempo de ejecución
aporta cobertura donde las firmas perimetrales y el modelo de anomalías tienen ángulos ciegos.
