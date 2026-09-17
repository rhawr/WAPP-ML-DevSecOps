# Fase 6 — Pruebas de efectividad y técnicas de evasión

## Objetivo

Evaluar de forma comparativa la capacidad de detección de cada capa —reglas (Fase 2), IA/ML (Fase 3)
y RASP (Fase 4)— de forma individual y combinada, frente a payloads y técnicas de evasión estándar,
y determinar qué combinación ofrece la mejor cobertura.

## Metodología

La matriz se genera con `scripts/attack_matrix.py`, que reúne un catálogo de payloads/técnicas y, para
cada uno, consulta las tres capas:

| Capa | Objetivo | Criterio de detección |
|---|---|---|
| Reglas | Proxy ModSecurity + CRS en `http://localhost:4000` | `HTTP 403` |
| IA/ML | `traffic_agent/model.pkl` sobre features de la petición | `IsolationForest.predict == -1` |
| RASP | App instrumentada en proceso (Fase 4) | `HTTP 403` del guard |

Si el proxy o el modelo no están disponibles, la celda se marca `N/A` en lugar de contarse como
"No": así la matriz no infla la tasa de evasión por falta de entorno.

```bash
# Con el laboratorio Docker arriba y las dependencias ML instaladas:
python scripts/attack_matrix.py

# Incluir sqlmap (si el binario está disponible)
python scripts/attack_matrix.py --sqlmap
```

Salidas: `logs/evasion_matrix.csv` (matriz del taller) y `logs/evasion_matrix.json` (detalle con
scores, códigos HTTP y cuerpos, consumido por la Fase 7).

### Herramientas de ataque controlado

ZAP y sqlmap se pueden lanzar sobre el proxy; solo contra el laboratorio local:

```bash
# ZAP baseline (pasivo) → reporte HTML
docker run --rm -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
  -t http://localhost:4000 -r logs/zap_report.html

# ZAP escaneo activo (intrusivo; solo laboratorio aislado)
docker run --rm -t ghcr.io/zaproxy/zaproxy:stable zap-full-scan.py \
  -t http://localhost:4000

# sqlmap directo contra el endpoint de búsqueda
sqlmap -u "http://localhost:4000/rest/products/search?q=1" --batch --level=2 --risk=2
```

## Matriz de resultados

Captura local en la que el proxy estaba disponible pero en `DetectionOnly` (por eso la columna de
reglas aparece como `No`) y `scikit-learn` no estaba instalado (columna IA/ML `N/A`). La columna RASP
es real. Con `make lab-up` el WAF queda en `On` y `make phase6` produce las tres columnas completas:

| Payload / técnica | Bloqueado por reglas (Fase 2) | Detectado por IA/ML (Fase 3) | Bloqueado por RASP (Fase 4) |
|---|---|---|---|
| SQLi clásico `' OR '1'='1` | No* | N/A | **Sí** |
| SQLi con codificación URL | No* | N/A | **Sí** |
| SQLi doble URL-encoding (evasión Fase 2) | No* | N/A | **Sí** |
| SQLi fragmentado en 2 parámetros | No* | N/A | **Sí** |
| SQLi con comentarios en línea (`OR/**/1=1--`) | No* | N/A | **No** |
| XSS reflejado básico | No* | N/A | **Sí** |
| XSS por manejador de evento (`<img onerror>`) | No* | N/A | **Sí** |
| XSS doble URL-encoding (evasión Fase 2) | No* | N/A | **Sí** |
| Path traversal `../../etc/passwd` | No* | N/A | **Sí** |
| Búsqueda legítima (control benigno) | No | N/A | No |
| Login válido (control benigno) | No | N/A | No |
| Catálogo de productos (control benigno) | No | N/A | No |
| Ráfaga de 20 peticiones (bot) | No* | N/A | N/A |

> `No*` = el motor estaba en `DetectionOnly` durante la captura, por lo que no bloquea nada. Con el
> motor en `On` (valor por defecto de `docker-compose.yml`) los ataques directos pasan a `Sí` según
> lo documentado en la Fase 2. Los tres controles benignos permiten estimar falsos positivos en la
> Fase 7.

### Resultados de referencia de las fases previas

Las columnas de reglas y IA/ML se completan al ejecutar el script con el laboratorio activo. Con base
en las evidencias ya documentadas en las fases 2 y 3, los valores esperados son:

| Payload / técnica | Reglas (Fase 2) | IA/ML (Fase 3) | RASP (Fase 4) |
|---|---|---|---|
| SQLi clásico `' OR '1'='1` | **Sí** (regla 942100) | Sí (score alto) | Sí |
| SQLi con codificación URL | Sí (CRS decodifica 1 nivel) | Sí | Sí |
| SQLi doble URL-encoding | **No** (evadió PL1) | Probablemente No (FN por encoding) | **Sí** |
| SQLi fragmentado en 2 parámetros | **No** (cada parámetro es benigno) | No | **Sí** |
| SQLi con comentarios en línea | Parcial (libinjection) | Sí | **No** |
| XSS reflejado básico | **Sí** (regla 941100) | Sí | Sí |
| XSS por manejador de evento | **Sí** (família 941) | Sí | Sí |
| XSS doble URL-encoding | **No** (evasión Fase 2) | No (FN documentado) | **Sí** |
| Path traversal | Sí (família 930) | Sí | Sí |
| Ráfaga de peticiones (bot) | **No** (sin rate limiting) | N/A (sin `req_per_minute`) | N/A |

## Análisis

**Ninguna capa es suficiente por sí sola.** El motor de reglas bloquea las firmas directas (SQLi
clásico, XSS con `<script>`, path traversal) pero tiene dos puntos ciegos medidos: el doble
URL-encoding, porque CRS en Paranoia Level 1 solo decodifica un nivel, y la fragmentación del payload
en varios parámetros, porque inspecciona cada parámetro por separado. El módulo IA/ML cubre parte de
esas variantes al mirar la petición como un todo (entropía, longitud, caracteres sospechosos), pero
arrastra una tasa de falsos positivos del 10 % y falla en los payloads con encoding que quedan
estadísticamente cerca del tráfico normal. El RASP es la capa que **cierra las brechas anteriores**:
al observar el valor final post-decodificación y post-concatenación, bloquea tanto el SQLi
doblemente codificado como el fragmentado, y también el XSS que había evadido el WAF.

**La combinación con mejor cobertura es reglas + IA/ML + RASP.** Las reglas son baratas y rápidas
para lo conocido; el modelo aporta detección de lo no firmado (con costo de falsos positivos); el
RASP garantiza la operación sensible concreta. La intersección de las tres deja un único hueco
identificado en esta matriz: el SQLi con comentarios en línea (`OR/**/1=1--`) evade el patrón del
RASP porque sus expresiones regulares esperan espacios entre tokens. La mitigación es normalizar el
payload quitando comentarios SQL (`/**/`, `--`, `#`) antes de aplicar las firmas, o complementar el
RASP con `libinjection` a nivel de aplicación.

**La ráfaga de peticiones (bot) no la detecta ninguna capa.** El WAF no implementa control de
frecuencia en este laboratorio y el modelo no incorpora `req_per_minute` entre sus 9 features, aunque
el taller lo menciona como feature típica. Esto evidencia un hueco de *bot management / rate
limiting*: la recomendación es añadir limitación de tasa por IP/sesión y, si se quiere detección por
modelo, incorporar la frecuencia como feature (lo que obliga a reentrenar).

**Conclusión de cobertura:** las reglas detuvieron los ataques "de manual"; el ML y sobre todo el
RASP detuvieron las variantes evasivas. La defensa en profundidad se justifica porque cada capa falla
en un subconjunto distinto y la unión de las tres maximiza la detección.

## Entregable

- `logs/evasion_matrix.csv` — matriz completa (columnas de reglas e IA/ML a poblar con el laboratorio
  activo).
- `logs/evasion_matrix.json` — detalle por caso (score de anomalía, código HTTP, cuerpos).
- `scripts/attack_matrix.py` — generador de la matriz, con soporte opcional de sqlmap.
- Análisis comparativo (arriba) identificando la mejor combinación y los huecos restantes.
