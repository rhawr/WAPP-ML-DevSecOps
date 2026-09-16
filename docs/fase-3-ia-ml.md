# Fase 3 — Detección por IA/ML (Isolation Forest)

## Objetivo

Entrenar un modelo de detección de anomalías basado en Isolation Forest (scikit-learn) sobre tráfico HTTP real generado contra el proxy WAAP, de forma que complemente al WAF de reglas de la Fase 2 detectando patrones anómalos sin depender de firmas conocidas. Se entrega el modelo serializado (`model.pkl`), una matriz de 10 peticiones con sus scores y una discusión sobre falsos positivos.

## Desarrollo

### 1. Arquitectura del sistema ML

El pipeline completo consta de cuatro componentes:

```
agent.py ──→ logs/features_normal_traffic.csv ──→ train_model.py ──→ model.pkl
                └──→ logs/traffic_dataset.csv  ──→ evaluate_model.py
```

| Módulo | Rol |
|---|---|
| `features.py` | Extracción de features a partir de URL + body de cada petición |
| `generators/normal.py` | Generador de tráfico legítimo simulando navegación en Juice Shop |
| `generators/attack.py` | Generador de ataques con variantes de encoding |
| `loaders/csic_loader.py` | Cargador del dataset CSIC 2010 (payloads anómalos reales) |
| `agent.py` | Agente principal: envía peticiones al proxy y guarda CSV etiquetado |
| `train_model.py` | Entrena Isolation Forest sobre tráfico normal y serializa `model.pkl` |
| `evaluate_model.py` | Evalúa el modelo contra el dataset completo y genera métricas |

---

### 2. Extracción de features (`features.py`)

Cada petición HTTP se convierte en un vector de **9 features numéricas**:

| # | Feature | Descripción |
|---|---|---|
| 1 | `status_code` | Código HTTP de respuesta (200, 401, 403…) |
| 2 | `response_time_ms` | Tiempo de respuesta en milisegundos |
| 3 | `url_length` | Longitud total de la URL incluyendo query string |
| 4 | `body_length` | Longitud del cuerpo de la petición en bytes |
| 5 | `entropy` | Entropía de Shannon sobre la concatenación URL + body |
| 6 | `n_params` | Número de parámetros en el query string |
| 7 | `has_suspicious_chars` | Detección de patrones sospechosos (`--`, `;`, `<script>`, `../`, `UNION`, `OR 1=1`, `'`, `%27`) |
| 8 | `param_max_length` | Longitud del parámetro más largo en query string o body |
| 9 | `special_char_ratio` | Proporción de caracteres no alfanuméricos en URL + body |

La entropía de Shannon detecta strings con alta aleatoriedad o densidad de caracteres especiales, que es característica de payloads codificados:

```python
def shannon_entropy(value: str) -> float:
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())
```

---

### 3. Generación de tráfico (`agent.py`)

El agente envía peticiones reales contra `http://localhost:4000` (proxy WAAP en `DetectionOnly`) en dos fases:

**Fase normal (200 peticiones):** Navegación legítima simulando un usuario real en Juice Shop — búsquedas de productos, listados, detalles, login con credenciales válidas, consulta de feedback.

**Fase de ataque (300 peticiones):** Payloads inyectados en los endpoints vulnerables de la Fase 1. Los ataques usan cuatro técnicas de representación:

```
raw              → ' OR 1=1--
url_encoded      → %27%20OR%201%3D1--
double_encoded   → %2527%2520OR%25201%253D1--
case_alternation → ' oR 1=1--
```

Los payloads provienen del dataset **CSIC 2010** (peticiones anómalas reales) y de payloads generados (`FALLBACK_PAYLOADS`). Grupos de 12 peticiones consecutivas simulan bursts de bot.

Salida generada:
- `logs/traffic_dataset.csv` — 500 filas etiquetadas (normal/attack), 14 columnas
- `logs/features_normal_traffic.csv` — solo las 200 filas normales, para entrenamiento

---

### 4. Entrenamiento del modelo (`train_model.py`)

```bash
python train_model.py
```

```
Modelo entrenado correctamente
  Filas normales usadas: 200
  Features: 9
  Contamination: 0.1
  Archivo creado: /home/d3vjh/Documents/UD/Mecanismos/traffic_agent/model.pkl
```

**Parámetros del modelo:**

```python
IsolationForest(
    n_estimators=200,      # Número de árboles de aislamiento
    contamination=0.10,    # Proporción esperada de anomalías en el conjunto normal
    random_state=42,       # Semilla para reproducibilidad
    n_jobs=-1,             # Usa todos los núcleos disponibles
)
```

El modelo se serializa junto con sus metadatos:

```python
artifact = {
    "model": model,
    "feature_columns": FEATURE_COLUMNS,
    "training_rows": 200,
    "contamination": 0.10,
    "trained_at": "2026-09-16T...",
}
joblib.dump(artifact, "model.pkl")
```

**Por qué Isolation Forest:**  
Isolation Forest es un algoritmo no supervisado que aísla anomalías construyendo árboles de decisión aleatorios. Las observaciones atípicas (payloads maliciosos) requieren menos particiones para ser aisladas que las normales. Es apropiado aquí porque:
- Solo necesita tráfico normal para entrenarse (no requiere ejemplos de ataque etiquetados).
- Es eficiente en alta dimensión.
- Produce un score continuo de anomalía, no solo una etiqueta binaria.

---

### 5. Evaluación del modelo (`evaluate_model.py`)

```bash
python evaluate_model.py
```

```
=== EVALUACIÓN DEL MODELO ===
Filas evaluadas: 500
Matriz de confusión: TN=180, FP=20, FN=50, TP=250
Accuracy: 86.00%
Detección de ataques (Recall): 83.33%
Precisión de ataques: 92.59%
F1 de ataques: 87.72%
Falsos positivos normales: 10.00%
ROC-AUC: 0.9217
```

---

## Evidencias

### Métricas del modelo (`logs/evaluation_metrics.json`)

```json
{
  "evaluated_at": "2026-09-16T01:28:56.699124+00:00",
  "rows_evaluated": 500,
  "confusion_matrix": { "TN": 180, "FP": 20, "FN": 50, "TP": 250 },
  "accuracy": 0.86,
  "attack_precision": 0.925926,
  "attack_recall_detection_rate": 0.833333,
  "attack_f1": 0.877193,
  "normal_false_positive_rate": 0.1,
  "roc_auc_anomaly_score": 0.921658
}
```

### Matriz de confusión

```
                 Predicho Normal   Predicho Attack
Real Normal           180 (TN)          20 (FP)
Real Attack            50 (FN)         250 (TP)
```

### Matriz de 10 peticiones con scores (`logs/evaluation_predictions.csv`)

| # | Método | Endpoint | Código | Score anomalía | Pred. | Real | Resultado |
|---|---|---|---|---|---|---|---|
| 1 | GET | `/rest/products/search?q=bread` | 200 | +0.039 | attack | normal | **FP** |
| 2 | GET | `/api/Products` | 200 | −0.162 | normal | normal | TN |
| 3 | GET | `/api/Products` | 200 | −0.163 | normal | normal | TN |
| 4 | GET | `/rest/products/search?q=tea` | 200 | +0.069 | attack | normal | **FP** |
| 5 | GET | `/api/Products` | 200 | −0.160 | normal | normal | TN |
| 6 | POST | `/rest/user/login` | 401 | +0.140 | attack | normal | **FP** |
| 7 | GET | `/rest/products/search?q=lemon` | 200 | −0.040 | normal | normal | TN |
| 8 | GET | `/api/Feedbacks` | 200 | −0.158 | normal | normal | TN |
| 9 | GET | `/api/Products/25` | 200 | −0.109 | normal | normal | TN |
| 10 | GET | `/rest/basket/1` | 401 | −0.123 | normal | normal | TN |

> Score positivo → más anómalo. Score negativo → más normal. El umbral de decisión cae en 0.

### Modelo serializado

```
model.pkl — 1.2 MB
Algoritmo: IsolationForest (sklearn 1.x)
Features de entrada: 9 columnas numéricas
```

---

### Discusión de falsos positivos

**Tasa observada:** 10% (20 FP de 200 peticiones normales).

Los falsos positivos identificados en el dataset corresponden a tres categorías:

**1. Peticiones con respuesta 401 (login fallido):**  
`POST /rest/user/login` con credenciales de prueba (`test@test.com / test123`) retornó 401 con frecuencia. El score de estas peticiones fue elevado (`+0.14`) porque la combinación de `body_length > 0` + `status_code=401` es poco frecuente en el tráfico de entrenamiento (el modelo solo vio tráfico exitoso o esperado). La solución sería incluir peticiones 401 legítimas en la fase de entrenamiento normal.

**2. Búsquedas con URL corta y un solo parámetro:**  
`/rest/products/search?q=bread` y `?q=tea` generan un `n_params=1` con `url_length≈50` que el modelo considera borderline. El score está apenas sobre el umbral (+0.039, +0.069). Incrementar el dataset de entrenamiento a 500+ peticiones reduciría esta varianza.

**3. Raíz `/` con URL muy corta:**  
`GET /` tiene `url_length=22` y `special_char_ratio≈0.22`, parámetros que el modelo no vio suficientemente en entrenamiento para centrar el umbral. Es el FP más difícil de eliminar sin ajustar el threshold.

**Impacto operativo:**  
Con una FP rate de 10%, en producción de alto volumen (10.000 req/hora) se generarían 1.000 alertas falsas por hora. Para reducirlo al 3–5%:
- Aumentar el dataset de entrenamiento a 1.000+ peticiones normales diversas.
- Bajar `contamination` de 0.10 a 0.05.
- Combinar el score de Isolation Forest con el score de anomalía del WAF (Fase 2) antes de decidir.

**Falsos negativos (FN = 50):**  
El 16.7% de ataques no fue detectado. Corresponden principalmente a ataques con doble URL encoding (`%2527...`) que generan features similares a tráfico normal (sin `has_suspicious_chars=True` porque el regex actúa sobre el string literal, no sobre el decodificado completo). Esto es coherente con el caso de evasión documentado en la Fase 2.

---

## Entregable

- `model.pkl` — modelo Isolation Forest entrenado sobre 200 peticiones normales reales.
- `logs/evaluation_metrics.json` — métricas completas: accuracy 86%, recall 83.33%, F1 87.72%, ROC-AUC 0.9217.
- `logs/evaluation_predictions.csv` — 500 predicciones individuales con scores.
- Matriz de 10 peticiones representativas con score de anomalía (ver tabla arriba).
- Discusión de falsos positivos con causas identificadas y estrategias de mitigación.

## Conclusión de la fase

El modelo Isolation Forest alcanzó un ROC-AUC de 0.92 y un F1 de 0.88, detectando el 83% de los ataques del dataset sin haber visto ningún ejemplo de ataque durante el entrenamiento. La tasa de falsos positivos del 10% es manejable en un entorno de laboratorio, pero requiere calibración antes de producción. Los falsos negativos se concentran en ataques con doble URL encoding, lo que evidencia que ninguna capa de detección es suficiente por sí sola — la combinación WAF (Fase 2) + ML (Fase 3) + RASP (Fase 4) busca cubrir los ángulos ciegos de cada técnica individualmente.
