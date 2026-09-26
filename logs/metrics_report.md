# Fase 7 — Panel de observabilidad y métricas

Generado: `2026-09-26T07:46:55.713840+00:00`
Fuente matriz: `/home/d3vjh/Documents/UD/Mecanismos/logs/evasion_matrix.json`  
Eventos: `/home/d3vjh/Documents/UD/Mecanismos/logs/waap_events.jsonl`

## Métricas por capa

| Capa | TP | FP | FN | TN | Tasa detección | FPR | FNR | Precisión | MTTD (ms) |
|---|---|---|---|---|---|---|---|---|---|
| Reglas (Fase 2) | 8 | 0 | 2 | 3 | 80.0% | 0.0% | 20.0% | 100.0% | 6.1292 |
| IA/ML (Fase 3) | 9 | 1 | 0 | 2 | 100.0% | 33.3% | 0.0% | 90.0% | 10.0305 |
| RASP (Fase 4) | 8 | 0 | 1 | 3 | 88.9% | 0.0% | 11.1% | 100.0% | 0.0193 |

## Cobertura combinada (reglas ∪ IA/ML ∪ RASP)

- TP=9  FP=1  FN=1  TN=2
- Tasa de detección: **90.0%** | FPR: 33.3%

## Eventos RASP

- Bloqueos: 12 | Permisos: 20
- Por tipo: {'sql_injection': 5, 'xss': 4, 'path_traversal': 2, 'deserialization': 1}
- guard_ms medio: 0.0193 | p95: 0.0309

## Métricas del modelo (Fase 3)

- Accuracy: 0.88 | Recall: 0.866667 | F1: 0.896552 | ROC-AUC: 0.952367

## Huecos de cobertura

- Ráfaga de 20 peticiones (bot)

## Recomendaciones de ajuste

- IA/ML: FPR=33.3% (>5%). Bajar contamination de 0.10 a 0.05 y/o subir el umbral de decisión (anomaly_threshold) para reducir alertas sobre tráfico legítimo.
- IA/ML (Fase 3): ROC-AUC=0.952367, recall=0.866667. Ampliar el set de entrenamiento normal para estabilizar el umbral.
- Reglas: FNR=20.0%. Subir Paranoia Level a 2 y habilitar decodificación múltiple para cubrir doble URL-encoding y fragmentación.
- RASP: FNR=11.1%. Normalizar comentarios SQL (/**/, --, #) antes de las firmas y considerar libinjection a nivel de aplicación para el caso con comentarios.
- Sin cobertura por ninguna capa: Ráfaga de 20 peticiones (bot). Priorizar rate limiting y features de frecuencia.
