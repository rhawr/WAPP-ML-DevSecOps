# Fase 7 — Panel de observabilidad y métricas

Generado: `2026-09-17T02:30:29.087522+00:00`
Fuente matriz: `/home/alejandropenagos/Escritorio/Alejandro/Mecanismos/WAPP-ML-DevSecOps/logs/evasion_matrix.json`  
Eventos: `/home/alejandropenagos/Escritorio/Alejandro/Mecanismos/WAPP-ML-DevSecOps/logs/waap_events.jsonl`

## Métricas por capa

| Capa | TP | FP | FN | TN | Tasa detección | FPR | FNR | Precisión | MTTD (ms) |
|---|---|---|---|---|---|---|---|---|---|
| Reglas (Fase 2) | 0 | 0 | 10 | 3 | 0.0% | 0.0% | 100.0% | N/A | N/A |
| IA/ML (Fase 3) | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | N/A |
| RASP (Fase 4) | 8 | 0 | 1 | 3 | 88.9% | 0.0% | 11.1% | 100.0% | 0.0333 |

## Cobertura combinada (reglas ∪ IA/ML ∪ RASP)

- TP=8  FP=0  FN=2  TN=3
- Tasa de detección: **80.0%** | FPR: 0.0%

## Eventos RASP

- Bloqueos: 44 | Permisos: 110
- Por tipo: {'sql_injection': 21, 'xss': 16, 'path_traversal': 6, 'deserialization': 1}
- guard_ms medio: 0.0333 | p95: 0.0715

## Métricas del modelo (Fase 3)

- Accuracy: 0.86 | Recall: 0.833333 | F1: 0.877193 | ROC-AUC: 0.921658

## Huecos de cobertura

- SQLi con comentarios en línea
- Ráfaga de 20 peticiones (bot)

## Recomendaciones de ajuste

- IA/ML (Fase 3): ROC-AUC=0.921658, recall=0.833333. Ampliar el set de entrenamiento normal para estabilizar el umbral.
- Reglas: FNR=100.0%. Subir Paranoia Level a 2 y habilitar decodificación múltiple para cubrir doble URL-encoding y fragmentación.
- RASP: FNR=11.1%. Normalizar comentarios SQL (/**/, --, #) antes de las firmas y considerar libinjection a nivel de aplicación para el caso con comentarios.
- Sin cobertura por ninguna capa: SQLi con comentarios en línea, Ráfaga de 20 peticiones (bot). Priorizar rate limiting y features de frecuencia.
