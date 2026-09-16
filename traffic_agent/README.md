# WAAP Traffic Agent

Generador de tráfico HTTP etiquetado para un laboratorio autorizado de OWASP Juice Shop detrás de ModSecurity + OWASP CRS. Todo el tráfico apunta al proxy `http://localhost:4000` por defecto; el acceso a un host no local exige `--allow-remote-target` para evitar ejecuciones accidentales fuera del laboratorio.

## Requisitos

```bash
cd traffic_agent
python -m pip install -r requirements.txt
```

Coloca los datasets así:

```text
datasets/
├── csic_2010/
│   ├── normalTrafficTraining.txt
│   ├── normalTrafficTest.txt
│   └── anomalousTrafficTest.txt
└── http_params/
    └── *.csv             # columnas: payload,label (1 = malicioso)
```

El cargador CSIC toma valores de los archivos con `anomal` en el nombre. El cargador de HttpParamsDataset toma solo filas con `label=1`. Si los directorios no existen o están vacíos, el agente continúa con una pequeña lista de payloads de demostración y los marca como `source=generated`.

## Ejecución

Primero inicia Juice Shop y el reverse proxy en tu laboratorio. Luego:

```bash
python agent.py
```

Ejecución corta para validar conectividad y formato:

```bash
python agent.py --normal-count 10 --attack-count 20 --mixed-count 10 --delay-min 0.1 --delay-max 0.3
```

Opciones principales:

```text
--target http://localhost:4000
--normal-count 200
--attack-count 300
--mixed-count 0
--output-dir logs
--datasets-dir datasets
--delay-min 0.5 --delay-max 2.0
--timeout 10
--seed 42
```

## Salidas

El agente crea:

- `logs/traffic_dataset.csv`: tráfico normal y de ataque, con su etiqueta y fuente.
- `logs/features_normal_traffic.csv`: solo filas `label=normal`, listo para entrenar un `IsolationForest`.

Cada fila incluye el timestamp UTC ISO 8601, método, URL final, estado HTTP (o `0` si se produjo timeout/error de red), tiempo de respuesta y las features solicitadas. `special_char_ratio` y `entropy` se calculan sobre URL + body; `n_params` cuenta query parameters, mientras que `param_max_length` considera valores de query y JSON/form body.

Las transformaciones URL-encoded y double URL-encoded se aplican a nivel de valor antes de que `requests` construya la URL. Esto puede producir codificación adicional en algunos casos; es intencional para conservar variantes de transporte y generar señales distintas para el detector.
