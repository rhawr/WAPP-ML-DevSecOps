# Fase 0 — Preparación del entorno

## Objetivo

Desplegar el laboratorio base compuesto por dos contenedores Docker: la aplicación web vulnerable OWASP Juice Shop y el proxy inverso WAAP (ModSecurity + OWASP CRS), verificando que ambos servicios sean accesibles y que el tráfico fluya correctamente a través del proxy antes de iniciar cualquier prueba de ataque.

## Desarrollo

### 1. Estructura del proyecto

Se creó el directorio de trabajo con la siguiente organización:

```
taller-waap/
├── docs/                  # Documentación por fase
├── logs/                  # Logs de contenedores y evidencias
├── scripts/               # Scripts de ataque y automatización
├── app/                   # Agente RASP (Fase 4)
├── waap/ml/               # Modelo ML (Fase 3)
├── pipeline/              # Pipeline DevSecOps (Fase 5)
├── docker-compose.yml
└── CLAUDE.md
```

### 2. Configuración de Docker Compose

Se definió `docker-compose.yml` con dos servicios:

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
      - MODSEC_RULE_ENGINE=DetectionOnly
      - PARANOIA=1
      - ANOMALY_INBOUND=5
      - ANOMALY_OUTBOUND=4
    depends_on:
      - juice-shop
```

**Decisiones de configuración:**
- Puerto `4000` para el proxy (el `8080` está ocupado por Burp Suite).
- `MODSEC_RULE_ENGINE=DetectionOnly` en la Fase 0–1: solo registra alertas, no bloquea tráfico.
- `PARANOIA=1`: nivel más bajo de CRS, menor tasa de falsos positivos.
- `ANOMALY_INBOUND=5` / `ANOMALY_OUTBOUND=4`: umbrales de puntuación para activar alertas.
- No se declara red bridge explícita; Docker Compose crea la red `mecanismos_default` automáticamente.

### 3. Levantamiento de contenedores

```bash
cd ~/Documents/UD/Mecanismos
docker compose up -d
```

Verificación de contenedores activos:

```bash
docker compose ps
```

```
NAME              IMAGE                               STATUS    PORTS
juice-shop-1      bkimminich/juice-shop               Up        0.0.0.0:3000->3000/tcp
waap-proxy-1      owasp/modsecurity-crs:nginx-alpine  Up        0.0.0.0:4000->8080/tcp
```

### 4. Verificación de acceso

**Acceso directo a Juice Shop (sin WAF):**
```bash
curl -s -o /dev/null -w "%{http_code}" http://localhost:3000
# 200
```

**Acceso a través del proxy WAAP:**
```bash
curl -s -o /dev/null -w "%{http_code}" http://localhost:4000
# 200
```

### 5. Verificación del motor ModSecurity

Los logs de arranque del proxy confirman la carga correcta del motor y las reglas CRS:

```
waap-proxy-1 | Running CRS plugin activation
waap-proxy-1 | Finished CRS plugin activation
waap-proxy-1 | Running CRS rule configuration
waap-proxy-1 | Detected CRS config file version: v3
waap-proxy-1 | Configuring 900110 for ANOMALY_INBOUND with inbound_anomaly_score_threshold=5
waap-proxy-1 | Configuring 900110 for ANOMALY_OUTBOUND with outbound_anomaly_score_threshold=4
waap-proxy-1 | Finished CRS rule configuration
waap-proxy-1 | 2026/09/16 00:09:44 [notice] 1#1: ModSecurity-nginx v1.0.4 (rules loaded inline/local/remote: 0/929/0)
waap-proxy-1 | 2026/09/16 00:09:44 [notice] 1#1: libmodsecurity3 version 3.0.16
```

Se cargaron **929 reglas locales** del conjunto OWASP CRS 3.3.10.

## Evidencias

```
Versiones confirmadas:
- ModSecurity-nginx: v1.0.4
- libmodsecurity3:   3.0.16
- OWASP CRS:         3.3.10

Endpoints accesibles:
- http://localhost:3000  → Juice Shop (directo, sin WAF)
- http://localhost:4000  → Juice Shop (a través de proxy WAAP)
```

## Entregable

- Contenedores `juice-shop` y `waap-proxy` corriendo (`docker compose ps`).
- Acceso confirmado a `http://localhost:3000` (directo) y `http://localhost:4000` (por proxy).
- Motor ModSecurity operativo en modo `DetectionOnly` con 929 reglas CRS cargadas.

## Conclusión de la fase

El entorno de laboratorio quedó operativo con ambos servicios corriendo en la misma red Docker interna. La separación entre el puerto directo (3000) y el proxy WAAP (4000) permite comparar el comportamiento de las peticiones con y sin protección a lo largo de las fases siguientes.
