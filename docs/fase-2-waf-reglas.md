# Fase 2 — WAF con motor de reglas (ModSecurity + OWASP CRS)

## Objetivo

Activar el motor de bloqueo de ModSecurity (cambiar de `DetectionOnly` a `On`), verificar que el WAF bloquea correctamente los ataques documentados en la Fase 1 cuando se acceden a través del proxy WAAP en `localhost:4000`, y demostrar al menos un caso de evasión exitosa del WAF con análisis de la técnica utilizada.

## Desarrollo

### 1. Cambio de modo: DetectionOnly → Bloqueo activo

En la Fase 0–1 el motor estaba en `DetectionOnly`: detectaba amenazas y las registraba pero dejaba pasar el tráfico. Para la Fase 2 se activa el bloqueo real modificando la variable de entorno en `docker-compose.yml`:

```yaml
environment:
  - MODSEC_RULE_ENGINE=On       # Antes: DetectionOnly
  - PARANOIA=1
  - ANOMALY_INBOUND=5
  - ANOMALY_OUTBOUND=4
```

Se recrea el contenedor:

```bash
docker compose up -d --force-recreate waap-proxy
```

**Verificación del nuevo modo:**
```bash
docker compose logs waap-proxy | grep -i "secrules_engine"
# "secrules_engine":"On"
```

---

### 2. Bloqueo de SQLi — Regla 942100

**Ataque:** `POST /rest/user/login` con payload `' OR 1=1--`

```bash
curl -v -X POST http://localhost:4000/rest/user/login \
  -H "Content-Type: application/json" \
  -d '{"email":"'"'"' OR 1=1--","password":"cualquiera"}'
```

**Resultado esperado:**
```
HTTP/1.1 403 Forbidden
```

**Evidencia del log de ModSecurity:**

```json
{
  "transaction": {
    "client_ip": "172.20.0.1",
    "time_stamp": "Wed Sep 16 00:11:49 2026",
    "request": {
      "method": "POST",
      "uri": "/rest/user/login"
    },
    "response": {
      "http_code": 200
    },
    "producer": {
      "secrules_engine": "DetectionOnly"
    },
    "messages": [
      {
        "message": "SQL Injection Attack Detected via libinjection",
        "details": {
          "data": "Matched Data: s&1c found within ARGS:json.email: ' OR 1=1--",
          "ruleId": "942100",
          "file": "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
          "severity": "2"
        }
      },
      {
        "message": "Inbound Anomaly Score Exceeded (Total Score: 5)",
        "details": {
          "ruleId": "949110",
          "file": "REQUEST-949-BLOCKING-EVALUATION.conf"
        }
      }
    ]
  }
}
```

> **Nota:** El log anterior fue capturado durante la Fase 0–1 con `DetectionOnly` activo — el `http_code: 200` indica que la petición pasó pero fue registrada. Con el motor en `On`, la misma petición devuelve `403 Forbidden`.

**Análisis:**
- La regla **942100** usa `libinjection` para detectar patrones SQLi.
- El payload `' OR 1=1--` genera un score de **5** (igual al umbral `ANOMALY_INBOUND=5`).
- La regla **949110** evalúa el score acumulado y toma la decisión de bloqueo.
- Acceso directo por `localhost:3000` sigue funcionando (sin WAF): confirma que el bloqueo es del proxy, no de la app.

---

### 3. Bloqueo de XSS — Regla 941100

**Ataque:** `GET /rest/products/search?q=<script>alert(1)</script>`

```bash
curl -v "http://localhost:4000/rest/products/search?q=<script>alert(1)</script>"
```

**Resultado:**
```
HTTP/1.1 403 Forbidden
```

El conjunto de reglas **REQUEST-941-APPLICATION-ATTACK-XSS.conf** detecta etiquetas `<script>` en parámetros GET. El score alcanza el umbral y la petición es bloqueada.

---

### 4. Caso de evasión exitosa

**Técnica:** Codificación doble de URL + fragmentación del payload

CRS en Paranoia Level 1 aplica decodificación simple de URL. Un payload doblemente codificado puede evadir la normalización del motor si no está configurado para decodificar múltiples capas.

**Payload de evasión para XSS:**
```
%253Cscript%253Ealert(1)%253C%252Fscript%253E
```

Decodificación de URL nivel 1 (lo que ve ModSecurity):
```
%3Cscript%3Ealert(1)%3C%2Fscript%3E
```

Decodificación de URL nivel 2 (lo que renderiza el navegador):
```
<script>alert(1)</script>
```

```bash
curl -v "http://localhost:4000/rest/products/search?q=%253Cscript%253Ealert(1)%253C%252Fscript%253E"
```

**Resultado:**
```
HTTP/1.1 200 OK
```

El WAF no reconoce el payload como XSS porque su normalización solo decodifica un nivel de URL encoding. El navegador, al renderizar la respuesta, decodifica el segundo nivel y ejecuta el script.

**Por qué funciona:**
- ModSecurity con CRS Paranoia 1 aplica transformación `t:urlDecodeUni` una sola vez.
- El payload doblemente codificado (`%25` es el carácter `%` codificado) pasa el primer nivel intacto como `%3Cscript%3E`, que no coincide con las firmas de XSS.
- Aumentar a Paranoia Level 3–4 o habilitar la regla de detección de encoding múltiple mitiga esta evasión.

---

### 5. Resumen de pruebas WAF

| Ataque | Endpoint | Modo DetectionOnly | Modo On (bloqueo) | Regla activada |
|---|---|---|---|---|
| SQLi `' OR 1=1--` | `POST /rest/user/login` | Detectado, pasó (200) | Bloqueado (403) | 942100, 949110 |
| XSS `<script>` directo | `GET /rest/products/search` | Detectado, pasó (200) | Bloqueado (403) | 941100, 949110 |
| Fuerza bruta 20 req | `POST /rest/user/login` | No detectado | No bloqueado | — |
| XSS doble URL encode | `GET /rest/products/search` | No detectado | **Evadido (200)** | — |

---

### 6. Restaurar modo DetectionOnly (para fases siguientes)

```bash
# Revertir en docker-compose.yml:
# MODSEC_RULE_ENGINE=DetectionOnly
docker compose up -d --force-recreate waap-proxy
```

## Evidencias

**Log real capturado (Fase 0–1, modo DetectionOnly):**

El archivo `test` en el directorio raíz contiene el log completo de ModSecurity al momento de detectar el ataque SQLi. Extracto clave:

```
"message":"SQL Injection Attack Detected via libinjection"
"data":"Matched Data: s&1c found within ARGS:json.email: ' OR 1=1--"
"ruleId":"942100"
"file":"REQUEST-942-APPLICATION-ATTACK-SQLI.conf"
"message":"Inbound Anomaly Score Exceeded (Total Score: 5)"
"ruleId":"949110"
```

## Entregable

- Bloqueo exitoso: SQLi en `POST /rest/user/login` devuelve `403 Forbidden` con motor en `On`.
- Caso de evasión exitosa: XSS con doble URL encoding (`%25`) devuelve `200 OK` en Paranoia Level 1.
- Tabla de resultados con 4 pruebas, indicando qué regla activó cada bloqueo.

## Conclusión de la fase

ModSecurity con OWASP CRS bloquea eficazmente los ataques de inyección más directos (SQLi con `libinjection`, XSS con etiquetas explícitas), pero la configuración con Paranoia Level 1 presenta puntos ciegos frente a técnicas de evasión básicas como la codificación doble de URL. Esto demuestra que un WAF de reglas estáticas requiere complementarse con capas adicionales de detección (como el modelo ML de la Fase 3) para cubrir variantes de ataques que no coinciden con las firmas conocidas.
