# Guía de montaje manual y evidencias del laboratorio WAAP

Taller de Mecanismos de Seguridad Informática. Universidad Distrital Francisco José de Caldas.
Docente: Octavio J. Salcedo Parra.

Prototipo de plataforma WAAP (Web Application and API Protection) que integra un motor
de reglas (WAF con ModSecurity y OWASP CRS), un módulo de detección por aprendizaje
automático (Isolation Forest), un agente RASP y un pipeline de DevSecOps.

---

## Introducción

El propósito de esta práctica es construir, capa por capa, un entorno de protección para
aplicaciones y APIs web. Se parte de una aplicación deliberadamente vulnerable (OWASP
Juice Shop) y se van agregando controles de seguridad. Primero un WAF de perímetro,
luego un modelo de detección de anomalías, después un agente de protección en tiempo de
ejecución y finalmente un pipeline que verifica el código antes de desplegarlo.

Todo el montaje se documenta de forma manual para evidenciar la comprensión de cada
componente. Una vez validado el procedimiento a mano, se consolidó en dos scripts
(setup.sh y shutdown.sh) descritos en el anexo de automatización.

---

## Requisitos previos

Antes de iniciar se verifica que la máquina cuenta con las herramientas necesarias.

| Requisito | Comando de verificación |
|---|---|
| Docker y Docker Compose | `docker compose version` |
| Python 3.10 a 3.13 | `python3 --version` |
| Puertos 3000 y 4000 libres | `ss -ltnp \| grep -E ':3000\|:4000'` |

---

## Fase 0. Preparación del entorno

En esta fase se prepara todo lo necesario para trabajar: se revisa la definición de los
contenedores, se crea el entorno de Python con sus dependencias y se levantan los
servicios. El WAF se inicia en modo de solo detección, tal como pide el taller para las
fases iniciales.

### Paso 0.1. Verificar Docker y Python

Se comprueba que las herramientas base están instaladas y en una versión compatible.

```bash
docker compose version
python3 --version
```

Salida esperada (referencia):
```text
Docker Compose version v2.26.1
Python 3.13.5
```

> Figura 1. Verificación de versiones de Docker Compose y Python.
> Espacio para captura.

### Paso 0.2. Revisar la definición de los contenedores

Se inspecciona el archivo que describe los dos servicios del laboratorio antes de
levantarlos.

```bash
cat docker-compose.yml
```

Salida esperada (fragmento):
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
      - MODSEC_RULE_ENGINE=${MODSEC_RULE_ENGINE:-On}
      - PARANOIA=${PARANOIA:-1}
```

> Figura 2. Contenido del archivo docker-compose.yml.
> Espacio para captura.

### Paso 0.3. Crear el entorno virtual de Python

Se crea un entorno virtual aislado en la carpeta del proyecto para no mezclar las
dependencias con las del sistema.

```bash
python3 -m venv .venv
```

No produce salida si termina bien. Se verifica que la carpeta quedó creada:

```bash
ls .venv
```

Salida esperada:
```text
bin  include  lib  lib64  pyvenv.cfg
```

> Figura 3. Creación del entorno virtual .venv.
> Espacio para captura.

### Paso 0.4. Activar el entorno e instalar las dependencias

Se activa el entorno y se instalan las librerías del laboratorio (Flask, requests,
scikit-learn, pandas y demás) desde el archivo de requerimientos.

```bash
source .venv/bin/activate
pip install -r requirements.txt
```

Salida esperada (últimas líneas):
```text
Successfully installed Flask-3.1.3 numpy-2.5.3 pandas-... scikit-learn-1.9.1 ...
```

> Figura 4. Instalación de las dependencias del laboratorio.
> Espacio para captura.

### Paso 0.5. Instalar las herramientas del pipeline

Se agregan las herramientas de análisis de seguridad que usará la Fase 5.

```bash
pip install semgrep pip-audit
```

Se comprueba la instalación:

```bash
semgrep --version
pip-audit --version
```

Salida esperada (referencia):
```text
1.178.0
pip-audit 2.10.1
```

> Figura 5. Instalación y verificación de Semgrep y pip-audit.
> Espacio para captura.

### Paso 0.6. Levantar los contenedores en modo de solo detección

Se levantan los servicios. En esta etapa inicial el WAF se configura en modo de solo
detección, de manera que observa y registra el tráfico sin bloquearlo. Así se puede
comprobar primero que la aplicación funciona a través del proxy.

```bash
MODSEC_RULE_ENGINE=DetectionOnly docker compose up -d
```

Salida esperada:
```text
 Container mecanismos-juice-shop-1  Started
 Container mecanismos-waap-proxy-1  Started
```

> Figura 6. Contenedores levantados con el WAF en modo de solo detección.
> Espacio para captura.

### Paso 0.7. Verificar el acceso directo y a través del proxy

Se confirma que la aplicación responde tanto de forma directa en el puerto 3000 como a
través del proxy en el puerto 4000.

```bash
curl -s -o /dev/null -w "Directo 3000: HTTP %{http_code}\n" http://localhost:3000/
curl -s -o /dev/null -w "Proxy 4000:   HTTP %{http_code}\n" http://localhost:4000/
```

Salida esperada:
```text
Directo 3000: HTTP 200
Proxy 4000:   HTTP 200
```

> Figura 7. La aplicación responde de forma directa y a través del proxy WAAP.
> Espacio para captura.

---

## Fase 1. Identificación de vulnerabilidades

Se identifican y comprueban las vulnerabilidades objetivo de la aplicación. Las pruebas
se hacen contra la aplicación directa en el puerto 3000, sin la protección del WAF, para
confirmar que las fallas existen.

| Número | Vulnerabilidad | Categoría OWASP | Endpoint |
|---|---|---|---|
| 1 | Inyección SQL en el login | A03:2021 Injection | POST /rest/user/login |
| 2 | XSS reflejado en la búsqueda | A03:2021 Injection | GET /rest/products/search?q= |
| 3 | IDOR en pedidos | A01:2021 Broken Access Control | GET /rest/basket/{id} |
| 4 | API expuesta | A05:2021 Security Misconfiguration | GET /api/Users, /api-docs |
| 5 | Fuerza bruta en el login | A07:2021 Auth Failures | POST /rest/user/login |

### Paso 1.1. Inyección SQL en el login

Se envía una comilla y una condición siempre verdadera en el campo de correo para saltar
la autenticación. Si la aplicación es vulnerable, devuelve un token de sesión válido sin
conocer la contraseña.

```bash
curl -s -X POST http://localhost:3000/rest/user/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"'"'"' OR 1=1--","password":"x"}'
```

Salida esperada (fragmento):
```text
{"authentication":{"token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...","bid":...,
"umail":"admin@juice-sh.op"}}
```

La respuesta entrega un token de administrador, lo que confirma el bypass de
autenticación.

> Figura 8. Inyección SQL en el login que devuelve un token de administrador.
> Espacio para captura.

### Paso 1.2. XSS reflejado en la búsqueda

Se envía una carga con etiquetas de script en el parámetro de búsqueda. En Juice Shop la
reflexión ocurre en el navegador, donde el término de búsqueda se muestra sin
sanitizar. Por eso la evidencia de ejecución se captura desde el navegador, abriendo la
siguiente dirección.

```text
http://localhost:3000/#/search?q=<iframe src="javascript:alert(`xss`)">
```

Se toma la captura del navegador mostrando el cuadro de alerta.

> Figura 9. XSS reflejado ejecutándose en el navegador desde el término de búsqueda.
> Espacio para captura.

### Paso 1.3. API expuesta y documentación accesible

Se consultan endpoints de la API que no deberían estar expuestos de forma abierta.

```bash
curl -s -o /dev/null -w "GET /api/Users -> HTTP %{http_code}\n" http://localhost:3000/api/Users
curl -s -o /dev/null -w "GET /api-docs  -> HTTP %{http_code}\n" http://localhost:3000/api-docs
```

Salida esperada:
```text
GET /api/Users -> HTTP 401
GET /api-docs  -> HTTP 301
```

El endpoint de usuarios existe y responde, y la documentación de la API redirige a su
interfaz, lo que evidencia una superficie de ataque mayor a la necesaria.

> Figura 10. Respuesta de los endpoints de la API expuesta.
> Espacio para captura.

### Paso 1.4. Fuerza bruta en el login

Se lanza una ráfaga de intentos de inicio de sesión para mostrar que la aplicación no
limita la cantidad de peticiones por unidad de tiempo.

```bash
for i in $(seq 1 20); do
  curl -s -o /dev/null -w "%{http_code} " -X POST http://localhost:3000/rest/user/login \
    -H 'Content-Type: application/json' \
    -d "{\"email\":\"admin@juice-sh.op\",\"password\":\"intento$i\"}"
done; echo
```

Salida esperada:
```text
401 401 401 401 401 401 401 401 401 401 401 401 401 401 401 401 401 401 401 401
```

Las veinte peticiones se procesan sin ningún bloqueo ni retardo, lo que confirma la
ausencia de control de fuerza bruta.

> Figura 11. Veinte intentos de login procesados sin bloqueo.
> Espacio para captura.

---

## Fase 2. Motor de reglas (WAF con ModSecurity y OWASP CRS)

Ahora se activa el WAF en modo de bloqueo y se demuestran dos cosas: que bloquea un
ataque conocido y que existe una técnica de evasión que lo atraviesa. Ese segundo punto
es el que justifica agregar las capas de aprendizaje automático y de RASP.

### Paso 2.1. Activar el WAF en modo de bloqueo

Se cambia el motor de reglas a modo activo y se recrea el contenedor del proxy para que
tome la nueva configuración.

```bash
MODSEC_RULE_ENGINE=On docker compose up -d --force-recreate waap-proxy
```

Se confirma el modo dentro del contenedor:

```bash
docker exec mecanismos-waap-proxy-1 sh -c 'echo $MODSEC_RULE_ENGINE'
```

Salida esperada:
```text
On
```

> Figura 12. WAF configurado en modo de bloqueo.
> Espacio para captura.

### Paso 2.2. Bloqueo de un ataque conocido

Se envía una inyección SQL clásica codificada en la URL a través del proxy. El WAF debe
responder con un código 403.

```bash
curl -s -o /dev/null -w "HTTP %{http_code}\n" \
  "http://localhost:4000/rest/products/search?q=%27%20OR%20%271%27%3D%271"
```

Salida esperada:
```text
HTTP 403
```

> Figura 13. Ataque SQL bloqueado por el WAF con respuesta 403.
> Espacio para captura.

### Paso 2.3. Caso de evasión exitosa

Se envía el mismo ataque con doble codificación de URL. El WAF decodifica solo una capa,
así que la firma no coincide y la petición pasa con código 200. Esta es la debilidad que
resolverán las siguientes capas.

```bash
curl -s -o /dev/null -w "HTTP %{http_code}\n" \
  "http://localhost:4000/rest/products/search?q=%2527%2520OR%2520%25271%2527%253D%25271"
```

Salida esperada:
```text
HTTP 200
```

> Figura 14. Ataque con doble codificación que evade el WAF.
> Espacio para captura.

---

## Fase 3. Detección por aprendizaje automático (Isolation Forest)

Se evalúa un modelo de detección de anomalías entrenado con tráfico normal. La prueba se
hace sobre un conjunto de 500 peticiones etiquetadas, 300 de ataque y 200 normales.

```bash
cd traffic_agent
python evaluate_model.py
cd ..
```

Salida esperada:
```text
=== EVALUACIÓN DEL MODELO ===
Filas evaluadas: 500
Matriz de confusión: TN=180, FP=20, FN=40, TP=260
Accuracy: 88.00%
Detección de ataques (Recall): 86.67%
Precisión de ataques: 92.86%
F1 de ataques: 89.66%
Falsos positivos normales: 10.00%
ROC-AUC: 0.9524
```

El modelo alcanza una exactitud del 88 por ciento y un área bajo la curva de 0,95. Con un
parámetro de contaminación de 0,10 el modelo asume que cerca del 10 por ciento del
tráfico es anómalo, lo que explica los falsos positivos sobre tráfico normal. Reducir ese
parámetro disminuye los falsos positivos pero también baja la detección.

> Figura 15. Métricas de evaluación del modelo Isolation Forest.
> Espacio para captura.

---

## Fase 4. Protección en tiempo de ejecución (RASP)

Se prueba el agente RASP, que vive dentro de la aplicación e inspecciona los valores ya
decodificados justo antes de ejecutarlos. Se ejecutan los casos de ataque con el agente
activo y desactivado, y se mide la latencia en cada escenario.

```bash
python app/run_rasp_tests.py --rounds 20 --cycles 2
```

Salida esperada:
```text
=== RESULTADOS FASE 4 ===
  rasp_on_fragmented           status=403 blocked=True
  rasp_on_double_encoded_xss   status=403 blocked=True
  rasp_on_path_traversal       status=403 blocked=True
  rasp_on_deserialization      status=403 blocked=True
  rasp_on_valid_login          status=200 blocked=False
  rasp_off_fragmented          status=200 blocked=False
  rasp_off_double_encoded_xss  status=200 blocked=False
  rasp_off_path_traversal      status=200 blocked=False
  rasp_off_deserialization     status=200 blocked=False
  rasp_off_valid_login         status=200 blocked=False
  Tiempo de guarda (in-process): media 0,02 ms, p95 0,03 ms
```

Con el agente activo se bloquean los cuatro ataques y el login válido sigue pasando. El
tiempo de inspección propio del RASP es de alrededor de 0,02 ms, muy por debajo del ruido
de la medición de red. Por eso el sobrecosto total de latencia puede salir levemente
positivo o negativo entre corridas. La conclusión práctica es que el costo del RASP es
despreciable.

> Figura 16. Bloqueo de los cuatro ataques con RASP activo y tabla de latencia.
> Espacio para captura.

---

## Fase 5. Pipeline de DevSecOps

Se ejecuta el pipeline de seguridad y se realiza el ejercicio de rojo y verde. Con el
código limpio el pipeline pasa y habilita el despliegue. Al inyectar una vulnerabilidad
el pipeline falla y bloquea el despliegue. Al corregirla vuelve a pasar.

### Paso 5.1. Pipeline con código limpio

```bash
python pipeline/run_pipeline.py
```

Salida esperada:
```text
[OK]    SAST      sast-semgrep
[OK]    SCA       sca-pip-audit
[SKIP]  BUILD     build-image
[SKIP]  CONTAINER container-trivy
[SKIP]  IaC       iac-checkov
[SKIP]  DAST      dast-zap
[OK]    DEPLOY    deploy-waap-rules
RESULTADO: VERDE: despliegue habilitado
```

Las etapas marcadas como SKIP requieren herramientas adicionales (podman, trivy, checkov)
que no están instaladas en esta máquina. El pipeline las omite sin contarlas como error.
Las puertas activas son Semgrep y pip-audit.

> Figura 17. Pipeline en verde con el código limpio.
> Espacio para captura.

### Paso 5.2. Ejercicio de rojo y verde

```bash
python pipeline/verify_pipeline.py --mode sast
```

Salida esperada:
```text
VERIFICACIÓN DEL PIPELINE
  [OK]  baseline_green
  [OK]  injected_red
  [OK]  failed_at_expected_stage
  [OK]  revert_green
RESULTADO: EXITOSO
```

El pipeline se pone en rojo cuando Semgrep detecta la consulta SQL concatenada que se
inyecta y bloquea el despliegue. Al revertir el cambio vuelve al estado verde.

> Figura 18. Pipeline en rojo con la vulnerabilidad inyectada y en verde tras corregir.
> Espacio para captura.

---

## Fase 6. Matriz de efectividad y evasión

Se lanza cada carga de ataque contra las tres capas por separado (reglas, aprendizaje
automático y RASP) y se registra cuál la detiene. Esta prueba requiere el proxy activo y
el modelo entrenado.

```bash
python scripts/attack_matrix.py
```

Salida esperada:
```text
Payload / técnica                            Reglas  IA/ML   RASP
SQLi clásico ' OR '1'='1                     Sí      Sí      Sí
SQLi con codificación URL                    Sí      Sí      Sí
SQLi doble URL-encoding (evasión Fase 2)     No      Sí      Sí
SQLi fragmentado en 2 parámetros             Sí      Sí      Sí
SQLi con comentarios en línea                Sí      Sí      No
XSS reflejado básico                         Sí      Sí      Sí
XSS por manejador de evento                  Sí      Sí      Sí
XSS doble URL-encoding (evasión Fase 2)      Sí      Sí      Sí
Path traversal ../../etc/passwd              Sí      Sí      Sí
Búsqueda legítima (control)                  No      No      No
Login válido (control)                       No      No      No
Catálogo de productos (control)              No      No      No
Ráfaga de 20 peticiones (bot)                No      N/A     N/A
```

Puntos importantes para el análisis escrito de al menos media página:

El ataque de inyección SQL con doble codificación evade el WAF, pero lo detienen tanto el
modelo como el RASP. Este es el caso que justifica las capas tres y cuatro. El ataque de
inyección SQL con comentarios en línea pasa el RASP pero lo detiene el WAF. Ninguna capa
es completa por sí sola, y en conjunto cubren casi todos los casos. El control de login
válido puede aparecer de vez en cuando como falso positivo del modelo, porque este usa el
tiempo de respuesta como una de sus variables y la latencia del login fluctúa. La ráfaga
de peticiones sale como no aplica, porque el CRS por defecto no frena la fuerza bruta y el
modelo no incorpora la frecuencia de peticiones por dirección IP.

> Figura 19. Matriz de efectividad por capa.
> Espacio para captura.

---

## Fase 7. Observabilidad y métricas

Se calculan las métricas por capa a partir de la matriz de la fase anterior y del flujo
de eventos, y se emite una recomendación de ajuste.

```bash
python observability/collect_metrics.py
```

Salida esperada:
```text
=== MÉTRICAS FASE 7 ===
  Reglas (Fase 2)  det=0,80   fpr=0,00
  IA/ML (Fase 3)   det=1,00   fpr entre 0,00 y 0,33
  RASP (Fase 4)    det=0,8889 fpr=0,00
  Combinada        det=0,90
  MTTD (ms): reglas cercano a 6, IA cercano a 9 a 25, RASP cercano a 0,02
```

Recomendaciones de ajuste. Subir el nivel de paranoia del CRS al nivel dos para cerrar el
hueco de la doble codificación en la capa de reglas, aceptando que aumentarán los falsos
positivos. Revisar el umbral de contaminación del modelo y agregar la frecuencia de
peticiones por dirección IP como variable, de modo que cubra el caso de la ráfaga. Añadir
al RASP una regla para los comentarios de inyección SQL en línea.

> Figura 20. Tabla de métricas por capa y reporte generado.
> Espacio para captura.

---

## Anexo. Automatización del montaje

Una vez validado el procedimiento manual, todo el proceso anterior se consolidó en dos
scripts para poder levantar y bajar el laboratorio de forma reproducible. Se documentan
aquí como cierre, después de haber demostrado el montaje a mano.

Para levantar todo el entorno de una sola vez:

```bash
./setup.sh
```

Para bajar todo el entorno sin dejar rastro de ejecución, conservando el código y las
evidencias:

```bash
./shutdown.sh
```

> Figura 21. Ejecución de los scripts de automatización setup.sh y shutdown.sh.
> Espacio para captura.

---

## Resumen de resultados

| Fase | Componente | Resultado observado |
|---|---|---|
| 0 | Entorno | Contenedores y entorno de Python operativos |
| 1 | Vulnerabilidades | Cinco fallas comprobadas contra la aplicación directa |
| 2 | WAF | Bloqueo del ataque conocido y evasión por doble codificación |
| 3 | Aprendizaje automático | Exactitud 88 por ciento, recall 86,7 por ciento, ROC-AUC 0,95 |
| 4 | RASP | Bloqueo de los cuatro ataques, costo de inspección cercano a 0,02 ms |
| 5 | Pipeline | Ejercicio de rojo y verde exitoso |
| 6 | Matriz | Tres capas integradas y evasión visible por capa |
| 7 | Métricas | Detección, falsos positivos y MTTD por capa, combinada del 90 por ciento |

---

## Cuestionario

Se responden las ocho preguntas del taller con base en la evidencia de las fases
anteriores. Cada respuesta cita la figura o la tabla que la sustenta.

Espacio para las ocho respuestas argumentadas.

---

## Referencias

Bkimminich. (2024). OWASP Juice Shop [Software]. OWASP Foundation.
https://owasp.org/www-project-juice-shop/

Docker Inc. (2024). Docker Compose documentation. https://docs.docker.com/compose/

OWASP Foundation. (2024). OWASP Core Rule Set. https://coreruleset.org/

Pedregosa, F., Varoquaux, G., Gramfort, A., Michel, V., Thirion, B., Grisel, O., y otros.
(2011). Scikit-learn: Machine learning in Python. Journal of Machine Learning Research,
12, 2825 a 2830.

Semgrep Inc. (2024). Semgrep documentation. https://semgrep.dev/docs/

Trail of Bits. (2024). pip-audit [Software]. https://github.com/pypa/pip-audit

Trustwave SpiderLabs. (2024). ModSecurity. https://github.com/owasp-modsecurity/ModSecurity
