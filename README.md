# PAN UF Tools

Colección de scripts Python para consultar información de URLs y dominios a través de las APIs de **Palo Alto Networks**.

---

## Scripts disponibles

| Script | API usada | Para qué |
|--------|-----------|----------|
| `pan_url_checker.py` | PAN-OS Firewall API | Categoría y riesgo de URLs via firewall |
| `pan_domain_checker.py` | DNS Security Threat Vault API | Información de amenazas de dominios (cloud) |
| `pan_wildfire_checker.py` | WildFire Public Cloud API | Veredicto de URLs en WildFire (con auto-envío si desconocida) |

---

## Requisitos

- Python 3.10+

```powershell
pip install -r requirements.txt
```

---

## Configuración

Copia `.env.example` como `.env` y rellena los valores:

```ini
# pan_url_checker.py
FIREWALL_IP=192.168.1.1
PAN_API_KEY=tu_clave_pan_aqui

# pan_domain_checker.py
DNS_API_KEY=tu_clave_dns_aqui

# pan_wildfire_checker.py
WILDFIRE_API_KEY=tu_clave_wildfire_aqui
```

> **¿Dónde obtengo la PAN API Key?**  
> En el firewall: **Device → Administrators → tu usuario → Generate API Key**, o via CLI:  
> `curl -k "https://IP/api/?type=keygen&user=admin&password=PASSWORD"`

> **¿Dónde obtengo la DNS API Key?**  
> En el [Customer Support Portal](https://support.paloaltonetworks.com) o en la consola de DNS Security.

> **¿Dónde obtengo la WildFire API Key?**  
> En el [Customer Support Portal](https://support.paloaltonetworks.com) → **Assets → API Keys**.

---

## pan_url_checker.py

Consulta la categoría y nivel de riesgo de URLs directamente contra la API del firewall PAN-OS.

### Uso

```powershell
python pan_url_checker.py                        # Modo interactivo
python pan_url_checker.py -u bbva.es             # URL individual
python pan_url_checker.py -u bbva.es -u g.com    # Múltiples URLs
python pan_url_checker.py -f urls.txt            # Desde fichero
python pan_url_checker.py -f urls.txt -u otra.com  # Combinado
```

### Ejemplo de salida

```
─────────────────────────────────────────────────────────────────────────────────────
URL                                           CATEGORÍA                      RIESGO
─────────────────────────────────────────────────────────────────────────────────────
bbva.es                                       financial-services             low-risk
malware-test.com                              malware                        high-risk
─────────────────────────────────────────────────────────────────────────────────────
```

| Riesgo | Color |
|--------|-------|
| `low-risk` | 🟢 Verde |
| `medium-risk` | 🟡 Amarillo |
| `high-risk` / `critical-risk` | 🔴 Rojo |

### Notas técnicas
- Autenticación via cabecera `X-PAN-KEY`.
- Certificados SSL auto-firmados aceptados automáticamente (`verify=False`).
- Timeout: **15 segundos** por URL.

---

## pan_domain_checker.py

Consulta información de dominios via la **API Threat Vault de DNS Security** (cloud). Envía los dominios en lotes para mayor eficiencia (hasta 50 por petición).

### Uso

```powershell
python pan_domain_checker.py                          # Modo interactivo
python pan_domain_checker.py -d malware-site.com      # Dominio individual
python pan_domain_checker.py -d d1.com -d d2.com      # Múltiples dominios
python pan_domain_checker.py -f dominios.txt          # Desde fichero
python pan_domain_checker.py -f dominios.txt -d extra.com  # Combinado
```

### Ejemplo de salida

```
─────────────────────────────────────────────────────────────────────────────────────────────────
DOMINIO                                  CATEGORÍA                    VEREDICTO      IPs CONOCIDAS
─────────────────────────────────────────────────────────────────────────────────────────────────
annexpublishers.org                      malware                      malicious      107.180.37.105
  ↳ Corroborated by intelligence sources
  ↳ URL sandbox analysis found this URL to be malicious.
google.com                               search-engines               benign         —
─────────────────────────────────────────────────────────────────────────────────────────────────
```

| Veredicto | Color |
|-----------|-------|
| `benign` | 🟢 Verde |
| `grayware` / `phishing` | 🟡 Amarillo |
| `malicious` | 🔴 Rojo |

### Notas técnicas
- Autenticación via cabecera `X-DNS-API-APIKEY`.
- Envío en lotes de hasta **50 dominios** por petición.
- Muestra categoría actual, veredicto, IPs conocidas y evidencias de la clasificación.

---

## pan_wildfire_checker.py

Consulta el veredicto de WildFire para una o varias URLs usando la **WildFire Public Cloud API**.

### Flujo de consulta

```
URL → GET /publicapi/get/verdict
         ├─ Veredicto conocido → muestra resultado
         └─ Desconocida (-102) → POST /publicapi/submit/link → informa del envío
```

### Uso

```powershell
python pan_wildfire_checker.py                           # Modo interactivo
python pan_wildfire_checker.py -u http://malware.com     # URL individual
python pan_wildfire_checker.py -u u1.com -u u2.com       # Múltiples URLs
python pan_wildfire_checker.py -f urls.txt               # Desde fichero
python pan_wildfire_checker.py -D -u http://test.com     # Con debug
```

### Ejemplo de salida

```
──────────────────────────────────────────────────────────────────────────────────────────────────
URL                                           VEREDICTO                    ANÁLISIS               ENVIADO
──────────────────────────────────────────────────────────────────────────────────────────────────
http://www.google.com                         benign                       2020-07-29T16:33:17    No
http://malware-site.com                       desconocida                                         Sí
  ↳ Enviado – SHA256: a3b1c2...
──────────────────────────────────────────────────────────────────────────────────────────────────
```

| Veredicto | Código | Color |
|-----------|--------|-------|
| `benign` | 0 | 🟢 Verde |
| `grayware` | 2 | 🟡 Amarillo |
| `phishing` | 4 | 🟡 Amarillo |
| `malware` | 1 | 🔴 Rojo |
| `C2` | 5 | 🔴 Rojo |
| `pending` | -100 | 🟡 Amarillo |
| `desconocida` | -102 | Gris (se envía a análisis) |

### Notas técnicas
- Autenticación via campo de formulario `apikey` en cada petición POST.
- **No consume cuota de submit** si la URL ya existe en la base de datos de WildFire.
- Las URLs desconocidas se envían automáticamente a análisis (`/submit/link`).
- El análisis puede tardar minutos; vuelve a consultar pasado un tiempo para obtener el veredicto final.

---

## Estructura del proyecto

```
pan-uf-tools/
├── pan_url_checker.py      # Script firewall PAN-OS
├── pan_domain_checker.py   # Script DNS Security Threat Vault
├── pan_wildfire_checker.py # Script WildFire Cloud API
├── .env                    # Configuración (no subir a git)
├── .env.example            # Plantilla de configuración
├── requirements.txt        # Dependencias Python
└── README.md
```

> ⚠️ Añade `.env` a tu `.gitignore` para no exponer las API Keys.



---

## Requisitos

- Python 3.10+
- Acceso a la API del firewall (clave API con permisos de operación)

```powershell
pip install -r requirements.txt
```

---

## Configuración

Copia `.env.example` como `.env` y rellena los valores:

```ini
FIREWALL_IP=192.168.1.1
PAN_API_KEY=tu_clave_api_aqui
```

> **¿Dónde obtengo la API Key?**  
> En el firewall: **Device → Administrators → tu usuario → Generate API Key**, o via CLI:  
> `curl -k "https://IP/api/?type=keygen&user=admin&password=PASSWORD"`

---

## Uso

### Modo interactivo (sin argumentos)

```powershell
python pan_url_checker.py
```

El script pedirá URLs una a una, mostrará el resultado inmediatamente y preguntará si quieres hacer otra consulta. Al terminar, muestra un resumen de todas las consultas de la sesión.

### URL individual

```powershell
python pan_url_checker.py -u bbva.es
```

### Múltiples URLs

```powershell
python pan_url_checker.py -u bbva.es -u google.com -u ejemplo.com
```

### Desde fichero

El fichero debe contener una URL por línea (se ignoran líneas vacías):

```powershell
python pan_url_checker.py -f urls.txt
```

**Ejemplo de `urls.txt`:**
```
bbva.es
google.com
ejemplo-malicioso.com
```

### Combinado (fichero + URLs adicionales)

```powershell
python pan_url_checker.py -f urls.txt -u otra-url.com
```

---

## Ejemplo de salida

```
Procesando 3 URL(s)...
  → Consultando bbva.es ... OK
  → Consultando google.com ... OK
  → Consultando malware-test.com ... OK

─────────────────────────────────────────────────────────────────────────────────────
URL                                           CATEGORÍA                      RIESGO
─────────────────────────────────────────────────────────────────────────────────────
bbva.es                                       financial-services             low-risk
google.com                                    search-engines                 low-risk
malware-test.com                              malware                        high-risk
─────────────────────────────────────────────────────────────────────────────────────
```

El nivel de riesgo se muestra con colores:

| Riesgo | Color |
|--------|-------|
| `low-risk` | 🟢 Verde |
| `medium-risk` | 🟡 Amarillo |
| `high-risk` | 🔴 Rojo |
| `critical-risk` | 🔴 Rojo / Negrita |

---

## Notas técnicas

- La petición usa la cabecera `X-PAN-KEY` para la autenticación.
- Los certificados SSL auto-firmados del firewall se aceptan automáticamente (`verify=False`).
- Si se pasa la misma URL varias veces (por `-u` y fichero), solo se consulta una vez.
- Timeout de conexión: **15 segundos** por URL.

---

## Estructura del proyecto

```
pan-uf-tools/
├── pan_url_checker.py   # Script principal
├── .env                 # Configuración (no subir a git)
├── .env.example         # Plantilla de configuración
├── requirements.txt     # Dependencias Python
└── README.md
```

> ⚠️ Añade `.env` a tu `.gitignore` para no exponer la API Key.
