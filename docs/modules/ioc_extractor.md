# Módulo: `ioc_extractor.py`

**Clase:** `IOCExtractor`
**Dependencias:** `iocextract`, `re`

---

## Responsabilidad

Extrae **16 tipos de Indicadores de Compromiso (IOC)** del texto de un informe de amenazas. Combina la biblioteca `iocextract` (para tipos estándar de red y hashes) con expresiones regulares propias (para artefactos Windows específicos: registry keys, named pipes, mutex, comandos).

Incluye lógica para manejar **IOCs ofuscados/defangeados** como `hxxp://`, `[.]com`, `10.10.10[.]1`.

---

## API pública

### `extract_all(text: str) → Dict[str, List[str]]`

Punto de entrada único. Extrae todos los tipos de IOC y retorna un diccionario con solo las claves que tienen resultados.

**Parámetros:**

| Param | Tipo | Descripción |
|-------|------|-------------|
| `text` | str | Texto completo del informe (normalmente `content["full_text"]`) |

**Retorno:** `Dict[str, List[str]]` — Solo incluye claves con listas no vacías.

```python
{
    "ipv4":          List[str],  # "10.1.2.3", "192.168.1.100"
    "ipv6":          List[str],  # "2001:db8::1"
    "domains":       List[str],  # "malicious.com", "c2.attacker.net"
    "urls":          List[str],  # "http://evil.com/payload.exe"
    "emails":        List[str],  # "attacker@protonmail.com"
    "md5":           List[str],  # "5d41402abc4b2a76b9719d911017c592"
    "sha1":          List[str],  # "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
    "sha256":        List[str],  # "2c26b46b..."
    "registry_keys": List[str],  # "HKCU\\Software\\Microsoft\\Windows\\Run"
    "file_paths":    List[str],  # "C:\\Windows\\Temp\\malware.exe", "/tmp/payload"
    "named_pipes":   List[str],  # "\\\\.\\pipe\\backdoor"
    "mutex_names":   List[str],  # "Global\\malware_mutex"
    "cves":          List[str],  # "CVE-2024-1234"
    "commands":      List[str],  # "powershell.exe -NoProfile -ExecutionPolicy Bypass"
    "service_names": List[str],  # "MalwareSvc", "WindowsUpdateHelper"
    "user_agents":   List[str],  # "Mozilla/5.0 (compatible; custom)"
}
```

---

## Lógica de extracción por tipo

### IPs (IPv4 / IPv6)

- **Librería:** `iocextract.extract_ips()` + `iocextract.extract_ipv6s()`
- **Defangeado:** Detecta `10.10.10[.]1`, `10[.]10[.]10[.]1` y los normaliza
- **Filtro (`_filter_private`):** Actualmente **no filtra IPs privadas**. Se incluyen IPs RFC1918 porque son relevantes para telemetría interna (ej. `10.5.9.31` es el victim).
- **Deduplicación:** `list(set(...))`

---

### Dominios

- **Librería:** `iocextract.extract_urls()` → extrae host de cada URL
- **Defangeado:** Detecta `evil[.]com`, `evil\.com` y normaliza
- **Filtro (`_filter_generic_domains`):** Excluye dominios de infraestructura legítima:

```python
_GENERIC_DOMAINS = {
    "microsoft.com", "windows.com", "windowsupdate.com",
    "google.com", "googleapis.com", "gstatic.com",
    "amazon.com", "amazonaws.com", "cloudfront.net",
    "apple.com", "icloud.com",
    "akamai.net", "akamaiedge.net",
    "cloudflare.com", "cloudflare.net",
    "github.com", "githubusercontent.com",
    "office.com", "office365.com", "microsoftonline.com",
    "symantec.com", "norton.com", "crowdstrike.com",
    "virustotal.com", "threatintelligenceplatform.com",
}
```

---

### URLs

- **Librería:** `iocextract.extract_urls(refang=True)`
- **Defangeado:** `hxxp://`, `hxxps://` → `http://`, `https://`
- Las URLs se incluyen íntegras; los dominios se extraen de ellas por separado.

---

### Emails

- **Librería:** `iocextract.extract_emails()`
- **Defangeado:** `user[@]domain[.]com` → `user@domain.com`

---

### Hashes (MD5, SHA1, SHA256)

- **Librería:** `iocextract.extract_md5s()`, `iocextract.extract_sha1s()`, `iocextract.extract_sha256s()`
- Normalización a minúsculas
- Longitudes esperadas: MD5=32, SHA1=40, SHA256=64

---

### Registry Keys

**Regex:**

```python
_RE_REGISTRY = re.compile(
    r'(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT'
    r'|HKEY_USERS|HKEY_CURRENT_CONFIG'
    r'|HKLM|HKCU|HKCR|HKU|HKCC)'
    r'\\[\\w\\\\]+',
    re.IGNORECASE
)
```

Detecta tanto la forma larga (`HKEY_LOCAL_MACHINE`) como la corta (`HKLM`).

---

### File Paths

**Regex Windows:**
```python
_RE_WIN_PATH = re.compile(
    r'[A-Za-z]:\\(?:[\w\s\-\.]+\\)*[\w\s\-\.]+(?:\.\w+)?'
)
```

**Regex Linux:**
```python
_RE_LINUX_PATH = re.compile(
    r'/(?:etc|tmp|var|usr|home|opt|proc|sys|dev|bin|sbin|lib)'
    r'(?:/[\w\.\-]+)+'
)
```

**Filtro de falsos positivos:**
- Mínimo 6 caracteres
- Excluye rutas de documentación y bibliotecas estándar: `/usr/share/doc`, `/etc/ld.so`, `/var/lib/dpkg`

---

### Named Pipes

```python
_RE_NAMED_PIPE = re.compile(
    r'\\\\\.\\pipe\\[\w\-\.]+',
    re.IGNORECASE
)
```

Detecta patrones como `\\.\pipe\backdoor`, `\\.\pipe\psexesvc`.

---

### Mutex Names

```python
_RE_MUTEX = re.compile(
    r'(?:Global\\|Local\\)?[\w\-]{6,50}(?:mutex|mtx|lock|sync)',
    re.IGNORECASE
)
```

---

### CVEs

```python
_RE_CVE = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
```

Detecta `CVE-2024-1234`, `CVE-2024-12345678`. Normaliza a mayúsculas.

---

### Comandos / Cmdlets

Dos patrones:

**PowerShell cmdlets:**
```python
_RE_PS_CMDLET = re.compile(
    r'(?:Invoke|Get|Set|Remove|New|Start|Stop|Add|Import|Export|Write|Read|'
    r'ConvertTo|ConvertFrom|Out|Select|Where|ForEach|Sort|Format|Test|Copy|'
    r'Move|Rename|Clear|Enable|Disable|Register|Unregister|Update|Install|'
    r'Uninstall|Publish|Connect|Disconnect|Enter|Exit|Find|Measure|Compare|'
    r'Restore|Backup|Mount|Dismount|Optimize|Repair|Reset|Restart|Suspend|Resume)'
    r'-\w+(?:\s+(?:-\w+\s+)?[\w\.\-\\/\'\"]+){0,3}',
    re.IGNORECASE
)
```

**Comandos shell:**
```python
_RE_SHELL_CMD = re.compile(
    r'(?:powershell(?:\.exe)?|cmd(?:\.exe)?|bash|sh|python\d?|perl|ruby|nc|netcat|'
    r'curl|wget|certutil|mshta|wscript|cscript|regsvr32|rundll32|msiexec|'
    r'schtasks|at\.exe|reg\.exe|net\.exe|sc\.exe|tasklist|taskkill|whoami|'
    r'ipconfig|ifconfig|netstat|nslookup|ping|tracert|arp|route|systeminfo|'
    r'wmic|wbadmin|vssadmin|bcdedit|icacls|cacls|takeown|attrib|xcopy|robocopy|'
    r'psexec|mimikatz|procdump|dbghelp|sekurlsa|lsadump|privilege)'
    r'(?:\.exe)?\s+[\w\-\./\\\'\"@=:]+(?:\s+[\w\-\./\\\'\"@=:]+){0,5}',
    re.IGNORECASE
)
```

**Post-procesado:**
- Se ordenan por longitud (descendente) para priorizar comandos más específicos
- Se retornan los 20 primeros

---

### Service Names

```python
_RE_SERVICE = re.compile(
    r'\b([A-Z][a-zA-Z0-9]{3,30}(?:Svc|Service|Helper|Agent|Host|Mgr|Monitor))\b'
)
```

---

### User Agents

```python
_RE_USER_AGENT = re.compile(
    r'Mozilla/\d\.\d\s*\([^)]+\)(?:\s+[^\n]{0,100})?'
)
```

---

## Pipeline interno de `extract_all()`

```
text
  │
  ├─ iocextract.extract_ips()      → ipv4_raw[]
  ├─ iocextract.extract_ipv6s()    → ipv6_raw[]
  ├─ iocextract.extract_urls()     → urls_raw[]  ──► dominios extraídos
  ├─ iocextract.extract_emails()   → emails_raw[]
  ├─ iocextract.extract_md5s()     → md5_raw[]
  ├─ iocextract.extract_sha1s()    → sha1_raw[]
  ├─ iocextract.extract_sha256s()  → sha256_raw[]
  │
  ├─ _extract_registry_keys()      → registry_keys[]
  ├─ _extract_file_paths()         → file_paths[]
  ├─ re.findall(_RE_NAMED_PIPE)    → named_pipes[]
  ├─ re.findall(_RE_MUTEX)         → mutex_names[]
  ├─ re.findall(_RE_CVE)           → cves[]
  ├─ _extract_commands()           → commands[]
  ├─ re.findall(_RE_SERVICE)       → service_names[]
  ├─ re.findall(_RE_USER_AGENT)    → user_agents[]
  │
  ├─ Defang normalization (refang all defanged IOCs)
  ├─ Deduplication (set() per type)
  ├─ Filtering:
  │    ipv4 → _filter_private() [actualmente pass-through]
  │    domains → _filter_generic_domains()
  │
  └─ Return {key: list for key, list in result.items() if list}
```

---

## Notas de implementación

- **iocextract** puede lanzar excepciones en textos malformados. `extract_all()` usa `try/except` por tipo para no perder otros IOCs si uno falla.
- Los **IOCs defangeados** aparecen frecuentemente en informes de seguridad para evitar hyperlinks accidentales. La normalización es crítica para no perderlos.
- El **filtro de dominios genéricos** usa un set para O(1) lookup.
- Los **comandos** son los IOCs más ruidosos: muchos falsos positivos de texto descriptivo. Por eso se limita a 20 y se ordena por longitud.
