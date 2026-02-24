# Módulo: `ttp_mapper.py`

**Clase:** `TTPMapper`
**Dependencias:** `mitreattack-python`, `re`

---

## Responsabilidad

Mapea el texto de un informe de amenazas a técnicas del framework **MITRE ATT&CK Enterprise**. Utiliza tres estrategias complementarias:

1. **Extracción explícita:** Busca IDs MITRE directamente en el texto (`T1234`, `T1234.001`)
2. **Keyword matching:** Compara palabras del texto con un mapa de ~400 keywords distribuidas en 40+ técnicas
3. **Tool detection:** Identifica herramientas conocidas (Mimikatz, Cobalt Strike...) y las mapea a sus técnicas asociadas

---

## API pública

### `__init__()`

Carga la base de datos MITRE ATT&CK Enterprise via `mitreattack-python`:
```python
from mitreattack.stix20 import MitreAttackData
self.mitre = MitreAttackData("enterprise-attack.json")
self.techniques = self.mitre.get_techniques(remove_revoked_deprecated=True)
self._technique_cache = {}
```

El archivo `enterprise-attack.json` se descarga automáticamente por `mitreattack-python` al primer uso.

---

### `extract_techniques(text: str) → List[Dict]`

**Parámetros:**

| Param | Tipo | Descripción |
|-------|------|-------------|
| `text` | str | Texto completo del informe |

**Retorno:** Lista de técnicas deduplicadas y ordenadas por kill chain.

```python
[
    {
        "id":              str,        # "T1566.001"
        "name":            str,        # "Spearphishing Attachment"
        "description":     str,        # Descripción MITRE completa
        "tactics":         List[str],  # ["Initial Access"]
        "platforms":       List[str],  # ["Windows", "macOS", "Linux"]
        "is_subtechnique": bool,       # True si tiene .XXX
        "triggered_by_tool": str,      # "cobalt strike" (si fue por tool detection)
    }
]
```

**Pipeline interno:**
```
text
  │
  ├─ 1. Explicit ID extraction: re.findall(r'\bT\d{4}(?:\.\d{3})?\b', text)
  │      Para cada ID → _get_technique(id) → añade a seen_ids
  │
  ├─ 2. Keyword matching: _search_by_keywords(text)
  │      Para cada TID en KEYWORD_MAP:
  │        Si algún keyword in text.lower() → añade técnica
  │
  ├─ 3. Tool detection: _search_by_tools(text)
  │      Para cada tool en TOOL_TTP_MAP:
  │        Si tool_name in text.lower() → añade técnica con triggered_by_tool
  │
  ├─ 4. Deduplicación por TID
  │
  └─ 5. Ordenar por tactic kill chain → _sort_by_tactic()
```

---

### `_get_technique(technique_id: str) → Optional[Dict]`

Busca una técnica en la base de datos MITRE con cache en memoria.

```python
# Cache hit O(1)
if technique_id in self._technique_cache:
    return self._technique_cache[technique_id]

# Search en enterprise-attack
technique = self.mitre.get_technique_by_id(technique_id)
if not technique:
    return self._minimal_entry(technique_id)  # Fallback
```

---

### `_minimal_entry(technique_id: str) → Dict`

Fallback para técnicas no encontradas en la base de datos (obsoletas, sub-técnicas nuevas, typos):

```python
{
    "id":              technique_id,
    "name":            technique_id,
    "description":     "Technique not found in MITRE database",
    "tactics":         ["Unknown"],
    "platforms":       [],
    "is_subtechnique": "." in technique_id,
    "triggered_by_tool": None,
}
```

---

## `KEYWORD_MAP`

Mapa de TID → keywords. Cobertura de 40+ técnicas con ~10 keywords cada una.

Extracto representativo:

```python
KEYWORD_MAP = {
    # INITIAL ACCESS
    "T1566":     ["phishing", "spearphishing", "malicious email", "malicious attachment",
                  "macro", "lnk file", "office document"],
    "T1566.001": ["spearphishing attachment", "docm", "xlsm", "macro document", "vba macro"],
    "T1190":     ["exploit public", "web application", "remote code execution",
                  "rce", "sql injection", "log4j", "log4shell", "proxylogon"],
    "T1133":     ["vpn", "remote desktop", "rdp", "citrix", "external remote services"],
    "T1195":     ["supply chain", "software supply", "build system", "solarwinds",
                  "3cx", "codecov"],

    # EXECUTION
    "T1059":     ["command interpreter", "script", "powershell", "cmd.exe",
                  "bash", "python", "wscript", "cscript"],
    "T1059.001": ["powershell", "powershell.exe", "iex", "invoke-expression",
                  "encodedcommand", "bypass executionpolicy", "downloadstring"],
    "T1059.003": ["cmd.exe", "command prompt", "batch file", "bat script",
                  "shell command"],
    "T1053":     ["scheduled task", "cron job", "schtasks", "at.exe", "crontab",
                  "launchd", "startup task"],
    "T1203":     ["exploit", "vulnerability", "buffer overflow", "use after free",
                  "memory corruption"],

    # PERSISTENCE
    "T1547":     ["autostart", "registry run", "startup folder", "boot persistence",
                  "run key", "runonce"],
    "T1543":     ["service", "create service", "install service", "malicious service",
                  "service control"],
    "T1574":     ["dll hijack", "dll sideload", "dll search order",
                  "phantom dll"],

    # PRIVILEGE ESCALATION
    "T1068":     ["privilege escalation", "kernel exploit", "local privilege",
                  "lpe", "uac bypass", "juicypotato"],
    "T1055":     ["process injection", "dll injection", "shellcode injection",
                  "process hollowing", "reflective"],
    "T1134":     ["token impersonation", "access token", "impersonate", "runas",
                  "steal token"],

    # DEFENSE EVASION
    "T1562":     ["disable defender", "tamper protection", "antivirus disable",
                  "impair defense", "disable security"],
    "T1070":     ["clear log", "event log", "indicator removal", "timestomp",
                  "wevtutil", "log tampering"],
    "T1027":     ["obfuscat", "encode", "base64", "packed", "encrypted payload",
                  "xor encoded"],
    "T1218":     ["lolbin", "signed binary", "regsvr32", "mshta", "certutil",
                  "rundll32", "living off the land"],

    # CREDENTIAL ACCESS
    "T1003":     ["credential dump", "password dump", "lsass", "sam database",
                  "ntds", "secretsdump", "hashdump"],
    "T1003.001": ["lsass memory", "procdump", "task manager dump",
                  "minidumpwritedump", "comsvcs.dll"],
    "T1558":     ["kerberoast", "as-rep roast", "ticket", "kerberos",
                  "spn", "golden ticket", "silver ticket"],
    "T1555":     ["browser password", "credential store", "password manager",
                  "chrome passwords", "firefox passwords"],

    # DISCOVERY
    "T1083":     ["file discovery", "directory listing", "file enumeration",
                  "dir command", "ls -la"],
    "T1018":     ["network scan", "port scan", "host discovery", "nmap",
                  "arp scan", "ping sweep"],
    "T1057":     ["process discovery", "process list", "tasklist", "ps aux",
                  "get-process"],
    "T1082":     ["system info", "hostname", "os version", "systeminfo",
                  "uname -a", "computer name"],

    # LATERAL MOVEMENT
    "T1021":     ["lateral movement", "remote service", "psexec", "wmiexec",
                  "smb", "ssh", "winrm"],
    "T1021.001": ["rdp", "remote desktop", "mstsc", "xfreerdp",
                  "remote desktop protocol"],
    "T1570":     ["lateral tool transfer", "copy tool", "smb share",
                  "admin share", "c$ share"],

    # COMMAND & CONTROL
    "T1071":     ["c2", "command and control", "beacon", "cobalt strike",
                  "c2 channel", "remote access"],
    "T1071.001": ["http c2", "https c2", "web beacon", "http beacon"],
    "T1090":     ["proxy", "socks", "tor", "domain fronting",
                  "multi-hop proxy"],
    "T1095":     ["raw socket", "tcp c2", "udp c2", "non-http c2",
                  "custom protocol"],

    # EXFILTRATION
    "T1041":     ["exfiltrat", "data theft", "data exfil", "c2 channel exfil",
                  "upload to c2"],
    "T1567":     ["cloud exfil", "dropbox", "onedrive", "google drive",
                  "mega.nz", "pastebin"],

    # IMPACT
    "T1486":     ["ransomware", "encrypt files", "ransom note", "locker",
                  ".encrypted", "cryptolocker"],
    "T1490":     ["inhibit recovery", "delete shadow", "vssadmin delete",
                  "bcdedit /set recoveryenabled", "backup deletion"],
    "T1485":     ["wiper", "destructive", "disk wipe", "mbr overwrite",
                  "data destruction"],
}
```

---

## `TOOL_TTP_MAP`

Mapeo de herramientas conocidas a su técnica MITRE principal:

```python
TOOL_TTP_MAP = {
    "mimikatz":        "T1003",     # Credential Access
    "procdump":        "T1003.001", # LSASS Memory
    "cobalt strike":   "T1071.001", # C2 over HTTP/S
    "cobaltstrike":    "T1071.001",
    "metasploit":      "T1059",     # Execution
    "meterpreter":     "T1059",
    "empire":          "T1059.001", # PowerShell
    "powersploit":     "T1059.001",
    "bloodhound":      "T1087",     # Account Discovery
    "sharphound":      "T1087",
    "responder":       "T1557",     # LLMNR Poisoning
    "impacket":        "T1003",     # Secretsdump
    "crackmapexec":    "T1021",     # Lateral Movement
    "psexec":          "T1021",
    "rubeus":          "T1558",     # Kerberoasting
    "kerbrute":        "T1110",     # Brute Force
    "nmap":            "T1046",     # Network Service Discovery
    "nessus":          "T1046",
    "sliver":          "T1071",     # C2
    "brute ratel":     "T1071",
    "havoc":           "T1071",
}
```

---

## `_sort_by_tactic()`

Ordena las técnicas por el orden del kill chain MITRE:

```python
TACTIC_ORDER = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command And Control",
    "Exfiltration",
    "Impact",
    "Unknown",  # Al final
]
```

Técnicas con múltiples tácticas se posicionan por la primera táctica en la lista.

---

## Notas de implementación

- **Cache de técnicas:** `_technique_cache` usa un dict en memoria. En ejecuciones largas con muchos reports, el cache se conserva durante toda la sesión.
- **enterprise-attack.json:** Se descarga a `~/.local/share/mitreattack/` la primera vez. Las ejecuciones posteriores son offline.
- **Sensibilidad al idioma:** Los keywords están en inglés. Informes en español u otros idiomas tendrán menor cobertura de keyword matching (aunque los IDs explícitos siguen funcionando).
- **Sub-técnicas:** `T1059.001` se trata como técnica independiente. Si el texto menciona explícitamente `T1059`, se añade solo `T1059`. No hay inferencia de padre→hijo automática.
