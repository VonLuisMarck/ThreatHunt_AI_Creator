# Integración con Shadow-Replay

Shadow-Replay es el framework de ejecución de playbooks de ataque del lab. ThreatHunt AI Creator genera JSON **100% compatibles** con su runner.

---

## Esquema completo del playbook

```json
{
  "playbook_id": "apt28_campaign_20240223",
  "name": "APT28 Campaign 2024",
  "description": "Texto libre con el razonamiento del LLM sobre la campaña",
  "generated_at": "2024-02-23T15:32:00.123456",
  "mandatory_agents": [ ... ],
  "events": [ ... ],

  // Campos extra añadidos por main.py (no consumidos por el runner):
  "emulation_snippets": [ ... ],
  "narrative_summary": "Texto Markdown narrativo"
}
```

---

## `mandatory_agents`

Lista de agentes que el runner debe tener conectados antes de empezar la ejecución.

```json
[
  {
    "agent_id": "agent_1",
    "agent_type": "windows",
    "description": "Windows victim — detection mode (10.5.9.31, domain-joined, CrowdStrike active)"
  },
  {
    "agent_id": "agent_2",
    "agent_type": "linux",
    "description": "Linux victim — lateral movement target (10.5.9.40, SSH: samba/password123)"
  }
]
```

### Reglas de asignación de agentes

| Plataforma | `agent_id` | Condición |
|------------|-----------|-----------|
| `windows` | `agent_1` | Siempre el primero |
| `linux` | `agent_2` | Si aparece en la secuencia de ataque |
| `cloud` | `agent_N` | Al final, si aparece |

El orden está forzado por `_PLATFORM_ORDER = ["windows", "linux", "cloud"]`.
Solo se incluyen plataformas que aparecen en `attack_sequence`.

---

## `events`

Array de eventos ordenados cronológicamente. Cada evento es una instrucción para un agente.

```json
{
  "event_id":            "initial_access_phishing",
  "name":                "Simulate phishing / Initial Access",
  "agent_id":            "agent_1",
  "required_agent_type": "windows",
  "payload_type":        "powershell",
  "payload":             "Write-Host '=== [T1566] ===' ; $wc = New-Object Net.WebClient ; ...",
  "mitre_technique":     "T1566.001",
  "success_trigger":     "credential_access_dump",
  "failure_action":      "abort"
}
```

### Campos del evento

| Campo | Tipo | Descripción |
|-------|------|-------------|
| `event_id` | string | Identificador único. Proviene del campo `stage` de `attack_sequence`. |
| `name` | string | Nombre legible. Proviene del campo `description` de `attack_sequence`. |
| `agent_id` | string | Qué agente ejecuta el payload (`agent_1`, `agent_2`, ...). |
| `required_agent_type` | string | Validación: el runner verifica que el agente sea de este tipo antes de ejecutar. |
| `payload_type` | string | `"powershell"` para Windows, `"python"` para Linux. |
| `payload` | string | **Siempre una sola línea.** Código ejecutable directo. Ver sección de payloads. |
| `mitre_technique` | string | ID MITRE (ej. `T1566.001`). Para correlación con detecciones. |
| `success_trigger` | string \| null | `event_id` del siguiente evento a ejecutar si este tiene éxito. `null` = fin del playbook. |
| `failure_action` | string | Qué hacer si el evento falla. Ver tabla abajo. |

### `failure_action`

| Valor | Comportamiento |
|-------|----------------|
| `"abort"` | Detiene la ejecución completa del playbook. Usado en los primeros 2 eventos (prerrequisitos críticos). |
| `"continue"` | Salta al siguiente evento aunque este haya fallado. |
| `"retry"` | Reintenta el evento. (Disponible en el runner; no generado actualmente por el sistema.) |

**Lógica de asignación:**
```python
"failure_action": "abort" if idx < 2 else "continue"
```
Los primeros 2 eventos de ataque usan `abort` porque si fallan (ej. sin conectividad C2 o sin agente), el resto del playbook no tiene sentido.

---

## Cadena de ejecución

```
Runner arranca
    │
    ▼
¿Todos los mandatory_agents están conectados?
    │ NO → Error, no ejecuta
    │ YES
    ▼
Ejecuta events[0]  (event_id = attack_sequence[0].stage)
    │
    ├─ SUCCESS → ejecuta events[success_trigger]
    └─ FAILURE → según failure_action:
                  abort   → para todo
                  continue→ ejecuta events[success_trigger] igualmente
                  retry   → reintenta
    │
    ▼
... (continúa la cadena)
    │
    ▼
Último evento de ataque → success_trigger = "cleanup_agent_2" (o _1 si no hay Linux)
    │
    ▼
cleanup_agent_2 (Linux) → success_trigger = "cleanup_agent_1"
    │
    ▼
cleanup_agent_1 (Windows) → success_trigger = null → FIN
```

---

## Payloads — formato one-liner

Todos los payloads en el campo `payload` son **una única línea** sin saltos de línea.

### PowerShell

Las plantillas de PowerShell ya terminan cada statement con `;`. El método `_to_oneliner` elimina las líneas de comentario (`#`) y une el resto con espacio:

```
# Ejemplo: _ps_persistence() colapsado
Write-Host '=== [T1547] PERSISTENCE ==='; Write-Host '  ├─ Host: 10.5.9.31'; $regPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'; $keyName = 'WindowsUpdateHelper'; Set-ItemProperty -Path $regPath -Name $keyName -Value 'powershell.exe -WindowStyle Hidden -NoProfile -Command "Start-Sleep 1"' -ErrorAction SilentlyContinue; Write-Host '  ├─ Registry Run key set (CrowdStrike: persistence detection)'; Start-Sleep -Seconds 3; Remove-ItemProperty -Path $regPath -Name $keyName -ErrorAction SilentlyContinue; Write-Host '  └─ Persistence key removed (cleanup)'
```

### Python — sin bloques indentados

Statements secuenciales separados por `; `:

```
import os, time; print('[CLEANUP] Demo completed — terminating Linux agent on 10.5.9.40'); time.sleep(2); os._exit(0)
```

### Python — con bloques indentados (`for`, `if`, `try`, `with`)

Se codifica el script completo en base64 y se envuelve en un exec:

```
import base64; exec(base64.b64decode('aW1wb3J0IHN1YnByb2Nlc3MKcHJpbnQoJz09...').decode())
```

El runner ejecuta esta línea con `python3 -c "..."` o equivalente.

---

## Eventos de cleanup

Siempre generados al final del playbook, en **orden inverso** al de `mandatory_agents`:

1. Si hay Linux y Windows: `cleanup_agent_2` → `cleanup_agent_1`
2. Solo Windows: `cleanup_agent_1`

**Cleanup Windows (PowerShell):**
```
Write-Host '[CLEANUP] Demo completed — terminating Windows agent on 10.5.9.31'; Start-Sleep -Seconds 2; Stop-Process -Id $PID -Force
```

**Cleanup Linux (Python one-liner):**
```
import os, time; print('[CLEANUP] Demo completed — terminating Linux agent on 10.5.9.40'); time.sleep(2); os._exit(0)
```

---

## Campos adicionales en el JSON raíz

Estos campos son añadidos por `main.py` pero **no son consumidos por el runner de Shadow-Replay**. Son metadatos de referencia:

### `emulation_snippets`

Array de snippets de emulación generados por `LLMAnalyzer.suggest_emulation_snippets()`. Formato:

```json
[
  {
    "technique_id": "T1003.001",
    "name": "LSASS Memory Dump",
    "tactic": "Credential Access",
    "platform": "windows",
    "code": "# [SIMULATION] T1003.001\n...",
    "detection_notes": "LSASS memory access attempt — Falcon CRITICAL alert",
    "source": "static_library",
    "stage_context": "Credential access after initial foothold"
  }
]
```

| Campo | Descripción |
|-------|-------------|
| `source` | `"static_library"` (pre-validado) o `"llm_generated"` (generado por el LLM) |
| `code` | Código multi-línea (para visualización en la UI, no para Shadow-Replay) |
| `detection_notes` | Qué detecta CrowdStrike con este snippet |

### `narrative_summary`

Texto Markdown generado por `LLMAnalyzer.generate_playbook_summary()`. Explica el playbook en lenguaje natural para el presentador de la demo.

---

## Ejemplo de playbook completo minimal

```json
{
  "playbook_id": "scattered_spider_20240223",
  "name": "Scattered Spider Telco Attack",
  "description": "Campaign targeting telecom sector via social engineering and SIM swapping",
  "generated_at": "2024-02-23T10:00:00",
  "mandatory_agents": [
    {
      "agent_id": "agent_1",
      "agent_type": "windows",
      "description": "Windows victim — detection mode (10.5.9.31, domain-joined, CrowdStrike active)"
    }
  ],
  "events": [
    {
      "event_id": "initial_access",
      "name": "Phishing / Initial Access simulation",
      "agent_id": "agent_1",
      "required_agent_type": "windows",
      "payload_type": "powershell",
      "payload": "Write-Host '=== [T1566] PHISHING ===' ; $wc = New-Object Net.WebClient ; $wc.Headers.Add('User-Agent','Mozilla/5.0') ; try { $wc.DownloadString('http://10.5.9.41:4444/ping') | Out-Null } catch { Write-Host '  C2 beacon attempted' }",
      "mitre_technique": "T1566",
      "success_trigger": "cleanup_agent_1",
      "failure_action": "abort"
    },
    {
      "event_id": "cleanup_agent_1",
      "name": "Cleanup — Terminate Windows Agent",
      "agent_id": "agent_1",
      "required_agent_type": "windows",
      "payload_type": "powershell",
      "payload": "Write-Host '[CLEANUP] Demo completed — terminating Windows agent on 10.5.9.31'; Start-Sleep -Seconds 2; Stop-Process -Id $PID -Force",
      "mitre_technique": "",
      "success_trigger": null,
      "failure_action": "continue"
    }
  ]
}
```
