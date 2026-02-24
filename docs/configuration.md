# Referencia de Configuración — `config.yaml`

---

## Estructura completa

```yaml
llm:
  provider: ollama              # Proveedor LLM (ver tabla)
  model: llama3                 # Modelo específico del proveedor
  temperature: 0.1              # Temperatura de generación (0.0–1.0)

output:
  playbook_dir: playbooks       # Directorio de salida para los JSON

demo:
  platform: windows             # Plataforma por defecto para snippets

lab:
  lab_context_prompt: promtps/lab_context.txt
  machines:
    win_prevention:
      ip: "10.5.9.30"
      os: windows
      domain_joined: true
      edr: crowdstrike
      edr_mode: prevention
    win_detection:
      ip: "10.5.9.31"
      os: windows
      domain_joined: true
      edr: crowdstrike
      edr_mode: detection
    linux_victim:
      ip: "10.5.9.40"
      os: linux
      domain_joined: false
      edr: none
      ssh_user: samba
      ssh_password: password123
    win_unmanaged:
      ip: "10.5.9.27"
      os: windows
      domain_joined: false
      edr: none
  c2:
    ip: "10.5.9.41"
    os: ubuntu
    port: 4444
  auxiliary:
    kali:
      ip: "10.5.9.21"
      os: kali
  integrations:
    firewall:
      vendor: palo_alto
      monitors_pairs:
        - ["10.5.9.30", "10.5.9.41"]
        - ["10.5.9.31", "10.5.9.41"]
        - ["10.5.9.30", "10.5.9.21"]
        - ["10.5.9.31", "10.5.9.21"]
    email:
      vendor: mimecast
      position: mx_gateway
```

---

## Sección `llm`

### `llm.provider`

| Valor | Descripción | Coste | Calidad |
|-------|-------------|-------|---------|
| `ollama` | Modelo local vía Ollama. Sin coste, sin API key. | Gratis | Media |
| `anthropic` | Claude API. Requiere `ANTHROPIC_API_KEY`. | De pago | Alta |
| `openai` | OpenAI API. Requiere `OPENAI_API_KEY`. | De pago | Alta |

### `llm.model`

Modelos recomendados por proveedor:

| Provider | Modelo recomendado | Notas |
|----------|-------------------|-------|
| `ollama` | `llama3.1:70b` | Mejor calidad local. `llama3` para pruebas rápidas. |
| `anthropic` | `claude-opus-4-6` | Máxima calidad. `claude-sonnet-4-5-20250929` para menos coste. |
| `openai` | `gpt-4o` | Recomendado. `gpt-4-turbo` como alternativa. |

### `llm.temperature`

- Rango: `0.0` – `1.0`
- Valor recomendado: `0.1` (respuestas consistentes y deterministas)
- No usar valores > `0.3` en producción: el parser JSON puede fallar con respuestas más creativas

---

## Variables de entorno (API keys)

Las API keys **no se guardan en `config.yaml`**. Se leen en tiempo de ejecución:

```bash
# Anthropic
export ANTHROPIC_API_KEY=sk-ant-api03-...

# OpenAI
export OPENAI_API_KEY=sk-proj-...
```

Si la variable no está definida, `_build_llm()` lanza `ValueError` con instrucciones.

---

## Sección `output`

### `output.playbook_dir`

Directorio donde se guardan los JSON generados. Se crea automáticamente si no existe.

```python
# En main.py:
output_dir = Path(config.get("output", {}).get("playbook_dir", "playbooks"))
output_dir.mkdir(parents=True, exist_ok=True)
```

Archivos generados:
- `{playbook_id}.json` — Playbook Shadow-Replay
- `{playbook_id}_emulation_snippets.json` — Snippets de emulación

---

## Sección `demo`

### `demo.platform`

Plataforma por defecto para la generación de snippets de emulación cuando una técnica es multi-plataforma.

| Valor | Efecto |
|-------|--------|
| `windows` | Genera código PowerShell preferentemente |
| `linux` | Genera código Python/Bash preferentemente |

---

## Sección `lab`

### `lab.lab_context_prompt`

Ruta al archivo de texto con el system prompt de topología del lab. Este contenido se inyecta en **todas** las llamadas al LLM via `LLMAnalyzer`.

**Cómo se carga:**

```python
# En llm_analyzer.py:
def _load_lab_context(config_path):
    cfg = yaml.safe_load(open(config_path))
    prompt_path = cfg["lab"]["lab_context_prompt"]
    base_dir = os.path.dirname(os.path.abspath(config_path))
    full_path = os.path.join(base_dir, prompt_path)
    return open(full_path).read().strip()
```

Falla silenciosamente (retorna `""`) si el archivo no existe, para no bloquear flujos sin contexto de lab.

---

### `lab.machines`

Cada máquina tiene la siguiente estructura:

| Campo | Tipo | Uso |
|-------|------|-----|
| `ip` | string | Hardcodeado en payloads generados |
| `os` | string | Informativo |
| `domain_joined` | bool | Afecta a descripción del agente en el brief |
| `edr` | string | Informativo (`crowdstrike` / `none`) |
| `edr_mode` | string | `detection` (alerta, no bloquea) / `prevention` (bloquea activamente) |
| `ssh_user` | string | Solo `linux_victim`. Incluido en payloads de lateral movement |
| `ssh_password` | string | Solo `linux_victim`. Incluido en payloads de lateral movement |

**Campos leídos por `PlaybookGenerator`:**

```python
self.win_detection_ip  = machines["win_detection"]["ip"]     # → payloads Windows
self.win_prevention_ip = machines["win_prevention"]["ip"]    # → demo brief
self.linux_ip          = machines["linux_victim"]["ip"]      # → payloads Linux + lateral
self.linux_user        = machines["linux_victim"]["ssh_user"]
self.linux_pass        = machines["linux_victim"]["ssh_password"]
self.win_unmanaged_ip  = machines["win_unmanaged"]["ip"]     # → demo brief
```

---

### `lab.c2`

| Campo | Tipo | Uso |
|-------|------|-----|
| `ip` | string | IP del servidor C2. Aparece en todos los payloads de comunicación |
| `os` | string | Informativo |
| `port` | int | Puerto del servidor C2. Forma `c2_url = http://{ip}:{port}` |

```python
self.c2_ip   = c2["ip"]    # "10.5.9.41"
self.c2_port = c2["port"]  # 4444
self.c2_url  = f"http://{self.c2_ip}:{self.c2_port}"  # "http://10.5.9.41:4444"
```

---

### `lab.auxiliary`

Máquinas auxiliares. Actualmente solo `kali`. No se usan en payloads automáticos, pero aparecen en el demo brief.

---

### `lab.integrations`

#### `firewall`

| Campo | Tipo | Descripción |
|-------|------|-------------|
| `vendor` | string | Informativo (`palo_alto`) |
| `monitors_pairs` | list[list[str,str]] | Pares de IPs cuyo tráfico es loggeado por el firewall |

Los payloads incluyen notas como `Write-Host '  ├─ NOTE: Palo Alto will log SSH connection'` basadas en esta configuración.

#### `email`

| Campo | Tipo | Descripción |
|-------|------|-------------|
| `vendor` | string | `mimecast` |
| `position` | string | `mx_gateway` — todo el correo pasa por aquí antes de llegar al lab |

Los payloads de phishing incluyen notas sobre Mimecast (`email URL rewritten`).

---

## Fallbacks

`PlaybookGenerator` y `LLMAnalyzer` cargan `config.yaml` con tolerancia a fallos:

```python
# playbook_generator.py
def _load_lab_cfg(config_path="config.yaml"):
    try:
        return yaml.safe_load(open(config_path)).get("lab", {})
    except Exception:
        return {}

# Valores fallback hardcodeados en __init__:
self.win_detection_ip = machines.get("win_detection", {}).get("ip", "10.5.9.31")
self.linux_ip         = machines.get("linux_victim",  {}).get("ip", "10.5.9.40")
# ... etc.
```

Esto significa que el sistema funciona incluso si `config.yaml` no existe, usando los valores por defecto del lab.

---

## Ejemplo: cambiar a otro lab

Supón que tu lab tiene IPs distintas:

```yaml
lab:
  machines:
    win_detection:
      ip: "192.168.10.50"
      edr_mode: detection
    linux_victim:
      ip: "192.168.10.60"
      ssh_user: ubuntu
      ssh_password: mysecretpass
  c2:
    ip: "192.168.10.100"
    port: 8080
```

Los payloads generados automáticamente usarán `192.168.10.50`, `192.168.10.60`, y `http://192.168.10.100:8080` sin ningún cambio de código.
