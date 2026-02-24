# Módulo: `llm_analyzer.py`

**Clase:** `LLMAnalyzer`
**Dependencias:** `langchain`, `langchain_anthropic`, `langchain_openai`, `langchain_community`, `yaml`, `json`, `re`

---

## Responsabilidad

Orquesta todas las llamadas al LLM. Recibe el contexto acumulado (texto, IOCs, TTPs) y produce:
- Análisis de la amenaza (`analyze_report`)
- Secuencia de ataque cronológica (`generate_attack_sequence`)
- Snippets de emulación por técnica (`suggest_emulation_snippets`)
- Resumen narrativo del playbook (`generate_playbook_summary`)

Gestiona ventanas de contexto por proveedor, chunking de documentos largos, y un robusto sistema de extracción de JSON de respuestas LLM.

---

## Configuración e inicialización

### `__init__(model_name, provider, config_path)`

| Param | Tipo | Default | Descripción |
|-------|------|---------|-------------|
| `model_name` | str | `"llama3"` | Identificador del modelo |
| `provider` | str | `"ollama"` | Proveedor LLM |
| `config_path` | str | `"config.yaml"` | Ruta al archivo de configuración |

```python
def __init__(self, model_name="llama3", provider="ollama", config_path="config.yaml"):
    self.provider = provider
    self.model_name = model_name
    self.lab_context = _load_lab_context(config_path)  # system prompt
    self.llm = _build_llm(provider, model_name, temperature=0.1)
    self.CHUNK_SIZE = _CONTEXT_LIMITS.get(provider, 4000)
    self.MAX_CHUNKS = 6
```

### Límites de contexto por proveedor

```python
_CONTEXT_LIMITS = {
    "anthropic": 16000,  # Ventana conservadora (Claude soporta 200k)
    "openai":    12000,  # GPT-4o soporta 128k
    "ollama":     4000,  # Modelos locales: conservador
}
```

---

## `_build_llm(provider, model_name, temperature)`

Factory de LLMs vía LangChain:

| Provider | Clase LangChain | API Key env var |
|----------|-----------------|-----------------|
| `anthropic` | `ChatAnthropic` | `ANTHROPIC_API_KEY` |
| `openai` | `ChatOpenAI` | `OPENAI_API_KEY` |
| `ollama` | `Ollama` | — (local) |

Configuración adicional para Anthropic: `max_tokens=4096`.

---

## API pública

### `analyze_report(content, iocs, ttps) → Dict`

Análisis principal del informe. Detecta actor, campaña, plataformas, riesgo de demo, y puntos de detección.

**Parámetros:**

| Param | Tipo | Descripción |
|-------|------|-------------|
| `content` | Dict | Salida de `PDFProcessor.extract_text()` |
| `iocs` | Dict | Salida de `IOCExtractor.extract_all()` |
| `ttps` | List[Dict] | Salida de `TTPMapper.extract_techniques()` |

**Flujo interno:**

```
1. _build_analysis_context(text, sections, key_findings, iocs, ttps)
     └─ Construye string de contexto compacto que cabe en CHUNK_SIZE

2. ¿len(full_text) > 2 × CHUNK_SIZE?
     YES → _summarize_chunks(full_text, sections)
              └─ Chunking + LLM summarization + consolidación
     NO  → usa full_text directamente

3. _run_analysis(context, iocs, ttps)
     └─ LLM call con el prompt de análisis + lab_context inyectado

4. _extract_json(response) → Dict
     └─ 4 estrategias de extracción (ver más abajo)

5. Validación y normalización del resultado
```

**Retorno (esquema completo):**

Ver [`docs/schemas/analysis.md`](../schemas/analysis.md).

---

### `generate_attack_sequence(analysis, ttps) → List[Dict]`

Genera la secuencia cronológica de etapas de ataque a ejecutar en el lab.

**Parámetros:**

| Param | Tipo | Descripción |
|-------|------|-------------|
| `analysis` | Dict | Salida de `analyze_report()` |
| `ttps` | List[Dict] | TTPs identificados |

**Prompt construido incluye:**
- Resumen del actor y campaña
- Lista de TTPs disponibles con sus IDs y nombres
- `attack_stages` del análisis (etapas conceptuales del LLM)
- Instrucción: generar secuencia ejecutable en el lab con IPs reales

**Retorno:**

```python
[
    {
        "stage":              str,       # Identificador único (ej. "initial_access_phishing")
        "stage_number":       int,       # Posición en la cadena
        "technique_id":       str,       # "T1566.001"
        "tactic":             str,       # "Initial Access"
        "platform":           str,       # "windows" | "linux" | "cloud"
        "execution_method":   str,       # "powershell" | "python" | "bash"
        "description":        str,       # Texto legible de la etapa
        "technical_details":  str,       # Detalles técnicos
        "execution_approach": str,       # Cómo ejecutarlo de forma segura
        "telemetry_generated": List[str],# Telemetría que generará en CrowdStrike
        "crowdstrike_detections": List[str], # Detecciones esperadas
        "detection_severity": str,       # "critical" | "high" | "medium" | "low"
        "prerequisites":      List[str], # Dependencias
        "outputs":            List[str], # Lo que produce esta etapa
    }
]
```

---

### `suggest_emulation_snippets(ttps, iocs, attack_sequence, platform) → List[Dict]`

Genera snippets de emulación para las técnicas del ataque.

**Estrategia de selección:**

```
Para cada técnica en attack_sequence (hasta 5):
  │
  ├─ ¿TID en emulation_library.EMULATION_LIBRARY?
  │     YES → get_emulation_snippet(tid, platform)
  │            source = "static_library"
  │
  └─ NO → _generate_llm_snippet(tid, ttp_meta, stage_meta, iocs, platform)
                source = "llm_generated"
```

**Personalización con IOCs:**

Si el snippet es LLM-generado, `_inject_iocs_into_snippet()` sustituye dominios/IPs genéricos del código por los IOCs reales extraídos del informe:

```python
# Para T1041, T1071, T1095:
c2_domain = iocs.get("domains", ["c2.example.com"])[0]
code = code.replace("c2.example.com", c2_domain)
code = code.replace("evil.com", c2_domain)
```

**Retorno:**

```python
[
    {
        "technique_id":    str,
        "name":            str,
        "tactic":          str,
        "platform":        str,        # "windows" | "linux"
        "code":            str,        # Código multi-línea (para visualización)
        "detection_notes": str | List, # Qué detecta CrowdStrike
        "source":          str,        # "static_library" | "llm_generated"
        "stage_context":   str,        # Descripción de la etapa donde se usa
    }
]
```

---

### `generate_playbook_summary(playbook, analysis) → str`

Genera un resumen narrativo en Markdown del playbook. Destinado al presentador de la demo.

**Contenido generado:**
- Resumen ejecutivo de la campaña
- Por qué es relevante para el cliente
- Qué detecta CrowdStrike en cada etapa
- Notas de presentación y talking points

---

## Métodos privados

### `_build_analysis_context(text, sections, key_findings, iocs, ttps) → str`

Construye el contexto que se envía al LLM. Estrategia para maximizar información útil dentro de `CHUNK_SIZE`:

```
Priority order:
1. Secciones más relevantes: executive_summary, threat_actor, attack_chain, ttps
2. key_findings (países, herramientas, actores, CVEs)
3. IOCs compactados (solo tipos con valores)
4. Lista de TTPs (IDs + nombres)
5. Texto libre restante (truncado al límite)
```

---

### `_summarize_chunks(full_text, sections) → str`

Para documentos que superan `2 × CHUNK_SIZE`:

```
Construir chunks prioritizando secciones con nombre
  │
  ├─ Sección "executive_summary" primero
  ├─ Luego "threat_actor", "attack_chain", "ttps"
  ├─ Resto de secciones en orden
  └─ Texto sin sección al final
  │
  ├─ Cada chunk > CHUNK_SIZE se subdivide
  ├─ Máximo MAX_CHUNKS = 6 chunks procesados
  │
  └─ Para cada chunk → _summarize_single_chunk(section_name, text)
       └─ LLM call: "Summarize this section focusing on threat actors, TTPs, IOCs"
  │
  └─ Concatenar resúmenes → contexto consolidado
```

---

### `_generate_llm_snippet(technique_id, ttp_meta, stage_meta, iocs, platform) → Optional[Dict]`

Genera un snippet de emulación vía LLM cuando la técnica no está en la biblioteca estática.

El prompt instrucciona al LLM a:
- Generar código **seguro** (solo simulación, no daño real)
- Incluir comentarios `[SIMULATION]`
- Generar telemetría que CrowdStrike pueda detectar
- Incluir limpieza/rollback

Retorna `None` si el LLM no puede generar un snippet válido.

---

### `_extract_json(text) → Any`

Extrae JSON de la respuesta del LLM con 4 estrategias en cascada:

```
Estrategia 1: json.loads(text.strip())
  → Funciona si el LLM devuelve JSON puro

Estrategia 2: regex r'\{[\s\S]*\}' o r'\[[\s\S]*\]'
  → Extrae JSON embebido en texto libre

Estrategia 3: Extraer bloque ```json ... ```
  → Funciona si el LLM envuelve JSON en código Markdown

Estrategia 4: Limpieza de errores comunes
  → Eliminar trailing commas: ,\s*} → }
  → Convertir comillas simples a dobles
  → Re-intentar json.loads()

Si todo falla → retorna {} o [] según el contexto
```

---

## Inyección del lab context

El `lab_context` (cargado de `promtps/lab_context.txt`) se inyecta al inicio de **cada prompt** enviado al LLM:

```python
prompt = f"{self.lab_context}\n\n{analysis_prompt}"
```

Esto garantiza que el LLM siempre tenga consciencia de la topología del lab (IPs, máquinas, integrations) al generar respuestas sobre payloads y secuencias de ataque.

---

## Robustez y manejo de errores

| Escenario | Comportamiento |
|-----------|----------------|
| API key no configurada | `ValueError` con instrucciones de configuración |
| LLM no disponible (Ollama down) | Excepción propagada al caller |
| JSON malformado en respuesta | `_extract_json()` con 4 fallbacks → dict/list vacío |
| Documento demasiado largo | `_summarize_chunks()` automático |
| Técnica no en biblioteca estática | `_generate_llm_snippet()` como fallback |
| Snippet LLM inválido | `None` → técnica omitida del resultado |
| `demonstrable: false` | Pipeline se detiene en `main.py` con mensaje explicativo |
