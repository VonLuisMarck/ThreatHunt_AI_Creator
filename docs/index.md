# ThreatHunt AI Creator — Documentación Técnica

> Convierte informes PDF de inteligencia de amenazas en playbooks ejecutables para el framework **Shadow-Replay**.

---

## Tabla de contenidos

| Documento | Descripción |
|-----------|-------------|
| **[architecture.md](architecture.md)** | Pipeline completo, diagrama de flujo de datos, interacción entre módulos |
| **[configuration.md](configuration.md)** | Referencia completa de `config.yaml`, variables de entorno, fallbacks |
| **[shadow_replay.md](shadow_replay.md)** | Integración con Shadow-Replay: esquema de playbook, cadena de eventos, ejecución de payloads |
| **[development.md](development.md)** | Guía de extensión: nuevas técnicas, proveedores LLM, plantillas de payload |
| **modules/** | Referencia de API por módulo |
| **schemas/** | Esquemas JSON completos con anotaciones campo a campo |

---

## Módulos

| Archivo | Clase principal | Responsabilidad |
|---------|-----------------|-----------------|
| [`src/pdf_processor.py`](modules/pdf_processor.md) | `PDFProcessor` | Extracción y estructuración de PDFs |
| [`src/ioc_extractor.py`](modules/ioc_extractor.md) | `IOCExtractor` | Extracción de 16 tipos de IOCs |
| [`src/ttp_mapper.py`](modules/ttp_mapper.md) | `TTPMapper` | Mapeo a MITRE ATT&CK (40+ técnicas) |
| [`src/llm_analyzer.py`](modules/llm_analyzer.md) | `LLMAnalyzer` | Análisis LLM multi-proveedor |
| [`src/playbook_generator.py`](modules/playbook_generator.md) | `PlaybookGenerator` | Generación de playbooks Shadow-Replay |
| [`src/emulation_library.py`](modules/emulation_library.md) | — | Biblioteca de snippets seguros (30+ técnicas) |

---

## Inicio rápido

### Requisitos

```bash
pip install -r requirements.txt
```

### CLI

```bash
python main.py reports/threat_report.pdf
```

Salida en `playbooks/<campaign_id>.json` y `playbooks/<campaign_id>_emulation_snippets.json`.

### Web UI

```bash
streamlit run app.py
```

### Cambiar proveedor LLM

```yaml
# config.yaml
llm:
  provider: anthropic          # ollama | anthropic | openai
  model: claude-opus-4-6
```

```bash
export ANTHROPIC_API_KEY=sk-ant-...
python main.py reports/report.pdf
```

---

## Pipeline en 6 pasos

```
PDF ──► [1] PDFProcessor ──► content{}
                                │
                        ┌───────┼───────┐
                  [2] IOCs   [3] TTPs  │
                        │       │      │
                        └───────┼───────┘
                                │
                       [4] LLMAnalyzer ──► analysis{} + attack_sequence[]
                                │
                       [5] EmulationSnippets[]
                                │
                       [6] PlaybookGenerator ──► playbook.json + brief.md
```

---

## Topología del lab (valores por defecto)

| Máquina | IP | OS | EDR | Credenciales |
|---------|----|----|-----|--------------|
| `win_detection` | `10.5.9.31` | Windows | CrowdStrike (detection) | — |
| `win_prevention` | `10.5.9.30` | Windows | CrowdStrike (prevention) | — |
| `linux_victim` | `10.5.9.40` | Linux | Ninguno | `samba / password123` |
| `win_unmanaged` | `10.5.9.27` | Windows | Ninguno | — |
| `c2_server` | `10.5.9.41:4444` | Ubuntu | — | — |
| `kali` | `10.5.9.21` | Kali | — | — |

> Los payloads generados usan estas IPs directamente. Actualiza `config.yaml` si cambia la topología.
