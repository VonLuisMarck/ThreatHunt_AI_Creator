# Arquitectura — ThreatHunt AI Creator

---

## Visión general del pipeline

El sistema transforma un informe PDF de inteligencia de amenazas en un playbook ejecutable para Shadow-Replay en **6 pasos secuenciales**. Cada paso enriquece el contexto acumulado.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        THREATHUNT AI CREATOR PIPELINE                       │
└─────────────────────────────────────────────────────────────────────────────┘

  ┌──────────┐
  │ PDF File │
  └────┬─────┘
       │
       ▼
┌──────────────────────────────────────────────────────────────┐
│ STEP 1 · PDFProcessor.extract_text()                         │
│                                                              │
│  PyMuPDF → raw blocks → heading detection → section mapping  │
│  → key_findings (countries, tools, malware, actors, CVEs)    │
│                                                              │
│  Output: content{full_text, pages[], sections{}, headings[], │
│                  key_findings{}, tables[], metadata{}}       │
└────────────────────────────┬─────────────────────────────────┘
                             │
            ┌────────────────┴────────────────┐
            │                                 │
            ▼                                 ▼
┌───────────────────────┐         ┌───────────────────────┐
│ STEP 2                │         │ STEP 3                │
│ IOCExtractor          │         │ TTPMapper             │
│ .extract_all()        │         │ .extract_techniques() │
│                       │         │                       │
│ 16 IOC types via      │         │ Explicit IDs (T1xxx)  │
│ iocextract + regex    │         │ + keyword matching    │
│ + defang handling     │         │ + tool-to-TTP map     │
│                       │         │ + MITRE ATT&CK data   │
│ Output: iocs{}        │         │                       │
└──────────┬────────────┘         │ Output: ttps[]        │
           │                      └──────────┬────────────┘
           └──────────────┬──────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 4 · LLMAnalyzer.analyze_report()                           │
│                                                                 │
│  Build context (text + sections + IOCs + TTPs + lab_context)    │
│  → If large doc: _summarize_chunks() first                      │
│  → LLM call → extract JSON with 4-strategy fallback            │
│  → generate_attack_sequence() → chronological attack stages    │
│                                                                 │
│  Output: analysis{threat_actor, campaign, demonstrable,         │
│                   attack_stages[], crowdstrike_products[],      │
│                   key_detection_points[]}                       │
│          attack_sequence[{stage, technique_id, platform,        │
│                           telemetry[], detection_severity}]     │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 5 · LLMAnalyzer.suggest_emulation_snippets()               │
│                                                                 │
│  For each TTP in attack_sequence:                               │
│    if TID in emulation_library → use pre-validated code         │
│    else → _generate_llm_snippet() → customize with IOCs         │
│                                                                 │
│  Output: snippets[{technique_id, code, platform,                │
│                    detection_notes, source}]                    │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 6 · PlaybookGenerator.generate()                           │
│                                                                 │
│  _determine_agents() → windows=agent_1, linux=agent_2          │
│  _generate_events():                                            │
│    for each stage → _generate_payload() → _to_oneliner()       │
│    → chain: success_trigger = next stage's event_id            │
│  _generate_cleanup_events() → reversed agent order             │
│                                                                 │
│  Output: playbook.json (Shadow-Replay compatible)              │
│          brief.md (demo documentation)                         │
└─────────────────────────────────────────────────────────────────┘
```

---

## Diagrama de clases

```
┌─────────────────────┐    uses    ┌──────────────────────┐
│    PDFProcessor     │───────────►│   PyMuPDF (fitz)     │
│  + extract_text()   │            └──────────────────────┘
│  + get_chunked_text()│
└──────────┬──────────┘
           │ content{}
           ▼
┌─────────────────────┐    uses    ┌──────────────────────┐
│   IOCExtractor      │───────────►│ iocextract + re      │
│  + extract_all()    │            └──────────────────────┘
└──────────┬──────────┘
           │ iocs{}
           ▼
┌─────────────────────┐    uses    ┌──────────────────────┐
│     TTPMapper       │───────────►│ mitreattack-python   │
│  + extract_techniques│           └──────────────────────┘
└──────────┬──────────┘
           │ ttps[]
           ▼
┌─────────────────────┐    uses    ┌──────────────────────┐
│    LLMAnalyzer      │───────────►│  LangChain + LLM     │
│  + analyze_report() │            │  (Ollama/Claude/GPT) │
│  + gen_sequence()   │            └──────────────────────┘
│  + suggest_snippets()│   uses    ┌──────────────────────┐
│  + gen_summary()    │───────────►│  EmulationLibrary    │
└──────────┬──────────┘            └──────────────────────┘
           │ analysis{} + attack_sequence[] + snippets[]
           ▼
┌─────────────────────┐    reads   ┌──────────────────────┐
│  PlaybookGenerator  │───────────►│   config.yaml        │
│  + generate()       │            │   (lab topology)     │
│  + gen_demo_brief() │            └──────────────────────┘
│  + _to_oneliner()   │
└──────────┬──────────┘
           │
    ┌──────┴──────┐
    ▼             ▼
playbook.json   brief.md
(Shadow-Replay) (Markdown)
```

---

## Flujo de datos detallado

### Datos acumulativos entre pasos

Cada paso recibe y enriquece el contexto:

```
main.py
  │
  ├─ content = PDFProcessor().extract_text(pdf_path)
  │     └─ {full_text: str, sections: dict, key_findings: dict, metadata: dict, ...}
  │
  ├─ iocs = IOCExtractor().extract_all(content["full_text"])
  │     └─ {ipv4: [], domains: [], sha256: [], commands: [], ...}  ← 16 tipos
  │
  ├─ ttps = TTPMapper().extract_techniques(content["full_text"])
  │     └─ [{id: "T1566", name: "Phishing", tactics: [...], ...}]
  │
  ├─ analysis = LLMAnalyzer.analyze_report(content, iocs, ttps)
  │     └─ {threat_actor, campaign_name, demonstrable, attack_stages, ...}
  │
  ├─ attack_sequence = LLMAnalyzer.generate_attack_sequence(analysis, ttps)
  │     └─ [{stage, technique_id, platform, telemetry[], detection_severity}]
  │
  ├─ snippets = LLMAnalyzer.suggest_emulation_snippets(ttps, iocs, attack_sequence)
  │     └─ [{technique_id, code, platform, source, detection_notes}]
  │
  └─ playbook = PlaybookGenerator().generate(analysis, attack_sequence, iocs, ttps)
        └─ {playbook_id, mandatory_agents[], events[]}
```

---

## Gestión del contexto LLM

El módulo `LLMAnalyzer` tiene que ajustarse a los límites de contexto de cada proveedor. La estrategia:

```
Documento recibido
       │
       ▼
¿len(text) > 2 × CHUNK_SIZE?
       │
  YES  │  NO
  │    └──────► Análisis directo
  │                    │
  ▼                    ▼
Chunking en secciones  LLM call con contexto completo
  │
  ▼
_summarize_chunks():
  ├─ Max 6 chunks
  ├─ Prioriza secciones con nombre (executive_summary, threat_actor, ...)
  ├─ LLM genera resumen por chunk
  └─ Consolidación → contexto final
       │
       ▼
Análisis sobre el resumen consolidado

CHUNK_SIZE por proveedor:
  anthropic → 16000 tokens
  openai    → 12000 tokens
  ollama    →  4000 tokens
```

---

## Selección de payload en `PlaybookGenerator`

```
_generate_payload(stage, iocs, agent_type)
         │
         ├─ agent_type == "windows"?
         │         │
         │    ┌────┴────────────────────────────────────────┐
         │    │ technique_id contains...                    │
         │    │  T1566 → _ps_phishing()                     │
         │    │  T1059 → _ps_execution(iocs)                │
         │    │  T1003 → _ps_credential_dump()              │
         │    │  T1021 → _ps_lateral_movement()             │
         │    │  T1547 → _ps_persistence()                  │
         │    │  T1082 → _ps_discovery()                    │
         │    │  T1562 → _ps_defense_evasion()              │
         │    │  T1105 → _ps_tool_transfer()                │
         │    │  T1041 → _ps_exfiltration()                 │
         │    │  else  → generic Windows fallback           │
         │    └─────────────────────────────────────────────┘
         │
         └─ agent_type == "linux"?
                   │
              ┌────┴────────────────────────────────────────┐
              │ technique_id contains...                    │
              │  T1021 → _py_lateral_receive()              │
              │  T1053 → _py_linux_persistence()            │
              │  T1082 → _py_linux_discovery()              │
              │  T1041 → _py_linux_exfiltration()           │
              │  else  → generic Linux fallback             │
              └─────────────────────────────────────────────┘
                   │
                   ▼
         _to_oneliner(code, payload_type)
                   │
        ┌──────────┴──────────────┐
        │ powershell              │ python
        │                         │
        │ strip comment lines     │  has indented blocks?
        │ join lines with " "     │   YES → base64 exec wrapper
        │ (templates already      │   NO  → join with "; "
        │  end lines with ;)      │
        └─────────────────────────┘
```

---

## Cadena de eventos en el playbook generado

```
attack_sequence[0]          →  event_id: "initial_access_phishing"
  success_trigger:             next = attack_sequence[1]
  failure_action: "abort"    (primeros 2 eventos: abort on fail)

attack_sequence[1]          →  event_id: "credential_access_dump"
  success_trigger:             next = attack_sequence[2]
  failure_action: "abort"

attack_sequence[2..N-1]     →  ...
  failure_action: "continue" (resto: continue on fail)

attack_sequence[N-1]        →  event_id: "last_attack_stage"
  success_trigger:             next = "cleanup_agent_2" (linux) o "cleanup_agent_1"

cleanup_agent_2             →  Linux cleanup (si hay agente linux)
  success_trigger:             "cleanup_agent_1"

cleanup_agent_1             →  Windows cleanup
  success_trigger:             null  (FIN)
```

> El orden de cleanup es inverso al orden de `mandatory_agents`: Linux se limpia primero, Windows último.

---

## Interacción con el entorno de lab

```
                    ┌─────────────────────────────────┐
                    │       PALO ALTO NGFW             │
                    │  Logs C2 traffic between:        │
                    │  10.5.9.30 ↔ 10.5.9.41          │
                    │  10.5.9.31 ↔ 10.5.9.41          │
                    └────────────────┬────────────────┘
                                     │
   ┌─────────────────┐               │              ┌─────────────────┐
   │ win_prevention  │               │              │ win_detection   │
   │ 10.5.9.30       │◄──────────────┤              │ 10.5.9.31       │
   │ CrowdStrike     │               │              │ CrowdStrike     │
   │ PREVENTION      │               │              │ DETECTION ← ★  │
   └─────────────────┘               │              └────────┬────────┘
                                     │                       │ SSH via Posh-SSH
   ┌─────────────────┐          ┌────┴───────┐              │
   │ win_unmanaged   │          │ C2 Server  │              ▼
   │ 10.5.9.27       │          │ 10.5.9.41  │     ┌─────────────────┐
   │ No EDR          │          │ port 4444  │     │ linux_victim    │
   └─────────────────┘          └────────────┘     │ 10.5.9.40       │
                                     │             │ No EDR          │
                                     │             │ SSH: samba/***  │
                              ┌──────┴──────┐      └─────────────────┘
                              │ Kali Linux  │
                              │ 10.5.9.21   │
                              └─────────────┘

★ = Máquina usada en todos los payloads Windows (detection mode: alerta sin bloquear)

MIMECAST (MX Gateway): todo el correo entrante pasa por Mimecast antes de llegar al lab
  → Reescritura de URLs en emails
  → Sandboxing de adjuntos
```
