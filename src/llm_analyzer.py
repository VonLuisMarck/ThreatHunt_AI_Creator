from langchain.prompts import PromptTemplate
from langchain.chains import LLMChain
from typing import Dict, List, Optional
import json
import re
import os

import yaml
from src.emulation_library import get_emulation_snippet, get_all_covered_techniques


def _load_lab_context(config_path: str = "config.yaml") -> str:
    """
    Lee la ruta del system prompt de arquitectura desde config.yaml y devuelve su contenido.
    Falla silenciosamente si el archivo no existe para no romper flujos sin lab context.
    """
    try:
        with open(config_path, "r") as f:
            cfg = yaml.safe_load(f)
        prompt_path = cfg.get("lab", {}).get("lab_context_prompt", "")
        if not prompt_path:
            return ""
        base_dir = os.path.dirname(os.path.abspath(config_path))
        full_path = os.path.join(base_dir, prompt_path)
        with open(full_path, "r") as f:
            return f.read().strip()
    except Exception:
        return ""


def _build_llm(provider: str, model_name: str, temperature: float = 0.1):
    """
    Factory que instancia el LLM correcto según el proveedor.

    Proveedores soportados:
    - ollama    → Ollama local (llama3, llama3.1:70b, mixtral, etc.)
    - anthropic → Claude API  (claude-opus-4-6, claude-sonnet-4-5, claude-haiku-4-5)
    - openai    → OpenAI API  (gpt-4o, gpt-4-turbo, gpt-4)

    Las API keys se leen de variables de entorno:
    - ANTHROPIC_API_KEY
    - OPENAI_API_KEY
    """
    if provider == "anthropic":
        from langchain_anthropic import ChatAnthropic
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            raise ValueError(
                "ANTHROPIC_API_KEY not set. Export it: export ANTHROPIC_API_KEY=sk-ant-..."
            )
        return ChatAnthropic(
            model=model_name,
            temperature=temperature,
            anthropic_api_key=api_key,
            max_tokens=4096,
        )

    if provider == "openai":
        from langchain_openai import ChatOpenAI
        api_key = os.environ.get("OPENAI_API_KEY", "")
        if not api_key:
            raise ValueError(
                "OPENAI_API_KEY not set. Export it: export OPENAI_API_KEY=sk-..."
            )
        return ChatOpenAI(
            model=model_name,
            temperature=temperature,
            openai_api_key=api_key,
        )

    # Default: Ollama local
    from langchain_community.llms import Ollama
    return Ollama(model=model_name, temperature=temperature)


# Context window per provider — determines how much text we send per call
_CONTEXT_LIMITS = {
    "anthropic": 16000,   # Claude has 200k context, we use 16k per call to be safe
    "openai":    12000,   # GPT-4o has 128k context
    "ollama":     4000,   # Local models: conservative default
}


class LLMAnalyzer:
    """
    Analiza reportes de amenazas usando LLM (Ollama local, Claude API u OpenAI).

    Proveedores:
    - ollama    : llama3, llama3.1:70b, mixtral, etc. (local, sin coste, menor calidad)
    - anthropic : claude-opus-4-6, claude-sonnet-4-5  (API, mayor calidad)
    - openai    : gpt-4o, gpt-4-turbo                 (API, buena calidad)

    Mejoras sobre la versión original:
    - Multi-proveedor con context window adaptativo
    - Procesamiento del texto COMPLETO mediante chunking
    - Extracción robusta de JSON con fallbacks
    - Lab context inyectado en todos los prompts
    """

    MAX_CHUNKS = 6

    def __init__(
        self,
        model_name: str = "llama3",
        provider: str = "ollama",
        config_path: str = "config.yaml",
    ):
        self.provider = provider
        self.model_name = model_name
        self.llm = _build_llm(provider, model_name)
        self.lab_context = _load_lab_context(config_path)
        # Adapt chunk size to provider's context window
        self.CHUNK_SIZE = _CONTEXT_LIMITS.get(provider, 4000)

    # ──────────────────────────────────────────────────────────────
    #  Main analysis (processes FULL document via chunking)
    # ──────────────────────────────────────────────────────────────

    def analyze_report(self, content: Dict, iocs: Dict, ttps: List[Dict]) -> Dict:
        """
        Análisis completo del reporte.

        Estrategia:
        1. Si el texto cabe en un chunk → análisis directo
        2. Si es más largo → extraer resúmenes por sección + análisis final unificado
        """
        full_text = content.get("full_text", "")
        sections = content.get("sections", {})
        key_findings = content.get("key_findings", {})

        # Build a rich context string combining sections and key findings
        context = self._build_analysis_context(full_text, sections, key_findings, iocs, ttps)

        # If context fits in one call, go direct; otherwise summarize first
        if len(context) <= self.CHUNK_SIZE * 2:
            return self._run_analysis(context, iocs, ttps)
        else:
            summary = self._summarize_chunks(full_text, sections)
            combined_context = self._build_analysis_context(
                summary, sections, key_findings, iocs, ttps
            )
            return self._run_analysis(combined_context, iocs, ttps)

    def generate_attack_sequence(self, analysis: Dict, ttps: List[Dict]) -> List[Dict]:
        """Genera secuencia de ataque basada en el análisis y los TTPs."""

        prompt = PromptTemplate(
            input_variables=["lab_context", "analysis", "ttps"],
            template="""{lab_context}

You are a cybersecurity automation engineer creating attack simulation sequences.

THREAT ANALYSIS:
{analysis}

AVAILABLE TTPs (MITRE ATT&CK):
{ttps}

Create a logical, chronological attack sequence for lab execution.
For each stage provide:
- stage: snake_case name
- stage_number: sequential integer
- technique_id: MITRE ATT&CK ID
- tactic: MITRE tactic name
- platform: windows/linux/cloud
- execution_method: powershell/python/bash/api
- description: what happens in this stage
- technical_details: how it works technically
- execution_approach: how to execute this technique in the isolated lab using real lab infrastructure
- telemetry_generated: list of telemetry events
- crowdstrike_detections: list of what CrowdStrike detects
- detection_severity: low/medium/high/critical
- prerequisites: list of required previous outputs
- outputs: list of what this stage produces

Respond with valid JSON array ONLY, no other text:
""",
        )

        chain = LLMChain(llm=self.llm, prompt=prompt)
        result = chain.run(
            lab_context=self.lab_context,
            analysis=json.dumps(analysis, indent=2),
            ttps=json.dumps(ttps[:15], indent=2),  # Top 15 TTPs
        )

        parsed = self._extract_json(result)
        if isinstance(parsed, list):
            return parsed
        return []

    # ──────────────────────────────────────────────────────────────
    #  NEW: Emulation code suggestions
    # ──────────────────────────────────────────────────────────────

    def suggest_emulation_snippets(
        self,
        ttps: List[Dict],
        iocs: Dict,
        attack_sequence: List[Dict],
        platform: str = "windows",
    ) -> List[Dict]:
        """
        Genera sugerencias de código de emulación para cada técnica encontrada.

        Estrategia:
        1. Para técnicas en la librería estática → usa el snippet pre-validado
        2. Para técnicas no cubiertas → genera con LLM
        3. Personaliza con IOCs del reporte cuando es posible
        """
        snippets: List[Dict] = []
        covered = set(get_all_covered_techniques())
        seen_tids: set = set()

        # Merge TTPs from both ttp_mapper and attack_sequence
        all_tids = [t["id"] for t in ttps]
        for stage in attack_sequence:
            tid = stage.get("technique_id", "")
            if tid and tid not in all_tids:
                all_tids.append(tid)

        for tid in all_tids:
            if tid in seen_tids:
                continue
            seen_tids.add(tid)

            # Find matching TTP metadata
            ttp_meta = next((t for t in ttps if t["id"] == tid), {})
            stage_meta = next(
                (s for s in attack_sequence if s.get("technique_id") == tid), {}
            )

            if tid in covered or tid.split(".")[0] in covered:
                # Use static library snippet
                snippet = get_emulation_snippet(tid, platform)
                if snippet:
                    # Customize with real IOCs if available
                    snippet["code"] = self._inject_iocs_into_snippet(
                        snippet["code"], iocs, tid
                    )
                    snippet["source"] = "static_library"
                    snippet["stage_context"] = stage_meta.get("description", "")
                    snippets.append(snippet)
            else:
                # Generate with LLM for uncovered techniques
                llm_snippet = self._generate_llm_snippet(
                    tid, ttp_meta, stage_meta, iocs, platform
                )
                if llm_snippet:
                    llm_snippet["source"] = "llm_generated"
                    snippets.append(llm_snippet)

        return snippets

    # ──────────────────────────────────────────────────────────────
    #  NEW: Playbook narrative summary
    # ──────────────────────────────────────────────────────────────

    def generate_playbook_summary(self, playbook: Dict, analysis: Dict) -> str:
        """
        Genera un resumen narrativo del playbook en lenguaje natural.
        Incluye: qué hace, cómo se ejecuta, qué detecta CrowdStrike.
        """
        prompt = PromptTemplate(
            input_variables=["lab_context", "playbook", "analysis"],
            template="""{lab_context}

You are a cybersecurity expert creating a human-readable summary of an attack simulation playbook.

PLAYBOOK DATA:
{playbook}

THREAT ANALYSIS CONTEXT:
{analysis}

Write a clear, structured summary that includes:

1. OVERVIEW (2-3 sentences): What this playbook simulates and why
2. THREAT ACTOR CONTEXT: Who the real attacker is and their motivation
3. ATTACK NARRATIVE: Step-by-step story of what happens (not technical, readable by executives)
4. WHAT CROWDSTRIKE DETECTS: List the key detection points in plain language
5. DEMO VALUE: Why this is useful for a CrowdStrike demonstration
6. REQUIREMENTS: What infrastructure is needed
7. DURATION: Estimated time to run the full demo

Keep it professional but accessible. Use plain English.
Do NOT use JSON format - write in paragraph/list format.
""",
        )

        chain = LLMChain(llm=self.llm, prompt=prompt)

        # Trim playbook to avoid token overflow
        playbook_trimmed = {
            k: v for k, v in playbook.items() if k != "events"
        }
        playbook_trimmed["events_summary"] = [
            {"id": e.get("event_id"), "name": e.get("name"), "technique": e.get("mitre_technique")}
            for e in playbook.get("events", [])[:10]
        ]

        result = chain.run(
            lab_context=self.lab_context,
            playbook=json.dumps(playbook_trimmed, indent=2),
            analysis=json.dumps(analysis, indent=2),
        )

        return result.strip()

    # ──────────────────────────────────────────────────────────────
    #  Private: chunked summarization
    # ──────────────────────────────────────────────────────────────

    def _summarize_chunks(self, full_text: str, sections: Dict) -> str:
        """
        Procesa el texto en chunks y devuelve un resumen consolidado.
        Prioriza secciones clave sobre texto plano.
        """
        summaries: List[str] = []

        # Priority: named sections first
        priority_sections = [
            "executive_summary", "attack_chain", "ttps", "threat_actor",
            "tools", "iocs", "recommendations"
        ]

        for sec_name in priority_sections:
            if sec_name in sections and len(summaries) < self.MAX_CHUNKS:
                text_chunk = sections[sec_name][:self.CHUNK_SIZE]
                summary = self._summarize_single_chunk(sec_name, text_chunk)
                if summary:
                    summaries.append(f"[{sec_name.upper()}]\n{summary}")

        # If we have room, add full-text chunks not covered by sections
        if len(summaries) < 3:
            chunk_count = 0
            for i in range(0, min(len(full_text), self.CHUNK_SIZE * self.MAX_CHUNKS), self.CHUNK_SIZE):
                if chunk_count >= 3:
                    break
                chunk = full_text[i: i + self.CHUNK_SIZE]
                summary = self._summarize_single_chunk(f"chunk_{i // self.CHUNK_SIZE + 1}", chunk)
                if summary:
                    summaries.append(summary)
                    chunk_count += 1

        return "\n\n".join(summaries)

    def _summarize_single_chunk(self, section_name: str, text: str) -> str:
        """Resume un chunk de texto para análisis posterior."""
        if not text.strip():
            return ""

        prompt = PromptTemplate(
            input_variables=["section", "text"],
            template="""Extract the key cybersecurity threat intelligence from this section.
Focus on: threat actors, attack techniques, tools used, IOCs, attack stages, targets.
Be concise (max 300 words).

SECTION: {section}
CONTENT:
{text}

Key intelligence extracted:""",
        )

        chain = LLMChain(llm=self.llm, prompt=prompt)
        try:
            return chain.run(section=section_name, text=text).strip()
        except Exception:
            return text[:500]  # Fallback: use raw text truncated

    # ──────────────────────────────────────────────────────────────
    #  Private: main analysis call
    # ──────────────────────────────────────────────────────────────

    def _run_analysis(self, context: str, iocs: Dict, ttps: List[Dict]) -> Dict:
        """Ejecuta el prompt de análisis principal."""
        prompt = PromptTemplate(
            input_variables=["text", "iocs", "ttps"],
            template="""You are an expert cybersecurity threat intelligence analyst.
Analyze this threat intelligence report content and provide a comprehensive assessment.

REPORT CONTENT / SUMMARIES:
{text}

EXTRACTED IOCs:
{iocs}

IDENTIFIED MITRE ATT&CK TECHNIQUES:
{ttps}

Provide analysis in this exact JSON format (no other text):
{{
  "threat_actor": "Name or 'Unknown'",
  "threat_actor_type": "cybercrime|espionage|hacktivism|unknown",
  "campaign_name": "Campaign or operation name",
  "attack_vector": "primary attack method",
  "platforms": ["windows", "linux", "cloud"],
  "target_industries": ["finance", "healthcare"],
  "target_geography": ["US", "EU"],
  "attack_stages": [
    {{
      "stage_name": "initial_access",
      "tactic": "Initial Access",
      "techniques": ["T1566.001"],
      "description": "Brief description",
      "key_tools": ["tool name"]
    }}
  ],
  "demonstrable": true,
  "demo_risk": "low|medium|high",
  "demo_complexity": "simple|moderate|complex",
  "setup_time": "minutes|hours|days",
  "required_expertise": "basic|intermediate|advanced",
  "crowdstrike_products": ["Falcon Prevent", "Falcon Insight"],
  "key_detection_points": ["What CrowdStrike detects at each stage"],
  "reasoning": "Detailed explanation of demonstrability assessment",
  "demo_modifications": "Suggested changes to make demo safe",
  "confidence_level": "low|medium|high",
  "attribution_confidence": "low|medium|high"
}}

Respond with JSON only:""",
        )

        chain = LLMChain(llm=self.llm, prompt=prompt)
        result = chain.run(
            text=context[:self.CHUNK_SIZE * 2],
            iocs=json.dumps(iocs, indent=2)[:1000],
            ttps=json.dumps(ttps[:10], indent=2),
        )

        parsed = self._extract_json(result)
        if isinstance(parsed, dict) and "threat_actor" in parsed:
            return parsed

        # Fallback
        return {
            "threat_actor": "Unknown",
            "campaign_name": "Unknown Campaign",
            "attack_vector": "Unknown",
            "platforms": ["windows"],
            "demonstrable": False,
            "demo_risk": "high",
            "reasoning": f"LLM parse error. Raw response: {result[:200]}",
            "confidence_level": "low",
        }

    # ──────────────────────────────────────────────────────────────
    #  Private: LLM snippet generation for uncovered TTPs
    # ──────────────────────────────────────────────────────────────

    def _generate_llm_snippet(
        self,
        technique_id: str,
        ttp_meta: Dict,
        stage_meta: Dict,
        iocs: Dict,
        platform: str,
    ) -> Optional[Dict]:
        """Genera un snippet de emulación con LLM para técnicas no cubiertas."""

        lang = "PowerShell" if platform == "windows" else "Python"

        prompt = PromptTemplate(
            input_variables=["lab_context", "technique_id", "technique_name",
                             "description", "stage_desc", "platform", "lang",
                             "iocs_sample"],
            template="""{lab_context}

You are a cybersecurity engineer creating a real attack emulation snippet for an isolated lab environment.

TECHNIQUE: {technique_id} - {technique_name}
DESCRIPTION: {description}
ATTACK STAGE CONTEXT: {stage_desc}
PLATFORM: {platform}
LANGUAGE: {lang}
IOCs FROM REPORT (for context): {iocs_sample}

Write a real, fully executable {lang} snippet for the isolated lab that:
1. Actually executes the technique to generate authentic telemetry and trigger real CrowdStrike detections
2. Uses the exact IPs, credentials, and C2 port from the lab architecture above — never use placeholders
3. Labels the target machine at the top, e.g.: # [WIN-DETECTION 10.5.9.31]
4. Includes cleanup at the end if files, registry keys, or connections are created
5. Has inline comments explaining which CrowdStrike detection each step triggers
6. Must be syntactically correct and executable as-is in the lab

Respond with ONLY the code, no explanation:""",
        )

        chain = LLMChain(llm=self.llm, prompt=prompt)
        iocs_sample = {
            k: v[:2] for k, v in iocs.items()
            if v and k in ("ipv4", "domains", "commands", "file_paths")
        }

        try:
            code = chain.run(
                lab_context=self.lab_context,
                technique_id=technique_id,
                technique_name=ttp_meta.get("name", technique_id),
                description=ttp_meta.get("description", "No description")[:200],
                stage_desc=stage_meta.get("description", "N/A"),
                platform=platform,
                lang=lang,
                iocs_sample=json.dumps(iocs_sample),
            ).strip()

            return {
                "technique_id": technique_id,
                "name": ttp_meta.get("name", technique_id),
                "tactic": (ttp_meta.get("tactics") or ["Unknown"])[0],
                "platform": platform,
                "code": code,
                "detection_notes": stage_meta.get(
                    "crowdstrike_detections", ["See code comments"]
                ),
            }
        except Exception:
            return None

    # ──────────────────────────────────────────────────────────────
    #  Private: context building and IOC injection
    # ──────────────────────────────────────────────────────────────

    def _build_analysis_context(
        self,
        text: str,
        sections: Dict,
        key_findings: Dict,
        iocs: Dict,
        ttps: List[Dict],
    ) -> str:
        """Construye el contexto de análisis combinando texto y hallazgos."""
        parts: List[str] = []

        # Key structured findings first (most signal, least noise)
        if key_findings:
            parts.append("KEY FINDINGS FROM REPORT STRUCTURE:")
            if key_findings.get("mentioned_tools"):
                parts.append(f"  Tools mentioned: {', '.join(key_findings['mentioned_tools'])}")
            if key_findings.get("mentioned_malware_types"):
                parts.append(f"  Malware types: {', '.join(key_findings['mentioned_malware_types'])}")
            if key_findings.get("cves"):
                parts.append(f"  CVEs: {', '.join(key_findings['cves'])}")
            if key_findings.get("mentioned_threat_actors"):
                parts.append(f"  Threat actors: {', '.join(key_findings['mentioned_threat_actors'])}")
            if key_findings.get("mentioned_sectors"):
                parts.append(f"  Target sectors: {', '.join(key_findings['mentioned_sectors'])}")
            if key_findings.get("mentioned_countries"):
                parts.append(f"  Countries: {', '.join(key_findings['mentioned_countries'])}")
            parts.append("")

        # High-priority sections
        for sec in ["executive_summary", "attack_chain", "threat_actor", "ttps"]:
            if sec in sections:
                parts.append(f"=== {sec.upper().replace('_', ' ')} ===")
                parts.append(sections[sec][:1500])
                parts.append("")

        # Raw text (truncated)
        if text:
            remaining = max(0, self.CHUNK_SIZE * 2 - sum(len(p) for p in parts))
            if remaining > 200:
                parts.append("=== FULL TEXT (EXCERPT) ===")
                parts.append(text[:remaining])

        return "\n".join(parts)

    def _inject_iocs_into_snippet(self, code: str, iocs: Dict, technique_id: str) -> str:
        """
        Personaliza snippets con IOCs reales del reporte cuando aplica.
        Solo sustituye placeholders seguros (dominios C2, IPs, etc.).
        """
        # Inject a real C2 domain if available (for T1041, T1071 techniques)
        if technique_id.startswith(("T1041", "T1071", "T1095")):
            domains = iocs.get("domains", [])
            if domains:
                # Use first domain as example C2 (clearly labeled as from report)
                c2_example = domains[0]
                code = code.replace(
                    "simulation-c2.example.com",
                    f"{c2_example}  # C2 domain from report (DO NOT connect - simulation only)"
                )

        return code

    # ──────────────────────────────────────────────────────────────
    #  Private: robust JSON extraction
    # ──────────────────────────────────────────────────────────────

    def _extract_json(self, text: str):
        """
        Extrae JSON de la respuesta del LLM de forma robusta.
        Intenta múltiples estrategias antes de fallar.
        """
        if not text:
            return None

        # Strategy 1: Direct parse
        try:
            return json.loads(text.strip())
        except json.JSONDecodeError:
            pass

        # Strategy 2: Find JSON object/array in text
        for pattern in [r"\{[\s\S]*\}", r"\[[\s\S]*\]"]:
            match = re.search(pattern, text)
            if match:
                try:
                    return json.loads(match.group())
                except json.JSONDecodeError:
                    pass

        # Strategy 3: Extract between markdown code blocks
        code_match = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
        if code_match:
            try:
                return json.loads(code_match.group(1).strip())
            except json.JSONDecodeError:
                pass

        # Strategy 4: Fix common LLM JSON errors (trailing commas, single quotes)
        cleaned = text.strip()
        cleaned = re.sub(r",\s*([}\]])", r"\1", cleaned)  # trailing commas
        cleaned = cleaned.replace("'", '"')               # single → double quotes
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            pass

        return None
