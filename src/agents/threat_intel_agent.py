"""
ThreatIntelAgent — Agente de inteligencia de amenazas.

Responsabilidades:
  1. Leer el Recon Briefing del canal de mensajes
  2. Análisis profundo: actor, campaña, plataformas, riesgo de demo
  3. Si la confianza es baja → pide aclaración a ReconAgent
  4. Escribe un "Intel Report" en el canal de mensajes para AttackPlanner

Modelo: Claude Opus (máximo razonamiento, dominio de threat intelligence)
"""

import json
import re
import yaml
from typing import Dict, Any, List

from src.llm_analyzer import _build_llm, _load_lab_context
from src.agents.state import AgentState, new_message


_ANALYSIS_PROMPT = """\
You are a senior threat intelligence analyst at CrowdStrike.
Your goal: assess whether this threat campaign can be safely demonstrated \
in a CrowdStrike lab, and produce a structured JSON analysis.

LAB CONTEXT:
{lab_context}

RECON BRIEFING (from ReconAgent):
{recon_briefing}

IOC SAMPLE:
{ioc_sample}

MITRE ATT&CK TECHNIQUES FOUND:
{ttp_list}

DOCUMENT EXCERPT:
{doc_excerpt}

Return ONLY valid JSON in this exact structure:
{{
  "threat_actor": "string",
  "threat_actor_type": "nation-state|cybercriminal|hacktivist|unknown",
  "campaign_name": "string",
  "attack_vector": "string",
  "platforms": ["windows", "linux"],
  "target_industries": ["string"],
  "target_geography": ["string"],
  "attack_stages": [
    {{
      "stage_name": "string",
      "tactic": "string",
      "techniques": ["T1234"],
      "description": "string",
      "key_tools": ["string"]
    }}
  ],
  "demonstrable": true,
  "demo_risk": "low|medium|high",
  "demo_complexity": "low|medium|high",
  "setup_time": "minutes|hours|days",
  "required_expertise": "beginner|intermediate|advanced",
  "crowdstrike_products": ["Falcon Prevent", "Falcon Insight"],
  "key_detection_points": ["string"],
  "reasoning": "string",
  "demo_modifications": "string",
  "confidence_level": "low|medium|high",
  "attribution_confidence": "low|medium|high",
  "needs_clarification": false,
  "clarification_question": ""
}}

If confidence_level is "low" OR you cannot determine threat_actor, set \
needs_clarification=true and clarification_question to a specific question \
for the ReconAgent to answer (it will do another pass on the raw PDF).
"""


def _load_agent_config(config_path: str = "config.yaml") -> Dict[str, Any]:
    try:
        with open(config_path) as f:
            cfg = yaml.safe_load(f)
        return cfg.get("agents", {}).get("threat_intel", {})
    except Exception:
        return {}


class ThreatIntelAgent:
    """Análisis profundo de inteligencia de amenazas con Claude Opus."""

    name = "ThreatIntelAgent"

    def __init__(self, config_path: str = "config.yaml", model_override: dict = None):
        agent_cfg   = _load_agent_config(config_path)
        if model_override:
            agent_cfg.update(model_override)
        provider    = agent_cfg.get("provider", "anthropic")
        model       = agent_cfg.get("model", "claude-opus-4-6")
        temperature = agent_cfg.get("temperature", 0.1)
        self.llm         = _build_llm(provider, model, temperature)
        self.lab_context = _load_lab_context(config_path)

    # ── LangGraph node ────────────────────────────────────────────

    def run(self, state: AgentState) -> dict:
        print(f"\n[{self.name}] Starting threat intelligence analysis...")

        recon_briefing = _extract_recon_briefing(state["messages"])
        ioc_sample     = _fmt_ioc_sample(state["iocs"])
        ttp_list       = _fmt_ttps(state["ttps"])
        doc_excerpt    = _get_doc_excerpt(state["content"])

        prompt = _ANALYSIS_PROMPT.format(
            lab_context=self.lab_context or "Standard CrowdStrike lab environment.",
            recon_briefing=recon_briefing,
            ioc_sample=ioc_sample,
            ttp_list=ttp_list,
            doc_excerpt=doc_excerpt,
        )

        response = self.llm.invoke(prompt)
        raw = response.content if hasattr(response, "content") else str(response)
        analysis = _extract_json(raw)

        needs_clarification = analysis.get("needs_clarification", False)
        clarification_q     = analysis.get("clarification_question", "")

        # Limpiar campos de control del análisis
        analysis.pop("needs_clarification", None)
        analysis.pop("clarification_question", None)

        demonstrable = analysis.get("demonstrable", False)
        confidence   = analysis.get("confidence_level", "medium")

        if needs_clarification and confidence == "low":
            print(f"[{self.name}] Low confidence — requesting clarification: {clarification_q!r}")
        else:
            print(f"[{self.name}] Actor: {analysis.get('threat_actor', '?')} | "
                  f"Demonstrable: {demonstrable} | Confidence: {confidence}")

        # Intel Report para AttackPlannerAgent
        intel_report = _build_intel_report(analysis)

        return {
            "analysis": analysis,
            "needs_recon_clarification": needs_clarification and confidence == "low",
            "clarification_question": clarification_q if needs_clarification else "",
            "messages": state["messages"] + [
                new_message(self.name, intel_report)
            ],
        }


# ── Helpers ───────────────────────────────────────────────────────

def _extract_recon_briefing(messages: list) -> str:
    for m in reversed(messages):
        if m["agent"] == "ReconAgent":
            return m["content"]
    return "No recon briefing available."


def _fmt_ioc_sample(iocs: dict) -> str:
    lines = []
    for k, v in iocs.items():
        if v:
            lines.append(f"  {k}: {v[:3]}" + (" ..." if len(v) > 3 else ""))
    return "\n".join(lines) if lines else "  none"


def _fmt_ttps(ttps: list) -> str:
    return "\n".join(
        f"  [{t.get('id')}] {t.get('name')} — {', '.join(t.get('tactics', []))}"
        for t in ttps[:20]
    ) or "  none"


def _get_doc_excerpt(content: dict) -> str:
    sections = content.get("sections", {})
    priority = ["executive_summary", "threat_actor", "attack_chain", "ttps"]
    text = ""
    for s in priority:
        if s in sections:
            text += sections[s][:800] + "\n"
    if not text:
        text = content.get("full_text", "")[:2000]
    return text[:3000]


def _build_intel_report(analysis: dict) -> str:
    stages = "\n".join(
        f"  {i+1}. [{s.get('stage_name')}] {s.get('description', '')} "
        f"(TTPs: {', '.join(s.get('techniques', []))})"
        for i, s in enumerate(analysis.get("attack_stages", []))
    )
    return (
        f"INTEL REPORT\n"
        f"Actor: {analysis.get('threat_actor')} ({analysis.get('threat_actor_type')})\n"
        f"Campaign: {analysis.get('campaign_name')}\n"
        f"Attack vector: {analysis.get('attack_vector')}\n"
        f"Platforms: {', '.join(analysis.get('platforms', []))}\n"
        f"Demonstrable: {analysis.get('demonstrable')} | Risk: {analysis.get('demo_risk')}\n"
        f"CrowdStrike products: {', '.join(analysis.get('crowdstrike_products', []))}\n"
        f"Detection points: {', '.join(analysis.get('key_detection_points', [])[:5])}\n"
        f"Attack stages:\n{stages}\n"
        f"Reasoning: {analysis.get('reasoning', '')}"
    )


def _extract_json(text: str) -> dict:
    # Strategy 1: direct parse
    try:
        return json.loads(text.strip())
    except Exception:
        pass
    # Strategy 2: regex
    m = re.search(r'\{[\s\S]*\}', text)
    if m:
        try:
            return json.loads(m.group())
        except Exception:
            pass
    # Strategy 3: markdown block
    m = re.search(r'```(?:json)?\s*([\s\S]*?)```', text)
    if m:
        try:
            return json.loads(m.group(1))
        except Exception:
            pass
    # Strategy 4: cleanup
    try:
        cleaned = re.sub(r',\s*([}\]])', r'\1', text)
        m = re.search(r'\{[\s\S]*\}', cleaned)
        if m:
            return json.loads(m.group())
    except Exception:
        pass
    return {"demonstrable": False, "reasoning": "Failed to parse LLM response",
            "confidence_level": "low", "threat_actor": "Unknown"}
