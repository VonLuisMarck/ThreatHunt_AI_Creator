"""
ReconAgent — Agente de reconocimiento.

Responsabilidades:
  1. Extracción estructural del PDF (PDFProcessor)
  2. Extracción de IOCs (IOCExtractor)
  3. Mapeo de TTPs (TTPMapper)
  4. Redacción de un "Recon Briefing" para ThreatIntelAgent (Haiku)
  5. Si recibe una clarification_question de ThreatIntelAgent → segunda
     pasada enfocada en responder esa pregunta concreta.

Modelo: Claude Haiku (rápido, barato — el trabajo pesado es determinista)
"""

import yaml
from datetime import datetime
from typing import Dict, Any

from src.pdf_processor import PDFProcessor
from src.ioc_extractor import IOCExtractor
from src.ttp_mapper import TTPMapper
from src.llm_client import LLMClient, load_lab_context, load_prompt
from src.agents.state import AgentState, new_message




def _load_agent_config(config_path: str = "config.yaml") -> Dict[str, Any]:
    try:
        with open(config_path) as f:
            cfg = yaml.safe_load(f)
        return cfg.get("agents", {}).get("recon", {})
    except Exception:
        return {}


class ReconAgent:
    """Agente de reconocimiento: extracción determinista + briefing LLM."""

    name = "ReconAgent"

    def __init__(self, config_path: str = "config.yaml", model_override: dict = None):
        agent_cfg = _load_agent_config(config_path)
        if model_override:
            agent_cfg.update(model_override)
        provider    = agent_cfg.get("provider", "anthropic")
        model       = agent_cfg.get("model", "claude-haiku-4-5-20251001")
        temperature = agent_cfg.get("temperature", 0.1)
        self.llm = LLMClient(provider, model, temperature, agent_name=self.name)
        self.lab_context = load_lab_context(config_path)

    # ── LangGraph node ────────────────────────────────────────────

    def run(self, state: AgentState) -> dict:
        print(f"\n[{self.name}] Starting recon on: {state['pdf_path']}")

        # ── Deterministic extraction ──────────────────────────────
        content = PDFProcessor().extract_text(state["pdf_path"])
        iocs    = IOCExtractor().extract_all(content["full_text"])
        ttps    = TTPMapper().extract_techniques(content["full_text"])

        print(f"[{self.name}] PDF: {content['metadata'].get('page_count')} pages | "
              f"IOCs: {sum(len(v) for v in iocs.values())} | TTPs: {len(ttps)}")

        # ── LLM Briefing ──────────────────────────────────────────
        clarification_note = ""
        if state.get("clarification_question"):
            clarification_note = (
                f"\nIMPORTANT — The Threat Intel Agent needs clarification on:\n"
                f"  \"{state['clarification_question']}\"\n"
                f"Make sure your briefing addresses this specific question.\n"
            )

        prompt = load_prompt("recon_briefing").format(
            clarification_note=clarification_note,
            page_count=content["metadata"].get("page_count", "?"),
            sections=", ".join(content.get("sections", {}).keys()) or "none detected",
            key_findings=_fmt_findings(content.get("key_findings", {})),
            ioc_summary=_fmt_ioc_summary(iocs),
            ttp_count=len(ttps),
            ttp_list=", ".join(f"{t['id']}:{t['name']}" for t in ttps[:15]),
        )

        full_prompt = f"{self.lab_context}\n\n{prompt}" if self.lab_context else prompt
        briefing_text = self.llm.invoke(full_prompt)

        print(f"[{self.name}] Recon briefing written ({len(briefing_text)} chars)")

        return {
            "content":  content,
            "iocs":     iocs,
            "ttps":     ttps,
            "needs_recon_clarification": False,
            "clarification_question":    "",
            "messages": state["messages"] + [
                new_message(self.name, briefing_text)
            ],
        }


# ── Helpers ───────────────────────────────────────────────────────

def _fmt_findings(kf: dict) -> str:
    parts = []
    if kf.get("mentioned_threat_actors"):
        parts.append(f"Actors: {', '.join(kf['mentioned_threat_actors'][:5])}")
    if kf.get("cves"):
        parts.append(f"CVEs: {', '.join(kf['cves'][:5])}")
    if kf.get("mentioned_tools"):
        parts.append(f"Tools: {', '.join(kf['mentioned_tools'][:5])}")
    if kf.get("mentioned_sectors"):
        parts.append(f"Sectors: {', '.join(kf['mentioned_sectors'][:4])}")
    if kf.get("mentioned_countries"):
        parts.append(f"Countries: {', '.join(kf['mentioned_countries'][:4])}")
    return " | ".join(parts) if parts else "none"


def _fmt_ioc_summary(iocs: dict) -> str:
    parts = [f"{k}:{len(v)}" for k, v in iocs.items() if v]
    return ", ".join(parts) if parts else "none"
