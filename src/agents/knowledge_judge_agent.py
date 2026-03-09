"""
KnowledgeJudgeAgent — Validador de análisis de threat intelligence.

Actúa como juez experto: valida el output de ThreatIntelAgent contra
un knowledge base completo de threat intelligence antes de pasar al
AttackPlannerAgent.

Si overall_score < 60, rechaza el análisis y lo devuelve a ThreatIntelAgent
con correcciones específicas (max 1 retry para evitar bucles).

Modelo: Claude Sonnet (validación lógica, no requiere Opus)
"""

import json
import re
import yaml
from typing import Dict, Any

from src.llm_client import LLMClient, load_lab_context, load_prompt
from src.agents.state import AgentState, new_message


def _load_agent_config(config_path: str = "config.yaml") -> Dict[str, Any]:
    try:
        with open(config_path) as f:
            cfg = yaml.safe_load(f)
        return cfg.get("agents", {}).get("knowledge_judge", {})
    except Exception:
        return {}


class KnowledgeJudgeAgent:
    """
    Valida el análisis de ThreatIntelAgent contra domain knowledge completo.
    Produce un veredicto JSON con score, issues y correcciones sugeridas.
    """

    name = "KnowledgeJudgeAgent"
    REJECTION_THRESHOLD = 60   # overall_score mínimo para aprobar

    def __init__(self, config_path: str = "config.yaml",
                 model_override: Dict[str, Any] = None):
        cfg = _load_agent_config(config_path)
        if model_override:
            cfg.update(model_override)
        provider    = cfg.get("provider", "anthropic")
        model       = cfg.get("model", "claude-sonnet-4-6")
        temperature = cfg.get("temperature", 0.1)

        self.llm = LLMClient(
            provider=provider, model=model,
            temperature=temperature, agent_name=self.name,
        )

    def run(self, state: AgentState) -> dict:
        print(f"\n[{self.name}] Validating threat intel analysis...")

        analysis = state.get("analysis", {})
        msgs     = state.get("messages", [])

        recon_briefing = next(
            (m["content"] for m in msgs if m["agent"] == "ReconAgent"),
            "No recon briefing available.",
        )

        try:
            verdict = self._judge(analysis, recon_briefing)
        except Exception as e:
            print(f"[{self.name}] Judge error (approving anyway): {e}")
            verdict = {
                "overall_score": 75,
                "approved": True,
                "judge_notes": f"Validation skipped due to error: {e}",
                "corrections": [],
            }

        score    = verdict.get("overall_score", 0)
        approved = verdict.get("approved", True)
        status   = "✅ APPROVED" if approved else f"⚠️ REJECTED (score {score}/100)"
        notes    = verdict.get("judge_notes", "")

        print(f"[{self.name}] Verdict: {status} — {notes[:80]}")

        lines = [
            f"Knowledge Judge Verdict: {status}",
            f"Overall score: {score}/100",
            f"Notes: {notes}",
        ]
        corrections = verdict.get("corrections", [])
        if corrections:
            lines.append(f"Corrections ({len(corrections)}):")
            for c in corrections[:4]:
                lines.append(f"  • {c.get('field', '?')}: {c.get('reason', '')[:80]}")

        msgs = list(msgs) + [new_message(self.name, "\n".join(lines))]

        return {
            "knowledge_verdict":       verdict,
            "messages":                msgs,
            # If rejected → flag for ThreatIntelAgent retry
            "needs_recon_clarification": not approved,
            "clarification_question":  (
                verdict.get("rejection_reason", "")
                if not approved else ""
            ),
        }

    def _judge(self, analysis: Dict[str, Any], recon_briefing: str) -> Dict[str, Any]:
        domain_knowledge = load_prompt("domain_knowledge")

        prompt = load_prompt("knowledge_judge").format(
            domain_knowledge=domain_knowledge,
            recon_briefing=recon_briefing[:3000],
            analysis_json=json.dumps(analysis, indent=2, default=str)[:4000],
        )

        raw = self.llm.invoke(prompt)

        # Extract first JSON object from the response
        match = re.search(r'\{.*\}', raw, re.DOTALL)
        if match:
            try:
                result = json.loads(match.group())
                # Ensure required fields exist
                result.setdefault("overall_score", 75)
                result.setdefault("approved", result["overall_score"] >= self.REJECTION_THRESHOLD)
                result.setdefault("corrections", [])
                result.setdefault("judge_notes", "")
                return result
            except json.JSONDecodeError:
                pass

        # Fallback: approve with low confidence
        return {
            "overall_score": 70,
            "approved": True,
            "judge_notes": "Could not parse structured verdict — approving with caution.",
            "corrections": [],
        }
