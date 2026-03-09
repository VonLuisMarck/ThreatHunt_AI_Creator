"""
PresentationAgent — Generador de material de ventas y executive brief.

Transforma el análisis técnico en:
  - Executive Brief (para CISO/VP Security — business language)
  - Sales Key Points (para el Account Executive)
  - Demo wow moments + ROI arguments

Se ejecuta al final del pipeline, después de ValidatorAgent.

Modelo: Claude Sonnet (creative writing con contexto de ventas)
"""

import json
import re
import yaml
from typing import Dict, Any, List

from src.llm_client import LLMClient, load_lab_context, load_prompt
from src.agents.state import AgentState, new_message


def _load_agent_config(config_path: str = "config.yaml") -> Dict[str, Any]:
    try:
        with open(config_path) as f:
            cfg = yaml.safe_load(f)
        return cfg.get("agents", {}).get("presentation", {})
    except Exception:
        return {}


class PresentationAgent:
    """
    Genera executive brief y key selling points basados en el análisis completo.
    """

    name = "PresentationAgent"

    def __init__(self, config_path: str = "config.yaml",
                 model_override: Dict[str, Any] = None):
        cfg = _load_agent_config(config_path)
        if model_override:
            cfg.update(model_override)
        provider    = cfg.get("provider", "anthropic")
        model       = cfg.get("model", "claude-sonnet-4-6")
        temperature = cfg.get("temperature", 0.2)

        self.llm         = LLMClient(
            provider=provider, model=model,
            temperature=temperature, agent_name=self.name,
        )
        self.lab_context = load_lab_context(config_path)

    def run(self, state: AgentState) -> dict:
        print(f"\n[{self.name}] Generating presentation materials...")

        analysis         = state.get("analysis", {})
        attack_sequence  = state.get("attack_sequence", [])
        narrative_summary = state.get("narrative_summary", "")
        msgs             = state.get("messages", [])

        try:
            presentation = self._generate(analysis, attack_sequence, narrative_summary)
        except Exception as e:
            print(f"[{self.name}] Generation error: {e}")
            presentation = {
                "headline": analysis.get("campaign_name", "Threat Campaign Demo"),
                "executive_brief_md": narrative_summary or "See playbook for details.",
                "key_selling_points": [],
                "demo_wow_moments": [],
                "error": str(e),
            }

        ksp_count = len(presentation.get("key_selling_points", []))
        wow_count = len(presentation.get("demo_wow_moments", []))
        headline  = presentation.get("headline", "N/A")

        print(f"[{self.name}] Presentation ready — {ksp_count} selling points, {wow_count} wow moments")

        msg_content = (
            f"Presentation Materials Generated\n"
            f"Headline: {headline}\n"
            f"Key selling points: {ksp_count}\n"
            f"Wow moments: {wow_count}\n"
            f"Estimated demo duration: {presentation.get('estimated_demo_duration', 'N/A')}\n"
        )
        if ksp_count:
            msg_content += f"Top point: {presentation['key_selling_points'][0][:100]}"

        msgs = list(msgs) + [new_message(self.name, msg_content)]

        return {
            "presentation": presentation,
            "messages":     msgs,
        }

    def _generate(
        self,
        analysis: Dict[str, Any],
        attack_sequence: List[Dict],
        narrative_summary: str,
    ) -> Dict[str, Any]:
        # Build compact attack chain for the prompt
        attack_chain = "\n".join(
            f"  Stage {s.get('stage_number', i+1)}: [{s.get('technique_id', '?')}] "
            f"{s.get('description', '')[:70]} "
            f"({s.get('detection_severity', '?')} severity)"
            for i, s in enumerate(attack_sequence[:8])
        )

        detection_points = "\n".join(
            f"  - {d}"
            for s in attack_sequence
            for d in s.get("crowdstrike_detections", [])
        )

        # Only pass fields useful for presentation
        analysis_summary = {k: analysis.get(k) for k in [
            "threat_actor", "campaign_name", "attack_vector",
            "platforms", "target_industries", "target_geography",
            "crowdstrike_products", "demo_risk", "key_detection_points",
        ] if analysis.get(k)}

        prompt = load_prompt("presentation_agent").format(
            lab_context      = (self.lab_context or "")[:800],
            analysis         = json.dumps(analysis_summary, indent=2),
            stage_count      = len(attack_sequence),
            attack_chain     = attack_chain[:2500] or "No attack stages generated.",
            detection_points = detection_points[:1500] or "No detections recorded.",
            playbook_summary = narrative_summary[:1000] or "No narrative summary available.",
        )

        raw = self.llm.invoke(prompt)

        match = re.search(r'\{.*\}', raw, re.DOTALL)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass

        # Fallback: return as executive brief markdown
        return {
            "headline":            analysis.get("campaign_name", "Threat Demo"),
            "executive_brief_md":  raw,
            "key_selling_points":  [],
            "demo_wow_moments":    [],
        }
