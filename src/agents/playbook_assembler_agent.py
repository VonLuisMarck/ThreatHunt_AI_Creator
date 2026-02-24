"""
PlaybookAssemblerAgent — Agente ensamblador del playbook Shadow-Replay.

Responsabilidades:
  1. Usar PlaybookGenerator (determinista) para construir el JSON Shadow-Replay
  2. Generar el narrative summary con Sonnet (resumen para el presentador)
  3. Adjuntar snippets al playbook
  4. Escribir "Playbook Ready" en el canal de mensajes

Modelo: Claude Sonnet para el narrative — el ensamblado del JSON es determinista.
"""

import yaml
from typing import Dict, Any

from src.playbook_generator import PlaybookGenerator
from src.llm_analyzer import _build_llm, _load_lab_context
from src.agents.state import AgentState, new_message


_SUMMARY_PROMPT = """\
You are a CrowdStrike sales engineer preparing a threat demo.
Write a narrative summary (300-400 words) of this attack playbook for \
the presenter. Include:

1. What threat this simulates and why it matters to the customer
2. The attack chain walkthrough (stage by stage, plain language)
3. What CrowdStrike detects at each stage and how the customer will see it
4. Key talking points and "wow moments" to highlight

PLAYBOOK:
- Campaign: {campaign}
- Threat Actor: {actor}
- Stages: {stage_count} attack events
- Agents required: {agents}
- CrowdStrike products: {products}
- Detection points: {detection_points}

ATTACK CHAIN:
{attack_chain}

Write in a professional, engaging style suitable for a customer demo.
"""


def _load_agent_config(config_path: str = "config.yaml") -> Dict[str, Any]:
    try:
        with open(config_path) as f:
            cfg = yaml.safe_load(f)
        return cfg.get("agents", {}).get("playbook_assembler", {})
    except Exception:
        return {}


class PlaybookAssemblerAgent:
    """Ensambla el playbook Shadow-Replay y genera la narrativa de demo."""

    name = "PlaybookAssemblerAgent"

    def __init__(self, config_path: str = "config.yaml", model_override: dict = None):
        agent_cfg   = _load_agent_config(config_path)
        if model_override:
            agent_cfg.update(model_override)
        provider    = agent_cfg.get("provider", "anthropic")
        model       = agent_cfg.get("model", "claude-sonnet-4-5-20250929")
        temperature = agent_cfg.get("temperature", 0.1)
        self.llm            = _build_llm(provider, model, temperature)
        self.lab_context    = _load_lab_context(config_path)
        self.playbook_gen   = PlaybookGenerator(config_path)
        self.config_path    = config_path

    # ── LangGraph node ────────────────────────────────────────────

    def run(self, state: AgentState) -> dict:
        print(f"\n[{self.name}] Assembling Shadow-Replay playbook...")

        analysis        = state.get("analysis", {})
        attack_sequence = state.get("attack_sequence", [])
        iocs            = state.get("iocs", {})
        ttps            = state.get("ttps", [])
        snippets        = state.get("snippets", [])

        # ── Deterministic JSON assembly ───────────────────────────
        playbook = self.playbook_gen.generate(analysis, attack_sequence, iocs, ttps)
        playbook["emulation_snippets"] = snippets

        print(f"[{self.name}] Playbook assembled: {len(playbook.get('events', []))} events, "
              f"{len(playbook.get('mandatory_agents', []))} agents")

        # ── Narrative summary (Sonnet) ────────────────────────────
        summary = self._generate_summary(playbook, analysis, attack_sequence)
        playbook["narrative_summary"] = summary

        print(f"[{self.name}] Narrative summary written ({len(summary)} chars)")

        return {
            "playbook":          playbook,
            "narrative_summary": summary,
            "messages": state["messages"] + [
                new_message(self.name, _build_ready_message(playbook))
            ],
        }

    # ── Summary generation ────────────────────────────────────────

    def _generate_summary(self, playbook: dict, analysis: dict, attack_sequence: list) -> str:
        attack_chain_text = "\n".join(
            f"  {i+1}. [{s.get('technique_id')}] {s.get('description', '')} "
            f"— CrowdStrike detects: {', '.join(s.get('crowdstrike_detections', [])[:2])}"
            for i, s in enumerate(attack_sequence)
        )

        prompt = _SUMMARY_PROMPT.format(
            campaign=analysis.get("campaign_name", "Unknown"),
            actor=analysis.get("threat_actor", "Unknown"),
            stage_count=len([e for e in playbook.get("events", []) if "cleanup" not in e["event_id"]]),
            agents=", ".join(a["agent_type"] for a in playbook.get("mandatory_agents", [])),
            products=", ".join(analysis.get("crowdstrike_products", [])),
            detection_points=", ".join(analysis.get("key_detection_points", [])[:5]),
            attack_chain=attack_chain_text,
        )

        try:
            response = self.llm.invoke(prompt)
            return response.content if hasattr(response, "content") else str(response)
        except Exception as e:
            return f"Summary generation failed: {e}"


# ── Helper ────────────────────────────────────────────────────────

def _build_ready_message(playbook: dict) -> str:
    events   = playbook.get("events", [])
    agents   = playbook.get("mandatory_agents", [])
    attack_e = [e for e in events if "cleanup" not in e.get("event_id", "")]
    return (
        f"PLAYBOOK READY\n"
        f"  ID: {playbook.get('playbook_id')}\n"
        f"  Name: {playbook.get('name')}\n"
        f"  Agents: {[a['agent_id'] + '(' + a['agent_type'] + ')' for a in agents]}\n"
        f"  Attack events: {len(attack_e)} | Cleanup events: {len(events) - len(attack_e)}\n"
        f"  First event: {events[0]['event_id'] if events else 'none'}\n"
        f"  Last trigger: {events[-1]['success_trigger'] if events else 'none'}"
    )
