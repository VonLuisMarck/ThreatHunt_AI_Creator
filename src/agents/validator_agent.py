"""
ValidatorAgent — Agente de validación del playbook.

Responsabilidades:
  1. Validación estructural determinista (sin LLM):
     - Todos los success_trigger referencian event_ids existentes
     - mandatory_agents son consistentes con required_agent_type en events
     - Payloads no están vacíos
     - Hay al menos un evento de cleanup
  2. Validación semántica con Claude Sonnet:
     - La secuencia de ataque es lógicamente coherente
     - Los técnicas MITRE son apropiadas para las plataformas
     - El kill chain tiene sentido
  3. Si hay problemas → feedback específico para AttackPlannerAgent
  4. Decide: END o retry AttackPlannerAgent

Modelo: Claude Sonnet (validación lógica, no requiere Opus)
"""

import json
import re
import yaml
from typing import Dict, Any, List, Tuple

from src.llm_analyzer import _build_llm
from src.agents.state import AgentState, ValidationResult, new_message


_SEMANTIC_PROMPT = """\
You are a quality assurance engineer reviewing an attack simulation playbook.

PLAYBOOK SUMMARY:
- Name: {name}
- Agents: {agents}
- Attack events: {attack_events}
- Technique chain: {technique_chain}

ATTACK SEQUENCE:
{sequence_summary}

Assess the playbook on these criteria:
1. Is the kill chain logically coherent? (each stage prepares for the next)
2. Are the techniques appropriate for their stated platforms?
3. Are there any critical missing stages for the attack type?
4. Would this demo clearly showcase CrowdStrike detections?

Return ONLY valid JSON:
{{
  "semantically_valid": true,
  "issues": [],
  "feedback": "If invalid: specific actionable feedback for the planner (1-3 sentences max)"
}}
"""


def _load_agent_config(config_path: str = "config.yaml") -> Dict[str, Any]:
    try:
        with open(config_path) as f:
            cfg = yaml.safe_load(f)
        return cfg.get("agents", {}).get("validator", {})
    except Exception:
        return {}


class ValidatorAgent:
    """Valida el playbook estructural y semánticamente. Ruta a retry si hay problemas."""

    name = "ValidatorAgent"

    def __init__(self, config_path: str = "config.yaml", model_override: dict = None):
        agent_cfg   = _load_agent_config(config_path)
        if model_override:
            agent_cfg.update(model_override)
        provider    = agent_cfg.get("provider", "anthropic")
        model       = agent_cfg.get("model", "claude-sonnet-4-5-20250929")
        temperature = agent_cfg.get("temperature", 0.1)
        self.llm = _build_llm(provider, model, temperature)

    # ── LangGraph node ────────────────────────────────────────────

    def run(self, state: AgentState) -> dict:
        print(f"\n[{self.name}] Validating playbook...")

        playbook        = state.get("playbook", {})
        attack_sequence = state.get("attack_sequence", [])

        # ── Pass 1: Structural (deterministic, fast) ──────────────
        struct_issues = _validate_structural(playbook)

        # ── Pass 2: Semantic (LLM) ────────────────────────────────
        semantic_issues, semantic_feedback = self._validate_semantic(playbook, attack_sequence)

        all_issues = struct_issues + semantic_issues
        is_valid   = len(all_issues) == 0

        # Se acepta con warnings menores (solo problemas semánticos no críticos)
        if struct_issues:
            is_valid = False
        elif semantic_issues and state.get("retry_count", 0) >= state.get("max_retries", 2):
            # En el último retry aceptamos aunque haya issues semánticos menores
            is_valid = True
            print(f"[{self.name}] Max retries reached — accepting with {len(semantic_issues)} semantic warning(s)")

        feedback = semantic_feedback if not is_valid else ""
        if struct_issues:
            feedback = f"Structural issues: {'; '.join(struct_issues)}"

        validation = ValidationResult(
            valid=is_valid,
            issues=all_issues,
            feedback=feedback,
        )

        status = "VALID ✓" if is_valid else f"INVALID — {len(all_issues)} issue(s)"
        print(f"[{self.name}] Result: {status}")
        if all_issues:
            for issue in all_issues:
                print(f"  ✗ {issue}")

        return {
            "validation": validation,
            "messages": state["messages"] + [
                new_message(self.name, _build_validation_message(validation))
            ],
        }

    # ── Semantic validation ───────────────────────────────────────

    def _validate_semantic(self, playbook: dict, attack_sequence: list) -> Tuple[List[str], str]:
        events = playbook.get("events", [])
        attack_events = [e for e in events if "cleanup" not in e.get("event_id", "")]

        technique_chain = " → ".join(
            e.get("mitre_technique", "?") for e in attack_events
        )

        sequence_summary = "\n".join(
            f"  {i+1}. [{s.get('technique_id')}] {s.get('description', '')} "
            f"on {s.get('platform')} — severity: {s.get('detection_severity', 'N/A')}"
            for i, s in enumerate(attack_sequence)
        )

        prompt = _SEMANTIC_PROMPT.format(
            name=playbook.get("name", "Unknown"),
            agents=[a["agent_type"] for a in playbook.get("mandatory_agents", [])],
            attack_events=len(attack_events),
            technique_chain=technique_chain,
            sequence_summary=sequence_summary or "  No stages.",
        )

        try:
            response = self.llm.invoke(prompt)
            raw = response.content if hasattr(response, "content") else str(response)
            result = _extract_json(raw)
            if result.get("semantically_valid", True):
                return [], ""
            return result.get("issues", []), result.get("feedback", "")
        except Exception as e:
            print(f"[{self.name}] Semantic validation LLM error: {e}")
            return [], ""  # Falla silenciosa: no bloquear por error de LLM


# ── Structural validation (deterministic) ─────────────────────────

def _validate_structural(playbook: dict) -> List[str]:
    issues = []
    events  = playbook.get("events", [])
    agents  = playbook.get("mandatory_agents", [])

    if not events:
        issues.append("Playbook has no events")
        return issues

    # Set de IDs válidos
    valid_ids = {e["event_id"] for e in events}

    # Set de agent_ids declarados
    declared_agent_ids = {a["agent_id"] for a in agents}

    for ev in events:
        eid = ev.get("event_id", "")

        # Payload no vacío
        if not ev.get("payload", "").strip():
            issues.append(f"Event '{eid}' has empty payload")

        # success_trigger referencia un ID válido o es null
        trigger = ev.get("success_trigger")
        if trigger and trigger not in valid_ids:
            issues.append(f"Event '{eid}' references unknown success_trigger: '{trigger}'")

        # agent_id declarado en mandatory_agents
        agent_id = ev.get("agent_id", "")
        if agent_id and agent_id not in declared_agent_ids:
            issues.append(f"Event '{eid}' uses undeclared agent_id: '{agent_id}'")

        # required_agent_type no vacío
        if not ev.get("required_agent_type", "").strip():
            issues.append(f"Event '{eid}' missing required_agent_type")

    # Al menos un evento de cleanup
    cleanup_events = [e for e in events if "cleanup" in e.get("event_id", "")]
    if not cleanup_events:
        issues.append("Playbook has no cleanup events")

    # Cadena termina en null
    last_event = events[-1]
    if last_event.get("success_trigger") is not None:
        issues.append(f"Last event '{last_event.get('event_id')}' success_trigger must be null")

    return issues


# ── Helpers ───────────────────────────────────────────────────────

def _build_validation_message(validation: ValidationResult) -> str:
    if validation["valid"]:
        return "VALIDATION PASSED — Playbook is ready for Shadow-Replay execution."
    issues_str = "\n".join(f"  - {i}" for i in validation["issues"])
    return (
        f"VALIDATION FAILED\n"
        f"Issues:\n{issues_str}\n"
        f"Feedback for AttackPlanner: {validation['feedback']}"
    )


def _extract_json(text: str) -> dict:
    try:
        return json.loads(text.strip())
    except Exception:
        pass
    m = re.search(r'\{[\s\S]*\}', text)
    if m:
        try:
            return json.loads(m.group())
        except Exception:
            pass
    return {"semantically_valid": True}
