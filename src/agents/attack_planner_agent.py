"""
AttackPlannerAgent — Agente planificador de la secuencia de ataque.

Responsabilidades:
  1. Leer el Intel Report de ThreatIntelAgent
  2. Si hay feedback del ValidatorAgent (retry) → incorporarlo
  3. Diseñar la secuencia de ataque cronológica y ejecutable en el lab
  4. Escribir el "Attack Plan" en el canal de mensajes

Modelo: Claude Opus (razonamiento estratégico + conocimiento del lab)
"""

import json
import re
import yaml
from typing import Dict, Any, List

from src.llm_analyzer import _build_llm, _load_lab_context
from src.agents.state import AgentState, new_message


_PLANNER_PROMPT = """\
You are an adversary emulation planner at CrowdStrike. Design an attack \
simulation sequence for the lab described below.

LAB TOPOLOGY:
{lab_context}

THREAT INTELLIGENCE (from ThreatIntelAgent):
{intel_report}

AVAILABLE MITRE TECHNIQUES:
{ttp_list}

{feedback_section}

Design a CHRONOLOGICAL, EXECUTABLE attack sequence. Each stage must:
- Be safe to run in the lab (simulation only, no real damage)
- Generate CrowdStrike telemetry and detections
- Map to a real MITRE technique
- Run on windows (agent_1 at 10.5.9.31) or linux (agent_2 at 10.5.9.40)
- Reference C2 at 10.5.9.41:4444 for network stages

Return ONLY valid JSON array:
[
  {{
    "stage": "snake_case_unique_id",
    "stage_number": 1,
    "technique_id": "T1566.001",
    "tactic": "Initial Access",
    "platform": "windows",
    "execution_method": "powershell",
    "description": "Human-readable stage description",
    "technical_details": "What happens technically",
    "execution_approach": "How to simulate safely",
    "telemetry_generated": ["Process creation: WINWORD.EXE -> powershell.exe"],
    "crowdstrike_detections": ["Suspicious Office macro execution"],
    "detection_severity": "high",
    "prerequisites": [],
    "outputs": ["initial_foothold"]
  }}
]

Include 4-8 stages covering the full attack chain. \
End with data collection/exfiltration if applicable.
"""

_FEEDBACK_TEMPLATE = """\
VALIDATOR FEEDBACK (retry #{retry_count}):
The previous attack plan had these issues:
{issues}

Specific feedback: {feedback}

Address ALL issues above in this new plan.
"""


def _load_agent_config(config_path: str = "config.yaml") -> Dict[str, Any]:
    try:
        with open(config_path) as f:
            cfg = yaml.safe_load(f)
        return cfg.get("agents", {}).get("attack_planner", {})
    except Exception:
        return {}


class AttackPlannerAgent:
    """Diseña la secuencia de ataque con Claude Opus, incorporando feedback del Validator."""

    name = "AttackPlannerAgent"

    def __init__(self, config_path: str = "config.yaml"):
        agent_cfg   = _load_agent_config(config_path)
        provider    = agent_cfg.get("provider", "anthropic")
        model       = agent_cfg.get("model", "claude-opus-4-6")
        temperature = agent_cfg.get("temperature", 0.1)
        self.llm         = _build_llm(provider, model, temperature)
        self.lab_context = _load_lab_context(config_path)

    # ── LangGraph node ────────────────────────────────────────────

    def run(self, state: AgentState) -> dict:
        retry = state.get("retry_count", 0)
        print(f"\n[{self.name}] Planning attack sequence "
              f"(attempt {retry + 1}/{state.get('max_retries', 2) + 1})...")

        intel_report    = _extract_intel_report(state["messages"])
        ttp_list        = _fmt_ttps(state["ttps"])
        feedback_section = _build_feedback_section(state)

        prompt = _PLANNER_PROMPT.format(
            lab_context=self.lab_context or "Standard CrowdStrike lab (win: 10.5.9.31, linux: 10.5.9.40, c2: 10.5.9.41:4444).",
            intel_report=intel_report,
            ttp_list=ttp_list,
            feedback_section=feedback_section,
        )

        response = self.llm.invoke(prompt)
        raw = response.content if hasattr(response, "content") else str(response)
        attack_sequence = _extract_json_list(raw)

        # Normalizar stage IDs (sin espacios, snake_case)
        for i, stage in enumerate(attack_sequence):
            stage["stage_number"] = i + 1
            if not stage.get("stage"):
                stage["stage"] = f"stage_{i+1}_{stage.get('technique_id', 'unknown').replace('.', '_').lower()}"

        print(f"[{self.name}] Generated {len(attack_sequence)} attack stages:")
        for s in attack_sequence:
            print(f"  [{s['stage_number']}] {s['technique_id']} — {s['description'][:60]}")

        plan_summary = _build_plan_summary(attack_sequence)

        return {
            "attack_sequence": attack_sequence,
            "retry_count": retry + 1,
            "messages": state["messages"] + [
                new_message(self.name, plan_summary)
            ],
        }


# ── Helpers ───────────────────────────────────────────────────────

def _extract_intel_report(messages: list) -> str:
    for m in reversed(messages):
        if m["agent"] == "ThreatIntelAgent":
            return m["content"]
    return "No Intel Report available."


def _fmt_ttps(ttps: list) -> str:
    return "\n".join(
        f"  {t.get('id')} | {t.get('name')} | {', '.join(t.get('tactics', []))} | {', '.join(t.get('platforms', []))}"
        for t in ttps
    ) or "  No techniques identified."


def _build_feedback_section(state: AgentState) -> str:
    validation = state.get("validation", {})
    retry = state.get("retry_count", 0)
    if retry == 0 or not validation.get("issues"):
        return ""
    issues_str = "\n".join(f"  - {issue}" for issue in validation.get("issues", []))
    return _FEEDBACK_TEMPLATE.format(
        retry_count=retry,
        issues=issues_str,
        feedback=validation.get("feedback", ""),
    )


def _build_plan_summary(attack_sequence: list) -> str:
    lines = ["ATTACK PLAN SUMMARY"]
    for s in attack_sequence:
        lines.append(
            f"  Stage {s['stage_number']}: [{s['technique_id']}] {s['description']}"
            f" | Platform: {s['platform']} | Severity: {s.get('detection_severity', 'N/A')}"
        )
    return "\n".join(lines)


def _extract_json_list(text: str) -> list:
    # Strategy 1: direct
    try:
        result = json.loads(text.strip())
        if isinstance(result, list):
            return result
    except Exception:
        pass
    # Strategy 2: regex
    m = re.search(r'\[[\s\S]*\]', text)
    if m:
        try:
            result = json.loads(m.group())
            if isinstance(result, list):
                return result
        except Exception:
            pass
    # Strategy 3: markdown
    m = re.search(r'```(?:json)?\s*([\s\S]*?)```', text)
    if m:
        try:
            result = json.loads(m.group(1))
            if isinstance(result, list):
                return result
        except Exception:
            pass
    # Strategy 4: cleanup
    try:
        cleaned = re.sub(r',\s*([}\]])', r'\1', text)
        m = re.search(r'\[[\s\S]*\]', cleaned)
        if m:
            result = json.loads(m.group())
            if isinstance(result, list):
                return result
    except Exception:
        pass
    return []
