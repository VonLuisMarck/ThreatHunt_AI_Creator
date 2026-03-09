"""
ThreatHunt AI Creator — Grafo de orquestación LangGraph.

Topología del grafo (8 agentes):

  recon ──► threat_intel ──► knowledge_judge ──► attack_planner ──► payload_crafter
    ▲              │                 │                   ▲                  │
    │ (clarif.)   │ (not demo.)     │ (rejected)        │ (retry)           ▼
    │            END             threat_intel        validator ◄── playbook_assembler
    │                                                     │
    │                                              presentation ──► END
    └──────────────────────────────────────────────────────

Interacciones via state["messages"]:
  ReconAgent          → "Recon Briefing"    → ThreatIntelAgent
  ThreatIntelAgent    → "Intel Report"      → KnowledgeJudgeAgent
  KnowledgeJudgeAgent → "Judge Verdict"     → AttackPlannerAgent (o ThreatIntel retry)
  AttackPlannerAgent  → "Attack Plan"       → PlaybookAssembler (contexto)
  PayloadCrafterAgent → "Payload Manifest"  → PlaybookAssembler
  PlaybookAssembler   → "Playbook Ready"    → ValidatorAgent
  ValidatorAgent      → "Validation result" → AttackPlannerAgent (retry) / PresentationAgent
  PresentationAgent   → "Presentation"      → END
"""

from typing import Literal
from langgraph.graph import StateGraph, END

from src.agents.state import AgentState, initial_state
from src.agents.recon_agent import ReconAgent
from src.agents.threat_intel_agent import ThreatIntelAgent
from src.agents.knowledge_judge_agent import KnowledgeJudgeAgent
from src.agents.attack_planner_agent import AttackPlannerAgent
from src.agents.payload_crafter_agent import PayloadCrafterAgent
from src.agents.playbook_assembler_agent import PlaybookAssemblerAgent
from src.agents.validator_agent import ValidatorAgent
from src.agents.presentation_agent import PresentationAgent


# ── Routing functions ─────────────────────────────────────────────

def route_after_recon(state: AgentState) -> Literal["threat_intel", "__end__"]:
    """Siempre avanza a threat_intel (el recon nunca falla fatalmente)."""
    if state.get("errors") and not state.get("content"):
        print("[Router] Recon failed critically — aborting.")
        return "__end__"
    return "threat_intel"


def route_after_intel(
    state: AgentState,
) -> Literal["recon", "knowledge_judge", "__end__"]:
    """
    - Si ThreatIntel pide aclaración → vuelve a ReconAgent (máx. 1 vez)
    - Si la amenaza no es demostrable → termina
    - Caso normal → KnowledgeJudgeAgent
    """
    if state.get("needs_recon_clarification") and state.get("retry_count", 0) == 0:
        print("[Router] ThreatIntel needs clarification → ReconAgent")
        return "recon"

    if not state.get("analysis", {}).get("demonstrable", False):
        print(f"[Router] Not demonstrable — stopping. "
              f"Reason: {state['analysis'].get('reasoning', 'N/A')[:100]}")
        return "__end__"

    return "knowledge_judge"


def route_after_knowledge_judge(
    state: AgentState,
) -> Literal["threat_intel", "attack_planner"]:
    """
    - Si el juez rechaza el análisis (score < 60) → vuelve a ThreatIntelAgent (máx. 1 vez)
    - Caso normal → AttackPlannerAgent
    """
    verdict     = state.get("knowledge_verdict", {})
    approved    = verdict.get("approved", True)
    retry_count = state.get("retry_count", 0)

    if not approved and retry_count < 1:
        score = verdict.get("overall_score", 0)
        print(f"[Router] Knowledge Judge rejected (score {score}/100) → ThreatIntelAgent retry")
        return "threat_intel"

    return "attack_planner"


def route_after_validation(
    state: AgentState,
) -> Literal["attack_planner", "presentation"]:
    """
    - Si inválido y quedan retries → AttackPlannerAgent con feedback
    - En todos los demás casos → PresentationAgent (siempre se presenta)
    """
    validation  = state.get("validation", {})
    retry_count = state.get("retry_count", 0)
    max_retries = state.get("max_retries", 2)

    if not validation.get("valid") and retry_count <= max_retries:
        issues = validation.get("issues", [])
        print(f"[Router] Validation failed ({len(issues)} issues) — "
              f"retry {retry_count}/{max_retries} → AttackPlannerAgent")
        return "attack_planner"

    status = "valid" if validation.get("valid") else f"max retries ({max_retries}) reached"
    print(f"[Router] Pipeline complete ({status}) → PresentationAgent")
    return "presentation"


# ── Graph builder ─────────────────────────────────────────────────

def build_graph(config_path: str = "config.yaml", agent_overrides: dict = None) -> StateGraph:
    """
    Construye y compila el grafo LangGraph.

    Args:
        config_path:     Ruta a config.yaml (para inicializar los agentes)
        agent_overrides: Overrides de modelo por agente, e.g.
                         {"recon": {"model": "claude-haiku-4-5-20251001", "provider": "anthropic"}}

    Returns:
        Grafo compilado listo para invocar.
    """
    ov = agent_overrides or {}
    # Instanciar agentes
    recon        = ReconAgent(config_path,          model_override=ov.get("recon"))
    intel        = ThreatIntelAgent(config_path,    model_override=ov.get("threat_intel"))
    judge        = KnowledgeJudgeAgent(config_path, model_override=ov.get("knowledge_judge"))
    planner      = AttackPlannerAgent(config_path,  model_override=ov.get("attack_planner"))
    crafter      = PayloadCrafterAgent(config_path, model_override=ov.get("payload_crafter"))
    assembler    = PlaybookAssemblerAgent(config_path, model_override=ov.get("playbook_assembler"))
    validator    = ValidatorAgent(config_path,      model_override=ov.get("validator"))
    presenter    = PresentationAgent(config_path,   model_override=ov.get("presentation"))

    # Construir grafo
    graph = StateGraph(AgentState)

    # Nodos
    graph.add_node("recon",              recon.run)
    graph.add_node("threat_intel",       intel.run)
    graph.add_node("knowledge_judge",    judge.run)
    graph.add_node("attack_planner",     planner.run)
    graph.add_node("payload_crafter",    crafter.run)
    graph.add_node("playbook_assembler", assembler.run)
    graph.add_node("validator",          validator.run)
    graph.add_node("presentation",       presenter.run)

    # Entry point
    graph.set_entry_point("recon")

    # Edges condicionales
    graph.add_conditional_edges(
        "recon",
        route_after_recon,
        {"threat_intel": "threat_intel", "__end__": END},
    )
    graph.add_conditional_edges(
        "threat_intel",
        route_after_intel,
        {
            "recon":            "recon",
            "knowledge_judge":  "knowledge_judge",
            "__end__":          END,
        },
    )
    graph.add_conditional_edges(
        "knowledge_judge",
        route_after_knowledge_judge,
        {
            "threat_intel":   "threat_intel",
            "attack_planner": "attack_planner",
        },
    )

    # Edges directos
    graph.add_edge("attack_planner",     "payload_crafter")
    graph.add_edge("payload_crafter",    "playbook_assembler")
    graph.add_edge("playbook_assembler", "validator")

    # Validator → retry loop o PresentationAgent
    graph.add_conditional_edges(
        "validator",
        route_after_validation,
        {"attack_planner": "attack_planner", "presentation": "presentation"},
    )

    # Presentation → END
    graph.add_edge("presentation", END)

    return graph.compile()


# ── Public runner ─────────────────────────────────────────────────

def run_pipeline(pdf_path: str, platform: str = "windows",
                 config_path: str = "config.yaml",
                 agent_overrides: dict = None) -> AgentState:
    """
    Ejecuta el pipeline multi-agente completo.

    Args:
        pdf_path:        Ruta al PDF de threat intelligence
        platform:        Plataforma por defecto ("windows" | "linux")
        config_path:     Ruta a config.yaml
        agent_overrides: Overrides de modelo por agente (opcional)

    Returns:
        Estado final con el playbook y todos los artefactos generados.
    """
    graph = build_graph(config_path, agent_overrides=agent_overrides)

    state = initial_state(pdf_path=pdf_path, platform=platform)

    print("\n" + "═" * 65)
    print("  THREATHUNT AI CREATOR — MULTI-AGENT PIPELINE (LangGraph)")
    print("═" * 65)
    print(f"  PDF:      {pdf_path}")
    print(f"  Platform: {platform}")
    print(f"  Config:   {config_path}")
    print("═" * 65)

    final_state = graph.invoke(state)

    _print_agent_conversation(final_state.get("messages", []))

    return final_state


# ── Debug helper ──────────────────────────────────────────────────

def _print_agent_conversation(messages: list):
    """Imprime el log de comunicación entre agentes."""
    if not messages:
        return
    print("\n" + "─" * 65)
    print("  AGENT CONVERSATION LOG")
    print("─" * 65)
    for msg in messages:
        print(f"\n  [{msg['agent']}] @ {msg['timestamp'][:19]}")
        for line in msg["content"].splitlines()[:8]:
            print(f"    {line}")
        total_lines = len(msg["content"].splitlines())
        if total_lines > 8:
            print(f"    ... ({total_lines - 8} more lines)")
