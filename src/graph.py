"""
ThreatHunt AI Creator — Grafo de orquestación LangGraph.

Topología del grafo:

  recon ──► threat_intel ──► attack_planner ──► payload_crafter
    ▲              │                 ▲                   │
    │ (clarif.)   │ (not demo.)     │ (retry)            ▼
    │            END             validator ◄── playbook_assembler
    │                                │
    └──────────────────────────────END (valid)

Interacciones entre agentes via state["messages"]:
  ReconAgent        → escribe "Recon Briefing"    → lee ThreatIntelAgent
  ThreatIntelAgent  → escribe "Intel Report"      → lee AttackPlannerAgent
  AttackPlannerAgent→ escribe "Attack Plan"       → lee PlaybookAssembler (contexto)
  PayloadCrafterAgent→ escribe "Payload Manifest" → lee PlaybookAssembler
  PlaybookAssembler → escribe "Playbook Ready"    → lee ValidatorAgent
  ValidatorAgent    → escribe "Validation result" → lee AttackPlannerAgent (si retry)
"""

from typing import Literal
from langgraph.graph import StateGraph, END

from src.agents.state import AgentState, initial_state
from src.agents.recon_agent import ReconAgent
from src.agents.threat_intel_agent import ThreatIntelAgent
from src.agents.attack_planner_agent import AttackPlannerAgent
from src.agents.payload_crafter_agent import PayloadCrafterAgent
from src.agents.playbook_assembler_agent import PlaybookAssemblerAgent
from src.agents.validator_agent import ValidatorAgent


# ── Routing functions ─────────────────────────────────────────────

def route_after_recon(state: AgentState) -> Literal["threat_intel", "__end__"]:
    """Siempre avanza a threat_intel (el recon nunca falla fatalmente)."""
    if state.get("errors") and not state.get("content"):
        print("[Router] Recon failed critically — aborting.")
        return "__end__"
    return "threat_intel"


def route_after_intel(
    state: AgentState,
) -> Literal["recon", "attack_planner", "__end__"]:
    """
    - Si ThreatIntel pide aclaración → vuelve a ReconAgent (máx. 1 vez)
    - Si la amenaza no es demostrable → termina
    - Caso normal → AttackPlannerAgent
    """
    if state.get("needs_recon_clarification") and state.get("retry_count", 0) == 0:
        print("[Router] ThreatIntel needs clarification → ReconAgent")
        return "recon"

    if not state.get("analysis", {}).get("demonstrable", False):
        print(f"[Router] Not demonstrable — stopping. "
              f"Reason: {state['analysis'].get('reasoning', 'N/A')[:100]}")
        return "__end__"

    return "attack_planner"


def route_after_validation(
    state: AgentState,
) -> Literal["attack_planner", "__end__"]:
    """
    - Si válido → END
    - Si inválido y quedan retries → AttackPlannerAgent con feedback
    - Si inválido y sin retries → END igualmente (mejor playbook posible)
    """
    validation  = state.get("validation", {})
    retry_count = state.get("retry_count", 0)
    max_retries = state.get("max_retries", 2)

    if validation.get("valid"):
        print("[Router] Playbook valid — pipeline complete ✓")
        return "__end__"

    if retry_count <= max_retries:
        issues = validation.get("issues", [])
        print(f"[Router] Validation failed ({len(issues)} issues) — "
              f"retry {retry_count}/{max_retries} → AttackPlannerAgent")
        return "attack_planner"

    print(f"[Router] Max retries ({max_retries}) reached — accepting current playbook")
    return "__end__"


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
    recon     = ReconAgent(config_path,     model_override=ov.get("recon"))
    intel     = ThreatIntelAgent(config_path, model_override=ov.get("threat_intel"))
    planner   = AttackPlannerAgent(config_path, model_override=ov.get("attack_planner"))
    crafter   = PayloadCrafterAgent(config_path, model_override=ov.get("payload_crafter"))
    assembler = PlaybookAssemblerAgent(config_path, model_override=ov.get("playbook_assembler"))
    validator = ValidatorAgent(config_path,  model_override=ov.get("validator"))

    # Construir grafo
    graph = StateGraph(AgentState)

    # Nodos — cada método .run() es el node function
    graph.add_node("recon",              recon.run)
    graph.add_node("threat_intel",       intel.run)
    graph.add_node("attack_planner",     planner.run)
    graph.add_node("payload_crafter",    crafter.run)
    graph.add_node("playbook_assembler", assembler.run)
    graph.add_node("validator",          validator.run)

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
            "recon":           "recon",
            "attack_planner":  "attack_planner",
            "__end__":         END,
        },
    )

    # Edges directos (sin condición)
    graph.add_edge("attack_planner",     "payload_crafter")
    graph.add_edge("payload_crafter",    "playbook_assembler")
    graph.add_edge("playbook_assembler", "validator")

    # Validator → retry loop o END
    graph.add_conditional_edges(
        "validator",
        route_after_validation,
        {"attack_planner": "attack_planner", "__end__": END},
    )

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
