"""
ThreatHunt AI Creator — Multi-Agent Pipeline (LangGraph)

Agentes disponibles:
  ReconAgent            — Extracción PDF + IOCs + TTPs + briefing (Haiku)
  ThreatIntelAgent      — Análisis profundo de amenaza (Opus)
  AttackPlannerAgent    — Diseño de secuencia de ataque (Opus)
  PayloadCrafterAgent   — Generación de snippets de emulación (Sonnet)
  PlaybookAssemblerAgent — Ensamblado de playbook Shadow-Replay (Sonnet + determinista)
  ValidatorAgent        — Validación y routing de retry (Sonnet)
"""

from src.agents.state import AgentState, initial_state
from src.agents.recon_agent import ReconAgent
from src.agents.threat_intel_agent import ThreatIntelAgent
from src.agents.attack_planner_agent import AttackPlannerAgent
from src.agents.payload_crafter_agent import PayloadCrafterAgent
from src.agents.playbook_assembler_agent import PlaybookAssemblerAgent
from src.agents.validator_agent import ValidatorAgent

__all__ = [
    "AgentState",
    "initial_state",
    "ReconAgent",
    "ThreatIntelAgent",
    "AttackPlannerAgent",
    "PayloadCrafterAgent",
    "PlaybookAssemblerAgent",
    "ValidatorAgent",
]
