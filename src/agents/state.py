"""
AgentState — estado compartido entre todos los agentes del grafo LangGraph.

Cada agente lee del estado lo que necesita y devuelve un dict parcial
con solo las claves que modifica. LangGraph fusiona el resultado con
el estado global automáticamente.
"""

from typing import TypedDict, List, Dict, Any, Optional
from datetime import datetime


class AgentMessage(TypedDict):
    """Mensaje de comunicación entre agentes."""
    agent:     str   # Nombre del agente emisor
    content:   str   # Contenido del mensaje (texto libre estructurado)
    timestamp: str   # ISO 8601


class ValidationResult(TypedDict):
    valid:    bool
    issues:   List[str]
    feedback: str   # Feedback específico para AttackPlannerAgent si hay retry


class AgentState(TypedDict):
    # ── Input inicial ──────────────────────────────────────────────
    pdf_path:  str
    platform:  str   # "windows" | "linux"

    # ── ReconAgent ────────────────────────────────────────────────
    content:   Dict[str, Any]         # PDFProcessor.extract_text()
    iocs:      Dict[str, List[str]]   # IOCExtractor.extract_all()
    ttps:      List[Dict]             # TTPMapper.extract_techniques()

    # ── ThreatIntelAgent ──────────────────────────────────────────
    analysis:                  Dict[str, Any]
    needs_recon_clarification: bool
    clarification_question:    str   # Pregunta específica al ReconAgent

    # ── AttackPlannerAgent ────────────────────────────────────────
    attack_sequence: List[Dict]

    # ── PayloadCrafterAgent ───────────────────────────────────────
    snippets: List[Dict]

    # ── PlaybookAssemblerAgent ────────────────────────────────────
    playbook:          Dict[str, Any]
    narrative_summary: str

    # ── ValidatorAgent ────────────────────────────────────────────
    validation: ValidationResult

    # ── Control de flujo ──────────────────────────────────────────
    retry_count: int
    max_retries: int
    errors:      List[str]

    # ── Canal de comunicación entre agentes ───────────────────────
    # Cada agente escribe aquí un resumen estructurado de sus hallazgos
    # para que los agentes siguientes puedan leerlo como contexto.
    messages: List[AgentMessage]


def new_message(agent: str, content: str) -> AgentMessage:
    """Helper para crear mensajes con timestamp automático."""
    return AgentMessage(
        agent=agent,
        content=content,
        timestamp=datetime.now().isoformat(),
    )


def initial_state(pdf_path: str, platform: str = "windows") -> AgentState:
    """Estado inicial vacío para arrancar el grafo."""
    return AgentState(
        pdf_path=pdf_path,
        platform=platform,
        content={},
        iocs={},
        ttps=[],
        analysis={},
        needs_recon_clarification=False,
        clarification_question="",
        attack_sequence=[],
        snippets=[],
        playbook={},
        narrative_summary="",
        validation=ValidationResult(valid=False, issues=[], feedback=""),
        retry_count=0,
        max_retries=2,
        errors=[],
        messages=[],
    )
