"""
PayloadCrafterAgent — Agente de generación de snippets de emulación.

Responsabilidades:
  1. Para cada técnica en attack_sequence:
     - Primero busca en emulation_library (código pre-validado)
     - Si no está → genera con Claude Sonnet (código seguro, solo simulación)
  2. Personaliza los snippets con IOCs reales del informe
  3. Escribe un "Payload Manifest" en el canal de mensajes

Modelo: Claude Sonnet (buen balance calidad/coste para generación de código)
"""

import json
import re
import yaml
from typing import Dict, Any, List, Optional

from src.llm_client import LLMClient, load_lab_context
from src.emulation_library import get_emulation_snippet, get_all_covered_techniques
from src.agents.state import AgentState, new_message


_SNIPPET_PROMPT = """\
You are a red team engineer writing SAFE SIMULATION code for CrowdStrike lab demos.

TECHNIQUE: {technique_id} — {technique_name}
TACTIC: {tactic}
PLATFORM: {platform}
STAGE CONTEXT: {stage_context}
REAL IOCs FROM REPORT: {ioc_context}
LAB: C2 at 10.5.9.41:4444, Windows victim at 10.5.9.31, Linux victim at 10.5.9.40

Write {payload_type} code that:
1. Starts with Write-Host/print('[SIMULATION] {technique_id} ...')
2. SIMULATES the technique behavior (generates telemetry, does NOT cause real damage)
3. Uses the lab IPs above (not placeholders)
4. Uses real IOCs from the report where applicable (C2 domain, hashes, etc.)
5. Includes cleanup at the end
6. Ends every PowerShell statement with ; (for one-liner conversion)

Return ONLY the code, no explanations, no markdown fences.
Max 40 lines. All code must be executable as-is.
"""


def _load_agent_config(config_path: str = "config.yaml") -> Dict[str, Any]:
    try:
        with open(config_path) as f:
            cfg = yaml.safe_load(f)
        return cfg.get("agents", {}).get("payload_crafter", {})
    except Exception:
        return {}


class PayloadCrafterAgent:
    """Genera snippets de emulación: librería estática primero, Sonnet como fallback."""

    name = "PayloadCrafterAgent"
    MAX_SNIPPETS = 6

    def __init__(self, config_path: str = "config.yaml", model_override: dict = None):
        agent_cfg   = _load_agent_config(config_path)
        if model_override:
            agent_cfg.update(model_override)
        provider    = agent_cfg.get("provider", "anthropic")
        model       = agent_cfg.get("model", "claude-sonnet-4-5-20250929")
        temperature = agent_cfg.get("temperature", 0.1)
        self.llm         = LLMClient(provider, model, temperature, agent_name=self.name)
        self.lab_context = load_lab_context(config_path)
        self._library_tids = set(get_all_covered_techniques())

    # ── LangGraph node ────────────────────────────────────────────

    def run(self, state: AgentState) -> dict:
        print(f"\n[{self.name}] Crafting emulation payloads...")

        platform       = state.get("platform", "windows")
        attack_sequence = state.get("attack_sequence", [])
        iocs           = state.get("iocs", {})
        snippets       = []

        # Limitar a MAX_SNIPPETS para no agotar tokens
        for stage in attack_sequence[:self.MAX_SNIPPETS]:
            tid = stage.get("technique_id", "")
            snippet = self._craft_snippet(tid, stage, iocs, platform)
            if snippet:
                snippets.append(snippet)

        sources = {s["source"] for s in snippets}
        print(f"[{self.name}] {len(snippets)} snippets crafted "
              f"(library: {sum(1 for s in snippets if s['source'] == 'static_library')}, "
              f"llm: {sum(1 for s in snippets if s['source'] == 'llm_generated')})")

        manifest = _build_manifest(snippets)

        return {
            "snippets": snippets,
            "messages": state["messages"] + [
                new_message(self.name, manifest)
            ],
        }

    # ── Snippet generation ─────────────────────────────────────────

    def _craft_snippet(self, tid: str, stage: dict, iocs: dict, platform: str) -> Optional[dict]:
        """Intenta librería estática primero, luego generación LLM."""

        # 1. Librería estática (pre-validada)
        if tid in self._library_tids:
            static = get_emulation_snippet(tid, platform)
            if static and static.get("code"):
                code = _inject_iocs(static["code"], iocs, tid)
                return {
                    "technique_id":    tid,
                    "name":            static.get("name", tid),
                    "tactic":          static.get("tactic", stage.get("tactic", "")),
                    "platform":        platform,
                    "code":            code,
                    "detection_notes": static.get("detection_notes", ""),
                    "source":          "static_library",
                    "stage_context":   stage.get("description", ""),
                }

        # 2. Generación LLM
        return self._llm_snippet(tid, stage, iocs, platform)

    def _llm_snippet(self, tid: str, stage: dict, iocs: dict, platform: str) -> Optional[dict]:
        payload_type = "PowerShell" if platform == "windows" else "Python3"
        ioc_context  = _fmt_ioc_context(iocs, tid)

        prompt = _SNIPPET_PROMPT.format(
            technique_id   = tid,
            technique_name = stage.get("description", tid),
            tactic         = stage.get("tactic", ""),
            platform       = platform,
            stage_context  = stage.get("technical_details", stage.get("description", "")),
            ioc_context    = ioc_context,
            payload_type   = payload_type,
        )

        try:
            code = self.llm.invoke(prompt)
            code = _strip_fences(code)
            if len(code) < 20:
                return None

            code = _inject_iocs(code, iocs, tid)

            return {
                "technique_id":    tid,
                "name":            stage.get("description", tid),
                "tactic":          stage.get("tactic", ""),
                "platform":        platform,
                "code":            code,
                "detection_notes": ", ".join(stage.get("crowdstrike_detections", [])),
                "source":          "llm_generated",
                "stage_context":   stage.get("description", ""),
            }
        except Exception as e:
            print(f"[{self.name}] LLM snippet failed for {tid}: {e}")
            return None


# ── Helpers ───────────────────────────────────────────────────────

def _inject_iocs(code: str, iocs: dict, tid: str) -> str:
    """Sustituye placeholders genéricos por IOCs reales del informe."""
    c2_domains = iocs.get("domains", [])
    if c2_domains and any(t in tid for t in ["T1041", "T1071", "T1095", "T1566"]):
        code = code.replace("c2.example.com", c2_domains[0])
        code = code.replace("evil.com", c2_domains[0])
        code = code.replace("malicious.com", c2_domains[0])
    return code


def _fmt_ioc_context(iocs: dict, tid: str) -> str:
    parts = []
    if iocs.get("domains"):
        parts.append(f"Domains: {iocs['domains'][:3]}")
    if iocs.get("ipv4"):
        parts.append(f"IPs: {iocs['ipv4'][:3]}")
    if iocs.get("sha256"):
        parts.append(f"SHA256: {iocs['sha256'][:2]}")
    if iocs.get("commands"):
        parts.append(f"Commands: {iocs['commands'][:2]}")
    return " | ".join(parts) if parts else "none"


def _strip_fences(code: str) -> str:
    """Elimina markdown code fences si el LLM los incluye."""
    code = re.sub(r'^```(?:powershell|python|bash|shell)?\s*\n?', '', code, flags=re.IGNORECASE)
    code = re.sub(r'\n?```\s*$', '', code)
    return code.strip()


def _build_manifest(snippets: list) -> str:
    lines = ["PAYLOAD MANIFEST"]
    for s in snippets:
        lines.append(
            f"  [{s['technique_id']}] {s['name']} | platform: {s['platform']} "
            f"| source: {s['source']}"
        )
    return "\n".join(lines)
