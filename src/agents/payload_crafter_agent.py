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

from src.llm_client import LLMClient, load_lab_context, load_prompt
from src.emulation_library import get_emulation_snippet, get_all_covered_techniques
from src.replay_generator import ReplayGenerator, classify_stage
from src.agents.state import AgentState, new_message




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
        model       = agent_cfg.get("model", "claude-sonnet-4-6")
        temperature = agent_cfg.get("temperature", 0.1)
        self.llm              = LLMClient(provider, model, temperature, agent_name=self.name)
        self.lab_context      = load_lab_context(config_path)
        self._library_tids    = set(get_all_covered_techniques())
        self._replay_gen      = ReplayGenerator()

    # ── LangGraph node ────────────────────────────────────────────

    def run(self, state: AgentState) -> dict:
        print(f"\n[{self.name}] Crafting emulation payloads...")

        platform        = state.get("platform", "windows")
        attack_sequence = state.get("attack_sequence", [])
        iocs            = state.get("iocs", {})
        generation_mode = state.get("generation_mode", "simulation")
        snippets        = []

        print(f"[{self.name}] Mode: {generation_mode}")

        # Generate replay scripts for 3P stages (email, cloud, SaaS)
        replay_scripts = self._replay_gen.generate_all(attack_sequence, iocs)
        if replay_scripts:
            print(f"[{self.name}] {len(replay_scripts)} replay scripts for 3P stages")

        # Generate code snippets for native stages (limit to MAX_SNIPPETS)
        native_stages = [s for s in attack_sequence if classify_stage(s) == "native"]
        for stage in native_stages[:self.MAX_SNIPPETS]:
            tid     = stage.get("technique_id", "")
            snippet = self._craft_snippet(tid, stage, iocs, platform, generation_mode)
            if snippet:
                snippets.append(snippet)

        print(f"[{self.name}] {len(snippets)} native snippets "
              f"(library: {sum(1 for s in snippets if s['source'] == 'static_library')}, "
              f"llm: {sum(1 for s in snippets if s['source'] == 'llm_generated')})")

        manifest = _build_manifest(snippets, replay_scripts)

        return {
            "snippets":      snippets,
            "replay_scripts": replay_scripts,
            "messages": list(state["messages"]) + [new_message(self.name, manifest)],
        }

    # ── Snippet generation ─────────────────────────────────────────

    def _craft_snippet(
        self, tid: str, stage: dict, iocs: dict,
        platform: str, generation_mode: str = "simulation",
    ) -> Optional[dict]:
        """
        Intenta librería estática primero (solo en simulation mode),
        luego generación LLM con el prompt adecuado al modo.
        """
        # 1. Librería estática (pre-validada) — solo en simulation mode
        if generation_mode == "simulation" and tid in self._library_tids:
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
                    "code_type":       "simulation",
                }

        # 2. Generación LLM (simulation o real_code)
        return self._llm_snippet(tid, stage, iocs, platform, generation_mode)

    def _llm_snippet(
        self, tid: str, stage: dict, iocs: dict,
        platform: str, generation_mode: str = "simulation",
    ) -> Optional[dict]:
        ioc_context = _fmt_ioc_context(iocs, tid)

        if generation_mode == "real_code":
            prompt_name = "real_code_windows" if platform == "windows" else "real_code_linux"
        else:
            prompt_name = "payload_snippet"

        fmt_kwargs = dict(
            technique_id   = tid,
            technique_name = stage.get("description", tid),
            tactic         = stage.get("tactic", ""),
            platform       = platform,
            stage_context  = stage.get("technical_details", stage.get("description", "")),
            ioc_context    = ioc_context,
        )
        # payload_snippet also needs payload_type
        if prompt_name == "payload_snippet":
            fmt_kwargs["payload_type"] = "PowerShell" if platform == "windows" else "Python3"

        prompt = load_prompt(prompt_name).format(**fmt_kwargs)

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
                "code_type":       generation_mode,
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


def _build_manifest(snippets: list, replay_scripts: list = None) -> str:
    lines = ["PAYLOAD MANIFEST"]
    for s in snippets:
        code_type = s.get("code_type", "simulation")
        marker = "⚡" if code_type == "real_code" else "🛡️"
        lines.append(
            f"  {marker} [{s['technique_id']}] {s['name']} | platform: {s['platform']} "
            f"| source: {s['source']} | mode: {code_type}"
        )
    if replay_scripts:
        lines.append(f"\nREPLAY SCRIPTS ({len(replay_scripts)} 3P stages):")
        for r in replay_scripts:
            lines.append(f"  📧 [{r['technique_id']}] {r['description'][:60]} → {r['filename']}")
    return "\n".join(lines)
