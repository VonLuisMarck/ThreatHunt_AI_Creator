"""
llm_client.py — Capa central de comunicación con LLM.

Todos los agentes y el analizador clásico pasan por aquí.
Un único punto para cambiar modelos, providers, parámetros y troubleshooting.

── Troubleshooting ──────────────────────────────────────────────────────────
Activa el modo debug para ver TODOS los prompts enviados y respuestas recibidas:

    LLM_DEBUG=1 python main.py ...
    LLM_DEBUG=1 streamlit run app.py

Los bloques se imprimen en stderr con separadores visuales claros.

── Editar prompts ───────────────────────────────────────────────────────────
Todos los prompts están en prompts/*.txt — edítalos sin tocar código Python.
Los cambios se aplican en el próximo uso (no hace falta reiniciar).

    prompts/recon_briefing.txt
    prompts/threat_intel_analysis.txt
    prompts/attack_planner.txt
    prompts/attack_planner_feedback.txt
    prompts/payload_snippet.txt
    prompts/playbook_summary.txt
    prompts/validator_semantic.txt
    prompts/analyzer_attack_sequence.txt
    prompts/analyzer_playbook_summary.txt
    prompts/analyzer_chunk_summary.txt
    prompts/analyzer_analysis.txt
    prompts/analyzer_emulation_snippet.txt

── Cambiar provider / modelo ────────────────────────────────────────────────
Edita config.yaml → sección agents.<nombre_agente>:

    provider: anthropic | openai | ollama
    model:    claude-opus-4-6 | gpt-4o | llama3
    temperature: 0.1

── Providers soportados ─────────────────────────────────────────────────────
  anthropic → Claude API      (ANTHROPIC_API_KEY)
  openai    → OpenAI API      (OPENAI_API_KEY)
  ollama    → Ollama local    (sin clave, modelo local)
  lmstudio  → LM Studio local (sin clave, API en localhost:1234)
             Modelos recomendados: llama-3.3-70b-instruct, mistral-large-instruct,
             phi-4, gemma-2-27b-it, mixtral-8x7b-instruct
             → Descarga LM Studio: https://lmstudio.ai
             → Activa "Local Server" en la pestaña Developer
  vllm      → vLLM server     (sin clave, API en VLLM_BASE_URL o localhost:8000)
             Modelos recomendados: meta-llama/Llama-3.3-70B-Instruct,
             mistralai/Mixtral-8x7B-Instruct-v0.1, microsoft/phi-4
             → pip install vllm
             → vllm serve meta-llama/Llama-3.3-70B-Instruct --port 8000
"""

import os
import sys
import yaml
from typing import List

# Directorio raíz del proyecto (un nivel arriba de src/)
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PROMPTS_DIR  = os.path.join(_PROJECT_ROOT, "prompts")

from langchain.prompts import PromptTemplate


# ── Context window por provider ───────────────────────────────────────────────
# Cuántos chars enviamos por llamada (conservador para no reventar tokens)
CONTEXT_LIMITS: dict = {
    "anthropic": 16000,   # Claude tiene 200k de contexto; usamos 16k por llamada
    "openai":    12000,   # GPT-4o tiene 128k
    "ollama":     4000,   # Modelos locales: default conservador
    "lmstudio":  12000,   # LM Studio: depende del modelo cargado (70B suele tener 128k)
    "vllm":      12000,   # vLLM: depende del modelo desplegado
}

# ── URLs por defecto para providers locales ───────────────────────────────────
_LOCAL_BASE_URLS: dict = {
    "lmstudio": "http://localhost:1234/v1",
    "vllm":     os.environ.get("VLLM_BASE_URL", "http://localhost:8000/v1"),
}

# ── Debug flag ────────────────────────────────────────────────────────────────
_DEBUG: bool = os.environ.get("LLM_DEBUG", "").strip() not in ("", "0", "false", "False")


# ── Factory de LLM ────────────────────────────────────────────────────────────

def build_llm(provider: str, model_name: str, temperature: float = 0.1):
    """
    Instancia el LLM correcto según el proveedor.
    Las API keys se leen de variables de entorno.
    """
    if provider == "anthropic":
        from langchain_anthropic import ChatAnthropic
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            raise ValueError(
                "ANTHROPIC_API_KEY not set. Export it: export ANTHROPIC_API_KEY=sk-ant-..."
            )
        return ChatAnthropic(
            model=model_name,
            temperature=temperature,
            anthropic_api_key=api_key,
            max_tokens=4096,
        )

    if provider == "openai":
        from langchain_openai import ChatOpenAI
        api_key = os.environ.get("OPENAI_API_KEY", "")
        if not api_key:
            raise ValueError(
                "OPENAI_API_KEY not set. Export it: export OPENAI_API_KEY=sk-..."
            )
        return ChatOpenAI(
            model=model_name,
            temperature=temperature,
            openai_api_key=api_key,
        )

    if provider in ("lmstudio", "vllm"):
        from langchain_openai import ChatOpenAI
        base_url = _LOCAL_BASE_URLS[provider]
        print(f"  [LLMClient] {provider.upper()} → {base_url}  model={model_name}")
        return ChatOpenAI(
            model=model_name,
            temperature=temperature,
            openai_api_key="lm-studio",   # valor requerido por la lib, no se envía
            openai_api_base=base_url,
        )

    # Default: Ollama local
    from langchain_community.llms import Ollama
    return Ollama(model=model_name, temperature=temperature)


# ── Lab context loader ────────────────────────────────────────────────────────

def load_lab_context(config_path: str = "config.yaml") -> str:
    """
    Lee el system prompt de arquitectura del lab desde config.yaml.
    Falla silenciosamente si el archivo no existe.
    """
    try:
        with open(config_path, "r") as f:
            cfg = yaml.safe_load(f)
        prompt_path = cfg.get("lab", {}).get("lab_context_prompt", "")
        if not prompt_path:
            return ""
        base_dir = os.path.dirname(os.path.abspath(config_path))
        full_path = os.path.join(base_dir, prompt_path)
        with open(full_path, "r") as f:
            return f.read().strip()
    except Exception:
        return ""


# ── Debug logger ──────────────────────────────────────────────────────────────

def _log(agent: str, direction: str, provider: str, model: str, text: str) -> None:
    sep = "═" * 70
    header = f"[LLM_DEBUG] {agent}  ▶  {direction}  ({provider}/{model})"
    print(f"\n{sep}\n{header}\n{sep}\n{text}\n{sep}", file=sys.stderr, flush=True)


# ── LLMClient ─────────────────────────────────────────────────────────────────

class LLMClient:
    """
    Wrapper central para todas las llamadas LLM del proyecto.

    Proporciona dos métodos de llamada que cubren todos los patrones existentes:
      • invoke(prompt)                              → str
      • chain_run(template, input_variables, **kw)  → str

    Activa el modo debug con la variable de entorno LLM_DEBUG=1.
    """

    def __init__(
        self,
        provider: str,
        model: str,
        temperature: float = 0.1,
        agent_name: str = "",
    ):
        self.provider      = provider
        self.model         = model
        self.temperature   = temperature
        self.agent_name    = agent_name or "LLMClient"
        self.context_limit = CONTEXT_LIMITS.get(provider, 4000)
        self._llm          = build_llm(provider, model, temperature)

    # ── Llamada directa ───────────────────────────────────────────────────────

    def invoke(self, prompt: str) -> str:
        """
        Envía un prompt completo al LLM y devuelve la respuesta como string.
        Sustituye el patrón:
            response = self.llm.invoke(prompt)
            content  = response.content if hasattr(response, "content") else str(response)
        """
        if _DEBUG:
            _log(self.agent_name, "PROMPT", self.provider, self.model, prompt)

        response = self._llm.invoke(prompt)
        content = response.content if hasattr(response, "content") else str(response)

        if _DEBUG:
            _log(self.agent_name, "RESPONSE", self.provider, self.model, content)

        return content

    # ── Llamada con PromptTemplate ────────────────────────────────────────────

    def chain_run(self, template: str, input_variables: List[str], **kwargs) -> str:
        """
        Ejecuta prompt | llm (LCEL) con PromptTemplate y devuelve el resultado como string.
        Compatible con Anthropic, OpenAI y Ollama via LangChain.
        """
        pt = PromptTemplate(input_variables=input_variables, template=template)

        if _DEBUG:
            rendered = pt.format(**kwargs)
            _log(self.agent_name, "CHAIN PROMPT", self.provider, self.model, rendered)

        chain    = pt | self._llm
        response = chain.invoke(kwargs)
        result   = response.content if hasattr(response, "content") else str(response)

        if _DEBUG:
            _log(self.agent_name, "CHAIN RESPONSE", self.provider, self.model, result)

        return result


# ── Cargador de prompts ───────────────────────────────────────────────────────

def load_prompt(name: str) -> str:
    """
    Carga el prompt desde prompts/<name>.txt.

    No usa caché: cada llamada lee el fichero desde disco.
    Así basta con editar el .txt y el próximo LLM call usará la versión nueva,
    sin reiniciar la app.

    Sintaxis dentro del .txt:
      {variable}   → placeholder sustituido por str.format() o PromptTemplate
      {{           → llave literal { en el texto enviado al LLM (ej. JSON de ejemplo)
      }}           → llave literal }
    """
    path = os.path.join(_PROMPTS_DIR, f"{name}.txt")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        raise FileNotFoundError(
            f"Prompt '{name}' no encontrado en: {path}\n"
            f"Comprueba que existe el fichero prompts/{name}.txt"
        )


# ── Aliases de compatibilidad hacia atrás ────────────────────────────────────
# llm_analyzer.py y código legacy pueden seguir usando los nombres con _

_build_llm        = build_llm
_load_lab_context = load_lab_context
_CONTEXT_LIMITS   = CONTEXT_LIMITS
