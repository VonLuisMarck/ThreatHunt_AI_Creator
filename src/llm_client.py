"""
llm_client.py — Capa central de comunicación con LLM.

Todos los agentes y el analizador clásico pasan por aquí.
Un único punto para cambiar modelos, providers, parámetros y troubleshooting.

── Troubleshooting ──────────────────────────────────────────────────────────
Activa el modo debug para ver TODOS los prompts enviados y respuestas recibidas:

    LLM_DEBUG=1 python main.py ...
    LLM_DEBUG=1 streamlit run app.py

Los bloques se imprimen en stderr con separadores visuales claros.

── Cambiar provider / modelo ────────────────────────────────────────────────
Edita config.yaml → sección agents.<nombre_agente>:

    provider: anthropic | openai | ollama
    model:    claude-opus-4-6 | gpt-4o | llama3
    temperature: 0.1

── Providers soportados ─────────────────────────────────────────────────────
  anthropic → Claude API  (ANTHROPIC_API_KEY)
  openai    → OpenAI API  (OPENAI_API_KEY)
  ollama    → Local LLM   (sin clave, modelo local)
"""

import os
import sys
import yaml
from typing import List

from langchain.prompts import PromptTemplate
from langchain.chains import LLMChain


# ── Context window por provider ───────────────────────────────────────────────
# Cuántos chars enviamos por llamada (conservador para no reventar tokens)
CONTEXT_LIMITS: dict = {
    "anthropic": 16000,   # Claude tiene 200k de contexto; usamos 16k por llamada
    "openai":    12000,   # GPT-4o tiene 128k
    "ollama":     4000,   # Modelos locales: default conservador
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
        Ejecuta un LLMChain con PromptTemplate y devuelve el resultado como string.
        Sustituye el patrón:
            prompt = PromptTemplate(input_variables=[...], template=\"\"\"..\"\"\")
            chain  = LLMChain(llm=self.llm, prompt=prompt)
            result = chain.run(var1=..., var2=...)
        """
        pt = PromptTemplate(input_variables=input_variables, template=template)

        if _DEBUG:
            rendered = pt.format(**kwargs)
            _log(self.agent_name, "CHAIN PROMPT", self.provider, self.model, rendered)

        chain = LLMChain(llm=self._llm, prompt=pt)
        result = chain.run(**kwargs)

        if _DEBUG:
            _log(self.agent_name, "CHAIN RESPONSE", self.provider, self.model, result)

        return result


# ── Aliases de compatibilidad hacia atrás ────────────────────────────────────
# llm_analyzer.py y código legacy pueden seguir usando los nombres con _

_build_llm       = build_llm
_load_lab_context = load_lab_context
_CONTEXT_LIMITS  = CONTEXT_LIMITS
