from langchain_community.llms import Ollama
from langchain.prompts import PromptTemplate
from langchain.chains import LLMChain
from typing import Dict, List
import json

class LLMAnalyzer:
    """Analiza reportes usando LLM local"""
    
    def __init__(self, model_name: str = "llama3"):
        self.llm = Ollama(
            model=model_name,
            temperature=0.1
        )
        
    def analyze_report(self, content: Dict, iocs: Dict, ttps: List[Dict]) -> Dict:
        """Análisis completo del reporte"""
        
        # Prompt para análisis
        analysis_prompt = PromptTemplate(
            input_variables=["text", "iocs", "ttps"],
            template="""You are a cybersecurity analyst reviewing a threat intelligence report.

REPORT TEXT:
{text}

EXTRACTED IOCs:
{iocs}

EXTRACTED TTPs:
{ttps}

Analyze this report and provide:
1. Threat actor name/group (if mentioned)
2. Attack campaign name
3. Primary attack vector
4. Target platforms (windows/linux/cloud)
5. Key attack stages in order
6. Whether this attack is DEMONSTRABLE in a lab environment (yes/no)
7. Risk level if demonstrated (low/medium/high)

Respond in JSON format:
{{
  "threat_actor": "...",
  "campaign_name": "...",
  "attack_vector": "...",
  "platforms": ["windows", "linux"],
  "attack_stages": ["initial_access", "credential_theft", "lateral_movement"],
  "demonstrable": true/false,
  "demo_risk": "low/medium/high",
  "reasoning": "..."
}}
"""
        )
        
        chain = LLMChain(llm=self.llm, prompt=analysis_prompt)
        
        result = chain.run(
            text=content['full_text'][:4000],  # Limitar tokens
            iocs=json.dumps(iocs, indent=2),
            ttps=json.dumps(ttps, indent=2)
        )
        
        try:
            return json.loads(result)
        except:
            # Fallback si el LLM no devuelve JSON válido
            return {
                "threat_actor": "Unknown",
                "demonstrable": False,
                "reasoning": "Failed to parse LLM response"
            }
    
    def generate_attack_sequence(self, analysis: Dict, ttps: List[Dict]) -> List[Dict]:
        """Genera secuencia de ataque basada en TTPs"""
        
        sequence_prompt = PromptTemplate(
            input_variables=["analysis", "ttps"],
            template="""Based on this threat analysis, create a logical attack sequence.

ANALYSIS:
{analysis}

AVAILABLE TTPs:
{ttps}

Create an attack chain with these stages. For each stage provide:
- Stage name
- MITRE technique ID
- Required platform (windows/linux/cloud)
- Brief description of what happens

Respond in JSON array format:
[
  {{
    "stage": "initial_access",
    "technique_id": "T1566.001",
    "platform": "windows",
    "description": "..."
  }}
]
"""
        )
        
        chain = LLMChain(llm=self.llm, prompt=sequence_prompt)
        
        result = chain.run(
            analysis=json.dumps(analysis, indent=2),
            ttps=json.dumps(ttps, indent=2)
        )
        
        try:
            return json.loads(result)
        except:
            return []
