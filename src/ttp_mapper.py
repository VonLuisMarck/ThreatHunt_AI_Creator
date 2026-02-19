from mitreattack.stix20 import MitreAttackData
from typing import List, Dict
import re

class TTPMapper:
    """Mapea técnicas a MITRE ATT&CK"""
    
    def __init__(self):
        # Cargar datos de MITRE ATT&CK
        self.mitre = MitreAttackData("enterprise-attack.json")
        self.techniques = self.mitre.get_techniques()
        
    def extract_techniques(self, text: str) -> List[Dict]:
        """Extrae técnicas MITRE del texto"""
        found_techniques = []
        
        # Buscar IDs explícitos (T1234)
        explicit_ids = re.findall(r'T\d{4}(?:\.\d{3})?', text)
        
        for tid in set(explicit_ids):
            technique = self._get_technique_by_id(tid)
            if technique:
                found_techniques.append(technique)
        
        # Búsqueda por keywords
        keyword_techniques = self._search_by_keywords(text)
        found_techniques.extend(keyword_techniques)
        
        # Deduplicar
        seen = set()
        unique_techniques = []
        for t in found_techniques:
            if t['id'] not in seen:
                seen.add(t['id'])
                unique_techniques.append(t)
        
        return unique_techniques
    
    def _get_technique_by_id(self, technique_id: str) -> Dict:
        """Obtiene detalles de técnica por ID"""
        for technique in self.techniques:
            if technique.id == technique_id:
                return {
                    'id': technique.id,
                    'name': technique.name,
                    'description': technique.description,
                    'tactics': [tactic.name for tactic in technique.tactics],
                    'platforms': technique.platforms if hasattr(technique, 'platforms') else []
                }
        return None
    
    def _search_by_keywords(self, text: str) -> List[Dict]:
        """Busca técnicas por keywords en el texto"""
        found = []
        
        # Keywords comunes por técnica
        keyword_map = {
            'T1566': ['phishing', 'spearphishing', 'malicious email'],
            'T1059': ['powershell', 'command line', 'cmd.exe', 'bash'],
            'T1003': ['credential dumping', 'lsass', 'sam', 'mimikatz'],
            'T1021': ['lateral movement', 'psexec', 'wmi', 'ssh'],
            'T1078': ['valid accounts', 'stolen credentials'],
            'T1486': ['ransomware', 'encryption', 'file encryption'],
            'T1562': ['disable logging', 'impair defenses'],
        }
        
        text_lower = text.lower()
        
        for tid, keywords in keyword_map.items():
            if any(kw in text_lower for kw in keywords):
                technique = self._get_technique_by_id(tid)
                if technique:
                    found.append(technique)
        
        return found
