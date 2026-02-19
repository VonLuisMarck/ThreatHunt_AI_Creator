from typing import Dict, List
import json
from datetime import datetime

class PlaybookGenerator:
    """Genera playbook en formato JSON objetivo"""
    
    def __init__(self):
        self.payload_templates = self._load_payload_templates()
    
    def generate(self, analysis: Dict, attack_sequence: List[Dict], 
                 iocs: Dict, ttps: List[Dict]) -> Dict:
        """Genera playbook completo"""
        
        playbook_id = self._generate_id(analysis.get('campaign_name', 'unknown'))
        
        # Determinar agentes necesarios
        agents = self._determine_agents(attack_sequence)
        
        # Generar eventos
        events = self._generate_events(attack_sequence, agents, iocs)
        
        playbook = {
            "playbook_id": playbook_id,
            "name": analysis.get('campaign_name', 'Unknown Campaign'),
            "description": analysis.get('reasoning', ''),
            "generated_at": datetime.now().isoformat(),
            "source_report": analysis.get('threat_actor', 'Unknown'),
            "mandatory_agents": agents,
            "events": events,
            "metadata": {
                "ttps": [t['id'] for t in ttps],
                "platforms": analysis.get('platforms', []),
                "risk_level": analysis.get('demo_risk', 'medium')
            }
        }
        
        return playbook
    
    def _generate_id(self, campaign_name: str) -> str:
        """Genera ID único para playbook"""
        clean_name = campaign_name.lower().replace(' ', '_').replace('-', '_')
        timestamp = datetime.now().strftime('%Y%m%d')
        return f"{clean_name}_{timestamp}"
    
    def _determine_agents(self, attack_sequence: List[Dict]) -> List[Dict]:
        """Determina agentes necesarios basado en plataformas"""
        platforms = set()
        for stage in attack_sequence:
            platforms.add(stage.get('platform', 'windows'))
        
        agents = []
        agent_id = 1
        
        platform_descriptions = {
            'windows': 'Windows workstation (initial access and credential theft)',
            'linux': 'Linux server (lateral movement target)',
            'cloud': 'Cloud environment (AWS/Azure operations)'
        }
        
        for platform in sorted(platforms):
            agents.append({
                "agent_id": f"agent_{agent_id}",
                "agent_type": platform,
                "description": platform_descriptions.get(platform, f"{platform} system")
            })
            agent_id += 1
        
        return agents
    
    def _generate_events(self, attack_sequence: List[Dict], 
                        agents: List[Dict], iocs: Dict) -> List[Dict]:
        """Genera eventos del playbook"""
        events = []
        
        for idx, stage in enumerate(attack_sequence):
            # Encontrar agente apropiado
            agent = next((a for a in agents if a['agent_type'] == stage.get('platform', 'windows')), agents[0])
            
            # Generar payload basado en técnica
            payload = self._generate_payload(stage, iocs)
            
            # Determinar siguiente evento
            next_trigger = attack_sequence[idx + 1]['stage'] if idx < len(attack_sequence) - 1 else None
            
            event = {
                "event_id": stage['stage'],
                "name": stage['description'],
                "agent_id": agent['agent_id'],
                "required_agent_type": agent['agent_type'],
                "payload_type": "powershell" if agent['agent_type'] == 'windows' else "python",
                "payload": payload,
                "mitre_technique": stage.get('technique_id', ''),
                "success_trigger": next_trigger,
                "failure_action": "abort" if idx < 2 else "continue"
            }
            
            events.append(event)
        
        # Agregar cleanup events
        events.extend(self._generate_cleanup_events(agents))
        
        return events
    
    def _generate_payload(self, stage: Dict, iocs: Dict) -> str:
        """Genera payload para el stage"""
        
        # Templates básicos por tipo de técnica
        technique_id = stage.get('technique_id', '')
        
        if 'T1566' in technique_id:  # Phishing
            return "Write-Host '[SIMULATION] Phishing email opened - downloading payload...'"
        
        elif 'T1059' in technique_id:  # Command execution
            if iocs.get('commands'):
                return f"# Simulated command execution\n{iocs['commands'][0]}"
            return "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command 'Write-Host \"Command executed\"'"
        
        elif 'T1003' in technique_id:  # Credential dumping
            return "Write-Host '[SIMULATION] Accessing credential store...'; Start-Sleep -Seconds 2"
        
        elif 'T1021' in technique_id:  # Lateral movement
            return "Write-Host '[SIMULATION] Establishing connection to remote system...'"
        
        else:
            return f"Write-Host '[SIMULATION] Executing {stage['description']}'"
    
    def _generate_cleanup_events(self, agents: List[Dict]) -> List[Dict]:
        """Genera eventos de limpieza"""
        cleanup_events = []
        
        for agent in reversed(agents):
            if agent['agent_type'] == 'windows':
                payload = "Write-Host '[CLEANUP] Terminating agent...'; Stop-Process -Id $PID -Force"
            else:
                payload = "import os\nprint('[CLEANUP] Terminating agent...')\nos._exit(0)"
            
            cleanup_events.append({
                "event_id": f"cleanup_{agent['agent_id']}",
                "name": f"Cleanup - Terminate {agent['agent_type'].title()} Agent",
                "agent_id": agent['agent_id'],
                "required_agent_type": agent['agent_type'],
                "payload_type": "powershell" if agent['agent_type'] == 'windows' else "python",
                "payload": payload,
                "success_trigger": None,
                "failure_action": "continue"
            })
        
        return cleanup_events
    
    def _load_payload_templates(self) -> Dict:
        """Carga templates de payloads"""
        # Esto se puede expandir con templates más sofisticados
        return {}
