#!/usr/bin/env python3
import yaml
import json
import sys
from pathlib import Path

from src.pdf_processor import PDFProcessor
from src.ioc_extractor import IOCExtractor
from src.ttp_mapper import TTPMapper
from src.llm_analyzer import LLMAnalyzer
from src.playbook_generator import PlaybookGenerator

def load_config():
    with open('config.yaml', 'r') as f:
        return yaml.safe_load(f)

def main(pdf_path: str):
    print("="*60)
    print("INTELLIGENCE REPORT → PLAYBOOK GENERATOR POC")
    print("="*60)
    
    config = load_config()
    
    # 1. Procesar PDF
    print("\n[1/5] Processing PDF...")
    pdf_processor = PDFProcessor()
    content = pdf_processor.extract_text(pdf_path)
    print(f"  ✓ Extracted {len(content['pages'])} pages")
    print(f"  ✓ Found {len(content['sections'])} sections")
    
    # 2. Extraer IOCs
    print("\n[2/5] Extracting IOCs...")
    ioc_extractor = IOCExtractor()
    iocs = ioc_extractor.extract_all(content['full_text'])
    total_iocs = sum(len(v) for v in iocs.values())
    print(f"  ✓ Extracted {total_iocs} IOCs")
    for ioc_type, values in iocs.items():
        if values:
            print(f"    - {ioc_type}: {len(values)}")
    
    # 3. Mapear TTPs
    print("\n[3/5] Mapping MITRE ATT&CK TTPs...")
    ttp_mapper = TTPMapper()
    ttps = ttp_mapper.extract_techniques(content['full_text'])
    print(f"  ✓ Identified {len(ttps)} techniques")
    for ttp in ttps[:5]:
        print(f"    - {ttp['id']}: {ttp['name']}")
    
    # 4. Analizar con LLM
    print("\n[4/5] Analyzing with LLM...")
    llm_analyzer = LLMAnalyzer(model_name=config['llm']['model'])
    analysis = llm_analyzer.analyze_report(content, iocs, ttps)
    print(f"  ✓ Threat Actor: {analysis.get('threat_actor', 'Unknown')}")
    print(f"  ✓ Demonstrable: {analysis.get('demonstrable', False)}")
    print(f"  ✓ Risk Level: {analysis.get('demo_risk', 'unknown')}")
    
    if not analysis.get('demonstrable', False):
        print("\n⚠️  Report not suitable for demo generation")
        print(f"Reason: {analysis.get('reasoning', 'Unknown')}")
        return
    
    # Generar secuencia de ataque
    attack_sequence = llm_analyzer.generate_attack_sequence(analysis, ttps)
    print(f"  ✓ Generated {len(attack_sequence)} attack stages")
    
    # 5. Generar Playbook
    print("\n[5/5] Generating Playbook...")
    playbook_gen = PlaybookGenerator()
    playbook = playbook_gen.generate(analysis, attack_sequence, iocs, ttps)
    
    # Guardar playbook
    output_dir = Path(config['output']['playbook_dir'])
    output_dir.mkdir(parents=True, exist_ok=True)
    
    output_file = output_dir / f"{playbook['playbook_id']}.json"
    with open(output_file, 'w') as f:
        json.dump(playbook, f, indent=2)
    
    print(f"  ✓ Playbook saved: {output_file}")
    print(f"  ✓ Playbook ID: {playbook['playbook_id']}")
    print(f"  ✓ Events: {len(playbook['events'])}")
    print(f"  ✓ Agents: {len(playbook['mandatory_agents'])}")
    
    print("\n" + "="*60)
    print("✅ PLAYBOOK GENERATION COMPLETE")
    print("="*60)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python main.py <path_to_pdf_report>")
        sys.exit(1)
    
    pdf_path = sys.argv[1]
    if not Path(pdf_path).exists():
        print(f"Error: File not found: {pdf_path}")
        sys.exit(1)
    
    main(pdf_path)
