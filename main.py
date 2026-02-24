#!/usr/bin/env python3
"""
ThreatHunt AI Creator - Advanced Threat Report Analyzer
Converts threat intelligence PDFs into executable attack simulation playbooks.

Usage:
  python main.py <pdf>           Classic single-LLM pipeline
  python main.py <pdf> --graph   Multi-agent LangGraph pipeline (specialized models)
"""
import yaml
import json
import sys
from pathlib import Path
from datetime import datetime

from src.pdf_processor import PDFProcessor
from src.ioc_extractor import IOCExtractor
from src.ttp_mapper import TTPMapper
from src.llm_analyzer import LLMAnalyzer
from src.playbook_generator import PlaybookGenerator


# ─────────────────────────────────────────────────────────────────
#  Output helpers
# ─────────────────────────────────────────────────────────────────

def banner(title: str, char: str = "=", width: int = 65):
    print(f"\n{char * width}")
    print(f"  {title}")
    print(f"{char * width}")


def section(title: str, width: int = 65):
    print(f"\n{'─' * width}")
    print(f"  {title}")
    print(f"{'─' * width}")


def bullet(label: str, value, indent: int = 2):
    pad = " " * indent
    if isinstance(value, list):
        if not value:
            return
        print(f"{pad}• {label}: {', '.join(str(v) for v in value[:8])}"
              + (" ..." if len(value) > 8 else ""))
    elif value:
        print(f"{pad}• {label}: {value}")


def load_config():
    try:
        with open("config.yaml", "r") as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        return {"llm": {"model": "llama3"}, "output": {"playbook_dir": "playbooks"}}


# ─────────────────────────────────────────────────────────────────
#  Display functions
# ─────────────────────────────────────────────────────────────────

def display_pdf_analysis(content: dict):
    """Muestra el análisis estructural del PDF."""
    section("PDF STRUCTURAL ANALYSIS")
    meta = content.get("metadata", {})
    bullet("Pages", meta.get("page_count"))
    bullet("Word count", f"{meta.get('word_count', 0):,}")
    bullet("Char count", f"{meta.get('char_count', 0):,}")
    bullet("Has tables", meta.get("has_tables"))
    bullet("Headings detected", meta.get("heading_count", 0))
    bullet("Sections detected", meta.get("section_count", 0))

    if content.get("sections"):
        print(f"\n  Sections found:")
        for sec_name in content["sections"]:
            print(f"    ✓ {sec_name.replace('_', ' ').title()}")

    if content.get("headings"):
        print(f"\n  Document headings (first 10):")
        for h in content["headings"][:10]:
            bold_marker = " [BOLD]" if h.get("is_bold") else ""
            print(f"    [{h['page']}] {h['text'][:70]}{bold_marker}")

    # Key findings
    kf = content.get("key_findings", {})
    if any(kf.values()):
        print("\n  Key entities found in report:")
        bullet("Countries", kf.get("mentioned_countries"))
        bullet("Sectors", kf.get("mentioned_sectors"))
        bullet("Tools", kf.get("mentioned_tools"))
        bullet("Malware types", kf.get("mentioned_malware_types"))
        bullet("Threat actors", kf.get("mentioned_threat_actors"))
        bullet("CVEs", kf.get("cves"))
        bullet("Explicit MITRE IDs", kf.get("mitre_ids_explicit"))


def display_iocs(iocs: dict):
    """Muestra los IOCs extraídos."""
    section("IOC EXTRACTION")
    total = sum(len(v) for v in iocs.values())
    print(f"\n  Total IOCs extracted: {total}")
    print()

    ioc_display_order = [
        ("ipv4", "IPv4 Addresses"),
        ("ipv6", "IPv6 Addresses"),
        ("domains", "Domains"),
        ("urls", "URLs"),
        ("emails", "Email Addresses"),
        ("sha256", "SHA256 Hashes"),
        ("sha1", "SHA1 Hashes"),
        ("md5", "MD5 Hashes"),
        ("cves", "CVEs"),
        ("registry_keys", "Registry Keys"),
        ("file_paths", "File Paths"),
        ("named_pipes", "Named Pipes"),
        ("mutex_names", "Mutex Names"),
        ("commands", "Commands/Cmdlets"),
        ("service_names", "Service Names"),
        ("user_agents", "User Agents"),
    ]

    for key, label in ioc_display_order:
        values = iocs.get(key, [])
        if values:
            print(f"  [{label}] ({len(values)} found)")
            for v in values[:3]:
                print(f"    ↳ {str(v)[:90]}")
            if len(values) > 3:
                print(f"    ... and {len(values) - 3} more")
            print()


def display_ttps(ttps: list):
    """Muestra los TTPs identificados."""
    section("MITRE ATT&CK TTP MAPPING")
    print(f"\n  Total techniques identified: {len(ttps)}")

    # Group by tactic
    by_tactic: dict = {}
    for t in ttps:
        for tactic in (t.get("tactics") or ["Unknown"]):
            if tactic not in by_tactic:
                by_tactic[tactic] = []
            by_tactic[tactic].append(t)

    tactic_order = [
        "Initial Access", "Execution", "Persistence",
        "Privilege Escalation", "Defense Evasion", "Credential Access",
        "Discovery", "Lateral Movement", "Collection",
        "Command And Control", "Exfiltration", "Impact", "Unknown",
    ]

    for tactic in tactic_order:
        techniques = by_tactic.get(tactic, [])
        if not techniques:
            continue
        print(f"\n  [{tactic}]")
        for t in techniques:
            tool_note = ""
            if t.get("triggered_by_tool"):
                tool_note = f" ← {t['triggered_by_tool']}"
            print(f"    • {t['id']}: {t['name']}{tool_note}")


def display_analysis(analysis: dict):
    """Muestra el análisis LLM del reporte."""
    section("THREAT INTELLIGENCE ANALYSIS (LLM)")

    print(f"\n  Threat Actor:     {analysis.get('threat_actor', 'Unknown')}")
    print(f"  Actor Type:       {analysis.get('threat_actor_type', 'Unknown')}")
    print(f"  Campaign:         {analysis.get('campaign_name', 'Unknown')}")
    print(f"  Attack Vector:    {analysis.get('attack_vector', 'Unknown')}")
    print(f"  Confidence:       {analysis.get('confidence_level', 'N/A')}")
    print(f"  Attribution:      {analysis.get('attribution_confidence', 'N/A')}")

    bullet("Platforms", analysis.get("platforms"))
    bullet("Target Industries", analysis.get("target_industries"))
    bullet("Target Geography", analysis.get("target_geography"))
    bullet("CrowdStrike Products", analysis.get("crowdstrike_products"))

    print(f"\n  Demonstrable:     {'✅ YES' if analysis.get('demonstrable') else '❌ NO'}")
    print(f"  Demo Risk:        {analysis.get('demo_risk', 'N/A').upper()}")
    print(f"  Complexity:       {analysis.get('demo_complexity', 'N/A')}")
    print(f"  Setup Time:       {analysis.get('setup_time', 'N/A')}")
    print(f"  Expertise Needed: {analysis.get('required_expertise', 'N/A')}")

    if analysis.get("attack_stages"):
        print("\n  Attack Stages:")
        for stage in analysis["attack_stages"]:
            tools_note = ""
            if stage.get("key_tools"):
                tools_note = f" [Tools: {', '.join(stage['key_tools'])}]"
            print(f"    {stage.get('stage_name', '?')}: {stage.get('description', '')[:60]}{tools_note}")

    if analysis.get("key_detection_points"):
        print("\n  CrowdStrike Detection Points:")
        for dp in analysis["key_detection_points"][:5]:
            print(f"    ◉ {str(dp)[:80]}")

    if analysis.get("reasoning"):
        print(f"\n  Assessment Reasoning:")
        print(f"    {analysis['reasoning'][:200]}")


def display_emulation_snippets(snippets: list):
    """Muestra los snippets de emulación generados."""
    section("EMULATION CODE SUGGESTIONS")
    print(f"\n  Generated {len(snippets)} emulation snippets")
    print("  All code is safe simulation - no real malicious actions\n")

    for i, snippet in enumerate(snippets, 1):
        src = snippet.get("source", "unknown")
        src_badge = "[LIBRARY]" if src == "static_library" else "[LLM-GEN]"
        print(f"  ┌─ Snippet {i}/{len(snippets)}: {snippet['technique_id']} - {snippet['name']} {src_badge}")
        print(f"  │  Tactic:   {snippet.get('tactic', 'N/A')}")
        print(f"  │  Platform: {snippet.get('platform', 'N/A')}")

        if snippet.get("stage_context"):
            print(f"  │  Context:  {snippet['stage_context'][:80]}")

        if snippet.get("detection_notes"):
            notes = snippet["detection_notes"]
            notes_str = notes if isinstance(notes, str) else "; ".join(str(n) for n in notes[:2])
            print(f"  │  Detects:  {notes_str[:100]}")

        print(f"  │")
        print(f"  │  Code:")
        code_lines = snippet.get("code", "").split("\n")
        for line in code_lines[:20]:  # Show first 20 lines
            print(f"  │    {line}")
        if len(code_lines) > 20:
            print(f"  │    ... ({len(code_lines) - 20} more lines)")
        print(f"  └{'─' * 60}")
        print()


def display_playbook_summary(summary: str):
    """Muestra el resumen narrativo del playbook."""
    section("PLAYBOOK NARRATIVE SUMMARY")
    print()
    for line in summary.split("\n"):
        print(f"  {line}")


def display_playbook_stats(playbook: dict):
    """Muestra estadísticas del playbook generado."""
    section("PLAYBOOK GENERATION COMPLETE")
    print(f"\n  Playbook ID:  {playbook.get('playbook_id', 'N/A')}")
    print(f"  Name:         {playbook.get('name', 'N/A')}")
    print(f"  Generated:    {playbook.get('generated_at', 'N/A')}")

    agents = playbook.get("mandatory_agents", [])
    events = playbook.get("events", [])
    meta = playbook.get("metadata", {})

    print(f"\n  Agents required: {len(agents)}")
    for agent in agents:
        print(f"    → {agent['agent_id']} ({agent['agent_type']}): {agent.get('description', '')[:60]}")

    print(f"\n  Events total: {len(events)}")
    attack_events = [e for e in events if "cleanup" not in e.get("event_id", "")]
    cleanup_events = [e for e in events if "cleanup" in e.get("event_id", "")]
    print(f"    Attack events:  {len(attack_events)}")
    print(f"    Cleanup events: {len(cleanup_events)}")

    print(f"\n  TTPs covered: {', '.join(meta.get('ttps', []))}")
    print(f"  Risk level:   {meta.get('risk_level', 'N/A').upper()}")
    print(f"  Platforms:    {', '.join(meta.get('platforms', []))}")


# ─────────────────────────────────────────────────────────────────
#  Main pipeline
# ─────────────────────────────────────────────────────────────────

def main(pdf_path: str):
    start_time = datetime.now()

    banner("THREATHUNT AI CREATOR - ADVANCED THREAT REPORT ANALYZER")
    print(f"  Report: {pdf_path}")
    print(f"  Start:  {start_time.strftime('%Y-%m-%d %H:%M:%S')}")

    config = load_config()
    llm_model = config.get("llm", {}).get("model", "llama3")
    output_dir = Path(config.get("output", {}).get("playbook_dir", "playbooks"))
    platform = config.get("demo", {}).get("platform", "windows")

    # ── Step 1: PDF Processing ──────────────────────────────────
    banner("STEP 1/6 · DEEP PDF ANALYSIS", char="─", width=50)
    pdf_processor = PDFProcessor()
    content = pdf_processor.extract_text(pdf_path)
    display_pdf_analysis(content)
    print(f"\n  ✓ PDF analysis complete")

    # ── Step 2: IOC Extraction ──────────────────────────────────
    banner("STEP 2/6 · IOC EXTRACTION", char="─", width=50)
    ioc_extractor = IOCExtractor()
    iocs = ioc_extractor.extract_all(content["full_text"])
    display_iocs(iocs)
    total_iocs = sum(len(v) for v in iocs.values())
    print(f"  ✓ {total_iocs} IOCs extracted ({len(iocs)} types)")

    # ── Step 3: TTP Mapping ────────────────────────────────────
    banner("STEP 3/6 · MITRE ATT&CK MAPPING", char="─", width=50)
    ttp_mapper = TTPMapper()
    ttps = ttp_mapper.extract_techniques(content["full_text"])
    display_ttps(ttps)
    print(f"\n  ✓ {len(ttps)} techniques identified")

    # ── Step 4: LLM Analysis (full document) ──────────────────
    banner("STEP 4/6 · LLM DEEP ANALYSIS", char="─", width=50)
    print("  Analyzing full document (chunked processing)...")
    llm_analyzer = LLMAnalyzer(model_name=llm_model)
    analysis = llm_analyzer.analyze_report(content, iocs, ttps)
    display_analysis(analysis)

    if not analysis.get("demonstrable", False):
        print("\n⚠️  Report assessed as NOT suitable for demo generation.")
        print(f"   Reason: {analysis.get('reasoning', 'Unknown')}")
        print("\n   Tip: Review the reasoning above and consider modifying the")
        print("   attack stages to make them demonstrable.")
        return

    print(f"\n  ✓ Analysis complete - threat is demonstrable")

    # Generate attack sequence
    print("\n  Generating attack sequence...")
    attack_sequence = llm_analyzer.generate_attack_sequence(analysis, ttps)
    print(f"  ✓ {len(attack_sequence)} attack stages generated")

    # ── Step 5: Emulation Snippets ─────────────────────────────
    banner("STEP 5/6 · EMULATION CODE GENERATION", char="─", width=50)
    print(f"  Generating safe emulation code for identified techniques...")
    snippets = llm_analyzer.suggest_emulation_snippets(
        ttps, iocs, attack_sequence, platform=platform
    )
    display_emulation_snippets(snippets)
    print(f"  ✓ {len(snippets)} emulation snippets generated")

    # ── Step 6: Playbook Generation ────────────────────────────
    banner("STEP 6/6 · PLAYBOOK GENERATION", char="─", width=50)
    playbook_gen = PlaybookGenerator()
    playbook = playbook_gen.generate(analysis, attack_sequence, iocs, ttps)

    # Generate narrative summary
    print("  Generating playbook narrative summary...")
    summary = llm_analyzer.generate_playbook_summary(playbook, analysis)
    display_playbook_summary(summary)

    # Attach emulation snippets to playbook metadata
    playbook["emulation_snippets"] = snippets
    playbook["narrative_summary"] = summary

    # Save playbook
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / f"{playbook['playbook_id']}.json"
    with open(output_file, "w") as f:
        json.dump(playbook, f, indent=2)

    display_playbook_stats(playbook)

    # Save emulation snippets as separate file for easy access
    snippets_file = output_dir / f"{playbook['playbook_id']}_emulation_snippets.json"
    with open(snippets_file, "w") as f:
        json.dump(snippets, f, indent=2)

    elapsed = (datetime.now() - start_time).seconds
    banner("✅  ANALYSIS & PLAYBOOK GENERATION COMPLETE")
    print(f"  Playbook saved:   {output_file}")
    print(f"  Snippets saved:   {snippets_file}")
    print(f"  Total time:       {elapsed}s")
    print(f"  Techniques found: {len(ttps)}")
    print(f"  Snippets ready:   {len(snippets)}")
    print(f"  Playbook events:  {len(playbook.get('events', []))}")
    print()


def main_graph(pdf_path: str):
    """Pipeline multi-agente LangGraph (modelos especializados por tarea)."""
    from src.graph import run_pipeline

    config  = load_config()
    platform = config.get("demo", {}).get("platform", "windows")
    output_dir = Path(config.get("output", {}).get("playbook_dir", "playbooks"))
    output_dir.mkdir(parents=True, exist_ok=True)

    final_state = run_pipeline(pdf_path, platform=platform)

    playbook = final_state.get("playbook", {})
    snippets = final_state.get("snippets", [])

    if not playbook:
        print("\n⚠️  No playbook generated.")
        analysis = final_state.get("analysis", {})
        if analysis:
            print(f"   Reason: {analysis.get('reasoning', 'Unknown')}")
        return

    # Save outputs
    output_file = output_dir / f"{playbook['playbook_id']}.json"
    with open(output_file, "w") as f:
        json.dump(playbook, f, indent=2)

    snippets_file = output_dir / f"{playbook['playbook_id']}_emulation_snippets.json"
    with open(snippets_file, "w") as f:
        json.dump(snippets, f, indent=2)

    validation = final_state.get("validation", {})
    banner("✅  MULTI-AGENT PIPELINE COMPLETE")
    print(f"  Playbook:   {output_file}")
    print(f"  Snippets:   {snippets_file}")
    print(f"  Events:     {len(playbook.get('events', []))}")
    print(f"  Agents:     {[a['agent_id'] + '(' + a['agent_type'] + ')' for a in playbook.get('mandatory_agents', [])]}")
    print(f"  Validation: {'PASSED ✓' if validation.get('valid') else 'accepted with warnings'}")
    print(f"  Retries:    {final_state.get('retry_count', 0) - 1}")
    print(f"  Agent msgs: {len(final_state.get('messages', []))}")
    print()


if __name__ == "__main__":
    args = sys.argv[1:]

    if not args or args[0] in ("-h", "--help"):
        print("Usage: python main.py <path_to_pdf_report> [--graph]")
        print()
        print("  --graph   Use multi-agent LangGraph pipeline (specialized models per task)")
        print()
        print("Example:")
        print("  python main.py reports/crowdstrike_report.pdf")
        print("  python main.py reports/crowdstrike_report.pdf --graph")
        sys.exit(1)

    pdf_path   = args[0]
    use_graph  = "--graph" in args

    if not Path(pdf_path).exists():
        print(f"Error: File not found: {pdf_path}")
        sys.exit(1)

    if use_graph:
        main_graph(pdf_path)
    else:
        main(pdf_path)
