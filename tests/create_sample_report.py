#!/usr/bin/env python3
"""
Genera un PDF de reporte de threat intelligence de muestra para testing.
No requiere ninguna dependencia adicional más allá de reportlab.
"""
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from pathlib import Path


def create_sample_report(output_path: str):
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=2*cm,
        leftMargin=2*cm,
        topMargin=2*cm,
        bottomMargin=2*cm,
    )

    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("H1", parent=styles["Heading1"], fontSize=18, spaceAfter=12)
    h2 = ParagraphStyle("H2", parent=styles["Heading2"], fontSize=14, spaceAfter=8)
    body = styles["BodyText"]
    body.spaceAfter = 6

    story = []

    # ── Title ──────────────────────────────────────────────────────
    story.append(Paragraph("THREAT INTELLIGENCE REPORT", h1))
    story.append(Paragraph("Operation: NightShadow — Ransomware Campaign Analysis", h2))
    story.append(Paragraph("Classification: TLP:AMBER | CrowdStrike Intelligence", body))
    story.append(Spacer(1, 0.5*cm))

    # ── Executive Summary ─────────────────────────────────────────
    story.append(Paragraph("Executive Summary", h2))
    story.append(Paragraph(
        "CrowdStrike Intelligence has identified a sophisticated ransomware campaign "
        "attributed to the CARBON SPIDER threat actor group, targeting financial services "
        "and healthcare organizations across the United States and Western Europe. "
        "The campaign, tracked as Operation NightShadow, leverages spearphishing emails "
        "with weaponized Excel attachments to achieve initial access, followed by "
        "credential theft and lateral movement before deploying ALPHV/BlackCat ransomware. "
        "This report provides technical details and recommendations for detection and mitigation.",
        body
    ))
    story.append(Spacer(1, 0.3*cm))

    # ── Threat Actor ──────────────────────────────────────────────
    story.append(Paragraph("Threat Actor Profile", h2))
    story.append(Paragraph(
        "CARBON SPIDER (also known as FIN7) is a financially motivated cybercrime group "
        "active since at least 2015. The group primarily targets the finance, healthcare, "
        "and retail sectors. They are known for sophisticated social engineering and "
        "use of tools including Cobalt Strike, Mimikatz, and custom PowerShell loaders. "
        "Attribution confidence: HIGH. Geographic origin: Eastern Europe.",
        body
    ))
    story.append(Spacer(1, 0.3*cm))

    # ── Attack Chain ──────────────────────────────────────────────
    story.append(Paragraph("Attack Chain Analysis", h2))
    story.append(Paragraph(
        "The attack follows a well-defined kill chain observed across multiple intrusions:",
        body
    ))

    stages = [
        ("Stage 1 – Initial Access (T1566.001)",
         "The threat actor sends spearphishing emails with malicious Excel attachments (.xlsm). "
         "The macro executes a PowerShell download cradle: "
         "powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand <base64>. "
         "The macro uses cmd.exe /c to spawn the process, creating a WINWORD.EXE → cmd.exe → "
         "powershell.exe process lineage."),
        ("Stage 2 – Execution (T1059.001)",
         "PowerShell downloads and executes an in-memory Cobalt Strike beacon via "
         "Invoke-Expression (IEX). AMSI bypass technique observed using reflection: "
         "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils'). "
         "The beacon communicates over HTTPS to the C2 infrastructure."),
        ("Stage 3 – Persistence (T1547.001)",
         "A registry run key is created for persistence: "
         "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdate. "
         "Additionally, a scheduled task named 'MicrosoftEdgeUpdateTaskMachineCore' is created "
         "via schtasks /create /tn MicrosoftEdgeUpdateTaskMachineCore /sc onlogon."),
        ("Stage 4 – Credential Access (T1003.001)",
         "Mimikatz is executed in memory via PowerShell to dump LSASS credentials: "
         "sekurlsa::logonpasswords. The tool accesses lsass.exe using OpenProcess with "
         "PROCESS_VM_READ. Credentials are also extracted from browser stores using LaZagne. "
         "procdump.exe -ma lsass.exe C:\\Windows\\Temp\\lsass.dmp was observed in one incident."),
        ("Stage 5 – Lateral Movement (T1021.002)",
         "Using stolen domain admin credentials, the actor moves laterally via SMB/PsExec: "
         "psexec.exe \\\\TARGET -u DOMAIN\\admin -p Password123 cmd.exe. "
         "WMI remote execution also observed: wmic /node:TARGET process call create 'payload.exe'. "
         "RDP (T1021.001) connections via mstsc.exe were used for interactive access."),
        ("Stage 6 – Impact (T1486)",
         "ALPHV/BlackCat ransomware is deployed and executed. Before encryption, shadow copies "
         "are deleted: vssadmin delete shadows /all /quiet && bcdedit /set {default} recoveryenabled No. "
         "Files are encrypted with a .locked extension. A ransom note 'RECOVER-FILES.txt' is dropped "
         "in every directory."),
    ]

    for title, desc in stages:
        story.append(Paragraph(title, ParagraphStyle("Stage", parent=styles["Heading3"], fontSize=11)))
        story.append(Paragraph(desc, body))
        story.append(Spacer(1, 0.2*cm))

    # ── TTPs Table ────────────────────────────────────────────────
    story.append(Paragraph("MITRE ATT&CK Techniques", h2))

    ttp_data = [
        ["Technique ID", "Name", "Tactic"],
        ["T1566.001", "Spearphishing Attachment", "Initial Access"],
        ["T1059.001", "PowerShell", "Execution"],
        ["T1047", "Windows Management Instrumentation", "Execution"],
        ["T1547.001", "Registry Run Keys", "Persistence"],
        ["T1053.005", "Scheduled Task", "Persistence"],
        ["T1548", "Bypass UAC", "Privilege Escalation"],
        ["T1562.001", "Disable Windows Defender", "Defense Evasion"],
        ["T1070.001", "Clear Windows Event Logs", "Defense Evasion"],
        ["T1027", "Obfuscated Files or Information", "Defense Evasion"],
        ["T1003.001", "LSASS Memory", "Credential Access"],
        ["T1555", "Credentials from Password Stores", "Credential Access"],
        ["T1018", "Remote System Discovery", "Discovery"],
        ["T1057", "Process Discovery", "Discovery"],
        ["T1021.001", "Remote Desktop Protocol", "Lateral Movement"],
        ["T1021.002", "SMB/Windows Admin Shares", "Lateral Movement"],
        ["T1486", "Data Encrypted for Impact", "Impact"],
        ["T1490", "Inhibit System Recovery", "Impact"],
    ]

    table = Table(ttp_data, colWidths=[3.5*cm, 7*cm, 5*cm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#CC0000")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("FONTSIZE", (0, 1), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F5F5")]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("PADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(table)
    story.append(Spacer(1, 0.5*cm))

    # ── IOCs ──────────────────────────────────────────────────────
    story.append(Paragraph("Indicators of Compromise", h2))

    story.append(Paragraph("<b>Network Indicators:</b>", body))
    network_iocs = [
        "185.220.101.45  (C2 server, AS-FRANTECH)",
        "91.199.212.52   (C2 server, AS-HOSTKEY)",
        "hxxps://cdn-update[.]com/beacon/check  (C2 URL)",
        "hxxp://185[.]220[.]101[.]45/stage2.ps1 (payload delivery)",
        "cdn-update.com  (C2 domain)",
        "windows-telemetry.net  (C2 domain)",
    ]
    for ioc in network_iocs:
        story.append(Paragraph(f"  • {ioc}", body))

    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph("<b>File Hashes (SHA256):</b>", body))
    hashes = [
        "a3f4b2c1d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2",
        "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3",
        "c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2",
    ]
    for h in hashes:
        story.append(Paragraph(f"  • {h}", body))

    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph("<b>Registry Keys:</b>", body))
    story.append(Paragraph(
        "  • HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdate", body))
    story.append(Paragraph(
        "  • HKLM\\SYSTEM\\CurrentControlSet\\Services\\NightShadowSvc", body))

    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph("<b>File Paths:</b>", body))
    paths = [
        "C:\\Windows\\Temp\\lsass.dmp",
        "C:\\ProgramData\\Microsoft\\payload.exe",
        "C:\\Users\\Public\\Documents\\beacon.ps1",
    ]
    for p in paths:
        story.append(Paragraph(f"  • {p}", body))

    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph("<b>CVE References:</b>", body))
    story.append(Paragraph("  • CVE-2021-34527 (PrintNightmare - privilege escalation)", body))
    story.append(Paragraph("  • CVE-2020-0796 (SMBGhost - lateral movement)", body))

    # ── Recommendations ───────────────────────────────────────────
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph("Recommendations", h2))
    recs = [
        "Enable PowerShell Script Block Logging and AMSI integration",
        "Deploy CrowdStrike Falcon Prevent with behavioral detection enabled",
        "Monitor for LSASS process access from non-system processes",
        "Enforce MFA on all VPN and RDP endpoints",
        "Block macro execution in Office documents from internet sources",
        "Monitor for vssadmin.exe and bcdedit.exe execution",
        "Deploy CrowdStrike Falcon Identity Protection for lateral movement detection",
    ]
    for rec in recs:
        story.append(Paragraph(f"  • {rec}", body))

    doc.build(story)
    print(f"✓ Sample report created: {output_path}")


if __name__ == "__main__":
    out_dir = Path(__file__).parent.parent / "data" / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    create_sample_report(str(out_dir / "sample_nightshadow_report.pdf"))
