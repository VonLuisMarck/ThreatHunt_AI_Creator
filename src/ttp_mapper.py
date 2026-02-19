from mitreattack.stix20 import MitreAttackData
from typing import List, Dict, Optional
import re


class TTPMapper:
    """
    Mapea técnicas al framework MITRE ATT&CK.

    Mejoras sobre la versión original:
    - Mapa de keywords ampliado: 7 → 40+ técnicas cubriendo todas las tácticas
    - Soporte de sub-técnicas (T1059.001, etc.)
    - Contexto táctico enriquecido
    - Búsqueda por tácticas además de técnicas
    - Detección de herramientas conocidas mapeadas a TTPs
    """

    # ──────────────────────────────────────────────────────────────
    #  Keyword → TTP mapping  (técnica_id: [keywords])
    #  Ordenado por táctica MITRE ATT&CK
    # ──────────────────────────────────────────────────────────────
    KEYWORD_MAP: Dict[str, List[str]] = {

        # ── Initial Access ────────────────────────────────────────
        "T1566":   ["phishing", "spearphishing", "malicious email", "lure", "bait email"],
        "T1566.001": ["malicious attachment", "docm", "xlsm", "macro attachment", "weaponized document"],
        "T1566.002": ["malicious link", "credential harvesting page", "phishing link", "href phishing"],
        "T1566.004": ["voice phishing", "vishing", "phone call"],
        "T1190":   ["exploit public", "web application exploit", "remote exploit", "rce", "sql injection",
                    "log4shell", "proxylogon", "proxyshell", "webshell"],
        "T1133":   ["external remote services", "vpn abuse", "citrix exploit", "pulse secure",
                    "fortivpn", "anyconnect", "remote access"],
        "T1195":   ["supply chain", "software supply chain", "compromised package", "malicious update",
                    "3cx", "solarwinds", "codecov"],
        "T1078":   ["valid accounts", "stolen credentials", "credential stuffing", "account takeover",
                    "password spray", "brute force login"],
        "T1091":   ["removable media", "usb", "thumb drive", "autorun"],

        # ── Execution ─────────────────────────────────────────────
        "T1059":   ["command line", "scripting", "interpreter abuse", "lolbin"],
        "T1059.001": ["powershell", "ps1", "invoke-expression", "iex", "invoke-command",
                      "encoded command", "bypass executionpolicy", "amsi bypass", "scriptblock"],
        "T1059.003": ["cmd.exe", "command prompt", "batch script", ".bat file"],
        "T1059.005": ["vbscript", "vbs", "wscript", "cscript", "visual basic script"],
        "T1059.007": ["javascript", "jscript", "node.js malware", "js payload"],
        "T1203":   ["exploit client", "browser exploit", "office exploit", "pdf exploit",
                    "memory corruption", "use after free", "heap spray"],
        "T1204":   ["user execution", "user clicks", "runs malicious", "opens attachment",
                    "double click", "lnk file"],
        "T1053":   ["scheduled task", "schtasks", "cron job", "at command", "task scheduler"],
        "T1047":   ["wmi", "windows management", "wmic process", "win32_process"],
        "T1218":   ["lolbas", "living off the land", "mshta", "rundll32", "regsvr32",
                    "certutil", "bitsadmin", "installutil"],

        # ── Persistence ───────────────────────────────────────────
        "T1547":   ["autostart", "run key", "startup folder", "winlogon", "userinit", "boot"],
        "T1547.001": ["registry run key", "hkcu run", "hklm run", "currentversion\\run"],
        "T1543":   ["create service", "new service", "malicious service", "sc create",
                    "createservice api"],
        "T1505":   ["webshell", "web shell", "aspx backdoor", "php backdoor", "server-side backdoor"],
        "T1574":   ["dll hijacking", "dll sideloading", "search order hijacking", "phantom dll"],
        "T1176":   ["browser extension", "malicious extension", "chrome extension"],

        # ── Privilege Escalation ──────────────────────────────────
        "T1068":   ["privilege escalation", "local exploit", "kernel exploit", "elevation of privilege",
                    "uac bypass", "eop"],
        "T1055":   ["process injection", "dll injection", "shellcode injection", "reflective loading",
                    "process hollowing", "thread injection", "apc injection"],
        "T1134":   ["token manipulation", "token impersonation", "seimpersonateprivilege",
                    "incognito", "runas"],
        "T1548":   ["bypass uac", "uac bypass", "eventvwr", "fodhelper", "sdclt", "auto-elevate"],

        # ── Defense Evasion ───────────────────────────────────────
        "T1562":   ["disable logging", "disable defender", "impair defense", "tamper protection",
                    "kill antivirus", "stop security service"],
        "T1562.001": ["disable windows defender", "set-mppreference", "add-mppreference exclusion",
                      "disable realtime monitoring"],
        "T1070":   ["clear event log", "wevtutil", "clear-eventlog", "delete logs",
                    "indicator removal", "cover tracks", "timestomp"],
        "T1036":   ["masquerading", "rename malware", "disguise", "fake process name",
                    "lsass.exe disguise", "svchost lookalike"],
        "T1027":   ["obfuscation", "base64 encoded", "xor encoding", "packed", "encrypted payload",
                    "string concatenation", "invoke-obfuscation"],
        "T1055.012": ["process doppelganging", "transactional ntfs"],
        "T1140":   ["deobfuscate", "decode payload", "certutil decode", "-decodeb64"],

        # ── Credential Access ─────────────────────────────────────
        "T1003":   ["credential dumping", "lsass", "sam database", "ntds.dit",
                    "procdump", "sekurlsa", "comsvcs.dll"],
        "T1003.001": ["lsass dump", "lsass.exe memory", "minidumpwritedump", "task manager dump",
                      "silent process exit", "nanodump"],
        "T1003.002": ["sam dump", "reg save hklm\\sam", "shadow copy sam"],
        "T1555":   ["browser passwords", "credential store", "saved passwords", "keychain",
                    "login data", "chrome passwords"],
        "T1552":   ["unsecured credentials", "credentials in files", "password in script",
                    "unattend.xml", "web.config password"],
        "T1558":   ["kerberoasting", "asreproasting", "golden ticket", "silver ticket",
                    "kerberos attack", "ticket granting", "rubeus", "impacket kerberos"],
        "T1110":   ["brute force", "password spray", "credential stuffing", "dictionary attack"],
        "T1056":   ["keylogging", "keylogger", "input capture", "credential capture"],

        # ── Discovery ─────────────────────────────────────────────
        "T1083":   ["file discovery", "directory listing", "dir /s", "find /type f",
                    "enumerate files"],
        "T1018":   ["remote system discovery", "network scan", "host discovery", "ping sweep",
                    "nmap", "arp scan", "nbtscan", "net view"],
        "T1057":   ["process discovery", "tasklist", "ps aux", "get-process",
                    "enumerate processes"],
        "T1082":   ["system information", "systeminfo", "uname -a", "whoami", "hostname",
                    "os version", "domain info"],
        "T1069":   ["permission groups", "net localgroup", "get-adgroup", "domain admins",
                    "group enumeration"],
        "T1016":   ["network configuration", "ipconfig", "ifconfig", "route print",
                    "network discovery"],
        "T1046":   ["port scan", "service scan", "nmap -sV", "open ports", "banner grab"],
        "T1087":   ["account discovery", "net user", "get-aduser", "ldap query users",
                    "enumerate accounts"],
        "T1135":   ["network share discovery", "net share", "smbclient -L", "shares enumeration"],

        # ── Lateral Movement ──────────────────────────────────────
        "T1021":   ["lateral movement", "remote execution", "pivot", "move laterally"],
        "T1021.001": ["rdp", "remote desktop", "mstsc", "xfreerdp", "rdp lateral"],
        "T1021.002": ["smb", "psexec", "wmi exec", "service exec", "admin shares"],
        "T1021.004": ["ssh lateral", "ssh tunneling", "ssh forwarding"],
        "T1021.006": ["winrm", "invoke-command", "enter-pssession", "powershell remoting"],
        "T1570":   ["lateral tool transfer", "scp malware", "copy tool", "upload implant"],

        # ── Collection ────────────────────────────────────────────
        "T1005":   ["data from local", "collect files", "stage files", "gather data"],
        "T1039":   ["data from network share", "collect from shares", "smb exfil"],
        "T1025":   ["data from removable", "usb data collection"],
        "T1074":   ["data staged", "staging directory", "archive before exfil", "rar encrypted"],
        "T1113":   ["screenshot", "screen capture", "printscreen"],
        "T1056.001": ["keylogging", "keystroke capture"],

        # ── C2 ────────────────────────────────────────────────────
        "T1071":   ["c2", "command and control", "c&c", "beacon", "callback"],
        "T1071.001": ["http c2", "https c2", "web request c2", "curl beacon"],
        "T1071.004": ["dns c2", "dns tunneling", "dnscat", "iodine"],
        "T1095":   ["tcp c2", "raw socket", "custom protocol c2"],
        "T1572":   ["protocol tunneling", "dns tunnel", "http tunnel", "icmp tunnel"],
        "T1090":   ["proxy", "multi-hop proxy", "tor", "onion routing", "domain fronting"],
        "T1102":   ["web service c2", "github c2", "pastebin c2", "dead drop resolver",
                    "telegram bot c2"],

        # ── Exfiltration ──────────────────────────────────────────
        "T1041":   ["exfiltration", "data theft", "data exfil", "steal data", "upload to c2"],
        "T1048":   ["exfil over alternative", "dns exfiltration", "icmp exfiltration"],
        "T1567":   ["exfil to cloud", "upload to s3", "dropbox exfil", "onedrive exfil",
                    "mega.nz upload"],

        # ── Impact ────────────────────────────────────────────────
        "T1486":   ["ransomware", "encrypt files", "file encryption", "ransom note",
                    ".locked", ".encrypted extension"],
        "T1490":   ["inhibit recovery", "vssadmin delete", "shadow copy delete", "bcdedit /set",
                    "wbadmin delete", "disable recovery"],
        "T1485":   ["data destruction", "wiper", "delete files", "format drive", "rm -rf /"],
        "T1489":   ["service stop", "net stop", "stop service", "disable critical service"],
        "T1491":   ["defacement", "web defacement", "deface"],
        "T1499":   ["endpoint dos", "resource exhaustion", "fork bomb", "cpu spike"],
    }

    # Known tools mapped to their primary TTP
    TOOL_TTP_MAP: Dict[str, str] = {
        "mimikatz": "T1003",
        "procdump": "T1003.001",
        "cobalt strike": "T1071.001",
        "brute ratel": "T1071.001",
        "sliver": "T1071.001",
        "havoc": "T1071.001",
        "metasploit": "T1059",
        "empire": "T1059.001",
        "covenant": "T1059.001",
        "meterpreter": "T1059",
        "psexec": "T1021.002",
        "bloodhound": "T1069",
        "sharphound": "T1069",
        "rubeus": "T1558",
        "kerbrute": "T1110",
        "crackmapexec": "T1021.002",
        "impacket": "T1003.002",
        "responder": "T1557",
        "nmap": "T1046",
        "chisel": "T1572",
        "ligolo": "T1090",
        "lazagne": "T1555",
    }

    def __init__(self):
        try:
            self.mitre = MitreAttackData("enterprise-attack.json")
            self.techniques = self.mitre.get_techniques()
            self._technique_cache: Dict[str, Optional[Dict]] = {}
        except Exception:
            # Graceful degradation if MITRE data file not found
            self.mitre = None
            self.techniques = []
            self._technique_cache = {}

    # ──────────────────────────────────────────────────────────────
    #  Public API
    # ──────────────────────────────────────────────────────────────

    def extract_techniques(self, text: str) -> List[Dict]:
        """Extrae técnicas MITRE del texto usando IDs explícitos y keywords."""
        found: List[Dict] = []

        # 1) Explicit MITRE IDs in text (T1234 or T1234.001)
        explicit_ids = set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text))
        for tid in explicit_ids:
            t = self._get_technique(tid)
            if t:
                found.append(t)

        # 2) Keyword-based detection
        keyword_hits = self._search_by_keywords(text)
        found.extend(keyword_hits)

        # 3) Known tool detection
        tool_hits = self._search_by_tools(text)
        found.extend(tool_hits)

        # Deduplicate preserving order
        seen: set = set()
        unique: List[Dict] = []
        for t in found:
            if t["id"] not in seen:
                seen.add(t["id"])
                unique.append(t)

        # Sort by tactic order
        return self._sort_by_tactic(unique)

    # ──────────────────────────────────────────────────────────────
    #  Private helpers
    # ──────────────────────────────────────────────────────────────

    def _get_technique(self, technique_id: str) -> Optional[Dict]:
        """Obtiene detalles de técnica por ID (con caché)."""
        if technique_id in self._technique_cache:
            return self._technique_cache[technique_id]

        result = None

        if self.mitre and self.techniques:
            for technique in self.techniques:
                ext_refs = getattr(technique, "external_references", [])
                for ref in ext_refs:
                    if (
                        getattr(ref, "source_name", "") == "mitre-attack"
                        and getattr(ref, "external_id", "") == technique_id
                    ):
                        tactics = []
                        for phase in getattr(technique, "kill_chain_phases", []):
                            tactics.append(phase.phase_name.replace("-", " ").title())

                        result = {
                            "id": technique_id,
                            "name": getattr(technique, "name", technique_id),
                            "description": getattr(technique, "description", "")[:300],
                            "tactics": tactics,
                            "platforms": getattr(technique, "x_mitre_platforms", []),
                            "is_subtechnique": "." in technique_id,
                        }
                        break
                if result:
                    break

        # Fallback: minimal entry if not found in MITRE data
        if not result:
            result = self._minimal_entry(technique_id)

        self._technique_cache[technique_id] = result
        return result

    def _minimal_entry(self, technique_id: str) -> Dict:
        """Entry mínimo cuando no se dispone de datos MITRE."""
        # Try to infer name from keyword map
        name = f"Technique {technique_id}"
        tactics = []
        for tid, keywords in self.KEYWORD_MAP.items():
            if tid == technique_id:
                # Map prefix to tactic
                tactic = self._tid_to_tactic(technique_id)
                if tactic:
                    tactics = [tactic]
                break
        return {
            "id": technique_id,
            "name": name,
            "description": "",
            "tactics": tactics,
            "platforms": [],
            "is_subtechnique": "." in technique_id,
        }

    def _search_by_keywords(self, text: str) -> List[Dict]:
        """Detecta técnicas por presencia de keywords en el texto."""
        found: List[Dict] = []
        text_lower = text.lower()

        for tid, keywords in self.KEYWORD_MAP.items():
            if any(kw in text_lower for kw in keywords):
                t = self._get_technique(tid)
                if t:
                    found.append(t)

        return found

    def _search_by_tools(self, text: str) -> List[Dict]:
        """Detecta técnicas a partir de herramientas conocidas mencionadas."""
        found: List[Dict] = []
        text_lower = text.lower()

        for tool, tid in self.TOOL_TTP_MAP.items():
            if tool in text_lower:
                t = self._get_technique(tid)
                if t and t not in found:
                    # Annotate with the tool that triggered it
                    t_copy = dict(t)
                    t_copy["triggered_by_tool"] = tool
                    found.append(t_copy)

        return found

    def _tid_to_tactic(self, tid: str) -> Optional[str]:
        """Inferencia heurística de táctica a partir del TID."""
        prefix_map = {
            "T1566": "Initial Access", "T1190": "Initial Access",
            "T1133": "Initial Access", "T1195": "Initial Access",
            "T1059": "Execution", "T1203": "Execution",
            "T1053": "Execution", "T1047": "Execution",
            "T1547": "Persistence", "T1543": "Persistence",
            "T1505": "Persistence", "T1574": "Persistence",
            "T1068": "Privilege Escalation", "T1055": "Defense Evasion",
            "T1134": "Privilege Escalation", "T1548": "Defense Evasion",
            "T1562": "Defense Evasion", "T1070": "Defense Evasion",
            "T1036": "Defense Evasion", "T1027": "Defense Evasion",
            "T1003": "Credential Access", "T1555": "Credential Access",
            "T1558": "Credential Access", "T1110": "Credential Access",
            "T1083": "Discovery", "T1018": "Discovery",
            "T1057": "Discovery", "T1082": "Discovery",
            "T1021": "Lateral Movement", "T1570": "Lateral Movement",
            "T1005": "Collection", "T1074": "Collection",
            "T1071": "Command And Control", "T1572": "Command And Control",
            "T1090": "Command And Control", "T1102": "Command And Control",
            "T1041": "Exfiltration", "T1048": "Exfiltration",
            "T1486": "Impact", "T1490": "Impact", "T1485": "Impact",
        }
        # Try exact match, then parent
        return prefix_map.get(tid) or prefix_map.get(tid.split(".")[0])

    def _sort_by_tactic(self, techniques: List[Dict]) -> List[Dict]:
        """Ordena técnicas por orden de táctica MITRE (kill chain)."""
        tactic_order = [
            "Initial Access", "Execution", "Persistence",
            "Privilege Escalation", "Defense Evasion", "Credential Access",
            "Discovery", "Lateral Movement", "Collection",
            "Command And Control", "Exfiltration", "Impact",
        ]

        def sort_key(t: Dict) -> int:
            tactics = t.get("tactics", [])
            for tactic in tactics:
                for i, ordered in enumerate(tactic_order):
                    if ordered.lower() in tactic.lower():
                        return i
            return 99

        return sorted(techniques, key=sort_key)
