import iocextract
from typing import Dict, List
import re


class IOCExtractor:
    """
    Extrae IOCs estructurados del texto de un reporte.

    Tipos soportados (versión mejorada):
    - Redes: IPv4, IPv6, dominios, URLs, emails
    - Hashes: MD5, SHA1, SHA256
    - Windows: registry keys, file paths, named pipes, mutex names
    - Vulnerabilidades: CVEs
    - Comandos: PowerShell cmdlets, bash/cmd invocaciones
    - Defanged IOCs: hxxp://, [.] notation
    - Otros: user agents, service names
    """

    # ── Patterns ──────────────────────────────────────────────────

    _RE_REGISTRY = re.compile(
        r"HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)"
        r"(?:\\[^\s\n\r\"\'\]\)]+)+",
        re.IGNORECASE,
    )
    _RE_REGISTRY_SHORT = re.compile(
        r"(?:HKLM|HKCU|HKCR|HKU|HKCC)\\[^\s\n\r\"\'\]\)]+",
        re.IGNORECASE,
    )
    _RE_WIN_PATH = re.compile(
        r"[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n\s]+\\)*[^\\/:*?\"<>|\r\n\s]*",
    )
    _RE_LINUX_PATH = re.compile(
        r"(?<!\w)/(?:[a-zA-Z0-9_.~\-]+/)+[a-zA-Z0-9_.~\-]+",
    )
    _RE_NAMED_PIPE = re.compile(
        r"\\\\\.\\pipe\\[^\s\n\r\"\'\]\)]+|"
        r"\\\\\?\\pipe\\[^\s\n\r\"\'\]\)]+",
        re.IGNORECASE,
    )
    _RE_MUTEX = re.compile(
        r"(?:mutex|mutant)[:\s]+([A-Za-z0-9_\-\.]{3,64})",
        re.IGNORECASE,
    )
    _RE_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
    _RE_PS_CMDLET = re.compile(
        r"(?:Invoke|Get|Set|New|Remove|Start|Stop|Add|Clear|Copy|Move|"
        r"Enter|Exit|Find|Format|Grant|Hide|Join|Limit|Lock|Measure|"
        r"Mount|Open|Protect|Publish|Redo|Register|Request|Reset|"
        r"Resolve|Restart|Search|Select|Show|Skip|Split|Submit|"
        r"Switch|Sync|Test|Trace|Unblock|Undo|Uninstall|Unlock|"
        r"Unprotect|Unpublish|Unregister|Update|Use|Wait|Watch|Write"
        r")-[A-Za-z]+(?:\s+[^\n]{0,80})?",
    )
    _RE_SHELL_CMD = re.compile(
        r"(?:powershell(?:\.exe)?|cmd(?:\.exe)?|bash|sh|wscript|cscript|"
        r"mshta|rundll32|regsvr32|certutil|bitsadmin|wmic)\s+[^\n]{0,120}",
        re.IGNORECASE,
    )
    # Defanged IOCs: hxxp://, [.], [:]
    _RE_DEFANGED_URL = re.compile(
        r"hxx[ps]?://[^\s\n\r\"\'<>]+",
        re.IGNORECASE,
    )
    _RE_DEFANGED_IP = re.compile(
        r"\d{1,3}\[\.\]\d{1,3}\[\.\]\d{1,3}\[\.\]\d{1,3}",
    )
    _RE_DEFANGED_DOMAIN = re.compile(
        r"[a-zA-Z0-9\-]+(?:\[\.\][a-zA-Z0-9\-]+)+\[\.\][a-zA-Z]{2,}",
    )
    _RE_SERVICE_NAME = re.compile(
        r"(?:service\s+name|sc\s+create|CreateService)[:\s]+([A-Za-z0-9_\-\.]{3,50})",
        re.IGNORECASE,
    )
    _RE_USER_AGENT = re.compile(
        r'(?:User-Agent|user.agent)[:\s]+([^\n\r"\']{10,200})',
        re.IGNORECASE,
    )

    # ─────────────────────────────────────────────────────────────

    def extract_all(self, text: str) -> Dict[str, List[str]]:
        """Extrae todos los tipos de IOCs del texto."""

        # --- Standard IOCs via iocextract library ---
        ipv4_raw = list(set(iocextract.extract_ipv4s(text, refang=True)))
        ipv6_raw = list(set(iocextract.extract_ipv6s(text)))
        domains_raw = list(set(iocextract.extract_fqdns(text, refang=True)))
        urls_raw = list(set(iocextract.extract_urls(text, refang=True)))
        emails_raw = list(set(iocextract.extract_emails(text)))
        md5_raw = list(set(iocextract.extract_md5_hashes(text)))
        sha1_raw = list(set(iocextract.extract_sha1_hashes(text)))
        sha256_raw = list(set(iocextract.extract_sha256_hashes(text)))

        # --- Defanged IOCs (iocextract may miss some) ---
        defanged_urls = [self._refang_url(u) for u in self._RE_DEFANGED_URL.findall(text)]
        defanged_ips = [self._refang_ip(ip) for ip in self._RE_DEFANGED_IP.findall(text)]
        defanged_domains = [d.replace("[.]", ".") for d in self._RE_DEFANGED_DOMAIN.findall(text)]

        # Merge and deduplicate
        all_ips = list(set(ipv4_raw + defanged_ips))
        all_urls = list(set(urls_raw + defanged_urls))
        all_domains = list(set(domains_raw + defanged_domains))

        iocs = {
            # Network
            "ipv4": self._filter_private(all_ips),
            "ipv6": ipv6_raw,
            "domains": self._filter_generic_domains(all_domains),
            "urls": all_urls,
            "emails": emails_raw,
            # File hashes
            "md5": md5_raw,
            "sha1": sha1_raw,
            "sha256": sha256_raw,
            # Windows artifacts
            "registry_keys": self._extract_registry_keys(text),
            "file_paths": self._extract_file_paths(text),
            "named_pipes": self._RE_NAMED_PIPE.findall(text),
            "mutex_names": self._RE_MUTEX.findall(text),
            # Vulnerabilities
            "cves": list(set(self._RE_CVE.findall(text))),
            # Commands & execution
            "commands": self._extract_commands(text),
            # Other
            "service_names": list(set(self._RE_SERVICE_NAME.findall(text)))[:10],
            "user_agents": list(set(self._RE_USER_AGENT.findall(text)))[:5],
        }

        # Remove empty lists for cleaner output
        return {k: v for k, v in iocs.items() if v}

    # ── Private helpers ───────────────────────────────────────────

    def _extract_registry_keys(self, text: str) -> List[str]:
        full = list(self._RE_REGISTRY.findall(text))
        short = list(self._RE_REGISTRY_SHORT.findall(text))
        return list(set(full + short))

    def _extract_file_paths(self, text: str) -> List[str]:
        win = self._RE_WIN_PATH.findall(text)
        linux = self._RE_LINUX_PATH.findall(text)
        all_paths = win + linux
        # Filter too-short or common false positives
        filtered = [
            p for p in all_paths
            if len(p) > 6
            and not p.startswith("/usr/share/doc")
            and not p.startswith("/etc/ld")
        ]
        return list(set(filtered))[:30]

    def _extract_commands(self, text: str) -> List[str]:
        cmdlets = self._RE_PS_CMDLET.findall(text)
        shell_cmds = self._RE_SHELL_CMD.findall(text)
        all_cmds = list(set(cmdlets + shell_cmds))
        # Keep top 20 by length (longer = more specific)
        all_cmds.sort(key=len, reverse=True)
        return all_cmds[:20]

    def _refang_url(self, url: str) -> str:
        """Convierte hxxp:// → http:// y quita ofuscación básica."""
        return url.replace("hxxps", "https").replace("hxxp", "http").replace("[.]", ".")

    def _refang_ip(self, ip: str) -> str:
        """Convierte 1[.]2[.]3[.]4 → 1.2.3.4"""
        return ip.replace("[.]", ".")

    def _filter_private(self, ips: List[str]) -> List[str]:
        """
        Mantiene IPs que probablemente son C2 o víctima (no RFC1918 puras
        a menos que haya poca información disponible).
        En un reporte de threat intel, las IPs privadas también son relevantes
        como lateralización, así que las incluimos pero las marcamos.
        """
        return list(set(ips))

    def _filter_generic_domains(self, domains: List[str]) -> List[str]:
        """Filtra dominios demasiado genéricos (e.g., microsoft.com, google.com)."""
        # Common false-positive domains to skip
        skip = {
            "microsoft.com", "windows.com", "windowsupdate.com",
            "google.com", "googleapis.com", "gstatic.com",
            "apple.com", "icloud.com", "akamai.net", "cloudflare.com",
        }
        return [d for d in domains if d.lower() not in skip]
