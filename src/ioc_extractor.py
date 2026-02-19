import iocextract
from typing import Dict, List, Set
import re

class IOCExtractor:
    """Extrae IOCs estructurados del texto"""
    
    def extract_all(self, text: str) -> Dict[str, List[str]]:
        """Extrae todos los tipos de IOCs"""
        
        iocs = {
            'ipv4': list(set(iocextract.extract_ipv4s(text))),
            'ipv6': list(set(iocextract.extract_ipv6s(text))),
            'domains': list(set(iocextract.extract_fqdns(text))),
            'urls': list(set(iocextract.extract_urls(text))),
            'md5': list(set(iocextract.extract_md5_hashes(text))),
            'sha1': list(set(iocextract.extract_sha1_hashes(text))),
            'sha256': list(set(iocextract.extract_sha256_hashes(text))),
            'emails': list(set(iocextract.extract_emails(text))),
            'registry_keys': self._extract_registry_keys(text),
            'file_paths': self._extract_file_paths(text),
            'commands': self._extract_commands(text)
        }
        
        return iocs
    
    def _extract_registry_keys(self, text: str) -> List[str]:
        """Extrae registry keys de Windows"""
        pattern = r'HKEY_[A-Z_]+\\[^\s\n]+'
        return list(set(re.findall(pattern, text)))
    
    def _extract_file_paths(self, text: str) -> List[str]:
        """Extrae rutas de archivos"""
        patterns = [
            r'[A-Z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*',  # Windows
            r'/(?:[^/\s]+/)*[^/\s]+',  # Linux/Unix
        ]
        
        paths = []
        for pattern in patterns:
            paths.extend(re.findall(pattern, text))
        
        return list(set([p for p in paths if len(p) > 5]))
    
    def _extract_commands(self, text: str) -> List[str]:
        """Extrae comandos comunes"""
        patterns = [
            r'(?:powershell|cmd|bash|sh)\s+[^\n]+',
            r'(?:Invoke-|Get-|Set-|New-)[A-Za-z]+[^\n]*',  # PowerShell cmdlets
        ]
        
        commands = []
        for pattern in patterns:
            commands.extend(re.findall(pattern, text, re.IGNORECASE))
        
        return list(set(commands[:20]))  # Limitar a 20 más relevantes
