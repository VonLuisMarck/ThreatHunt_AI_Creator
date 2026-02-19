import fitz  # PyMuPDF
from typing import Dict, List
import re

class PDFProcessor:
    """Extrae y estructura contenido de PDFs de inteligencia"""
    
    def __init__(self):
        self.sections = {}
    
    def extract_text(self, pdf_path: str) -> Dict[str, any]:
        """Extrae texto completo y metadata"""
        doc = fitz.open(pdf_path)
        
        full_text = ""
        pages = []
        
        for page_num, page in enumerate(doc):
            text = page.get_text()
            full_text += text
            pages.append({
                'page_num': page_num + 1,
                'text': text
            })
        
        # Detectar secciones comunes
        sections = self._identify_sections(full_text)
        
        return {
            'full_text': full_text,
            'pages': pages,
            'sections': sections,
            'metadata': {
                'page_count': len(doc),
                'title': doc.metadata.get('title', ''),
                'author': doc.metadata.get('author', '')
            }
        }
    
    def _identify_sections(self, text: str) -> Dict[str, str]:
        """Identifica secciones clave del reporte"""
        sections = {}
        
        # Patrones comunes en reportes de CrowdStrike
        patterns = {
            'executive_summary': r'(?i)(executive summary|overview)(.*?)(?=\n[A-Z][a-z]+ [A-Z]|$)',
            'ttps': r'(?i)(tactics,? techniques,? and procedures|ttps?)(.*?)(?=\n[A-Z][a-z]+ [A-Z]|$)',
            'iocs': r'(?i)(indicators of compromise|iocs?)(.*?)(?=\n[A-Z][a-z]+ [A-Z]|$)',
            'recommendations': r'(?i)(recommendations|mitigations?)(.*?)(?=\n[A-Z][a-z]+ [A-Z]|$)'
        }
        
        for section_name, pattern in patterns.items():
            match = re.search(pattern, text, re.DOTALL)
            if match:
                sections[section_name] = match.group(2).strip()
        
        return sections
