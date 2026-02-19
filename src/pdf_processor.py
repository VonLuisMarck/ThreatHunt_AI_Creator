import fitz  # PyMuPDF
from typing import Dict, List, Optional
import re
from collections import defaultdict


class PDFProcessor:
    """
    Análisis profundo y estructurado de PDFs de inteligencia de amenazas.

    Mejoras sobre la versión original:
    - Detección de headings por tamaño de fuente y negrita
    - Extracción de tablas (PyMuPDF 1.23+)
    - 10 categorías de secciones con múltiples patrones cada una
    - Extracción de hallazgos clave (países, sectores, herramientas, malware)
    - Chunking inteligente por sección para procesamiento LLM
    """

    SECTION_PATTERNS = {
        "executive_summary": [
            r"(?i)executive\s+summary",
            r"(?i)resumen\s+ejecutivo",
            r"(?i)^overview$",
            r"(?i)^abstract$",
            r"(?i)key\s+findings",
        ],
        "threat_actor": [
            r"(?i)threat\s+actor",
            r"(?i)actor\s+profile",
            r"(?i)attribution",
            r"(?i)adversary\s+profile",
            r"(?i)who\s+is\s+behind",
        ],
        "attack_chain": [
            r"(?i)attack\s+chain",
            r"(?i)kill\s+chain",
            r"(?i)infection\s+chain",
            r"(?i)attack\s+flow",
            r"(?i)intrusion\s+chain",
            r"(?i)campaign\s+timeline",
        ],
        "ttps": [
            r"(?i)tactics,?\s*techniques,?\s*and\s*procedures",
            r"(?i)\bttps?\b",
            r"(?i)mitre\s+att&?ck",
            r"(?i)technique\s+details",
            r"(?i)attack\s+techniques",
        ],
        "iocs": [
            r"(?i)indicators?\s+of\s+compromise",
            r"(?i)\biocs?\b",
            r"(?i)technical\s+indicators",
            r"(?i)network\s+indicators",
            r"(?i)file\s+indicators",
            r"(?i)appendix.*indicator",
        ],
        "tools": [
            r"(?i)tools?\s+and\s+malware",
            r"(?i)tools?\s+used",
            r"(?i)malware\s+analysis",
            r"(?i)tooling",
            r"(?i)capabilities",
            r"(?i)arsenal",
        ],
        "vulnerabilities": [
            r"(?i)vulnerabilit",
            r"(?i)exploited\s+cve",
            r"(?i)zero.?day",
            r"(?i)patch",
            r"(?i)security\s+flaw",
        ],
        "recommendations": [
            r"(?i)recommendations?",
            r"(?i)mitigations?",
            r"(?i)countermeasures",
            r"(?i)defenses?",
            r"(?i)remediation",
            r"(?i)protective\s+measures",
        ],
        "detection": [
            r"(?i)detection\s+guidance",
            r"(?i)hunting\s+queries",
            r"(?i)sigma\s+rules?",
            r"(?i)yara\s+rules?",
            r"(?i)snort\s+rules?",
            r"(?i)detection\s+opportunities",
        ],
        "impact": [
            r"(?i)impact\s+assessment",
            r"(?i)consequences",
            r"(?i)damage\s+assessment",
            r"(?i)affected\s+organizations",
        ],
    }

    # Well-known tools/malware families for key findings
    _KNOWN_TOOLS = [
        "cobalt strike", "mimikatz", "metasploit", "empire", "covenant",
        "brute ratel", "sliver", "havoc", "meterpreter", "psexec", "wce",
        "procdump", "lazagne", "nirsoft", "bloodhound", "sharphound",
        "rubeus", "kerbrute", "crackmapexec", "impacket", "responder",
        "nmap", "masscan", "chisel", "ngrok", "frp", "ligolo",
    ]
    _KNOWN_MALWARE = [
        "ransomware", "trojan", "backdoor", "rat", "rootkit", "bootkit",
        "wiper", "infostealer", "keylogger", "spyware", "botnet", "dropper",
        "loader", "stager", "downloader", "cryptominer", "banker",
    ]
    _KNOWN_ACTORS = [
        r"apt\d+", "lazarus", "scattered spider", "alphv", "lockbit",
        "revil", "conti", "cl0p", "fancy bear", "cozy bear", "sandworm",
        "volt typhoon", "midnight blizzard", "kimsuky", "turla", "fin7",
        "fin8", "ta505", "carbanak", "lapsus\\$", "darkside", "blackcat",
    ]
    _KNOWN_SECTORS = [
        "healthcare", "finance", "banking", "government", "energy",
        "telecom", "telecommunications", "manufacturing", "retail",
        "education", "defense", "critical infrastructure", "transportation",
        "aerospace", "pharmaceutical", "insurance", "media",
    ]
    _KNOWN_COUNTRIES = [
        "russia", "china", "iran", "north korea", "usa", "united states",
        "uk", "united kingdom", "ukraine", "germany", "france", "israel",
        "india", "pakistan", "nigeria", "brazil",
    ]

    def __init__(self):
        self.sections: Dict[str, str] = {}
        self.headings: List[Dict] = []

    # ──────────────────────────────────────────────────────────────
    #  Public API
    # ──────────────────────────────────────────────────────────────

    def extract_text(self, pdf_path: str) -> Dict:
        """Extracción avanzada con análisis estructural completo."""
        doc = fitz.open(pdf_path)

        full_text = ""
        pages = []
        all_blocks: List[Dict] = []

        for page_num, page in enumerate(doc):
            text = page.get_text()
            full_text += text

            blocks = self._analyze_blocks(
                page.get_text("dict")["blocks"], page_num + 1
            )
            all_blocks.extend(blocks)

            tables = self._extract_tables(page)

            pages.append({
                "page_num": page_num + 1,
                "text": text,
                "structured_blocks": blocks,
                "tables": tables,
            })

        headings = self._extract_headings(all_blocks)
        sections = self._identify_sections_advanced(full_text, headings)
        key_findings = self._extract_key_findings(full_text)

        self.headings = headings
        self.sections = sections

        return {
            "full_text": full_text,
            "pages": pages,
            "sections": sections,
            "headings": headings,
            "key_findings": key_findings,
            "tables": [t for p in pages for t in p["tables"]],
            "metadata": {
                "page_count": len(doc),
                "title": doc.metadata.get("title", ""),
                "author": doc.metadata.get("author", ""),
                "subject": doc.metadata.get("subject", ""),
                "creator": doc.metadata.get("creator", ""),
                "word_count": len(full_text.split()),
                "char_count": len(full_text),
                "has_tables": any(p["tables"] for p in pages),
                "heading_count": len(headings),
                "section_count": len(sections),
            },
        }

    def get_chunked_text(self, content: Dict, chunk_size: int = 3000) -> List[Dict]:
        """
        Divide el contenido en chunks procesables por el LLM.
        Prioriza secciones detectadas; si no hay, divide por páginas/tamaño.
        """
        chunks: List[Dict] = []

        # 1) Use named sections when available
        if content.get("sections"):
            for section_name, section_text in content["sections"].items():
                if len(section_text.strip()) < 80:
                    continue
                # Sections larger than chunk_size get split further
                for offset in range(0, len(section_text), chunk_size):
                    chunk_text = section_text[offset: offset + chunk_size]
                    if chunk_text.strip():
                        chunks.append({
                            "section": section_name,
                            "text": chunk_text,
                            "offset": offset,
                        })

        # 2) Always also chunk the full text to avoid missing inter-section content
        full_text = content.get("full_text", "")
        if full_text:
            for i in range(0, len(full_text), chunk_size):
                chunk_text = full_text[i: i + chunk_size]
                if chunk_text.strip():
                    chunks.append({
                        "section": f"fulltext_chunk_{i // chunk_size + 1}",
                        "text": chunk_text,
                        "offset": i,
                    })

        return chunks

    # ──────────────────────────────────────────────────────────────
    #  Block / heading analysis
    # ──────────────────────────────────────────────────────────────

    def _analyze_blocks(self, raw_blocks: List, page_num: int) -> List[Dict]:
        """Convierte bloques PyMuPDF en dicts enriquecidos con info de formato."""
        structured: List[Dict] = []

        for block in raw_blocks:
            if block.get("type") != 0:  # Only text blocks
                continue

            lines = block.get("lines", [])
            if not lines:
                continue

            font_sizes: List[float] = []
            font_names: List[str] = []
            text_parts: List[str] = []
            is_bold = False

            for line in lines:
                for span in line.get("spans", []):
                    font_sizes.append(span.get("size", 10))
                    font_names.append(span.get("font", ""))
                    text_parts.append(span.get("text", ""))
                    if "Bold" in span.get("font", "") or (span.get("flags", 0) & 16):
                        is_bold = True

            text_content = " ".join(text_parts).strip()
            if not text_content:
                continue

            avg_size = sum(font_sizes) / len(font_sizes) if font_sizes else 10.0

            structured.append({
                "text": text_content,
                "avg_font_size": avg_size,
                "is_bold": is_bold,
                "font_names": list(set(font_names)),
                "page": page_num,
                "bbox": block.get("bbox", []),
            })

        return structured

    def _extract_headings(self, blocks: List[Dict]) -> List[Dict]:
        """Detecta headings usando tamaño de fuente relativo y negrita."""
        if not blocks:
            return []

        sizes = [b["avg_font_size"] for b in blocks]
        avg_size = sum(sizes) / len(sizes)
        heading_threshold = avg_size * 1.12  # 12% above average

        headings: List[Dict] = []
        for block in blocks:
            text = block["text"].strip()
            size = block["avg_font_size"]
            bold = block["is_bold"]

            if len(text) < 3 or len(text) > 200:
                continue
            if text.startswith(("•", "-", "·", "*", "○")):
                continue
            # Ignore lines that look like body text (long sentences)
            if len(text.split()) > 20 and not bold:
                continue

            is_heading = (size >= heading_threshold or bold) and len(text.split()) <= 18
            if is_heading:
                headings.append({
                    "text": text,
                    "font_size": size,
                    "page": block["page"],
                    "is_bold": bold,
                })

        return headings

    # ──────────────────────────────────────────────────────────────
    #  Section identification
    # ──────────────────────────────────────────────────────────────

    def _identify_sections_advanced(
        self, text: str, headings: List[Dict]
    ) -> Dict[str, str]:
        """
        Identificación de secciones en dos pasadas:
        1) Basada en headings detectados por fuente
        2) Fallback por regex sobre el texto plano
        """
        sections: Dict[str, str] = {}
        heading_texts = [h["text"] for h in headings]

        # Pass 1: heading-based extraction
        for section_name, patterns in self.SECTION_PATTERNS.items():
            for heading in heading_texts:
                matched = any(re.search(p, heading) for p in patterns)
                if not matched:
                    continue

                idx = text.find(heading)
                if idx == -1:
                    continue

                # Find position of next heading
                end_pos = len(text)
                for other in heading_texts:
                    if other == heading:
                        continue
                    pos = text.find(other, idx + len(heading))
                    if 0 < pos < end_pos:
                        end_pos = pos

                content = text[idx + len(heading): end_pos].strip()
                if len(content) > 80:
                    sections[section_name] = content[:5000]
                break  # first matching heading wins

        # Pass 2: regex fallback for sections not found via headings
        for section_name, patterns in self.SECTION_PATTERNS.items():
            if section_name in sections:
                continue
            for pattern in patterns:
                match = re.search(
                    pattern + r"[\s\S]{0,50}\n([\s\S]*?)(?=\n[A-Z][A-Z]|\Z)",
                    text,
                    re.IGNORECASE,
                )
                if match:
                    content = match.group(1).strip()
                    if len(content) > 80:
                        sections[section_name] = content[:5000]
                        break

        return sections

    # ──────────────────────────────────────────────────────────────
    #  Table extraction
    # ──────────────────────────────────────────────────────────────

    def _extract_tables(self, page) -> List[Dict]:
        """Extrae tablas usando PyMuPDF 1.23+ find_tables()."""
        tables: List[Dict] = []
        try:
            tab = page.find_tables()
            for t in tab.tables:
                data = t.extract()
                if data:
                    tables.append({
                        "rows": len(data),
                        "cols": len(data[0]) if data else 0,
                        "data": data,
                    })
        except (AttributeError, Exception):
            pass  # find_tables not available in older PyMuPDF
        return tables

    # ──────────────────────────────────────────────────────────────
    #  Key findings extraction
    # ──────────────────────────────────────────────────────────────

    def _extract_key_findings(self, text: str) -> Dict:
        """
        Extrae entidades y hallazgos clave del texto completo.
        Busca: países, sectores, herramientas, malware, CVEs, actores conocidos.
        """
        text_lower = text.lower()

        def find_keywords(keywords: List[str]) -> List[str]:
            found = []
            for kw in keywords:
                if re.search(r"\b" + re.escape(kw.lower()) + r"\b", text_lower):
                    found.append(kw)
            return found

        def find_patterns(patterns: List[str]) -> List[str]:
            found: List[str] = []
            for p in patterns:
                found.extend(re.findall(p, text, re.IGNORECASE))
            return list(set(found))

        return {
            "mentioned_countries": find_keywords(self._KNOWN_COUNTRIES),
            "mentioned_sectors": find_keywords(self._KNOWN_SECTORS),
            "mentioned_tools": find_keywords(self._KNOWN_TOOLS),
            "mentioned_malware_types": find_keywords(self._KNOWN_MALWARE),
            "mentioned_threat_actors": find_patterns(
                [r"\b" + re.escape(a) + r"\b" for a in self._KNOWN_ACTORS]
            ),
            "cves": list(set(re.findall(r"CVE-\d{4}-\d{4,7}", text))),
            "mitre_ids_explicit": list(
                set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text))
            ),
        }
