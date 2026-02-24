# Módulo: `pdf_processor.py`

**Clase:** `PDFProcessor`
**Dependencias:** `PyMuPDF (fitz)`, `re`, `statistics`

---

## Responsabilidad

Extrae y estructura el contenido de un PDF de inteligencia de amenazas. El resultado es un diccionario rico (`content`) que sirve de entrada a todos los módulos siguientes.

Va más allá de una simple extracción de texto: detecta **encabezados** por tamaño de fuente, mapea el documento a **secciones temáticas** (executive summary, TTPs, IOCs, etc.) y extrae **entidades clave** (países, herramientas, malware, actores) mediante regex y listas de palabras clave.

---

## API pública

### `extract_text(pdf_path: str) → Dict`

Punto de entrada principal. Procesa el PDF completo y retorna el diccionario `content`.

**Parámetros:**

| Param | Tipo | Descripción |
|-------|------|-------------|
| `pdf_path` | str | Ruta absoluta o relativa al archivo PDF |

**Retorno:** `Dict` con las siguientes claves:

```python
{
    "full_text":    str,            # Todo el texto concatenado (pág 1..N)
    "pages":        List[Dict],     # Datos estructurados por página
    "sections":     Dict[str, str], # Texto agrupado por sección temática
    "headings":     List[Dict],     # Encabezados detectados con metadatos
    "key_findings": Dict,           # Entidades clave detectadas
    "tables":       List[Dict],     # Tablas extraídas (PyMuPDF 1.23+)
    "metadata":     Dict,           # Metadatos del PDF (título, autor, páginas...)
}
```

**Estructura detallada de `pages[]`:**
```python
{
    "page_num":          int,   # Número de página (1-indexed)
    "text":              str,   # Texto plano de la página
    "structured_blocks": List,  # Bloques con {text, font_size, is_bold, y_pos}
    "tables":            List,  # Tablas de esta página
}
```

**Estructura detallada de `sections{}`:**

Las secciones mapeadas son:
- `executive_summary`
- `threat_actor`
- `attack_chain`
- `ttps`
- `iocs`
- `tools`
- `vulnerabilities`
- `recommendations`
- `detection`
- `impact`

Cada valor es el texto completo de esa sección. Si una sección no se encuentra, no aparece en el dict.

**Estructura detallada de `headings[]`:**
```python
{
    "text":      str,    # Texto del encabezado
    "font_size": float,  # Tamaño de fuente detectado
    "page":      int,    # Número de página
    "is_bold":   bool,   # ¿Texto en negrita?
    "y_pos":     float,  # Posición vertical en la página
}
```

**Estructura detallada de `key_findings{}`:**
```python
{
    "mentioned_countries":     List[str],  # ej. ["russia", "china"]
    "mentioned_sectors":       List[str],  # ej. ["finance", "healthcare"]
    "mentioned_tools":         List[str],  # ej. ["cobalt strike", "mimikatz"]
    "mentioned_malware_types": List[str],  # ej. ["ransomware", "trojan"]
    "mentioned_threat_actors": List[str],  # ej. ["APT28", "Lazarus"]
    "cves":                    List[str],  # ej. ["CVE-2024-1234"]
    "mitre_ids_explicit":      List[str],  # ej. ["T1566.001", "T1003"]
}
```

**Estructura detallada de `metadata{}`:**
```python
{
    "page_count":    int,
    "title":         str,
    "author":        str,
    "subject":       str,
    "creator":       str,
    "word_count":    int,
    "char_count":    int,
    "has_tables":    bool,
    "heading_count": int,
    "section_count": int,
}
```

---

### `get_chunked_text(content: Dict, chunk_size: int = 3000) → List[Dict]`

Divide el texto del documento en chunks para procesamiento LLM.

**Estrategia de chunking:**
1. Primero intenta usar secciones nombradas (si `content["sections"]` no está vacío)
2. Cada sección que supera `chunk_size` se subdivide recursivamente
3. Si no hay secciones, divide el `full_text` linealmente

**Retorno:** Lista de dicts:
```python
[
    {
        "section": str,   # Nombre de sección ("executive_summary", "chunk_3", ...)
        "text":    str,   # Contenido del chunk
        "offset":  int,   # Posición de inicio en el full_text
    }
]
```

---

## Métodos privados

### `_analyze_blocks(raw_blocks, page_num) → List[Dict]`

Convierte los bloques crudos de PyMuPDF en bloques estructurados.

Cada bloque PyMuPDF es un span con `font_size`, `flags` (bold=16), y `text`. Este método:
1. Filtra spans vacíos o con solo espacios
2. Extrae `font_size` y determina `is_bold` por el flag de fuente
3. Retorna lista normalizada

---

### `_extract_headings(blocks) → List[Dict]`

Detecta encabezados basándose en tamaño de fuente.

**Algoritmo:**
1. Calcula el tamaño de fuente promedio del documento con `statistics.mean()`
2. Un bloque se considera encabezado si: `font_size > avg_font_size * 1.12` O `is_bold == True AND len(text) < 100`
3. Filtra textos que parecen cuerpo (> 200 caracteres) aunque tengan fuente grande

---

### `_identify_sections_advanced(text, headings) → Dict[str, str]`

Dos pasadas para mapear texto a secciones:

**Pasada 1 — basada en encabezados:**
- Usa los encabezados detectados como delimitadores
- Para cada encabezado, busca en `SECTION_PATTERNS` a qué sección corresponde
- Extrae el texto entre ese encabezado y el siguiente

**Pasada 2 — fallback regex:**
- Para secciones que no encontró en la pasada 1
- Usa patrones regex como `r'executive\s+summary'`, `r'threat\s+actor'`, etc.
- Extrae texto tras el match hasta el próximo encabezado identificado

**`SECTION_PATTERNS`:**

```python
SECTION_PATTERNS = {
    "executive_summary":  [r"executive\s+summary", r"overview", r"abstract", ...],
    "threat_actor":       [r"threat\s+actor", r"adversary", r"attribution", ...],
    "attack_chain":       [r"attack\s+chain", r"kill\s+chain", r"intrusion", ...],
    "ttps":               [r"ttp", r"technique", r"tactic", r"mitre", ...],
    "iocs":               [r"indicator", r"ioc", r"artifact", ...],
    "tools":              [r"tool", r"malware", r"software", ...],
    "vulnerabilities":    [r"vulnerabilit", r"cve", r"exploit", ...],
    "recommendations":    [r"recommendation", r"mitigation", r"remediation", ...],
    "detection":          [r"detection", r"hunting", r"telemetry", ...],
    "impact":             [r"impact", r"consequence", r"damage", ...],
}
```

---

### `_extract_tables(page) → List[Dict]`

Extrae tablas usando `page.find_tables()` de PyMuPDF 1.23+.

Retorna lista de:
```python
{"rows": int, "cols": int, "data": List[List[str]]}
```

Falla silenciosamente si PyMuPDF es < 1.23 o si la página no tiene tablas.

---

### `_extract_key_findings(text) → Dict`

Detecta entidades clave mediante búsqueda de palabras clave en el texto completo.

**Listas de detección:**

| Entidad | Ejemplos | Método |
|---------|----------|--------|
| Países | russia, china, iran, usa, ukraine, germany, france, israel, india, north korea, dprk, uk, australia, japan, brazil | `word in text.lower()` |
| Sectores | healthcare, finance, banking, government, energy, telecom, manufacturing, retail, defense, education, transportation, utility, pharmaceutical, insurance, media | `word in text.lower()` |
| Herramientas | cobalt strike, mimikatz, metasploit, empire, bloodhound, nmap, nessus, burpsuite, sqlmap, hydra, john the ripper, hashcat, impacket, responder, crackmapexec, psexec, procdump, winpeas, linpeas, meterpreter, sliver, brute ratel | `word in text.lower()` |
| Malware | ransomware, trojan, backdoor, rat, rootkit, wiper, keylogger, spyware, botnet, dropper, loader, stealer, downloader | `word in text.lower()` |
| Actores | APT[1-99], Lazarus, Sandworm, Cozy Bear, Fancy Bear, Scattered Spider, ALPHV, LockBit, Conti, BlackCat, REvil, DarkSide, HAFNIUM | regex `r'\b(APT\d+|ActorName)\b'` |
| CVEs | CVE-YYYY-NNNNN | regex `r'CVE-\d{4}-\d{4,7}'` |
| MITRE IDs | T1234, T1234.001 | regex `r'\bT\d{4}(?:\.\d{3})?\b'` |

---

## Notas de implementación

- **PyMuPDF blocks:** El método `get_text("blocks")` retorna tuplas con `(x0, y0, x1, y1, text, block_no, block_type)`. Los spans de texto son `block_type == 0`.
- **Font size detection:** Se usa `get_text("dict")` para acceder a los spans con metadatos de fuente.
- **Tolerancia a PDFs escaneados:** Si un PDF es una imagen (OCR requerido), `full_text` estará vacío o casi vacío. El sistema continúa pero la calidad de análisis será baja.
