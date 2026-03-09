"""
run_history.py — Persistencia de análisis anteriores.

Guarda cada análisis como JSON en run_history/<timestamp>_<pdf_name>.json
y proporciona funciones de listado y carga para el panel de historial.
"""

import json
import os
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional

_PROJECT_ROOT = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_HISTORY_DIR  = _PROJECT_ROOT / "run_history"
_MAX_RUNS     = 25


def _ensure_dir():
    _HISTORY_DIR.mkdir(parents=True, exist_ok=True)


def save_run(results: dict, filename: str = "report.pdf") -> str:
    """
    Persiste el dict de resultados en disco.
    Devuelve el run_id (nombre del fichero sin extensión).
    """
    _ensure_dir()
    stem  = Path(filename).stem[:40]
    ts    = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_id = f"{ts}_{stem}"
    path  = _HISTORY_DIR / f"{run_id}.json"

    analysis = results.get("analysis", {})
    iocs     = results.get("iocs", {})

    payload = {
        "_run_id":   run_id,
        "_saved_at": datetime.now().isoformat(),
        "_pdf_name": filename,
        "_preview": {
            "threat_actor":  analysis.get("threat_actor", "Unknown"),
            "campaign_name": analysis.get("campaign_name", ""),
            "demonstrable":  analysis.get("demonstrable", False),
            "demo_risk":     analysis.get("demo_risk", ""),
            "total_iocs":    sum(len(v) for v in iocs.values()) if iocs else 0,
            "total_ttps":    len(results.get("ttps", [])),
            "pipeline":      results.get("_pipeline", "classic"),
        },
        **results,
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2, default=str)

    return run_id


def list_runs() -> List[Dict[str, Any]]:
    """
    Devuelve los últimos _MAX_RUNS análisis (más reciente primero).
    Cada entrada contiene solo la metadata de preview.
    """
    _ensure_dir()
    files = sorted(_HISTORY_DIR.glob("*.json"), reverse=True)[:_MAX_RUNS]
    runs  = []
    for f in files:
        try:
            with open(f, encoding="utf-8") as fp:
                data = json.load(fp)
            ts_raw = data.get("_saved_at", "")
            ts_display = ts_raw[:16].replace("T", " ") if ts_raw else f.stem[:15]
            runs.append({
                "run_id":     data.get("_run_id", f.stem),
                "saved_at":   ts_display,
                "pdf_name":   data.get("_pdf_name", f.stem),
                "preview":    data.get("_preview", {}),
            })
        except Exception:
            continue
    return runs


def load_run(run_id: str) -> Optional[Dict[str, Any]]:
    """
    Carga un análisis completo dado su run_id.
    Devuelve None si no existe o está corrupto.
    """
    path = _HISTORY_DIR / f"{run_id}.json"
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def delete_run(run_id: str) -> bool:
    """Elimina un run del historial. Devuelve True si se eliminó."""
    path = _HISTORY_DIR / f"{run_id}.json"
    try:
        path.unlink()
        return True
    except Exception:
        return False
