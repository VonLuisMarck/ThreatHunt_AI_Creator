#!/bin/bash
# ThreatHunt AI Creator — Web UI launcher
# Usage: ./run_ui.sh [port]

PORT=${1:-8501}
cd "$(dirname "$0")"

echo "================================================"
echo "  ThreatHunt AI Creator — Web UI"
echo "================================================"
echo ""

# Check Python deps
python3 -c "import streamlit" 2>/dev/null || {
    echo "⚠  Streamlit not found. Installing all dependencies..."
    # stix2-elevator needs legacy setuptools to build its C extensions
    pip install "setuptools<67" --quiet
    pip install -r requirements.txt --quiet
    echo "✓ Dependencies installed"
}

# Check Ollama
if command -v ollama &>/dev/null; then
    if ollama list 2>/dev/null | grep -q "llama3"; then
        echo "✓ Ollama running with llama3"
    else
        echo "⚠  Ollama found but llama3 not pulled. Run: ollama pull llama3"
    fi
else
    echo "⚠  Ollama not found — LLM steps will be skipped"
    echo "   Install: curl -fsSL https://ollama.com/install.sh | sh"
fi

echo ""
echo "  Opening browser at http://localhost:$PORT"
echo "  Press Ctrl+C to stop"
echo ""

streamlit run app.py --server.port "$PORT"
