#!/bin/bash
set -e

echo "=========================================="
echo "  ThreatHunt AI Creator — Setup"
echo "=========================================="
echo ""

# ── 1. Directory structure ─────────────────────────────────────────────────
echo "📁 Creating directory structure..."
mkdir -p data/reports data/vector_db playbooks promtps src tests

# ── 2. .env file (API keys) ────────────────────────────────────────────────
if [ ! -f .env ]; then
    echo ""
    echo "🔑 API Key Setup"
    echo "─────────────────────────────────────────"
    cp .env.example .env
    echo "Created .env from .env.example"
    echo ""
    read -r -p "Enter your Anthropic API key (or press Enter to skip): " ANTHROPIC_KEY
    if [ -n "$ANTHROPIC_KEY" ]; then
        sed -i "s|sk-ant-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx|$ANTHROPIC_KEY|g" .env
        echo "✓ Anthropic API key saved to .env"
    else
        echo "  Skipped — edit .env manually before running the app."
    fi
else
    echo "✓ .env already exists — skipping API key setup"
fi

# ── 3. Python virtual environment ─────────────────────────────────────────
echo ""
echo "🐍 Setting up Python virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "✓ Virtual environment created"
else
    echo "✓ Virtual environment already exists"
fi
source venv/bin/activate

# ── 4. Python dependencies ─────────────────────────────────────────────────
echo ""
echo "📦 Installing Python dependencies..."
pip install --upgrade pip --quiet
pip install -r requirements.txt

# ── 5. MITRE ATT&CK data ──────────────────────────────────────────────────
ATTACK_JSON="enterprise-attack.json"
if [ ! -f "$ATTACK_JSON" ]; then
    echo ""
    echo "⬇️  Downloading MITRE ATT&CK data..."
    curl -fsSL -o "$ATTACK_JSON" \
        https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
    echo "✓ MITRE ATT&CK data downloaded"
else
    echo "✓ MITRE ATT&CK data already present"
fi

# ── 6. Local model providers (optional) ───────────────────────────────────
echo ""
echo "🖥️  Local model providers (optional — all free, no API key needed):"
echo ""

if command -v ollama &> /dev/null; then
    echo "  ✓ Ollama already installed"
    echo "    Models: ollama pull llama3.1:8b  (fast)  |  ollama pull mixtral:8x7b  (quality)"
else
    echo "  ○ Ollama  → https://ollama.com/download"
    echo "    After install: ollama pull llama3.1:8b"
fi
echo ""
echo "  ○ LM Studio (RECOMMENDED for local — best model variety + easy setup)"
echo "    Download: https://lmstudio.ai"
echo "    Setup: open app → Search → download llama-3.3-70b-instruct or mistral-large"
echo "           then Developer tab → Start Server  (port 1234)"
echo ""
echo "  ○ vLLM  (maximum GPU throughput — requires Linux + NVIDIA GPU ≥ 40GB VRAM)"
echo "    pip install vllm"
echo "    vllm serve meta-llama/Llama-3.3-70B-Instruct --port 8000"
echo ""
echo "  NOTE: DeepSeek, Qwen, Yi and other Chinese-origin models are not supported."

# ── 7. Sample report ──────────────────────────────────────────────────────
SAMPLE_SCRIPT="tests/create_sample_report.py"
if [ -f "$SAMPLE_SCRIPT" ]; then
    echo ""
    echo "📄 Creating sample PDF report..."
    python "$SAMPLE_SCRIPT"
else
    echo "ℹ️  Sample report script not found at $SAMPLE_SCRIPT — skipping."
fi

echo ""
echo "=========================================="
echo "✅ Setup Complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "  1. Activate the environment:  source venv/bin/activate"
echo "  2. Make sure .env has your API key (ANTHROPIC_API_KEY)"
echo "  3. Launch the UI:             streamlit run app.py"
echo "     Or use the CLI:            python main.py report.pdf [--graph]"
echo ""
