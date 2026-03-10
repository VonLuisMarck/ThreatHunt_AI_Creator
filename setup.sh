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

# ── 6a. Ollama ─────────────────────────────────────────────────────────────
if command -v ollama &> /dev/null; then
    echo "  ✓ Ollama already installed"
    echo "    Models: ollama pull llama3.1:8b  (fast)  |  ollama pull mixtral:8x7b  (quality)"
else
    echo "  ○ Ollama  → https://ollama.com/download"
    echo "    After install: ollama pull llama3.1:8b"
fi

# ── 6b. LM Studio (RECOMMENDED) ────────────────────────────────────────────
echo ""
_OS="$(uname -s)"
_ARCH="$(uname -m)"

_lmstudio_installed() {
    # Check common install locations across platforms
    command -v lms &> /dev/null || \
    [ -d "/Applications/LM Studio.app" ] || \
    [ -f "$HOME/.local/bin/lmstudio" ] || \
    ls "$HOME"/LMStudio*.AppImage 2>/dev/null | grep -q .
}

if _lmstudio_installed; then
    echo "  ✓ LM Studio already installed"
    echo "    → Open app → Developer tab → Start Server (port 1234)"
else
    echo "  ○ LM Studio  (RECOMMENDED — best quality for local inference)"
    echo "    Recommended models (Western origin only):"
    echo "      llama-3.3-70b-instruct  (Meta, USA)    ← best overall"
    echo "      mistral-large-instruct  (Mistral, France) ← best for code/analysis"
    echo "      phi-4                   (Microsoft, USA)  ← fastest, low VRAM"
    echo "      gemma-2-27b-it          (Google, USA)     ← best narrative writing"
    echo ""

    read -r -p "  Install LM Studio now? [y/N] " _INSTALL_LMS
    if [[ "$_INSTALL_LMS" =~ ^[Yy]$ ]]; then
        if [ "$_OS" = "Darwin" ]; then
            # macOS ────────────────────────────────────────────────────────
            if command -v brew &> /dev/null; then
                echo "  Installing via Homebrew..."
                brew install --cask lm-studio
                echo "  ✓ LM Studio installed"
            else
                # Detect Apple Silicon vs Intel and download the .dmg
                if [ "$_ARCH" = "arm64" ]; then
                    _LMS_URL="https://releases.lmstudio.ai/mac/arm/latest/download"
                else
                    _LMS_URL="https://releases.lmstudio.ai/mac/x86/latest/download"
                fi
                echo "  Downloading LM Studio for macOS ($ARCH)..."
                curl -fsSL --location -o /tmp/LMStudio.dmg "$_LMS_URL"
                hdiutil attach /tmp/LMStudio.dmg -quiet
                cp -R "/Volumes/LM Studio/LM Studio.app" /Applications/
                hdiutil detach "/Volumes/LM Studio" -quiet
                rm /tmp/LMStudio.dmg
                echo "  ✓ LM Studio installed to /Applications"
            fi

        elif [ "$_OS" = "Linux" ]; then
            # Linux — AppImage ─────────────────────────────────────────────
            if [ "$_ARCH" = "x86_64" ]; then
                _LMS_URL="https://releases.lmstudio.ai/linux/x86/latest/download"
            else
                echo "  ⚠️  LM Studio Linux only supports x86_64. Skipping."
                _LMS_URL=""
            fi

            if [ -n "$_LMS_URL" ]; then
                echo "  Downloading LM Studio AppImage..."
                curl -fsSL --location -o "$HOME/LMStudio.AppImage" "$_LMS_URL"
                chmod +x "$HOME/LMStudio.AppImage"
                echo "  ✓ LM Studio saved to ~/LMStudio.AppImage"
                echo "    Run with:  ~/LMStudio.AppImage"
                echo "    Or add a desktop shortcut via your file manager."
            fi

        else
            echo "  ⚠️  Automatic install not supported on this OS."
            echo "     Download manually from https://lmstudio.ai"
        fi
    else
        echo "  Skipped — download manually from https://lmstudio.ai"
    fi
    echo ""
    echo "  After install: open LM Studio → Search → download a model"
    echo "                 then Developer tab → Start Server (port 1234)"
fi

# ── 6c. vLLM ───────────────────────────────────────────────────────────────
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
