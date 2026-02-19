#!/bin/bash

echo "=========================================="
echo "Intel-to-Playbook POC Setup"
echo "=========================================="

# Crear directorios
echo "Creating directory structure..."
mkdir -p data/reports data/vector_db data/playbooks prompts src tests

# Instalar Ollama si no está instalado
if ! command -v ollama &> /dev/null; then
    echo "Installing Ollama..."
    curl -fsSL https://ollama.com/install.sh | sh
else
    echo "✓ Ollama already installed"
fi

# Descargar modelo
echo "Downloading Llama3 model (this may take a few minutes)..."
ollama pull llama3

# Crear entorno virtual
echo "Creating Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Instalar dependencias
echo "Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Descargar MITRE ATT&CK data
echo "Downloading MITRE ATT&CK data..."
wget -q https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json

# Crear reporte de ejemplo
echo "Creating sample report..."
python tests/create_sample_report.py

echo ""
echo "=========================================="
echo "✅ Setup Complete!"
echo "=========================================="
echo ""
echo "To run the POC:"
echo "  1. source venv/bin/activate"
echo "  2. python main.py data/reports/sample_ransomware_report.pdf"
echo ""
