#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")"

if ls dist/preauditor_ia-*.whl >/dev/null 2>&1; then
  python3 -m pip install dist/preauditor_ia-*.whl --no-deps --no-build-isolation
else
  python3 -m pip install . --no-build-isolation
fi

if python3 -c "import reportlab" >/dev/null 2>&1; then
  echo "PDF: reportlab detectado."
else
  echo "Aviso PDF: reportlab no esta disponible. Instala con: python3 -m pip install reportlab"
fi

if command -v ollama >/dev/null 2>&1; then
  echo "Ollama: comando detectado. Puedes usar --ollama para triage local."
else
  echo "Aviso Ollama: no detectado. La herramienta funciona igual; instala Ollama si quieres triage local IA."
fi

echo "Pre-Auditor IA instalado. Prueba: preauditor --profile pro --list-rules"
