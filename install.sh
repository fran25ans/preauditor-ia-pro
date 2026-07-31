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

if command -v apktool >/dev/null 2>&1; then
  echo "Android: apktool detectado. mobile-release-radar podra decodificar AndroidManifest.xml con mas precision."
else
  echo "Aviso Android: apktool no detectado. mobile-release-radar funciona, pero el analisis APK sera menos preciso."
fi

if command -v jadx >/dev/null 2>&1; then
  echo "Android: jadx detectado para revisiones manuales avanzadas."
else
  echo "Aviso Android: jadx no detectado. Es opcional para revisiones manuales avanzadas."
fi

echo "Pre-Auditor IA instalado. Prueba: preauditor --profile pro --list-rules"
echo "Mobile Release Radar instalado. Prueba: mobile-release-radar ./app.apk --out mobile-report.md"
