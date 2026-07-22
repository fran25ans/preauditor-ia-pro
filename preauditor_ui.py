#!/usr/bin/env python3
"""Local web UI for Pre-Auditor IA Pro."""

from __future__ import annotations

import argparse
import html
import json
import secrets
import tempfile
import threading
import webbrowser
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlparse

import preauditor


APP_ROOT = Path.cwd().resolve()
SESSION_TOKEN = secrets.token_urlsafe(32)
MAX_POST_BYTES = 1024 * 1024
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]"}
GENERATED_ARTIFACT_ROOTS = {(APP_ROOT / "deliverables").resolve()}


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def header_hostname(value: str) -> str:
    value = value.strip().lower()
    if value.startswith("["):
        return value.split("]", 1)[0] + "]"
    return value.split(":", 1)[0]


def is_loopback_bind(host: str) -> bool:
    return host.lower() in {"127.0.0.1", "localhost", "::1", "[::1]"}


def is_within(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def assert_write_allowed(path: Path, allow_external: bool = False) -> None:
    if allow_external:
        return
    if is_within(path, APP_ROOT):
        return
    if any(is_within(path, root) for root in GENERATED_ARTIFACT_ROOTS):
        return
    raise ValueError("Escritura fuera de la carpeta de trabajo no permitida sin confirmacion explicita.")


def page_shell(content: str) -> bytes:
    return f"""<!doctype html>
<html lang="es" id="app-html">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Pre-Auditor IA Pro</title>
  <style>
    :root {{ --ink:#172033; --muted:#667085; --line:#d8dee8; --panel:#f7f9fc; --brand:#0f766e; --brand-dark:#115e59; --critical:#a31925; --high:#c2410c; --medium:#9a6700; --low:#176f4d; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; font-family:Arial, sans-serif; color:var(--ink); background:#eef3f8; }}
    header {{ background:#fff; border-bottom:1px solid var(--line); padding:22px 28px; }}
    main {{ max-width:1240px; margin:0 auto; padding:24px; }}
    h1 {{ margin:0 0 6px; font-size:30px; }}
    h2 {{ margin:0 0 14px; font-size:19px; }}
    h3 {{ margin:18px 0 10px; font-size:13px; letter-spacing:.02em; text-transform:uppercase; color:var(--muted); }}
    p {{ margin:0 0 10px; color:var(--muted); }}
    .topbar {{ max-width:1240px; margin:0 auto; display:flex; justify-content:space-between; align-items:flex-start; gap:18px; }}
    .status {{ display:flex; gap:8px; flex-wrap:wrap; justify-content:flex-end; }}
    .pill {{ border:1px solid var(--line); border-radius:999px; padding:6px 10px; background:#f8fafc; font-size:12px; font-weight:700; color:var(--brand-dark); }}
    .grid {{ display:grid; grid-template-columns:430px 1fr; gap:18px; align-items:start; }}
    .panel {{ background:#fff; border:1px solid var(--line); border-radius:8px; padding:18px; box-shadow:0 8px 24px rgba(15,23,42,.05); }}
    .section {{ border-top:1px solid var(--line); padding-top:14px; margin-top:14px; }}
    .section:first-child {{ border-top:0; padding-top:0; margin-top:0; }}
    label {{ display:block; font-size:13px; font-weight:700; margin:12px 0 5px; }}
    input, select, button {{ width:100%; border:1px solid var(--line); border-radius:6px; padding:10px; font-size:14px; background:#fff; color:var(--ink); }}
    .path-picker {{ display:grid; grid-template-columns:1fr 104px; gap:8px; }}
    .check {{ display:flex; gap:8px; align-items:center; font-size:13px; font-weight:700; margin:12px 0 5px; }}
    .check input {{ width:auto; }}
    button {{ background:var(--brand); color:#fff; border-color:var(--brand); font-weight:700; cursor:pointer; margin-top:16px; }}
    button:hover {{ background:var(--brand-dark); border-color:var(--brand-dark); }}
    .primary {{ font-size:15px; padding:13px; }}
    .path-picker button {{ margin-top:0; }}
    button:disabled {{ opacity:.55; cursor:wait; }}
    .modal {{ position:fixed; inset:0; display:none; place-items:center; background:rgba(15,23,42,.42); padding:20px; z-index:20; }}
    .modal.open {{ display:grid; }}
    .modal-card {{ width:min(760px,100%); max-height:82vh; overflow:hidden; background:#fff; border:1px solid var(--line); border-radius:8px; box-shadow:0 18px 60px rgba(15,23,42,.24); }}
    .modal-head {{ display:grid; grid-template-columns:1fr auto; gap:12px; align-items:center; padding:14px; border-bottom:1px solid var(--line); }}
    .modal-body {{ padding:14px; }}
    .browser-path {{ margin-bottom:10px; }}
    .browser-list {{ border:1px solid var(--line); border-radius:8px; max-height:390px; overflow:auto; }}
    .browser-row {{ display:grid; grid-template-columns:1fr auto; gap:8px; align-items:center; padding:10px 12px; border-bottom:1px solid var(--line); }}
    .browser-row:last-child {{ border-bottom:0; }}
    .browser-row button {{ width:auto; margin:0; padding:7px 10px; }}
    .secondary {{ background:#fff; color:var(--brand); }}
    .secondary:hover {{ background:#eefaf7; color:var(--brand-dark); }}
    .quick-actions {{ display:grid; grid-template-columns:1fr 1fr; gap:8px; margin-bottom:8px; }}
    .note {{ border:1px solid #c7d2fe; background:#eef2ff; color:#3730a3; border-radius:8px; padding:12px; font-size:13px; }}
    .warning {{ border:1px solid #facc15; background:#fefce8; color:#854d0e; border-radius:8px; padding:12px; margin:10px 0; font-size:13px; }}
    .progress-list {{ display:grid; gap:8px; margin-top:12px; }}
    .progress-step {{ border:1px solid var(--line); border-radius:8px; padding:10px; background:#fff; color:var(--muted); }}
    .progress-step.active {{ border-color:var(--brand); color:var(--brand-dark); background:#eefaf7; font-weight:700; }}
    .kpis {{ display:grid; grid-template-columns:repeat(5,minmax(0,1fr)); gap:10px; margin:12px 0 18px; }}
    .kpi {{ background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:12px; }}
    .kpi span {{ display:block; color:var(--muted); font-size:12px; text-transform:uppercase; }}
    .kpi strong {{ display:block; margin-top:5px; font-size:22px; }}
    .badge {{ display:inline-block; color:#fff; border-radius:999px; padding:4px 9px; font-size:12px; font-weight:700; }}
    .Critica {{ background:var(--critical); }} .Alta {{ background:var(--high); }} .Media {{ background:var(--medium); }} .Baja {{ background:var(--low); }}
    .finding {{ border-top:1px solid var(--line); padding:12px 0; }}
    code {{ background:#eef2f7; border-radius:4px; padding:2px 5px; }}
    a {{ color:var(--brand); font-weight:700; text-decoration:none; }}
    .links {{ display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:8px; margin:12px 0 18px; }}
    .links a {{ border:1px solid var(--line); border-radius:6px; padding:10px; background:#fff; }}
    .empty {{ border:1px dashed var(--line); border-radius:8px; padding:18px; background:#f8fafc; }}
    .empty ul {{ margin:10px 0 0; padding-left:18px; color:var(--muted); }}
    .rule-tools {{ display:grid; grid-template-columns:1fr 140px 160px 140px; gap:8px; margin-bottom:12px; }}
    .rule-list {{ border:1px solid var(--line); border-radius:8px; max-height:560px; overflow:auto; }}
    .rule-card {{ border-bottom:1px solid var(--line); padding:12px; }}
    .rule-card:last-child {{ border-bottom:0; }}
    .rule-card h3 {{ margin:0 0 8px; color:var(--ink); font-size:15px; text-transform:none; letter-spacing:0; }}
    .rule-meta {{ display:flex; gap:8px; flex-wrap:wrap; margin-bottom:8px; }}
    .rule-meta span {{ border:1px solid var(--line); border-radius:999px; padding:3px 8px; font-size:12px; color:var(--muted); }}
    textarea {{ width:100%; min-height:320px; border:1px solid var(--line); border-radius:6px; padding:12px; font:13px/1.45 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; color:var(--ink); background:#fbfdff; resize:vertical; }}
    .editor-actions {{ display:grid; grid-template-columns:repeat(4,1fr); gap:8px; margin:10px 0; }}
    .editor-actions button {{ margin-top:0; }}
    .success {{ border:1px solid #86efac; background:#f0fdf4; color:#166534; border-radius:8px; padding:12px; margin:10px 0; font-size:13px; }}
    .comparison {{ border:1px solid #99f6e4; background:#f0fdfa; border-radius:8px; padding:14px; margin:12px 0 18px; }}
    .comparison.regresion {{ border-color:#fecaca; background:#fef2f2; }}
    .comparison.estable {{ border-color:#d8dee8; background:#f8fafc; }}
    .comparison-grid {{ display:grid; grid-template-columns:repeat(4,1fr); gap:8px; margin-top:10px; }}
    .comparison-grid div {{ background:#fff; border:1px solid var(--line); border-radius:8px; padding:10px; }}
    .comparison-grid span {{ display:block; color:var(--muted); font-size:12px; text-transform:uppercase; }}
    .comparison-grid strong {{ display:block; margin-top:4px; font-size:20px; }}
    .review-controls {{ display:grid; grid-template-columns:1fr 1fr 1fr auto; gap:8px; margin-top:8px; }}
    .review-controls button {{ margin-top:0; width:auto; }}
    .error {{ color:#a31925; font-weight:700; }}
    @media (max-width:900px) {{ .topbar {{ display:block; }} .status {{ justify-content:flex-start; margin-top:12px; }} .grid,.kpis,.links,.quick-actions,.rule-tools,.editor-actions,.comparison-grid,.review-controls {{ grid-template-columns:1fr; }} }}
  </style>
</head>
<body>
  <header>
    <div class="topbar">
      <div>
        <h1>Pre-Auditor IA Pro</h1>
        <p data-i18n="headerSubtitle">Análisis local preliminar de seguridad para código, APIs, CI/CD, cloud e IA. Detecta patrones de riesgo, prioriza evidencias y genera entregables para validación experta.</p>
      </div>
      <div class="status">
        <span class="pill" data-i18n="pillLocal">Local</span>
        <span class="pill" data-i18n="pillPrivate">Privado</span>
        <span class="pill">Pro</span>
      </div>
    </div>
  </header>
  <main>{content}</main>
</body>
</html>
""".encode("utf-8")


def render_home() -> bytes:
    profiles = "".join(f"<option value='{p}'>{p}</option>" for p in sorted(preauditor.PROFILES))
    stacks = "".join(f"<option value='{s}'>{s}</option>" for s in sorted(preauditor.STACKS))
    demo_target = APP_ROOT / "sample-vulnerable"
    demo_output = APP_ROOT / "deliverables" / "demo-product"
    rules_by_profile = {
        profile: {rule.rule_id for rule in preauditor.rules_for_profile(profile)}
        for profile in sorted(preauditor.PROFILES)
    }
    rules_catalog = [
        {
            "id": rule.rule_id,
            "title": rule.title,
            "severity": rule.severity,
            "category": rule.category,
            "cvss": rule.cvss,
            "confidence": rule.confidence,
            "effort": rule.remediation_effort,
            "reference": rule.reference,
            "description": rule.description,
            "recommendation": rule.recommendation,
            "profiles": [profile for profile, ids in rules_by_profile.items() if rule.rule_id in ids],
        }
        for rule in preauditor.RULES
    ]
    rules_catalog_en = [
        {
            "id": rule.rule_id,
            "title": preauditor.RULE_TITLES_EN.get(rule.rule_id, rule.title),
            "severity": preauditor.severity_label(rule.severity, "en"),
            "raw_severity": rule.severity,
            "category": preauditor.category_label(rule.category, "en"),
            "raw_category": rule.category,
            "cvss": rule.cvss,
            "confidence": preauditor.confidence_label(rule.confidence, "en"),
            "effort": preauditor.effort_label(rule.remediation_effort, "en"),
            "reference": rule.reference,
            "description": preauditor.EN_CATEGORY_TEXTS.get(preauditor.category_label(rule.category, "en"), {}).get(
                "description",
                f"The scanner detected evidence related to {preauditor.RULE_TITLES_EN.get(rule.rule_id, rule.title).lower()}.",
            ),
            "recommendation": preauditor.EN_CATEGORY_TEXTS.get(preauditor.category_label(rule.category, "en"), {}).get(
                "recommendation",
                "Validate the finding manually and apply the control recommended by the responsible security team.",
            ),
            "profiles": [profile for profile, ids in rules_by_profile.items() if rule.rule_id in ids],
        }
        for rule in preauditor.RULES
    ]
    rule_categories = sorted({rule["category"] for rule in rules_catalog})
    content = f"""
<div class="grid">
  <section class="panel">
    <h2 data-i18n="newScan">Nuevo escaneo</h2>
    <p class="note" data-i18n="demoNote">Demo recomendada: usa una carpeta concreta de proyecto. Evita escanear carpetas grandes como el escritorio completo.</p>
    <div class="quick-actions">
      <button type="button" id="demo-preset" class="secondary" data-i18n="quickDemo">Demo rápida</button>
      <button type="button" id="clear-advanced" class="secondary" data-i18n="fastMode">Modo rápido</button>
      <button type="button" id="rules-open" class="secondary" data-i18n="ruleCatalog">Catálogo de reglas</button>
      <button type="button" id="guided-demo" class="secondary" data-i18n="guidedDemo">Demo guiada</button>
      <button type="button" id="custom-rules-open" class="secondary" data-i18n="customRules">Reglas custom</button>
    </div>
    <form id="scan-form">
      <div class="section">
        <h3 data-i18n="scanSection">Escaneo</h3>
        <label data-i18n="projectPath">Ruta del proyecto</label>
        <div class="path-picker">
          <input name="target" value="{html.escape(str(demo_target if demo_target.exists() else APP_ROOT))}" required>
          <button type="button" class="browse-button" data-target="target" data-i18n="browse">Explorar</button>
        </div>
        <label data-i18n="profile">Perfil</label>
        <select name="profile">{profiles}</select>
        <label data-i18n="stack">Stack</label>
        <select name="stack">{stacks}</select>
      </div>
      <div class="section">
        <h3 data-i18n="reportSection">Informe</h3>
        <label data-i18n="outputFolder">Carpeta de salida</label>
        <div class="path-picker">
          <input name="output_dir" value="{html.escape(str(APP_ROOT / 'deliverables' / 'ui-scan'))}" required>
          <button type="button" class="browse-button" data-target="output_dir" data-i18n="browse">Explorar</button>
        </div>
        <label data-i18n="client">Cliente</label>
        <input name="client" value="Cliente demo">
        <label data-i18n="auditor">Auditor</label>
        <input name="auditor" value="Francisco José Gimeno">
        <label data-i18n="scope">Alcance</label>
        <input name="scope" value="Análisis preliminar local de seguridad">
        <label data-i18n="reportVersion">Versión del informe</label>
        <input name="report_version" value="{datetime.now().strftime('%Y.%m')}">
        <label data-i18n="reportLanguage">Idioma de informes</label>
        <select name="language">
          <option value="es">Español</option>
          <option value="en">English</option>
        </select>
      </div>
      <div class="section">
        <h3 data-i18n="advancedOptions">Opciones avanzadas</h3>
        <label data-i18n="customRulesFile">Reglas custom YAML/JSON</label>
        <input name="rules_file" placeholder="/ruta/a/preauditor-rules.yml">
        <label class="check"><input type="checkbox" name="auto_compare" value="1" checked> <span data-i18n="compareBaseline">Comparar con baseline anterior de la carpeta de salida</span></label>
        <label data-i18n="optionalBaseline">Baseline anterior opcional</label>
        <input name="compare_baseline" placeholder="/ruta/a/baseline.json">
        <label class="check"><input type="checkbox" name="allow_external_write" value="1"> <span data-i18n="allowExternalWrite">Permitir escrituras fuera de la carpeta de trabajo</span></label>
        <label class="check"><input type="checkbox" name="ollama" value="1"> <span data-i18n="ollamaTriage">Triage local con Ollama</span></label>
        <label data-i18n="ollamaModel">Modelo Ollama</label>
        <input name="ollama_model" value="llama3.1">
        <label data-i18n="ollamaUrl">URL Ollama</label>
        <input name="ollama_url" value="http://127.0.0.1:11434">
        <label data-i18n="ollamaLimit">Limite Ollama</label>
        <input name="ollama_limit" value="20">
        <label data-i18n="ollamaMinSeverity">Severidad minima Ollama</label>
        <select name="ollama_min_severity">
          <option value="Alta">Alta</option>
          <option value="Critica">Critica</option>
          <option value="Media">Media</option>
          <option value="Baja">Baja</option>
        </select>
        <label class="check"><input type="checkbox" name="ollama_filter_fp" value="1"> <span data-i18n="hideLikelyFp">Ocultar probables falsos positivos</span></label>
      </div>
      <button id="scan-button" class="primary" type="submit" data-i18n="generate">Generar análisis preliminar</button>
    </form>
  </section>
  <section class="panel">
    <h2 data-i18n="deliveryPanel">Panel de entrega</h2>
    <div id="result">
      <div class="empty">
        <p><strong data-i18n="readyTitle">Listo para generar un pack de revisión preliminar.</strong></p>
        <p data-i18n="readyBody">El resultado incluirá resumen ejecutivo, informe técnico, dashboard, JSON, SARIF, baseline y checklist de remediación.</p>
        <ul>
          <li data-i18n="readyBullet1">La auditoría automática no sustituye la revisión experta.</li>
          <li data-i18n="readyBullet2">Los hallazgos se entregan priorizados para validación humana.</li>
          <li data-i18n="readyBullet3">Usa la demo rápida para una presentación controlada.</li>
        </ul>
      </div>
    </div>
  </section>
</div>
<div id="rules-modal" class="modal" role="dialog" aria-modal="true">
  <div class="modal-card">
    <div class="modal-head">
      <strong data-i18n="rulesCatalogTitle">Catálogo de reglas</strong>
      <button type="button" id="rules-close" class="secondary" data-i18n="close">Cerrar</button>
    </div>
    <div class="modal-body">
      <p data-i18n="rulesCatalogBody">Reglas determinísticas locales agrupadas por severidad, categoría y perfil. Ollama es una capa opcional de triage, no sustituye estas reglas.</p>
      <div class="rule-tools">
        <input id="rule-search" placeholder="Buscar regla, OWASP, categoría..." data-i18n-placeholder="ruleSearch">
        <select id="rule-severity">
          <option value="" data-i18n="severityAny">Severidad</option>
          <option value="Critica" data-i18n="sevCritical">Crítica</option>
          <option value="Alta" data-i18n="sevHigh">Alta</option>
          <option value="Media" data-i18n="sevMedium">Media</option>
          <option value="Baja" data-i18n="sevLow">Baja</option>
        </select>
        <select id="rule-category">
          <option value="" data-i18n="categoryAny">Categoría</option>
          {''.join(f'<option value="{html.escape(category)}">{html.escape(category)}</option>' for category in rule_categories)}
        </select>
        <select id="rule-profile">
          <option value="" data-i18n="profileAny">Perfil</option>
          {''.join(f'<option value="{html.escape(profile)}">{html.escape(profile)}</option>' for profile in sorted(preauditor.PROFILES))}
        </select>
      </div>
      <p><strong id="rule-count"></strong></p>
      <div id="rule-list" class="rule-list"></div>
    </div>
  </div>
</div>
<div id="custom-rules-modal" class="modal" role="dialog" aria-modal="true">
  <div class="modal-card">
    <div class="modal-head">
      <strong data-i18n="customRulesTitle">Editor de reglas custom</strong>
      <button type="button" id="custom-rules-close" class="secondary" data-i18n="close">Cerrar</button>
    </div>
    <div class="modal-body">
      <p data-i18n="customRulesBody">Las reglas core son de solo lectura. Este editor crea o modifica un pack YAML externo para políticas internas del cliente.</p>
      <label data-i18n="customRulesYaml">Archivo YAML de reglas custom</label>
      <input id="custom-rules-path" value="{html.escape(str(APP_ROOT / 'custom-rules.yml'))}">
      <div class="editor-actions">
        <button type="button" id="custom-template" class="secondary" data-i18n="template">Plantilla</button>
        <button type="button" id="custom-load" class="secondary" data-i18n="load">Cargar</button>
        <button type="button" id="custom-validate" class="secondary" data-i18n="validate">Validar</button>
        <button type="button" id="custom-save" data-i18n="saveAndUse">Guardar y usar</button>
      </div>
      <textarea id="custom-rules-text" spellcheck="false"></textarea>
      <div id="custom-rules-message"></div>
    </div>
  </div>
</div>
<div id="folder-modal" class="modal" role="dialog" aria-modal="true">
  <div class="modal-card">
    <div class="modal-head">
      <strong data-i18n="selectFolder">Seleccionar carpeta</strong>
      <button type="button" id="folder-close" class="secondary" data-i18n="close">Cerrar</button>
    </div>
    <div class="modal-body">
      <div class="path-picker browser-path">
        <input id="folder-current" value="{html.escape(str(Path.home()))}">
        <button type="button" id="folder-go" data-i18n="go">Ir</button>
      </div>
      <div class="path-picker browser-path">
        <button type="button" id="folder-parent" class="secondary" data-i18n="parentFolder">Subir nivel</button>
        <button type="button" id="folder-select" data-i18n="useFolder">Usar esta carpeta</button>
      </div>
      <div id="folder-list" class="browser-list"></div>
    </div>
  </div>
</div>
<script>
const form = document.getElementById('scan-form');
const button = document.getElementById('scan-button');
const result = document.getElementById('result');
const folderModal = document.getElementById('folder-modal');
const folderCurrent = document.getElementById('folder-current');
const folderList = document.getElementById('folder-list');
let activePathInput = null;
const demoTarget = {json.dumps(str(demo_target))};
const demoOutput = {json.dumps(str(demo_output))};
const rulesCatalog = {json.dumps(rules_catalog, ensure_ascii=False)};
const rulesCatalogEn = {json.dumps(rules_catalog_en, ensure_ascii=False)};
const customRulesTemplate = `rules:
  - id: CLIENT-001
    title: Flag interno de bypass activado
    severity: Alta
    category: Politica interna
    cvss: 8.1
    confidence: Media
    remediation_effort: Baja
    regexes:
      - bypassAuth\\s*[:=]\\s*true
      - DISABLE_AUTH\\s*=\\s*true
    file_globs:
      - "*.js"
      - "*.ts"
      - "*.py"
      - "*.env*"
    description: Detecta flags internos que pueden desactivar autenticación o controles de seguridad.
    why_dangerous: Si este flag llega a produccion, puede permitir acceso no autorizado.
    exploit_concept: Un atacante podria aprovechar endpoints o flujos sin controles efectivos.
    recommendation: Eliminar el flag o limitarlo a tests aislados fuera de produccion.
    secure_example: Usar feature flags controlados por entorno y validaciones server-side.
    reference: Politica interna / OWASP A01 Broken Access Control
`;
const UI_TRANSLATIONS = {{
  es: {{
    headerSubtitle: 'Análisis local preliminar de seguridad para código, APIs, CI/CD, cloud e IA. Detecta patrones de riesgo, prioriza evidencias y genera entregables para validación experta.',
    pillLocal: 'Local',
    pillPrivate: 'Privado',
    newScan: 'Nuevo escaneo',
    demoNote: 'Demo recomendada: usa una carpeta concreta de proyecto. Evita escanear carpetas grandes como el escritorio completo.',
    quickDemo: 'Demo rápida',
    fastMode: 'Modo rápido',
    ruleCatalog: 'Catálogo de reglas',
    guidedDemo: 'Demo guiada',
    customRules: 'Reglas custom',
    scanSection: 'Escaneo',
    projectPath: 'Ruta del proyecto',
    browse: 'Explorar',
    profile: 'Perfil',
    stack: 'Stack',
    reportSection: 'Informe',
    outputFolder: 'Carpeta de salida',
    client: 'Cliente',
    auditor: 'Auditor',
    scope: 'Alcance',
    reportVersion: 'Versión del informe',
    reportLanguage: 'Idioma de la interfaz e informes',
    advancedOptions: 'Opciones avanzadas',
    customRulesFile: 'Reglas custom YAML/JSON',
    compareBaseline: 'Comparar con baseline anterior de la carpeta de salida',
    optionalBaseline: 'Baseline anterior opcional',
    allowExternalWrite: 'Permitir escrituras fuera de la carpeta de trabajo',
    ollamaTriage: 'Triage local con Ollama',
    ollamaModel: 'Modelo Ollama',
    ollamaUrl: 'URL Ollama',
    ollamaLimit: 'Límite Ollama',
    ollamaMinSeverity: 'Severidad mínima Ollama',
    hideLikelyFp: 'Ocultar probables falsos positivos',
    generate: 'Generar análisis preliminar',
    deliveryPanel: 'Panel de entrega',
    readyTitle: 'Listo para generar un pack de revisión preliminar.',
    readyBody: 'El resultado incluirá resumen ejecutivo, informe técnico, dashboard, JSON, SARIF, baseline y checklist de remediación.',
    readyBullet1: 'La auditoría automática no sustituye la revisión experta.',
    readyBullet2: 'Los hallazgos se entregan priorizados para validación humana.',
    readyBullet3: 'Usa la demo rápida para una presentación controlada.',
    rulesCatalogTitle: 'Catálogo de reglas',
    close: 'Cerrar',
    rulesCatalogBody: 'Reglas determinísticas locales agrupadas por severidad, categoría y perfil. Ollama es una capa opcional de triage, no sustituye estas reglas.',
    ruleSearch: 'Buscar regla, OWASP, categoría...',
    severityAny: 'Severidad',
    categoryAny: 'Categoría',
    profileAny: 'Perfil',
    sevCritical: 'Crítica',
    sevHigh: 'Alta',
    sevMedium: 'Media',
    sevLow: 'Baja',
    customRulesTitle: 'Editor de reglas custom',
    customRulesBody: 'Las reglas core son de solo lectura. Este editor crea o modifica un pack YAML externo para políticas internas del cliente.',
    customRulesYaml: 'Archivo YAML de reglas custom',
    template: 'Plantilla',
    load: 'Cargar',
    validate: 'Validar',
    saveAndUse: 'Guardar y usar',
    selectFolder: 'Seleccionar carpeta',
    go: 'Ir',
    parentFolder: 'Subir nivel',
    useFolder: 'Usar esta carpeta',
    loading: 'Cargando...',
    open: 'Abrir',
    noFolders: 'Sin subcarpetas visibles.',
    guidedReadyTitle: 'Demo guiada preparada.',
    guidedReadyBody: 'Pulsa “Generar análisis preliminar” y enseña los entregables en este orden:',
    guidedBullet1: 'Dashboard: vista ejecutiva y filtros.',
    guidedBullet2: 'Informe técnico HTML: evidencia y remediación.',
    guidedBullet3: 'Resumen PDF: entrega para dirección.',
    guidedBullet4: 'JSON/SARIF: integración técnica y CI/CD.',
    ruleCount: '{{count}} reglas visibles de {{total}}',
    confidence: 'Confianza',
    fix: 'Corrección',
    reference: 'Referencia',
    scanningTitle: 'Escaneando proyecto...',
    progress1: '1. Leyendo archivos y aplicando reglas locales',
    progress2: '2. Priorizando severidad, CVSS y hallazgos compuestos',
    progress3: '3. Generando informe, dashboard, JSON, SARIF y checklist',
    progress4: '4. Preparando enlaces de entrega',
    risk: 'Riesgo',
    critical: 'Críticos',
    high: 'Altos',
    total: 'Total',
    humanReview: 'Validación humana',
    pending: 'pendientes',
    confirmed: 'confirmados',
    falsePositive: 'falsos positivos',
    accepted: 'aceptados',
    fixed: 'corregidos',
    revalidated: 'revalidados',
    beforeAfter: 'Comparativa antes/después',
    new: 'Nuevos',
    persistent: 'Persistentes',
    improvement: 'Mejora',
    priorityFindings: 'Hallazgos prioritarios',
    noFindings: 'Sin hallazgos.',
    baseline: 'Baseline',
    projectSha: 'SHA256 proyecto',
    ollama: 'Ollama',
    probableReal: 'reales',
    reviewNeeded: 'revisión',
    likelyFp: 'falsos positivos',
    customRulesCount: 'Reglas custom',
    manualEvidence: 'Motivo / evidencia manual',
    ticket: 'Ticket',
    fixCommit: 'Commit de fix',
    verification: 'Verificación',
    save: 'Guardar',
    saved: 'Guardado',
    technicalHtml: 'Informe técnico HTML',
    executivePdf: 'Resumen PDF',
    technicalMd: 'Informe técnico MD',
    findingsJson: 'Hallazgos JSON',
    checklist: 'Checklist',
    invalidReviewSave: 'No se pudo guardar la validación',
    templateLoaded: 'Plantilla cargada. Cambia id, regexes y recomendación para tu cliente.',
    fileLoaded: 'Archivo cargado: {{path}}',
    invalidRules: 'Reglas inválidas',
    customRuleValidated: '{{count}} regla(s) custom validada(s): {{rules}}',
    cannotLoadFile: 'No se pudo cargar el archivo',
    cannotSave: 'No se pudo guardar',
    customRuleSaved: '{{count}} regla(s) guardada(s). Se usarán en el próximo escaneo.',
    unknownError: 'Error desconocido'
  }},
  en: {{
    headerSubtitle: 'Local preliminary security analysis for code, APIs, CI/CD, cloud and AI. It detects risk patterns, prioritizes evidence and generates deliverables for expert validation.',
    pillLocal: 'Local',
    pillPrivate: 'Private',
    newScan: 'New Scan',
    demoNote: 'Recommended demo: use a specific project folder. Avoid scanning large folders such as the whole Desktop.',
    quickDemo: 'Quick Demo',
    fastMode: 'Fast Mode',
    ruleCatalog: 'Rule Catalog',
    guidedDemo: 'Guided Demo',
    customRules: 'Custom Rules',
    scanSection: 'Scan',
    projectPath: 'Project Path',
    browse: 'Browse',
    profile: 'Profile',
    stack: 'Stack',
    reportSection: 'Report',
    outputFolder: 'Output Folder',
    client: 'Client',
    auditor: 'Reviewer',
    scope: 'Scope',
    reportVersion: 'Report Version',
    reportLanguage: 'Interface and Report Language',
    advancedOptions: 'Advanced Options',
    customRulesFile: 'Custom Rules YAML/JSON',
    compareBaseline: 'Compare with previous baseline from the output folder',
    optionalBaseline: 'Optional previous baseline',
    allowExternalWrite: 'Allow writes outside the working folder',
    ollamaTriage: 'Local triage with Ollama',
    ollamaModel: 'Ollama Model',
    ollamaUrl: 'Ollama URL',
    ollamaLimit: 'Ollama Limit',
    ollamaMinSeverity: 'Minimum Ollama Severity',
    hideLikelyFp: 'Hide likely false positives',
    generate: 'Generate Preliminary Analysis',
    deliveryPanel: 'Delivery Panel',
    readyTitle: 'Ready to generate a preliminary review package.',
    readyBody: 'The result includes an executive summary, technical report, dashboard, JSON, SARIF, baseline and remediation checklist.',
    readyBullet1: 'The automated audit does not replace expert review.',
    readyBullet2: 'Findings are prioritized for human validation.',
    readyBullet3: 'Use the quick demo for a controlled presentation.',
    rulesCatalogTitle: 'Rule Catalog',
    close: 'Close',
    rulesCatalogBody: 'Local deterministic rules grouped by severity, category and profile. Ollama is an optional triage layer and does not replace these rules.',
    ruleSearch: 'Search rule, OWASP, category...',
    severityAny: 'Severity',
    categoryAny: 'Category',
    profileAny: 'Profile',
    sevCritical: 'Critical',
    sevHigh: 'High',
    sevMedium: 'Medium',
    sevLow: 'Low',
    customRulesTitle: 'Custom Rules Editor',
    customRulesBody: 'Core rules are read-only. This editor creates or modifies an external YAML pack for internal team policies.',
    customRulesYaml: 'Custom Rules YAML File',
    template: 'Template',
    load: 'Load',
    validate: 'Validate',
    saveAndUse: 'Save and Use',
    selectFolder: 'Select Folder',
    go: 'Go',
    parentFolder: 'Parent Folder',
    useFolder: 'Use This Folder',
    loading: 'Loading...',
    open: 'Open',
    noFolders: 'No visible subfolders.',
    guidedReadyTitle: 'Guided demo ready.',
    guidedReadyBody: 'Click “Generate Preliminary Analysis” and show the deliverables in this order:',
    guidedBullet1: 'Dashboard: executive view and filters.',
    guidedBullet2: 'Technical HTML report: evidence and remediation.',
    guidedBullet3: 'PDF summary: management-ready delivery.',
    guidedBullet4: 'JSON/SARIF: technical and CI/CD integration.',
    ruleCount: '{{count}} visible rules out of {{total}}',
    confidence: 'Confidence',
    fix: 'Fix',
    reference: 'Reference',
    scanningTitle: 'Scanning project...',
    progress1: '1. Reading files and applying local rules',
    progress2: '2. Prioritizing severity, CVSS and composite findings',
    progress3: '3. Generating report, dashboard, JSON, SARIF and checklist',
    progress4: '4. Preparing delivery links',
    risk: 'Risk',
    critical: 'Critical',
    high: 'High',
    total: 'Total',
    humanReview: 'Human Review',
    pending: 'pending',
    confirmed: 'confirmed',
    falsePositive: 'false positives',
    accepted: 'accepted',
    fixed: 'fixed',
    revalidated: 'revalidated',
    beforeAfter: 'Before/After Comparison',
    new: 'New',
    persistent: 'Persistent',
    improvement: 'Improvement',
    priorityFindings: 'Priority Findings',
    noFindings: 'No findings.',
    baseline: 'Baseline',
    projectSha: 'Project SHA256',
    ollama: 'Ollama',
    probableReal: 'real',
    reviewNeeded: 'review',
    likelyFp: 'false positives',
    customRulesCount: 'Custom Rules',
    manualEvidence: 'Manual rationale / evidence',
    ticket: 'Ticket',
    fixCommit: 'Fix commit',
    verification: 'Verification',
    save: 'Save',
    saved: 'Saved',
    technicalHtml: 'Technical HTML Report',
    executivePdf: 'Executive PDF Summary',
    technicalMd: 'Technical MD Report',
    findingsJson: 'Findings JSON',
    checklist: 'Checklist',
    invalidReviewSave: 'Could not save the review decision',
    templateLoaded: 'Template loaded. Change id, regexes and recommendation for your team.',
    fileLoaded: 'File loaded: {{path}}',
    invalidRules: 'Invalid rules',
    customRuleValidated: '{{count}} custom rule(s) validated: {{rules}}',
    cannotLoadFile: 'Could not load the file',
    cannotSave: 'Could not save',
    customRuleSaved: '{{count}} rule(s) saved. They will be used in the next scan.',
    unknownError: 'Unknown error'
  }}
}};
function escapeHtml(value) {{
  return String(value ?? '').replace(/[&<>"']/g, ch => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[ch]));
}}
function currentLanguage() {{
  return form.elements.language?.value === 'en' ? 'en' : 'es';
}}
function t(key, vars = {{}}) {{
  let text = (UI_TRANSLATIONS[currentLanguage()] || UI_TRANSLATIONS.es)[key] || UI_TRANSLATIONS.es[key] || key;
  Object.entries(vars).forEach(([name, value]) => {{
    text = text.split('{{{{' + name + '}}}}').join(String(value));
    text = text.split('{{' + name + '}}').join(String(value));
  }});
  return text;
}}
function activeRulesCatalog() {{
  return currentLanguage() === 'en' ? rulesCatalogEn : rulesCatalog;
}}
function applyUiLanguage() {{
  const language = currentLanguage();
  document.documentElement.lang = language;
  document.querySelectorAll('[data-i18n]').forEach(element => {{
    element.textContent = (UI_TRANSLATIONS[language] || UI_TRANSLATIONS.es)[element.dataset.i18n] || element.textContent;
  }});
  document.querySelectorAll('[data-i18n-placeholder]').forEach(element => {{
    element.placeholder = (UI_TRANSLATIONS[language] || UI_TRANSLATIONS.es)[element.dataset.i18nPlaceholder] || element.placeholder;
  }});
  renderRuleCategoryOptions();
  if (document.getElementById('rules-modal').classList.contains('open')) renderRules();
}}
const uiToken = {json.dumps(SESSION_TOKEN)};
const nativeFetch = window.fetch.bind(window);
window.fetch = (url, options = {{}}) => {{
  const headers = new Headers(options.headers || {{}});
  headers.set('X-Preauditor-Token', uiToken);
  return nativeFetch(url, {{ ...options, headers }});
}};
const reviewLabels = {{
  es: {{
    pending: 'Pendiente',
    confirmed: 'Confirmado',
    false_positive: 'Falso positivo',
    accepted_risk: 'Riesgo aceptado',
    fixed: 'Corregido',
    revalidated: 'Revalidado'
  }},
  en: {{
    pending: 'Pending',
    confirmed: 'Confirmed',
    false_positive: 'False positive',
    accepted_risk: 'Accepted risk',
    fixed: 'Fixed',
    revalidated: 'Revalidated'
  }}
}};
function currentReviewLabels() {{
  return reviewLabels[currentLanguage()] || reviewLabels.es;
}}
function renderRuleCategoryOptions() {{
  const select = document.getElementById('rule-category');
  const current = select.value;
  const categories = new Map();
  activeRulesCatalog().forEach(rule => categories.set(rule.raw_category || rule.category, rule.category));
  select.innerHTML = `<option value="">${{escapeHtml(t('categoryAny'))}}</option>` + Array.from(categories.entries())
    .sort((a, b) => a[1].localeCompare(b[1]))
    .map(([value, label]) => `<option value="${{escapeHtml(value)}}">${{escapeHtml(label)}}</option>`)
    .join('');
  select.value = current;
}}
function renderRules() {{
  const catalog = activeRulesCatalog();
  const q = document.getElementById('rule-search').value.toLowerCase();
  const severity = document.getElementById('rule-severity').value;
  const category = document.getElementById('rule-category').value;
  const profile = document.getElementById('rule-profile').value;
  const filtered = catalog.filter(rule => (
    (!severity || (rule.raw_severity || rule.severity) === severity) &&
    (!category || (rule.raw_category || rule.category) === category) &&
    (!profile || rule.profiles.includes(profile)) &&
    (!q || JSON.stringify(rule).toLowerCase().includes(q))
  ));
  document.getElementById('rule-count').textContent = t('ruleCount', {{ count: filtered.length, total: catalog.length }});
  document.getElementById('rule-list').innerHTML = filtered.map(rule => `
    <article class="rule-card">
      <h3>${{escapeHtml(rule.id)}} · ${{escapeHtml(rule.title)}}</h3>
      <div class="rule-meta">
        <span>${{escapeHtml(rule.severity)}}</span>
        <span>${{escapeHtml(rule.category)}}</span>
        <span>CVSS~${{escapeHtml(rule.cvss)}}</span>
        <span>${{escapeHtml(t('confidence'))}} ${{escapeHtml(rule.confidence)}}</span>
        <span>${{escapeHtml(rule.profiles.join(', '))}}</span>
      </div>
      <p>${{escapeHtml(rule.description)}}</p>
      <p><strong>${{escapeHtml(t('fix'))}}:</strong> ${{escapeHtml(rule.recommendation)}}</p>
      <p><strong>${{escapeHtml(t('reference'))}}:</strong> ${{escapeHtml(rule.reference)}}</p>
    </article>
  `).join('');
}}
async function loadFolder(path) {{
  folderList.innerHTML = `<div class="browser-row"><span>${{escapeHtml(t('loading'))}}</span></div>`;
  const response = await fetch(`/browse?path=${{encodeURIComponent(path || '')}}`);
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || 'No se pudo leer la carpeta');
  folderCurrent.value = data.path;
  folderList.innerHTML = data.directories.map(item => `
    <div class="browser-row">
      <span>${{escapeHtml(item.name)}}</span>
      <button type="button" data-path="${{escapeHtml(item.path)}}">${{escapeHtml(t('open'))}}</button>
    </div>
  `).join('') || `<div class="browser-row"><span>${{escapeHtml(t('noFolders'))}}</span></div>`;
}}
document.querySelectorAll('.browse-button').forEach(browse => {{
  browse.addEventListener('click', async () => {{
    activePathInput = form.elements[browse.dataset.target];
    folderModal.classList.add('open');
    try {{
      await loadFolder(activePathInput.value);
    }} catch (error) {{
      folderList.innerHTML = `<div class="browser-row"><span class="error">${{escapeHtml(error.message)}}</span></div>`;
    }}
  }});
}});
folderList.addEventListener('click', async event => {{
  const openButton = event.target.closest('button[data-path]');
  if (!openButton) return;
  try {{
    await loadFolder(openButton.dataset.path);
  }} catch (error) {{
    folderList.innerHTML = `<div class="browser-row"><span class="error">${{escapeHtml(error.message)}}</span></div>`;
  }}
}});
document.getElementById('folder-go').addEventListener('click', async () => loadFolder(folderCurrent.value));
document.getElementById('folder-parent').addEventListener('click', async () => {{
  const parts = folderCurrent.value.replace(/\\/+$/, '').split('/');
  const parent = parts.length > 1 ? parts.slice(0, -1).join('/') || '/' : '/';
  await loadFolder(parent);
}});
document.getElementById('folder-select').addEventListener('click', () => {{
  if (activePathInput) activePathInput.value = folderCurrent.value;
  folderModal.classList.remove('open');
}});
document.getElementById('folder-close').addEventListener('click', () => folderModal.classList.remove('open'));
folderModal.addEventListener('click', event => {{
  if (event.target === folderModal) folderModal.classList.remove('open');
}});
document.getElementById('demo-preset').addEventListener('click', () => {{
  form.elements.target.value = demoTarget;
  form.elements.output_dir.value = demoOutput;
  form.elements.profile.value = 'pro';
  form.elements.stack.value = 'generic';
  form.elements.client.value = currentLanguage() === 'en' ? 'Product Manager Demo' : 'Demo Product Manager';
  form.elements.scope.value = currentLanguage() === 'en' ? 'Controlled demo over a vulnerable sample project' : 'Demo controlada sobre proyecto vulnerable de ejemplo';
  form.elements.ollama.checked = false;
  applyUiLanguage();
}});
document.getElementById('clear-advanced').addEventListener('click', () => {{
  form.elements.rules_file.value = '';
  form.elements.compare_baseline.value = '';
  form.elements.auto_compare.checked = true;
  form.elements.ollama.checked = false;
  form.elements.ollama_filter_fp.checked = false;
  form.elements.ollama_limit.value = '5';
}});
form.elements.language.addEventListener('change', () => {{
  applyUiLanguage();
}});
document.getElementById('guided-demo').addEventListener('click', () => {{
  document.getElementById('demo-preset').click();
  result.innerHTML = `
    <div class="empty">
      <p><strong>${{escapeHtml(t('guidedReadyTitle'))}}</strong></p>
      <p>${{escapeHtml(t('guidedReadyBody'))}}</p>
      <ul>
        <li>${{escapeHtml(t('guidedBullet1'))}}</li>
        <li>${{escapeHtml(t('guidedBullet2'))}}</li>
        <li>${{escapeHtml(t('guidedBullet3'))}}</li>
        <li>${{escapeHtml(t('guidedBullet4'))}}</li>
      </ul>
    </div>
  `;
}});
document.getElementById('rules-open').addEventListener('click', () => {{
  document.getElementById('rules-modal').classList.add('open');
  renderRules();
}});
document.getElementById('rules-close').addEventListener('click', () => document.getElementById('rules-modal').classList.remove('open'));
['rule-search','rule-severity','rule-category','rule-profile'].forEach(id => document.getElementById(id).addEventListener('input', renderRules));
document.getElementById('rules-modal').addEventListener('click', event => {{
  if (event.target === document.getElementById('rules-modal')) document.getElementById('rules-modal').classList.remove('open');
}});
const customRulesModal = document.getElementById('custom-rules-modal');
const customRulesPath = document.getElementById('custom-rules-path');
const customRulesText = document.getElementById('custom-rules-text');
const customRulesMessage = document.getElementById('custom-rules-message');
function customMessage(kind, message) {{
  customRulesMessage.innerHTML = `<div class="${{kind}}">${{escapeHtml(message)}}</div>`;
}}
document.getElementById('custom-rules-open').addEventListener('click', () => {{
  customRulesPath.value = form.elements.rules_file.value || customRulesPath.value;
  if (!customRulesText.value.trim()) customRulesText.value = customRulesTemplate;
  customRulesMessage.innerHTML = '';
  customRulesModal.classList.add('open');
}});
document.getElementById('custom-rules-close').addEventListener('click', () => customRulesModal.classList.remove('open'));
customRulesModal.addEventListener('click', event => {{
  if (event.target === customRulesModal) customRulesModal.classList.remove('open');
}});
document.getElementById('custom-template').addEventListener('click', () => {{
  customRulesText.value = customRulesTemplate;
  customMessage('success', t('templateLoaded'));
}});
document.getElementById('custom-load').addEventListener('click', async () => {{
  try {{
    const response = await fetch(`/custom-rules?path=${{encodeURIComponent(customRulesPath.value)}}`);
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || t('cannotLoadFile'));
    customRulesText.value = data.text;
    customMessage('success', t('fileLoaded', {{ path: data.path }}));
  }} catch (error) {{
    customMessage('warning', error.message);
  }}
}});
document.getElementById('custom-validate').addEventListener('click', async () => {{
  try {{
    const response = await fetch('/custom-rules/validate', {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify({{ text: customRulesText.value }})
    }});
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || t('invalidRules'));
    customMessage('success', t('customRuleValidated', {{ count: data.count, rules: data.rules.join(', ') }}));
  }} catch (error) {{
    customMessage('warning', error.message);
  }}
}});
document.getElementById('custom-save').addEventListener('click', async () => {{
  try {{
    const response = await fetch('/custom-rules/save', {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify({{ path: customRulesPath.value, text: customRulesText.value, allow_external_write: form.elements.allow_external_write.checked ? '1' : '' }})
    }});
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || t('cannotSave'));
    form.elements.rules_file.value = data.path;
    customMessage('success', t('customRuleSaved', {{ count: data.count }}));
  }} catch (error) {{
    customMessage('warning', error.message);
  }}
}});
async function saveReview(button) {{
  const container = button.closest('.finding');
  const payload = {{
    review_path: button.dataset.reviewPath,
    fingerprint: button.dataset.fingerprint,
    rule_id: button.dataset.ruleId,
    title: button.dataset.title,
    file: button.dataset.file,
    line: Number(button.dataset.line || 0),
    status: container.querySelector('[data-review-status]').value,
    reviewed_by: form.elements.auditor.value,
    rationale: container.querySelector('[data-review-rationale]').value,
    ticket: container.querySelector('[data-review-ticket]').value,
    fix_commit: container.querySelector('[data-review-fix]').value,
    verification: container.querySelector('[data-review-verification]').value
  }};
  const response = await fetch('/review', {{
    method: 'POST',
    headers: {{ 'Content-Type': 'application/json' }},
    body: JSON.stringify(payload)
  }});
  const data = await response.json();
  if (!response.ok) {{
    alert(data.error || t('invalidReviewSave'));
    return;
  }}
  button.textContent = t('saved');
  setTimeout(() => button.textContent = t('save'), 1200);
}}
form.addEventListener('submit', async (event) => {{
  event.preventDefault();
  button.disabled = true;
  result.innerHTML = `
    <div class="empty">
      <p><strong>${{escapeHtml(t('scanningTitle'))}}</strong></p>
      <div class="progress-list">
        <div class="progress-step active">${{escapeHtml(t('progress1'))}}</div>
        <div class="progress-step active">${{escapeHtml(t('progress2'))}}</div>
        <div class="progress-step active">${{escapeHtml(t('progress3'))}}</div>
        <div class="progress-step">${{escapeHtml(t('progress4'))}}</div>
      </div>
    </div>`;
  const payload = Object.fromEntries(new FormData(form).entries());
  try {{
    const response = await fetch('/scan', {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify(payload)
    }});
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || t('unknownError'));
    const isEnglish = data.language === 'en';
    const resultText = UI_TRANSLATIONS[isEnglish ? 'en' : 'es'];
    const linkLabels = {{
      Dashboard: 'Dashboard',
      'Informe técnico HTML': resultText.technicalHtml,
      'Resumen PDF': resultText.executivePdf,
      'Informe técnico MD': resultText.technicalMd,
      'Hallazgos JSON': resultText.findingsJson,
      SARIF: 'SARIF',
      Baseline: resultText.baseline,
      Review: 'Review',
      Checklist: resultText.checklist
    }};
    const preferred = ['Dashboard', 'Informe técnico HTML', 'Resumen PDF', 'Informe técnico MD', 'Hallazgos JSON', 'SARIF', 'Baseline', 'Review', 'Checklist'];
    const links = preferred.filter(name => data.files[name]).map(name => `<a href="/artifact?path=${{encodeURIComponent(data.files[name])}}" target="_blank">${{escapeHtml(linkLabels[name] || name)}}</a>`).join('');
    const warnings = (data.warnings || []).map(w => `<div class="warning">${{escapeHtml(w)}}</div>`).join('');
    const labels = currentReviewLabels();
    const reviewOptions = Object.entries(labels).map(([value, label]) => `<option value="${{value}}">${{label}}</option>`).join('');
    const findings = data.findings.slice(0, 10).map(f => `
      <div class="finding">
        <span class="badge ${{f.severity}}">${{f.severity}}</span>
        <strong>${{f.rule_id}} · ${{f.title}}</strong>
        <p><code>${{f.file}}:${{f.line}}</code> · CVSS ${{f.cvss}} · ${{f.category}}</p>
        <p><strong>${{escapeHtml(resultText.humanReview)}}:</strong> ${{escapeHtml(labels[f.review?.status || 'pending'])}}</p>
        <div class="review-controls">
          <select data-review-status>${{reviewOptions}}</select>
          <input data-review-rationale placeholder="${{escapeHtml(resultText.manualEvidence)}}" value="${{escapeHtml(f.review?.rationale || '')}}">
          <input data-review-ticket placeholder="${{escapeHtml(resultText.ticket)}}" value="${{escapeHtml(f.review?.ticket || '')}}">
          <button type="button"
            data-review-path="${{escapeHtml(data.review_path)}}"
            data-fingerprint="${{escapeHtml(f.fingerprint)}}"
            data-rule-id="${{escapeHtml(f.rule_id)}}"
            data-title="${{escapeHtml(f.title)}}"
            data-file="${{escapeHtml(f.file)}}"
            data-line="${{escapeHtml(f.line)}}"
            onclick="saveReview(this)">${{escapeHtml(resultText.save)}}</button>
        </div>
        <div class="review-controls">
          <input data-review-fix placeholder="${{escapeHtml(resultText.fixCommit)}}" value="${{escapeHtml(f.review?.fix_commit || '')}}">
          <input data-review-verification placeholder="${{escapeHtml(resultText.verification)}}" value="${{escapeHtml(f.review?.verification || '')}}">
        </div>
      </div>`).join('');
    const comparison = data.comparison ? `
      <div class="comparison ${{data.comparison.status}}">
        <p><strong>${{resultText.beforeAfter}}:</strong> ${{data.comparison_status_label || data.comparison.status}}</p>
        <p>${{escapeHtml(resultText.baseline)}}: <code>${{escapeHtml(data.comparison.baseline)}}</code></p>
        <div class="comparison-grid">
          <div><span>${{resultText.new}}</span><strong>${{data.comparison.new}}</strong></div>
          <div><span>${{resultText.fixed}}</span><strong>${{data.comparison.fixed}}</strong></div>
          <div><span>${{resultText.persistent}}</span><strong>${{data.comparison.persistent}}</strong></div>
          <div><span>${{resultText.improvement}}</span><strong>${{data.comparison.improvement_percent}}%</strong></div>
        </div>
      </div>
    ` : '';
    result.innerHTML = `
      <div class="kpis">
        <div class="kpi"><span>${{resultText.risk}}</span><strong>${{data.risk}}</strong></div>
        <div class="kpi"><span>${{resultText.critical}}</span><strong>${{data.counts.Critica}}</strong></div>
        <div class="kpi"><span>${{resultText.high}}</span><strong>${{data.counts.Alta}}</strong></div>
        <div class="kpi"><span>${{resultText.total}}</span><strong>${{data.findings.length}}</strong></div>
        <div class="kpi"><span>AI Agent</span><strong>${{data.ai.score}}/100</strong></div>
      </div>
      ${{data.ollama ? `<p><strong>${{resultText.ollama}}:</strong> ${{resultText.probableReal}}=${{data.ollama.probable_real}} · ${{resultText.reviewNeeded}}=${{data.ollama.requiere_revision}} · ${{resultText.likelyFp}}=${{data.ollama.probable_falso_positivo}}</p>` : ''}}
      ${{data.custom_rules ? `<p><strong>${{resultText.customRulesCount}}:</strong> ${{data.custom_rules}}</p>` : ''}}
      <p><strong>${{resultText.humanReview}}:</strong> ${{resultText.pending}}=${{data.review_counts.pending}} · ${{resultText.confirmed}}=${{data.review_counts.confirmed}} · ${{resultText.falsePositive}}=${{data.review_counts.false_positive}} · ${{resultText.accepted}}=${{data.review_counts.accepted_risk}} · ${{resultText.fixed}}=${{data.review_counts.fixed}} · ${{resultText.revalidated}}=${{data.review_counts.revalidated}}</p>
      ${{comparison}}
      ${{warnings}}
      <p><strong>${{resultText.projectSha}}:</strong> <code>${{data.project_sha256}}</code></p>
      <div class="links">${{links}}</div>
      <h2>${{resultText.priorityFindings}}</h2>
      ${{findings || `<p>${{resultText.noFindings}}</p>`}}
    `;
    document.querySelectorAll('[data-review-status]').forEach((select, index) => {{
      const finding = data.findings[index];
      if (finding?.review?.status) select.value = finding.review.status;
    }});
  }} catch (error) {{
    result.innerHTML = `<p class="error">${{error.message}}</p>`;
  }} finally {{
    button.disabled = false;
  }}
}});
applyUiLanguage();
</script>
"""
    return page_shell(content)


def safe_artifact(path_value: str) -> Path | None:
    path = Path(unquote(path_value)).expanduser().resolve()
    if any(path == root or root in path.parents for root in GENERATED_ARTIFACT_ROOTS):
        return path if path.exists() and path.is_file() else None
    return None


def browse_folder(path_value: str) -> dict:
    candidate = Path(unquote(path_value or str(Path.home()))).expanduser()
    if not candidate.is_absolute():
        candidate = (APP_ROOT / candidate).resolve()
    else:
        candidate = candidate.resolve()

    while not candidate.exists() and candidate != candidate.parent:
        candidate = candidate.parent
    if not candidate.exists() or not candidate.is_dir():
        candidate = Path.home().resolve()

    directories = []
    try:
        for child in candidate.iterdir():
            if child.name.startswith("."):
                continue
            if child.is_dir():
                directories.append(
                    {
                        "name": child.name,
                        "path": str(child.resolve()),
                    }
                )
    except OSError as exc:
        raise ValueError(f"No se puede leer la carpeta: {exc}") from exc

    directories.sort(key=lambda item: item["name"].lower())
    return {
        "path": str(candidate),
        "parent": str(candidate.parent),
        "directories": directories,
    }


def resolve_custom_rules_path(path_value: str) -> Path:
    if not path_value.strip():
        raise ValueError("Indica una ruta para el archivo de reglas custom.")
    path = Path(unquote(path_value)).expanduser()
    if not path.is_absolute():
        path = (APP_ROOT / path).resolve()
    else:
        path = path.resolve()
    if path.suffix.lower() not in {".yml", ".yaml", ".json"}:
        raise ValueError("El archivo de reglas custom debe ser .yml, .yaml o .json.")
    return path


def validate_custom_rules_text(text: str) -> list[preauditor.Rule]:
    if not text.strip():
        raise ValueError("El contenido de reglas custom esta vacio.")
    with tempfile.NamedTemporaryFile("w", suffix=".yml", encoding="utf-8", delete=False) as handle:
        handle.write(text)
        temp_path = Path(handle.name)
    try:
        return preauditor.load_custom_rules(temp_path)
    finally:
        temp_path.unlink(missing_ok=True)


def load_custom_rules_text(path_value: str) -> dict:
    path = resolve_custom_rules_path(path_value)
    if not path.exists():
        raise ValueError(f"Archivo no encontrado: {path}")
    return {"path": str(path), "text": path.read_text(encoding="utf-8", errors="replace")}


def save_custom_rules_text(path_value: str, text: str, allow_external_write: bool = False) -> dict:
    rules = validate_custom_rules_text(text)
    path = resolve_custom_rules_path(path_value)
    assert_write_allowed(path, allow_external_write)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.rstrip() + "\n", encoding="utf-8")
    return {"path": str(path), "count": len(rules), "rules": [rule.rule_id for rule in rules]}


def save_review_decision(payload: dict) -> dict:
    review_path = Path(payload.get("review_path", "")).expanduser().resolve()
    if review_path.suffix.lower() != ".json":
        raise ValueError("La validación humana debe guardarse en un archivo JSON.")
    if not any(is_within(review_path, root) for root in GENERATED_ARTIFACT_ROOTS):
        raise ValueError("review.json solo puede guardarse en carpetas generadas por la herramienta en esta sesion.")
    review_path.parent.mkdir(parents=True, exist_ok=True)
    records = preauditor.load_review_records(review_path)
    fingerprint = str(payload.get("fingerprint", "")).strip()
    if not fingerprint:
        raise ValueError("Falta fingerprint del hallazgo.")
    record = preauditor.normalize_review_record(
        {
            "fingerprint": fingerprint,
            "status": payload.get("status", "pending"),
            "reviewed_by": payload.get("reviewed_by", ""),
            "reviewed_at": utc_timestamp(),
            "rationale": payload.get("rationale", ""),
            "ticket": payload.get("ticket", ""),
            "fix_commit": payload.get("fix_commit", ""),
            "verification": payload.get("verification", ""),
            "rule_id": payload.get("rule_id", ""),
            "title": payload.get("title", ""),
            "file": payload.get("file", ""),
            "line": payload.get("line", 0),
        }
    )
    records[fingerprint] = record
    review_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "updated_at": utc_timestamp(),
                "reviews": list(records.values()),
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    return {"path": str(review_path), "record": record}


def scan_project(payload: dict) -> dict:
    target = Path(payload.get("target", "")).expanduser().resolve()
    if not target.exists() or not target.is_dir():
        raise ValueError(f"Ruta invalida: {target}")

    output_dir = Path(payload.get("output_dir", "")).expanduser().resolve()
    assert_write_allowed(output_dir, bool(payload.get("allow_external_write")))
    output_dir.mkdir(parents=True, exist_ok=True)
    GENERATED_ARTIFACT_ROOTS.add(output_dir)
    profile = payload.get("profile", "pro")
    stack = payload.get("stack", "generic")
    if profile not in preauditor.PROFILES:
        raise ValueError(f"Perfil invalido: {profile}")
    if stack not in preauditor.STACKS:
        raise ValueError(f"Stack invalido: {stack}")

    language = payload.get("language", "es") if payload.get("language", "es") in preauditor.LANGUAGES else "es"
    client = payload.get("client", "Cliente no especificado")
    auditor = payload.get("auditor", "Consultor especializado")
    scope = payload.get("scope", "Análisis preliminar local de seguridad")
    if language == "en":
        if client == "Cliente no especificado":
            client = "Unspecified client"
        if auditor == "Consultor especializado":
            auditor = "Specialist reviewer"
        if scope == "Análisis preliminar local de seguridad":
            scope = "Local preliminary security assessment"
    meta = preauditor.ReportMeta(
        client=client,
        auditor=auditor,
        scope=scope,
        version=payload.get("report_version", "1.0"),
        stack=stack,
        language=language,
    )
    rules_file = payload.get("rules_file", "").strip()
    custom_rules = preauditor.load_custom_rules(Path(rules_file).expanduser().resolve() if rules_file else None)
    findings = preauditor.scan(target, profile, custom_rules=custom_rules)
    ollama_assessments = {}
    if payload.get("ollama"):
        try:
            ollama_limit = int(payload.get("ollama_limit", "20"))
        except ValueError:
            ollama_limit = 20
        ollama_min_severity = payload.get("ollama_min_severity", "Alta")
        if ollama_min_severity not in preauditor.SEVERITY_ORDER:
            ollama_min_severity = "Alta"
        ollama_assessments = preauditor.analyze_with_ollama(
            findings,
            meta,
            payload.get("ollama_url", "http://127.0.0.1:11434"),
            payload.get("ollama_model", "llama3.1"),
            max(ollama_limit, 0),
            ollama_min_severity,
        )
        if payload.get("ollama_filter_fp"):
            findings = preauditor.filter_ollama_false_positives(findings, ollama_assessments)
    project_sha = preauditor.project_hash(target)

    files = {
        "Informe técnico MD": output_dir / "informe-tecnico.md",
        "Informe técnico HTML": output_dir / "informe-tecnico.html",
        "Resumen PDF": output_dir / "resumen-direccion.pdf",
        "Dashboard": output_dir / "dashboard.html",
        "Hallazgos JSON": output_dir / "hallazgos.json",
        "SARIF": output_dir / "hallazgos.sarif",
        "Baseline": output_dir / "baseline.json",
        "Checklist": output_dir / "checklist-remediacion.md",
        "Review": output_dir / "review.json",
    }
    review_records = preauditor.load_review_records(files["Review"])
    compare_value = payload.get("compare_baseline", "").strip()
    compare_path = Path(compare_value).expanduser().resolve() if compare_value else None
    auto_compare = bool(payload.get("auto_compare"))
    if not compare_path and auto_compare and files["Baseline"].exists():
        compare_path = files["Baseline"]
    comparison = preauditor.compare_with_baseline(findings, compare_path)

    markdown = preauditor.render_markdown(
        findings,
        target,
        profile,
        meta,
        project_sha,
        comparison=comparison,
        ollama_assessments=ollama_assessments,
        review_records=review_records,
    )
    pdf_written = preauditor.write_report(
        markdown,
        files["Informe técnico MD"],
        files["Informe técnico HTML"],
        findings,
        target,
        profile,
        meta,
        files["Resumen PDF"],
        files["Dashboard"],
        project_sha,
        comparison=comparison,
        ollama_assessments=ollama_assessments,
        review_records=review_records,
    )
    preauditor.write_json(
        findings,
        files["Hallazgos JSON"],
        profile,
        meta,
        project_sha,
        comparison=comparison,
        ollama_assessments=ollama_assessments,
        review_records=review_records,
    )
    preauditor.write_sarif(findings, files["SARIF"], meta.language)
    files["Baseline"].write_text(
        json.dumps(preauditor.baseline_payload(findings, target, profile, meta, project_sha, review_records), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    if not files["Review"].exists():
        files["Review"].write_text(
            json.dumps(
                {
                    "schema_version": "1.0",
                    "updated_at": utc_timestamp(),
                    "reviews": [],
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
    preauditor.write_checklist(findings, files["Checklist"], meta.language)
    ai_score, ai_level, ai_reasons = preauditor.ai_agent_risk_score(findings)
    ollama_counts = None
    if ollama_assessments:
        ollama_counts = {"probable_real": 0, "requiere_revision": 0, "probable_falso_positivo": 0}
        for assessment in ollama_assessments.values():
            verdict = assessment.get("verdict", "requiere_revision")
            ollama_counts[verdict] = ollama_counts.get(verdict, 0) + 1
    warnings = []
    if not pdf_written:
        if meta.language == "en":
            warnings.append("PDF not generated: install reportlab or run the UI from a Python environment where it is available.")
        else:
            warnings.append("PDF no generado: instala reportlab o ejecuta la UI desde un entorno que lo tenga disponible.")
    existing_files = {name: str(path) for name, path in files.items() if path.exists()}

    return {
        "language": meta.language,
        "risk": preauditor.risk_label(preauditor.global_risk(findings), meta.language),
        "counts": preauditor.severity_counts(findings),
        "project_sha256": project_sha,
        "ai": {"score": ai_score, "level": preauditor.level_label(ai_level, meta.language), "raw_level": ai_level, "reasons": ai_reasons},
        "ollama": ollama_counts,
        "custom_rules": len(custom_rules),
        "comparison": comparison,
        "comparison_status_label": preauditor.comparison_status_label(comparison["status"], meta.language) if comparison else None,
        "review_counts": preauditor.review_counts(findings, review_records),
        "review_path": str(files["Review"]),
        "warnings": warnings,
        "files": existing_files,
        "findings": [preauditor.finding_payload(finding, review_records, meta.language) for finding in findings],
    }


class Handler(BaseHTTPRequestHandler):
    def end_headers(self) -> None:
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        super().end_headers()

    def validate_host(self) -> bool:
        host = header_hostname(self.headers.get("Host", ""))
        return host in LOOPBACK_HOSTS

    def validate_origin(self) -> bool:
        origin = self.headers.get("Origin")
        if not origin:
            return True
        parsed = urlparse(origin)
        return (parsed.hostname or "").lower() in {"127.0.0.1", "localhost", "::1"} and parsed.port in {None, self.server.server_port}

    def send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if not self.validate_host():
            self.send_error(400, "Host no permitido")
            return
        parsed = urlparse(self.path)
        if parsed.path in {"/browse", "/custom-rules"} and self.headers.get("X-Preauditor-Token") != SESSION_TOKEN:
            self.send_json(403, {"error": "Token de sesion invalido"})
            return
        if parsed.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(render_home())
            return
        if parsed.path == "/artifact":
            params = parse_qs(parsed.query)
            artifact = safe_artifact(params.get("path", [""])[0])
            if not artifact:
                self.send_error(404)
                return
            content_type = "application/octet-stream"
            if artifact.suffix == ".html":
                content_type = "text/html; charset=utf-8"
            elif artifact.suffix == ".pdf":
                content_type = "application/pdf"
            elif artifact.suffix in {".json", ".sarif"}:
                content_type = "application/json; charset=utf-8"
            elif artifact.suffix == ".md":
                content_type = "text/plain; charset=utf-8"
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.end_headers()
            self.wfile.write(artifact.read_bytes())
            return
        if parsed.path == "/browse":
            params = parse_qs(parsed.query)
            try:
                body = json.dumps(
                    browse_folder(params.get("path", [""])[0]),
                    ensure_ascii=False,
                ).encode("utf-8")
                self.send_response(200)
            except Exception as exc:
                body = json.dumps({"error": str(exc)}, ensure_ascii=False).encode("utf-8")
                self.send_response(400)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == "/custom-rules":
            params = parse_qs(parsed.query)
            try:
                body = json.dumps(
                    load_custom_rules_text(params.get("path", [""])[0]),
                    ensure_ascii=False,
                ).encode("utf-8")
                self.send_response(200)
            except Exception as exc:
                body = json.dumps({"error": str(exc)}, ensure_ascii=False).encode("utf-8")
                self.send_response(400)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_error(404)

    def do_POST(self) -> None:
        if not self.validate_host():
            self.send_json(400, {"error": "Host no permitido"})
            return
        if not self.validate_origin():
            self.send_json(403, {"error": "Origin no permitido"})
            return
        if self.headers.get("X-Preauditor-Token") != SESSION_TOKEN:
            self.send_json(403, {"error": "Token de sesion invalido"})
            return
        content_type = self.headers.get("Content-Type", "")
        if not content_type.lower().startswith("application/json"):
            self.send_json(415, {"error": "Content-Type debe ser application/json"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_json(400, {"error": "Content-Length invalido"})
            return
        if length > MAX_POST_BYTES:
            self.send_json(413, {"error": "Peticion demasiado grande"})
            return
        if self.path not in {"/scan", "/custom-rules/validate", "/custom-rules/save", "/review"}:
            self.send_error(404)
            return
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            if self.path == "/scan":
                response = scan_project(payload)
            elif self.path == "/custom-rules/validate":
                rules = validate_custom_rules_text(payload.get("text", ""))
                response = {"count": len(rules), "rules": [rule.rule_id for rule in rules]}
            elif self.path == "/custom-rules/save":
                response = save_custom_rules_text(payload.get("path", ""), payload.get("text", ""), bool(payload.get("allow_external_write")))
            else:
                response = save_review_decision(payload)
            body = json.dumps(response, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(body)
        except Exception as exc:
            body = json.dumps({"error": str(exc)}, ensure_ascii=False).encode("utf-8")
            self.send_response(400)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:
        return


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Interfaz web local de Pre-Auditor IA Pro.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--open", action="store_true", help="Abrir automáticamente en el navegador.")
    parser.add_argument("--allow-remote", action="store_true", help="Permite escuchar fuera de loopback. Uso no recomendado.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.allow_remote and not is_loopback_bind(args.host):
        print("Por seguridad, la UI solo escucha en loopback. Usa --allow-remote si entiendes el riesgo.")
        return 2
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    url = f"http://{args.host}:{args.port}"
    print(f"Pre-Auditor IA Pro UI: {url}")
    if args.open:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nCerrando UI...")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
