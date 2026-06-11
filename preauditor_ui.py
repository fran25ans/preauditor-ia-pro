#!/usr/bin/env python3
"""Local web UI for Pre-Auditor IA Pro."""

from __future__ import annotations

import argparse
import html
import json
import tempfile
import threading
import webbrowser
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlparse

import preauditor


APP_ROOT = Path.cwd().resolve()


def page_shell(content: str) -> bytes:
    return f"""<!doctype html>
<html lang="es">
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
    .error {{ color:#a31925; font-weight:700; }}
    @media (max-width:900px) {{ .topbar {{ display:block; }} .status {{ justify-content:flex-start; margin-top:12px; }} .grid,.kpis,.links,.quick-actions,.rule-tools,.editor-actions {{ grid-template-columns:1fr; }} }}
  </style>
</head>
<body>
  <header>
    <div class="topbar">
      <div>
        <h1>Pre-Auditor IA Pro</h1>
        <p>Primer analista local de seguridad: detecta riesgos, prioriza hallazgos y genera un pack listo para revision experta.</p>
      </div>
      <div class="status">
        <span class="pill">Local</span>
        <span class="pill">Privado</span>
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
    rule_categories = sorted({rule["category"] for rule in rules_catalog})
    content = f"""
<div class="grid">
  <section class="panel">
    <h2>Nuevo escaneo</h2>
    <p class="note">Demo recomendada: usa una carpeta concreta de proyecto. Evita escanear carpetas grandes como el escritorio completo.</p>
    <div class="quick-actions">
      <button type="button" id="demo-preset" class="secondary">Demo rápida</button>
      <button type="button" id="clear-advanced" class="secondary">Modo rápido</button>
      <button type="button" id="rules-open" class="secondary">Catálogo de reglas</button>
      <button type="button" id="guided-demo" class="secondary">Demo guiada</button>
      <button type="button" id="custom-rules-open" class="secondary">Reglas custom</button>
    </div>
    <form id="scan-form">
      <div class="section">
        <h3>Escaneo</h3>
        <label>Ruta del proyecto</label>
        <div class="path-picker">
          <input name="target" value="{html.escape(str(demo_target if demo_target.exists() else APP_ROOT))}" required>
          <button type="button" class="browse-button" data-target="target">Explorar</button>
        </div>
        <label>Perfil</label>
        <select name="profile">{profiles}</select>
        <label>Stack</label>
        <select name="stack">{stacks}</select>
      </div>
      <div class="section">
        <h3>Informe</h3>
        <label>Carpeta de salida</label>
        <div class="path-picker">
          <input name="output_dir" value="{html.escape(str(APP_ROOT / 'deliverables' / 'ui-scan'))}" required>
          <button type="button" class="browse-button" data-target="output_dir">Explorar</button>
        </div>
        <label>Cliente</label>
        <input name="client" value="Cliente demo">
        <label>Auditor</label>
        <input name="auditor" value="Francisco José Gimeno">
        <label>Alcance</label>
        <input name="scope" value="Pre-auditoria local de seguridad">
        <label>Versión del informe</label>
        <input name="report_version" value="{datetime.now().strftime('%Y.%m')}">
      </div>
      <div class="section">
        <h3>Opciones avanzadas</h3>
        <label>Reglas custom YAML/JSON</label>
        <input name="rules_file" placeholder="/ruta/a/preauditor-rules.yml">
        <label class="check"><input type="checkbox" name="ollama" value="1"> Triage local con Ollama</label>
        <label>Modelo Ollama</label>
        <input name="ollama_model" value="llama3.1">
        <label>URL Ollama</label>
        <input name="ollama_url" value="http://127.0.0.1:11434">
        <label>Limite Ollama</label>
        <input name="ollama_limit" value="20">
        <label>Severidad minima Ollama</label>
        <select name="ollama_min_severity">
          <option value="Alta">Alta</option>
          <option value="Critica">Critica</option>
          <option value="Media">Media</option>
          <option value="Baja">Baja</option>
        </select>
        <label class="check"><input type="checkbox" name="ollama_filter_fp" value="1"> Ocultar probables falsos positivos</label>
      </div>
      <button id="scan-button" class="primary" type="submit">Generar pre-auditoria profesional</button>
    </form>
  </section>
  <section class="panel">
    <h2>Panel de entrega</h2>
    <div id="result">
      <div class="empty">
        <p><strong>Listo para generar un pack profesional.</strong></p>
        <p>El resultado incluirá resumen ejecutivo, informe tecnico, dashboard, JSON, SARIF, baseline y checklist de remediacion.</p>
        <ul>
          <li>La auditoria automatica no sustituye la revision experta.</li>
          <li>Los hallazgos se entregan priorizados para validacion humana.</li>
          <li>Usa la demo rapida para una presentacion controlada.</li>
        </ul>
      </div>
    </div>
  </section>
</div>
<div id="rules-modal" class="modal" role="dialog" aria-modal="true">
  <div class="modal-card">
    <div class="modal-head">
      <strong>Catálogo de reglas</strong>
      <button type="button" id="rules-close" class="secondary">Cerrar</button>
    </div>
    <div class="modal-body">
      <p>Reglas determinísticas locales agrupadas por severidad, categoría y perfil. Ollama es una capa opcional de triage, no sustituye estas reglas.</p>
      <div class="rule-tools">
        <input id="rule-search" placeholder="Buscar regla, OWASP, categoría...">
        <select id="rule-severity">
          <option value="">Severidad</option>
          <option value="Critica">Crítica</option>
          <option value="Alta">Alta</option>
          <option value="Media">Media</option>
          <option value="Baja">Baja</option>
        </select>
        <select id="rule-category">
          <option value="">Categoría</option>
          {''.join(f'<option value="{html.escape(category)}">{html.escape(category)}</option>' for category in rule_categories)}
        </select>
        <select id="rule-profile">
          <option value="">Perfil</option>
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
      <strong>Editor de reglas custom</strong>
      <button type="button" id="custom-rules-close" class="secondary">Cerrar</button>
    </div>
    <div class="modal-body">
      <p>Las reglas core son de solo lectura. Este editor crea o modifica un pack YAML externo para políticas internas del cliente.</p>
      <label>Archivo YAML de reglas custom</label>
      <input id="custom-rules-path" value="{html.escape(str(APP_ROOT / 'custom-rules.yml'))}">
      <div class="editor-actions">
        <button type="button" id="custom-template" class="secondary">Plantilla</button>
        <button type="button" id="custom-load" class="secondary">Cargar</button>
        <button type="button" id="custom-validate" class="secondary">Validar</button>
        <button type="button" id="custom-save">Guardar y usar</button>
      </div>
      <textarea id="custom-rules-text" spellcheck="false"></textarea>
      <div id="custom-rules-message"></div>
    </div>
  </div>
</div>
<div id="folder-modal" class="modal" role="dialog" aria-modal="true">
  <div class="modal-card">
    <div class="modal-head">
      <strong>Seleccionar carpeta</strong>
      <button type="button" id="folder-close" class="secondary">Cerrar</button>
    </div>
    <div class="modal-body">
      <div class="path-picker browser-path">
        <input id="folder-current" value="{html.escape(str(Path.home()))}">
        <button type="button" id="folder-go">Ir</button>
      </div>
      <div class="path-picker browser-path">
        <button type="button" id="folder-parent" class="secondary">Subir nivel</button>
        <button type="button" id="folder-select">Usar esta carpeta</button>
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
    description: Detecta flags internos que pueden desactivar autenticacion o controles de seguridad.
    why_dangerous: Si este flag llega a produccion, puede permitir acceso no autorizado.
    exploit_concept: Un atacante podria aprovechar endpoints o flujos sin controles efectivos.
    recommendation: Eliminar el flag o limitarlo a tests aislados fuera de produccion.
    secure_example: Usar feature flags controlados por entorno y validaciones server-side.
    reference: Politica interna / OWASP A01 Broken Access Control
`;
function escapeHtml(value) {{
  return String(value ?? '').replace(/[&<>"']/g, ch => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[ch]));
}}
function renderRules() {{
  const q = document.getElementById('rule-search').value.toLowerCase();
  const severity = document.getElementById('rule-severity').value;
  const category = document.getElementById('rule-category').value;
  const profile = document.getElementById('rule-profile').value;
  const filtered = rulesCatalog.filter(rule => (
    (!severity || rule.severity === severity) &&
    (!category || rule.category === category) &&
    (!profile || rule.profiles.includes(profile)) &&
    (!q || JSON.stringify(rule).toLowerCase().includes(q))
  ));
  document.getElementById('rule-count').textContent = `${{filtered.length}} reglas visibles de ${{rulesCatalog.length}}`;
  document.getElementById('rule-list').innerHTML = filtered.map(rule => `
    <article class="rule-card">
      <h3>${{escapeHtml(rule.id)}} · ${{escapeHtml(rule.title)}}</h3>
      <div class="rule-meta">
        <span>${{escapeHtml(rule.severity)}}</span>
        <span>${{escapeHtml(rule.category)}}</span>
        <span>CVSS~${{escapeHtml(rule.cvss)}}</span>
        <span>Confianza ${{escapeHtml(rule.confidence)}}</span>
        <span>${{escapeHtml(rule.profiles.join(', '))}}</span>
      </div>
      <p>${{escapeHtml(rule.description)}}</p>
      <p><strong>Corrección:</strong> ${{escapeHtml(rule.recommendation)}}</p>
      <p><strong>Referencia:</strong> ${{escapeHtml(rule.reference)}}</p>
    </article>
  `).join('');
}}
async function loadFolder(path) {{
  folderList.innerHTML = '<div class="browser-row"><span>Cargando...</span></div>';
  const response = await fetch(`/browse?path=${{encodeURIComponent(path || '')}}`);
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || 'No se pudo leer la carpeta');
  folderCurrent.value = data.path;
  folderList.innerHTML = data.directories.map(item => `
    <div class="browser-row">
      <span>${{escapeHtml(item.name)}}</span>
      <button type="button" data-path="${{escapeHtml(item.path)}}">Abrir</button>
    </div>
  `).join('') || '<div class="browser-row"><span>Sin subcarpetas visibles.</span></div>';
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
  form.elements.client.value = 'Demo Product Manager';
  form.elements.scope.value = 'Demo controlada sobre proyecto vulnerable de ejemplo';
  form.elements.ollama.checked = false;
}});
document.getElementById('clear-advanced').addEventListener('click', () => {{
  form.elements.rules_file.value = '';
  form.elements.ollama.checked = false;
  form.elements.ollama_filter_fp.checked = false;
  form.elements.ollama_limit.value = '5';
}});
document.getElementById('guided-demo').addEventListener('click', () => {{
  document.getElementById('demo-preset').click();
  result.innerHTML = `
    <div class="empty">
      <p><strong>Demo guiada preparada.</strong></p>
      <p>Pulsa “Generar pre-auditoría profesional” y enseña los entregables en este orden:</p>
      <ul>
        <li>Dashboard: vista ejecutiva y filtros.</li>
        <li>Informe técnico HTML: evidencia y remediación.</li>
        <li>Resumen PDF: entrega para dirección.</li>
        <li>JSON/SARIF: integración técnica y CI/CD.</li>
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
  customMessage('success', 'Plantilla cargada. Cambia id, regexes y recomendación para tu cliente.');
}});
document.getElementById('custom-load').addEventListener('click', async () => {{
  try {{
    const response = await fetch(`/custom-rules?path=${{encodeURIComponent(customRulesPath.value)}}`);
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'No se pudo cargar el archivo');
    customRulesText.value = data.text;
    customMessage('success', `Archivo cargado: ${{data.path}}`);
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
    if (!response.ok) throw new Error(data.error || 'Reglas invalidas');
    customMessage('success', `${{data.count}} regla(s) custom validada(s): ${{data.rules.join(', ')}}`);
  }} catch (error) {{
    customMessage('warning', error.message);
  }}
}});
document.getElementById('custom-save').addEventListener('click', async () => {{
  try {{
    const response = await fetch('/custom-rules/save', {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify({{ path: customRulesPath.value, text: customRulesText.value }})
    }});
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'No se pudo guardar');
    form.elements.rules_file.value = data.path;
    customMessage('success', `${{data.count}} regla(s) guardada(s). Se usaran en el proximo escaneo.`);
  }} catch (error) {{
    customMessage('warning', error.message);
  }}
}});
form.addEventListener('submit', async (event) => {{
  event.preventDefault();
  button.disabled = true;
  result.innerHTML = `
    <div class="empty">
      <p><strong>Escaneando proyecto...</strong></p>
      <div class="progress-list">
        <div class="progress-step active">1. Leyendo archivos y aplicando reglas locales</div>
        <div class="progress-step active">2. Priorizando severidad, CVSS y hallazgos compuestos</div>
        <div class="progress-step active">3. Generando informe, dashboard, JSON, SARIF y checklist</div>
        <div class="progress-step">4. Preparando enlaces de entrega</div>
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
    if (!response.ok) throw new Error(data.error || 'Error desconocido');
    const preferred = ['Dashboard', 'Informe técnico HTML', 'Resumen PDF', 'Informe técnico MD', 'Hallazgos JSON', 'SARIF', 'Baseline', 'Checklist'];
    const links = preferred.filter(name => data.files[name]).map(name => `<a href="/artifact?path=${{encodeURIComponent(data.files[name])}}" target="_blank">${{name}}</a>`).join('');
    const warnings = (data.warnings || []).map(w => `<div class="warning">${{escapeHtml(w)}}</div>`).join('');
    const findings = data.findings.slice(0, 10).map(f => `
      <div class="finding">
        <span class="badge ${{f.severity}}">${{f.severity}}</span>
        <strong>${{f.rule_id}} · ${{f.title}}</strong>
        <p><code>${{f.file}}:${{f.line}}</code> · CVSS ${{f.cvss}} · ${{f.category}}</p>
      </div>`).join('');
    result.innerHTML = `
      <div class="kpis">
        <div class="kpi"><span>Riesgo</span><strong>${{data.risk}}</strong></div>
        <div class="kpi"><span>Criticos</span><strong>${{data.counts.Critica}}</strong></div>
        <div class="kpi"><span>Altos</span><strong>${{data.counts.Alta}}</strong></div>
        <div class="kpi"><span>Total</span><strong>${{data.findings.length}}</strong></div>
        <div class="kpi"><span>AI Agent</span><strong>${{data.ai.score}}/100</strong></div>
      </div>
      ${{data.ollama ? `<p><strong>Ollama:</strong> reales=${{data.ollama.probable_real}} · revisión=${{data.ollama.requiere_revision}} · falsos positivos=${{data.ollama.probable_falso_positivo}}</p>` : ''}}
      ${{data.custom_rules ? `<p><strong>Reglas custom:</strong> ${{data.custom_rules}}</p>` : ''}}
      ${{warnings}}
      <p><strong>SHA256 proyecto:</strong> <code>${{data.project_sha256}}</code></p>
      <div class="links">${{links}}</div>
      <h2>Hallazgos prioritarios</h2>
      ${{findings || '<p>Sin hallazgos.</p>'}}
    `;
  }} catch (error) {{
    result.innerHTML = `<p class="error">${{error.message}}</p>`;
  }} finally {{
    button.disabled = false;
  }}
}});
</script>
"""
    return page_shell(content)


def safe_artifact(path_value: str) -> Path | None:
    path = Path(unquote(path_value)).expanduser().resolve()
    allowed_roots = [APP_ROOT, Path("/private/tmp").resolve()]
    if any(path == root or root in path.parents for root in allowed_roots):
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


def save_custom_rules_text(path_value: str, text: str) -> dict:
    rules = validate_custom_rules_text(text)
    path = resolve_custom_rules_path(path_value)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.rstrip() + "\n", encoding="utf-8")
    return {"path": str(path), "count": len(rules), "rules": [rule.rule_id for rule in rules]}


def scan_project(payload: dict) -> dict:
    target = Path(payload.get("target", "")).expanduser().resolve()
    if not target.exists() or not target.is_dir():
        raise ValueError(f"Ruta invalida: {target}")

    output_dir = Path(payload.get("output_dir", "")).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    profile = payload.get("profile", "pro")
    stack = payload.get("stack", "generic")
    if profile not in preauditor.PROFILES:
        raise ValueError(f"Perfil invalido: {profile}")
    if stack not in preauditor.STACKS:
        raise ValueError(f"Stack invalido: {stack}")

    meta = preauditor.ReportMeta(
        client=payload.get("client", "Cliente no especificado"),
        auditor=payload.get("auditor", "Consultor especializado"),
        scope=payload.get("scope", "Pre-auditoria local de seguridad"),
        version=payload.get("report_version", "1.0"),
        stack=stack,
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
    }
    markdown = preauditor.render_markdown(findings, target, profile, meta, project_sha, ollama_assessments=ollama_assessments)
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
        ollama_assessments=ollama_assessments,
    )
    preauditor.write_json(findings, files["Hallazgos JSON"], profile, meta, project_sha, ollama_assessments=ollama_assessments)
    preauditor.write_sarif(findings, files["SARIF"])
    files["Baseline"].write_text(
        json.dumps(preauditor.baseline_payload(findings, target, profile, meta, project_sha), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    preauditor.write_checklist(findings, files["Checklist"])
    ai_score, ai_level, ai_reasons = preauditor.ai_agent_risk_score(findings)
    ollama_counts = None
    if ollama_assessments:
        ollama_counts = {"probable_real": 0, "requiere_revision": 0, "probable_falso_positivo": 0}
        for assessment in ollama_assessments.values():
            verdict = assessment.get("verdict", "requiere_revision")
            ollama_counts[verdict] = ollama_counts.get(verdict, 0) + 1
    warnings = []
    if not pdf_written:
        warnings.append("PDF no generado: instala reportlab o ejecuta la UI desde un entorno que lo tenga disponible.")
    existing_files = {name: str(path) for name, path in files.items() if path.exists()}

    return {
        "risk": preauditor.global_risk(findings),
        "counts": preauditor.severity_counts(findings),
        "project_sha256": project_sha,
        "ai": {"score": ai_score, "level": ai_level, "reasons": ai_reasons},
        "ollama": ollama_counts,
        "custom_rules": len(custom_rules),
        "warnings": warnings,
        "files": existing_files,
        "findings": [preauditor.asdict(finding) for finding in findings],
    }


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        parsed = urlparse(self.path)
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
        if self.path not in {"/scan", "/custom-rules/validate", "/custom-rules/save"}:
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            if self.path == "/scan":
                response = scan_project(payload)
            elif self.path == "/custom-rules/validate":
                rules = validate_custom_rules_text(payload.get("text", ""))
                response = {"count": len(rules), "rules": [rule.rule_id for rule in rules]}
            else:
                response = save_custom_rules_text(payload.get("path", ""), payload.get("text", ""))
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
    parser.add_argument("--open", action="store_true", help="Abrir automaticamente en el navegador.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
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
