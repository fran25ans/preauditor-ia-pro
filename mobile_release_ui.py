#!/usr/bin/env python3
"""Local web UI for Mobile Release Radar."""

from __future__ import annotations

import argparse
import html
import json
import secrets
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

import mobile_release_radar


APP_ROOT = Path.cwd().resolve()
SESSION_TOKEN = secrets.token_urlsafe(32)
MAX_POST_BYTES = 1024 * 1024
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]"}
GENERATED_ARTIFACT_ROOTS = {(APP_ROOT / "deliverables").resolve()}
MOBILE_EXTENSIONS = mobile_release_radar.ANDROID_EXTENSIONS | mobile_release_radar.IOS_EXTENSIONS


def header_hostname(value: str) -> str:
    value = value.strip().lower()
    if value.startswith("["):
        return value.split("]", 1)[0] + "]"
    return value.split(":", 1)[0]


def is_loopback_bind(host: str) -> bool:
    return host.lower() in {"127.0.0.1", "localhost", "::1", "[::1]"}


def is_within(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def assert_write_allowed(path: Path) -> None:
    if is_within(path, APP_ROOT):
        return
    if any(is_within(path, root) for root in GENERATED_ARTIFACT_ROOTS):
        return
    raise ValueError("Output folder must be inside the working folder or a generated deliverables folder.")


def page_shell(content: str) -> bytes:
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Mobile Release Radar</title>
  <style>
    :root {{ --ink:#172033; --muted:#667085; --line:#d8dee8; --panel:#f7f9fc; --brand:#0f766e; --brand-dark:#115e59; --critical:#a31925; --high:#c2410c; --medium:#9a6700; --low:#176f4d; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; font-family:Arial, sans-serif; color:var(--ink); background:#eef3f8; }}
    header {{ background:#fff; border-bottom:1px solid var(--line); padding:22px 28px; }}
    main {{ max-width:1240px; margin:0 auto; padding:24px; }}
    h1 {{ margin:0 0 6px; font-size:30px; }}
    h2 {{ margin:0 0 14px; font-size:19px; }}
    h3 {{ margin:18px 0 10px; font-size:13px; letter-spacing:.02em; text-transform:uppercase; color:var(--muted); }}
    p {{ margin:0 0 10px; color:var(--muted); line-height:1.45; }}
    label {{ display:block; font-size:13px; font-weight:700; margin:12px 0 5px; }}
    input, select, button {{ width:100%; border:1px solid var(--line); border-radius:6px; padding:10px; font-size:14px; background:#fff; color:var(--ink); }}
    button {{ background:var(--brand); color:#fff; border-color:var(--brand); font-weight:700; cursor:pointer; margin-top:16px; }}
    button:hover {{ background:var(--brand-dark); border-color:var(--brand-dark); }}
    button:disabled {{ opacity:.55; cursor:wait; }}
    code {{ background:#eef2f7; border-radius:4px; padding:2px 5px; }}
    a {{ color:var(--brand); font-weight:700; text-decoration:none; }}
    .topbar {{ max-width:1240px; margin:0 auto; display:flex; justify-content:space-between; align-items:flex-start; gap:18px; }}
    .status {{ display:flex; gap:8px; flex-wrap:wrap; justify-content:flex-end; }}
    .pill {{ border:1px solid var(--line); border-radius:999px; padding:6px 10px; background:#f8fafc; font-size:12px; font-weight:700; color:var(--brand-dark); }}
    .grid {{ display:grid; grid-template-columns:430px 1fr; gap:18px; align-items:start; }}
    .panel {{ background:#fff; border:1px solid var(--line); border-radius:8px; padding:18px; box-shadow:0 8px 24px rgba(15,23,42,.05); }}
    .section {{ border-top:1px solid var(--line); padding-top:14px; margin-top:14px; }}
    .section:first-child {{ border-top:0; padding-top:0; margin-top:0; }}
    .path-picker {{ display:grid; grid-template-columns:1fr 104px; gap:8px; }}
    .path-picker button {{ margin-top:0; }}
    .secondary {{ background:#fff; color:var(--brand); }}
    .secondary:hover {{ background:#eefaf7; color:var(--brand-dark); }}
    .quick-actions {{ display:grid; grid-template-columns:1fr 1fr; gap:8px; margin-bottom:8px; }}
    .note {{ border:1px solid #c7d2fe; background:#eef2ff; color:#3730a3; border-radius:8px; padding:12px; font-size:13px; }}
    .empty {{ border:1px dashed var(--line); border-radius:8px; padding:18px; background:#f8fafc; }}
    .kpis {{ display:grid; grid-template-columns:repeat(5,minmax(0,1fr)); gap:10px; margin:12px 0 18px; }}
    .kpi {{ background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:12px; min-height:78px; }}
    .kpi span {{ display:block; color:var(--muted); font-size:12px; text-transform:uppercase; }}
    .kpi strong {{ display:block; margin-top:5px; font-size:22px; }}
    .decision {{ display:inline-block; border-radius:999px; padding:6px 10px; color:#fff; font-weight:700; background:var(--brand); }}
    .decision.blocked {{ background:var(--critical); }}
    .decision.needs_review {{ background:var(--high); }}
    .links {{ display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:8px; margin:12px 0 18px; }}
    .links a {{ border:1px solid var(--line); border-radius:6px; padding:10px; background:#fff; }}
    .finding {{ border-top:1px solid var(--line); padding:12px 0; }}
    .badge {{ display:inline-block; color:#fff; border-radius:999px; padding:4px 9px; font-size:12px; font-weight:700; }}
    .Critical {{ background:var(--critical); }} .High {{ background:var(--high); }} .Medium {{ background:var(--medium); }} .Low {{ background:var(--low); }}
    .delta {{ border:1px solid #99f6e4; background:#f0fdfa; border-radius:8px; padding:14px; margin:12px 0 18px; }}
    .delta-grid {{ display:grid; grid-template-columns:repeat(4,1fr); gap:8px; margin-top:10px; }}
    .delta-grid div {{ background:#fff; border:1px solid var(--line); border-radius:8px; padding:10px; }}
    .delta-grid span {{ display:block; color:var(--muted); font-size:12px; text-transform:uppercase; }}
    .delta-grid strong {{ display:block; margin-top:4px; font-size:20px; }}
    .modal {{ position:fixed; inset:0; display:none; place-items:center; background:rgba(15,23,42,.42); padding:20px; z-index:20; }}
    .modal.open {{ display:grid; }}
    .modal-card {{ width:min(780px,100%); max-height:82vh; overflow:hidden; background:#fff; border:1px solid var(--line); border-radius:8px; box-shadow:0 18px 60px rgba(15,23,42,.24); }}
    .modal-head {{ display:grid; grid-template-columns:1fr auto; gap:12px; align-items:center; padding:14px; border-bottom:1px solid var(--line); }}
    .modal-body {{ padding:14px; }}
    .browser-path {{ margin-bottom:10px; }}
    .browser-list {{ border:1px solid var(--line); border-radius:8px; max-height:390px; overflow:auto; }}
    .browser-row {{ display:grid; grid-template-columns:1fr auto auto; gap:8px; align-items:center; padding:10px 12px; border-bottom:1px solid var(--line); }}
    .browser-row:last-child {{ border-bottom:0; }}
    .browser-row button {{ width:auto; margin:0; padding:7px 10px; }}
    .error {{ color:#a31925; font-weight:700; }}
    .warning {{ border:1px solid #facc15; background:#fefce8; color:#854d0e; border-radius:8px; padding:12px; margin:10px 0; font-size:13px; }}
    @media (max-width:900px) {{ .topbar {{ display:block; }} .status {{ justify-content:flex-start; margin-top:12px; }} .grid,.kpis,.links,.quick-actions,.delta-grid {{ grid-template-columns:1fr; }} }}
  </style>
</head>
<body>
  <header>
    <div class="topbar">
      <div>
        <h1>Mobile Release Radar</h1>
        <p>Local release gate for Android APK/AAB and iOS IPA builds. It compares artifacts, highlights mobile risk deltas and generates review deliverables.</p>
      </div>
      <div class="status">
        <span class="pill">Local</span>
        <span class="pill">Android</span>
        <span class="pill">iOS</span>
      </div>
    </div>
  </header>
  <main>{content}</main>
</body>
</html>
""".encode("utf-8")


def render_home() -> bytes:
    demo_apk = Path("/Users/franciscojosegimenoesteban/Downloads/85.apk")
    default_artifact = demo_apk if demo_apk.exists() else APP_ROOT
    default_output = APP_ROOT / "deliverables" / "mobile-ui-scan"
    content = f"""
<div class="grid">
  <section class="panel">
    <h2>New Mobile Release Check</h2>
    <p class="note">Recommended flow: select the current APK/AAB/IPA and optionally the previous build to get a before/after release delta.</p>
    <div class="quick-actions">
      <button type="button" id="demo-preset" class="secondary">Use 85.apk Demo</button>
      <button type="button" id="clear-previous" class="secondary">Current Build Only</button>
    </div>
    <form id="scan-form">
      <div class="section">
        <h3>Artifacts</h3>
        <label>Current APK/AAB/IPA</label>
        <div class="path-picker">
          <input name="artifact" value="{html.escape(str(default_artifact))}" required>
          <button type="button" class="browse-button" data-target="artifact" data-kind="file">Browse</button>
        </div>
        <label>Previous APK/AAB/IPA optional</label>
        <div class="path-picker">
          <input name="previous" placeholder="/path/to/previous.apk">
          <button type="button" class="browse-button" data-target="previous" data-kind="file">Browse</button>
        </div>
        <label>Platform</label>
        <select name="platform">
          <option value="auto">Auto detect</option>
          <option value="android">Android</option>
          <option value="ios">iOS</option>
        </select>
      </div>
      <div class="section">
        <h3>Output</h3>
        <label>Output folder</label>
        <div class="path-picker">
          <input name="output_dir" value="{html.escape(str(default_output))}" required>
          <button type="button" class="browse-button" data-target="output_dir" data-kind="folder">Browse</button>
        </div>
      </div>
      <button id="scan-button" class="primary" type="submit">Analyze Mobile Release</button>
    </form>
  </section>
  <section class="panel">
    <h2>Release Decision</h2>
    <div id="result">
      <div class="empty">
        <p><strong>Ready to analyze a mobile build.</strong></p>
        <p>The result will include release decision, score, Android/iOS metadata, findings, before/after delta and links to HTML, Markdown and JSON deliverables.</p>
      </div>
    </div>
  </section>
</div>
<div id="browser-modal" class="modal" role="dialog" aria-modal="true">
  <div class="modal-card">
    <div class="modal-head">
      <strong>Select Path</strong>
      <button type="button" id="browser-close" class="secondary">Close</button>
    </div>
    <div class="modal-body">
      <div class="path-picker browser-path">
        <input id="browser-current" value="{html.escape(str(Path.home()))}">
        <button type="button" id="browser-go">Go</button>
      </div>
      <div class="path-picker browser-path">
        <button type="button" id="browser-parent" class="secondary">Parent Folder</button>
        <button type="button" id="browser-select-folder">Use This Folder</button>
      </div>
      <div id="browser-list" class="browser-list"></div>
    </div>
  </div>
</div>
<script>
const form = document.getElementById('scan-form');
const button = document.getElementById('scan-button');
const result = document.getElementById('result');
const browserModal = document.getElementById('browser-modal');
const browserCurrent = document.getElementById('browser-current');
const browserList = document.getElementById('browser-list');
let activePathInput = null;
let activeBrowseKind = 'file';
const demoArtifact = {json.dumps(str(demo_apk))};
const uiToken = {json.dumps(SESSION_TOKEN)};
const nativeFetch = window.fetch.bind(window);
window.fetch = (url, options = {{}}) => {{
  const headers = new Headers(options.headers || {{}});
  headers.set('X-Mobile-Radar-Token', uiToken);
  return nativeFetch(url, {{ ...options, headers }});
}};
function escapeHtml(value) {{
  return String(value ?? '').replace(/[&<>"']/g, ch => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[ch]));
}}
async function loadPath(path) {{
  browserList.innerHTML = '<div class="browser-row"><span>Loading...</span></div>';
  const response = await fetch(`/browse?path=${{encodeURIComponent(path || '')}}&kind=${{encodeURIComponent(activeBrowseKind)}}`);
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || 'Could not read path');
  browserCurrent.value = data.path;
  const folders = data.directories.map(item => `
    <div class="browser-row">
      <span>📁 ${{escapeHtml(item.name)}}</span>
      <button type="button" data-open="${{escapeHtml(item.path)}}">Open</button>
      <span></span>
    </div>
  `).join('');
  const files = data.files.map(item => `
    <div class="browser-row">
      <span>📦 ${{escapeHtml(item.name)}}</span>
      <button type="button" data-select="${{escapeHtml(item.path)}}">Use</button>
      <span>${{escapeHtml(item.size_label)}}</span>
    </div>
  `).join('');
  browserList.innerHTML = folders + files || '<div class="browser-row"><span>No visible folders or mobile artifacts.</span><span></span><span></span></div>';
}}
document.querySelectorAll('.browse-button').forEach(browse => {{
  browse.addEventListener('click', async () => {{
    activePathInput = form.elements[browse.dataset.target];
    activeBrowseKind = browse.dataset.kind || 'file';
    document.getElementById('browser-select-folder').style.display = activeBrowseKind === 'folder' ? 'block' : 'none';
    browserModal.classList.add('open');
    try {{
      await loadPath(activePathInput.value);
    }} catch (error) {{
      browserList.innerHTML = `<div class="browser-row"><span class="error">${{escapeHtml(error.message)}}</span><span></span><span></span></div>`;
    }}
  }});
}});
browserList.addEventListener('click', async event => {{
  const openButton = event.target.closest('button[data-open]');
  const selectButton = event.target.closest('button[data-select]');
  if (openButton) {{
    await loadPath(openButton.dataset.open);
  }}
  if (selectButton && activePathInput) {{
    activePathInput.value = selectButton.dataset.select;
    browserModal.classList.remove('open');
  }}
}});
document.getElementById('browser-go').addEventListener('click', async () => loadPath(browserCurrent.value));
document.getElementById('browser-parent').addEventListener('click', async () => {{
  const parts = browserCurrent.value.replace(/\\/+$/, '').split('/');
  const parent = parts.length > 1 ? parts.slice(0, -1).join('/') || '/' : '/';
  await loadPath(parent);
}});
document.getElementById('browser-select-folder').addEventListener('click', () => {{
  if (activePathInput) activePathInput.value = browserCurrent.value;
  browserModal.classList.remove('open');
}});
document.getElementById('browser-close').addEventListener('click', () => browserModal.classList.remove('open'));
browserModal.addEventListener('click', event => {{
  if (event.target === browserModal) browserModal.classList.remove('open');
}});
document.getElementById('demo-preset').addEventListener('click', () => {{
  form.elements.artifact.value = demoArtifact;
  form.elements.previous.value = '';
  form.elements.platform.value = 'auto';
}});
document.getElementById('clear-previous').addEventListener('click', () => {{
  form.elements.previous.value = '';
}});
form.addEventListener('submit', async event => {{
  event.preventDefault();
  button.disabled = true;
  result.innerHTML = `
    <div class="empty">
      <p><strong>Analyzing mobile release...</strong></p>
      <p>Decoding artifact, extracting mobile metadata, comparing release delta and generating deliverables.</p>
    </div>
  `;
  const payload = Object.fromEntries(new FormData(form).entries());
  try {{
    const response = await fetch('/scan', {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify(payload)
    }});
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Unknown error');
    const files = ['HTML Report', 'Markdown Report', 'JSON Data'].filter(name => data.files[name]).map(name =>
      `<a href="/artifact?path=${{encodeURIComponent(data.files[name])}}" target="_blank">${{escapeHtml(name)}}</a>`
    ).join('');
    const findings = data.findings.slice(0, 10).map(f => `
      <div class="finding">
        <span class="badge ${{escapeHtml(f.severity)}}">${{escapeHtml(f.severity)}}</span>
        <strong>${{escapeHtml(f.rule_id)}} · ${{escapeHtml(f.title)}}</strong>
        <p><code>${{escapeHtml(f.location)}}</code> · ${{escapeHtml(f.category)}}</p>
        <p><strong>Evidence:</strong> <code>${{escapeHtml(f.evidence)}}</code></p>
        <p><strong>Fix:</strong> ${{escapeHtml(f.recommendation)}}</p>
      </div>
    `).join('');
    const addedDangerous = data.comparison.added_dangerous_permissions.slice(0, 8).map(x => `<li><code>${{escapeHtml(x)}}</code></li>`).join('');
    const addedComponents = data.comparison.added_exported_components.slice(0, 8).map(x => `<li><code>${{escapeHtml(x)}}</code></li>`).join('');
    const addedDomains = data.comparison.added_domains.slice(0, 8).map(x => `<li><code>${{escapeHtml(x)}}</code></li>`).join('');
    result.innerHTML = `
      <p><span class="decision ${{escapeHtml(data.decision)}}">${{escapeHtml(data.decision.toUpperCase())}}</span></p>
      <div class="kpis">
        <div class="kpi"><span>Release Score</span><strong>${{data.release_score}}/100</strong></div>
        <div class="kpi"><span>Platform</span><strong>${{escapeHtml(data.platform)}}</strong></div>
        <div class="kpi"><span>Findings</span><strong>${{data.findings.length}}</strong></div>
        <div class="kpi"><span>New</span><strong>${{data.comparison.new_findings}}</strong></div>
        <div class="kpi"><span>Fixed</span><strong>${{data.comparison.fixed_findings}}</strong></div>
      </div>
      <p><strong>App:</strong> ${{escapeHtml(data.app_name || data.package_name || data.bundle_id || 'Unknown')}}</p>
      <p><strong>Artifact:</strong> <code>${{escapeHtml(data.artifact)}}</code></p>
      <div class="delta">
        <p><strong>Before/after release delta</strong></p>
        <div class="delta-grid">
          <div><span>Persistent</span><strong>${{data.comparison.persistent_findings}}</strong></div>
          <div><span>New permissions</span><strong>${{data.comparison.added_permissions.length}}</strong></div>
          <div><span>New exported</span><strong>${{data.comparison.added_exported_components.length}}</strong></div>
          <div><span>New domains</span><strong>${{data.comparison.added_domains.length}}</strong></div>
        </div>
      </div>
      <div class="links">${{files}}</div>
      ${{addedDangerous ? `<h3>New dangerous permissions</h3><ul>${{addedDangerous}}</ul>` : ''}}
      ${{addedComponents ? `<h3>New exported components</h3><ul>${{addedComponents}}</ul>` : ''}}
      ${{addedDomains ? `<h3>New domains</h3><ul>${{addedDomains}}</ul>` : ''}}
      <h2>Priority Findings</h2>
      ${{findings || '<p>No findings detected.</p>'}}
    `;
  }} catch (error) {{
    result.innerHTML = `<p class="error">${{escapeHtml(error.message)}}</p>`;
  }} finally {{
    button.disabled = false;
  }}
}});
</script>
"""
    return page_shell(content)


def safe_artifact(path_value: str) -> Path | None:
    path = Path(unquote(path_value)).expanduser().resolve()
    if any(path == root or root in path.parents for root in GENERATED_ARTIFACT_ROOTS):
        return path if path.exists() and path.is_file() else None
    return None


def size_label(size: int) -> str:
    if size > 1024 * 1024:
        return f"{size / 1024 / 1024:.1f} MB"
    if size > 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size} B"


def browse_path(path_value: str, kind: str = "file") -> dict:
    candidate = Path(unquote(path_value or str(Path.home()))).expanduser()
    if not candidate.is_absolute():
        candidate = (APP_ROOT / candidate).resolve()
    else:
        candidate = candidate.resolve()
    if candidate.is_file():
        candidate = candidate.parent
    while not candidate.exists() and candidate != candidate.parent:
        candidate = candidate.parent
    if not candidate.exists() or not candidate.is_dir():
        candidate = Path.home().resolve()
    directories = []
    files = []
    try:
        for child in candidate.iterdir():
            if child.name.startswith("."):
                continue
            if child.is_dir():
                directories.append({"name": child.name, "path": str(child.resolve())})
            elif kind == "file" and child.suffix.lower() in MOBILE_EXTENSIONS:
                files.append({"name": child.name, "path": str(child.resolve()), "size_label": size_label(child.stat().st_size)})
    except OSError as exc:
        raise ValueError(f"Could not read folder: {exc}") from exc
    directories.sort(key=lambda item: item["name"].lower())
    files.sort(key=lambda item: item["name"].lower())
    return {"path": str(candidate), "directories": directories, "files": files}


def scan_mobile_release(payload: dict) -> dict:
    artifact = Path(payload.get("artifact", "")).expanduser().resolve()
    previous_value = payload.get("previous", "").strip()
    previous_path = Path(previous_value).expanduser().resolve() if previous_value else None
    output_dir = Path(payload.get("output_dir", "")).expanduser().resolve()
    assert_write_allowed(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    GENERATED_ARTIFACT_ROOTS.add(output_dir)
    platform = payload.get("platform", "auto")
    if platform not in {"auto", "android", "ios"}:
        platform = "auto"
    current = mobile_release_radar.analyze_artifact(artifact, platform)
    previous = mobile_release_radar.analyze_artifact(previous_path, platform) if previous_path else None
    result = mobile_release_radar.result_payload(current, previous)
    files = {
        "Markdown Report": output_dir / "mobile-release-report.md",
        "HTML Report": output_dir / "mobile-release-report.html",
        "JSON Data": output_dir / "mobile-release-report.json",
    }
    mobile_release_radar.write_outputs(result, files["Markdown Report"], files["HTML Report"], files["JSON Data"])
    current_payload = result["current"]
    return {
        "decision": result["decision"],
        "release_score": result["release_score"],
        "platform": current_payload["platform"],
        "artifact": current_payload["artifact"],
        "package_name": current_payload.get("package_name", ""),
        "bundle_id": current_payload.get("bundle_id", ""),
        "app_name": current_payload.get("display_name", ""),
        "findings": current_payload["findings"],
        "comparison": result["comparison"],
        "files": {name: str(path) for name, path in files.items() if path.exists()},
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
        return header_hostname(self.headers.get("Host", "")) in LOOPBACK_HOSTS

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
            self.send_error(400, "Host not allowed")
            return
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(render_home())
            return
        if parsed.path in {"/browse"} and self.headers.get("X-Mobile-Radar-Token") != SESSION_TOKEN:
            self.send_json(403, {"error": "Invalid session token"})
            return
        if parsed.path == "/browse":
            params = parse_qs(parsed.query)
            try:
                self.send_json(200, browse_path(params.get("path", [""])[0], params.get("kind", ["file"])[0]))
            except Exception as exc:
                self.send_json(400, {"error": str(exc)})
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
            elif artifact.suffix == ".json":
                content_type = "application/json; charset=utf-8"
            elif artifact.suffix == ".md":
                content_type = "text/plain; charset=utf-8"
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.end_headers()
            self.wfile.write(artifact.read_bytes())
            return
        self.send_error(404)

    def do_POST(self) -> None:
        if not self.validate_host():
            self.send_json(400, {"error": "Host not allowed"})
            return
        if not self.validate_origin():
            self.send_json(403, {"error": "Origin not allowed"})
            return
        if self.headers.get("X-Mobile-Radar-Token") != SESSION_TOKEN:
            self.send_json(403, {"error": "Invalid session token"})
            return
        if not self.headers.get("Content-Type", "").lower().startswith("application/json"):
            self.send_json(415, {"error": "Content-Type must be application/json"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_json(400, {"error": "Invalid Content-Length"})
            return
        if length > MAX_POST_BYTES:
            self.send_json(413, {"error": "Request too large"})
            return
        if self.path != "/scan":
            self.send_error(404)
            return
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            self.send_json(200, scan_mobile_release(payload))
        except Exception as exc:
            self.send_json(400, {"error": str(exc)})

    def log_message(self, format: str, *args) -> None:
        return


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Local web UI for Mobile Release Radar.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8780)
    parser.add_argument("--open", action="store_true", help="Open automatically in the browser.")
    args = parser.parse_args(argv)
    if not is_loopback_bind(args.host):
        parser.error("For safety, Mobile Release Radar UI only listens on loopback.")
    return args


def main() -> int:
    args = parse_args()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    url = f"http://{args.host}:{args.port}"
    print(f"Mobile Release Radar UI: {url}")
    if args.open:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nClosing Mobile Release Radar UI...")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
