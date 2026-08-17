#!/usr/bin/env python3
"""Local web UI for ProofSec dynamic authorization validation."""

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

from proofsec.attack_engine import run_dynamic_tests, write_proofs
from proofsec.contract import propose_security_contract, write_contract
from proofsec.invariants import (
    confirm_all_proposed,
    evaluate_invariants,
    invariant_state_payload,
    write_invariant_state,
)
from proofsec.security_model import build_security_model, write_model_json, write_model_sqlite


APP_ROOT = Path.cwd().resolve()
SESSION_TOKEN = secrets.token_urlsafe(32)
MAX_POST_BYTES = 1024 * 1024
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]"}
GENERATED_ARTIFACT_ROOTS = {(APP_ROOT / "deliverables").resolve()}


def is_loopback_bind(host: str) -> bool:
    return host.lower() in {"127.0.0.1", "localhost", "::1", "[::1]"}


def header_hostname(value: str) -> str:
    value = value.strip().lower()
    if value.startswith("["):
        return value.split("]", 1)[0] + "]"
    return value.split(":", 1)[0]


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
  <title>ProofSec</title>
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
    .note {{ border:1px solid #c7d2fe; background:#eef2ff; color:#3730a3; border-radius:8px; padding:12px; font-size:13px; }}
    .warning {{ border:1px solid #facc15; background:#fffbeb; color:#854d0e; border-radius:8px; padding:12px; margin:10px 0; font-size:13px; }}
    .empty {{ border:1px dashed var(--line); border-radius:8px; padding:18px; background:#f8fafc; }}
    .kpis {{ display:grid; grid-template-columns:repeat(5,minmax(0,1fr)); gap:10px; margin:12px 0 18px; }}
    .kpi {{ background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:12px; min-height:78px; }}
    .kpi span {{ display:block; color:var(--muted); font-size:12px; text-transform:uppercase; }}
    .kpi strong {{ display:block; margin-top:5px; font-size:22px; }}
    .links {{ display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:8px; margin:12px 0 18px; }}
    .links a {{ border:1px solid var(--line); border-radius:6px; padding:10px; background:#fff; }}
    .proof {{ border-top:1px solid var(--line); padding:12px 0; }}
    .proof:first-child {{ border-top:0; }}
    .badge {{ display:inline-block; color:#fff; border-radius:999px; padding:4px 9px; font-size:12px; font-weight:700; }}
    .proven {{ background:var(--critical); }} .fixed {{ background:var(--low); }} .unknown {{ background:var(--medium); }}
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
    @media (max-width:900px) {{ .topbar {{ display:block; }} .status {{ justify-content:flex-start; margin-top:12px; }} .grid,.kpis,.links {{ grid-template-columns:1fr; }} }}
  </style>
</head>
<body>
  <header>
    <div class="topbar">
      <div>
        <h1>ProofSec</h1>
        <p>Local security-invariant validation for authorized apps. Build a model, confirm the contract and run dynamic BOLA/BFLA/privilege checks with reproducible evidence.</p>
      </div>
      <div class="status">
        <span class="pill">Local</span>
        <span class="pill">Authorized targets only</span>
        <span class="pill">Proofs</span>
      </div>
    </div>
  </header>
  <main>{content}</main>
</body>
</html>
""".encode("utf-8")


def render_home() -> bytes:
    default_project = APP_ROOT / "examples" / "proofsec-spring-demo"
    default_output = APP_ROOT / "deliverables" / "proofsec-ui"
    default_config = APP_ROOT / "examples" / "proofsec-runtime.example.json"
    content = f"""
<div class="grid">
  <section class="panel">
    <h2>Run ProofSec</h2>
    <p class="note">Dynamic checks only execute when the runtime config has <code>target.authorized: true</code>. By default, only localhost targets are allowed.</p>
    <form id="proofsec-form">
      <div class="section">
        <h3>Project</h3>
        <label>Project path</label>
        <div class="path-picker">
          <input name="target" value="{html.escape(str(default_project))}" required>
          <button type="button" class="browse-button" data-target="target" data-kind="folder">Browse</button>
        </div>
        <label>Stack</label>
        <select name="stack">
          <option value="auto">Auto</option>
          <option value="spring-boot" selected>Spring Boot</option>
          <option value="spring">Spring</option>
        </select>
        <label>Output folder</label>
        <div class="path-picker">
          <input name="output_dir" value="{html.escape(str(default_output))}" required>
          <button type="button" class="browse-button" data-target="output_dir" data-kind="folder">Browse</button>
        </div>
      </div>
      <div class="section">
        <h3>Dynamic Validation</h3>
        <label>Runtime config</label>
        <div class="path-picker">
          <input name="config" value="{html.escape(str(default_config))}" required>
          <button type="button" class="browse-button" data-target="config" data-kind="file">Browse</button>
        </div>
        <label>Test type</label>
        <select name="test_type">
          <option value="bola">BOLA / IDOR</option>
          <option value="bfla">BFLA</option>
          <option value="privilege">Privilege escalation</option>
          <option value="all">All</option>
        </select>
        <label class="check"><input type="checkbox" name="run_dynamic" value="1" checked> Run dynamic validation after model/contract</label>
        <label class="check"><input type="checkbox" name="confirm_all" value="1" checked> Confirm proposed invariants for this run</label>
      </div>
      <button id="run-button" type="submit">Generate ProofSec Analysis</button>
    </form>
  </section>
  <section class="panel">
    <h2>Security Proofs</h2>
    <div id="result">
      <div class="empty">
        <p><strong>Ready.</strong></p>
        <p>This view generates the security model, proposed contract, invariant state and optional dynamic proof file.</p>
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
const form = document.getElementById('proofsec-form');
const button = document.getElementById('run-button');
const result = document.getElementById('result');
const browserModal = document.getElementById('browser-modal');
const browserCurrent = document.getElementById('browser-current');
const browserList = document.getElementById('browser-list');
let activePathInput = null;
let activeBrowseKind = 'folder';
const uiToken = {json.dumps(SESSION_TOKEN)};
const nativeFetch = window.fetch.bind(window);
window.fetch = (url, options = {{}}) => {{
  const headers = new Headers(options.headers || {{}});
  headers.set('X-ProofSec-Token', uiToken);
  return nativeFetch(url, {{ ...options, headers }});
}};
function escapeHtml(value) {{
  return String(value ?? '').replace(/[&<>"']/g, ch => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[ch]));
}}
async function loadPath(path) {{
  browserCurrent.value = path;
  browserList.innerHTML = '<div class="browser-row">Loading...</div>';
  const response = await fetch('/browse?path=' + encodeURIComponent(path));
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error || 'Cannot browse path');
  browserCurrent.value = payload.path;
  browserList.innerHTML = payload.entries.map(entry => {{
    const escapedPath = escapeHtml(entry.path);
    const type = entry.is_dir ? 'Folder' : 'File';
    const openButton = entry.is_dir ? `<button type="button" data-open="${{escapedPath}}" class="secondary">Open</button>` : '';
    const selectable = activeBrowseKind === 'folder' ? entry.is_dir : !entry.is_dir;
    const selectButton = selectable ? `<button type="button" data-select="${{escapedPath}}">Select</button>` : '';
    return `<div class="browser-row"><div><strong>${{escapeHtml(entry.name)}}</strong><br><small>${{type}}</small></div>${{openButton}}${{selectButton}}</div>`;
  }}).join('') || '<div class="browser-row">No entries</div>';
}}
document.querySelectorAll('.browse-button').forEach(button => {{
  button.addEventListener('click', async () => {{
    activePathInput = document.querySelector(`[name="${{button.dataset.target}}"]`);
    activeBrowseKind = button.dataset.kind || 'folder';
    browserModal.classList.add('open');
    try {{ await loadPath(activePathInput.value || browserCurrent.value); }}
    catch (error) {{ browserList.innerHTML = `<div class="browser-row error">${{escapeHtml(error.message)}}</div>`; }}
  }});
}});
browserList.addEventListener('click', async event => {{
  const openPath = event.target.dataset.open;
  const selectPath = event.target.dataset.select;
  if (openPath) await loadPath(openPath);
  if (selectPath && activePathInput) {{
    activePathInput.value = selectPath;
    browserModal.classList.remove('open');
  }}
}});
document.getElementById('browser-go').addEventListener('click', () => loadPath(browserCurrent.value));
document.getElementById('browser-parent').addEventListener('click', () => {{
  const parts = browserCurrent.value.split('/').filter(Boolean);
  parts.pop();
  loadPath('/' + parts.join('/'));
}});
document.getElementById('browser-select-folder').addEventListener('click', () => {{
  if (activePathInput) activePathInput.value = browserCurrent.value;
  browserModal.classList.remove('open');
}});
document.getElementById('browser-close').addEventListener('click', () => browserModal.classList.remove('open'));
form.addEventListener('submit', async event => {{
  event.preventDefault();
  button.disabled = true;
  button.textContent = 'Running ProofSec...';
  result.innerHTML = '<div class="empty"><p><strong>Working...</strong></p><p>Building model, contract, invariant state and dynamic evidence if enabled.</p></div>';
  try {{
    const response = await fetch('/run', {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify(Object.fromEntries(new FormData(form).entries())),
    }});
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || 'ProofSec failed');
    result.innerHTML = renderResult(payload);
  }} catch (error) {{
    result.innerHTML = `<p class="error">${{escapeHtml(error.message)}}</p>`;
  }} finally {{
    button.disabled = false;
    button.textContent = 'Generate ProofSec Analysis';
  }}
}});
function artifactLink(path, label) {{
  return path ? `<a href="/artifact?path=${{encodeURIComponent(path)}}" target="_blank">${{escapeHtml(label)}}</a>` : '';
}}
function renderResult(payload) {{
  const k = payload.kpis || {{}};
  const proofLinks = payload.files || {{}};
  const proofs = (payload.proofs || []).slice(0, 8).map(proof => {{
    const cls = String(proof.exploitability || '').toLowerCase();
    return `<div class="proof">
      <span class="badge ${{cls}}">${{escapeHtml(proof.exploitability)}}</span>
      <strong>${{escapeHtml(proof.vulnerability)}}</strong>
      <p>${{escapeHtml(proof.conclusion)}}</p>
      <p><code>${{escapeHtml(proof.endpoint)}}</code> identity <code>${{escapeHtml(proof.identity)}}</code> expected <code>${{escapeHtml(proof.expected)}}</code>, actual <code>${{escapeHtml(proof.actual)}}</code></p>
    </div>`;
  }}).join('');
  const warning = payload.dynamic_warning ? `<div class="warning">${{escapeHtml(payload.dynamic_warning)}}</div>` : '';
  return `<div class="kpis">
    <div class="kpi"><span>Endpoints</span><strong>${{k.endpoints_discovered ?? 0}}</strong></div>
    <div class="kpi"><span>Roles</span><strong>${{k.roles_discovered ?? 0}}</strong></div>
    <div class="kpi"><span>Invariants</span><strong>${{k.invariants ?? 0}}</strong></div>
    <div class="kpi"><span>Tests</span><strong>${{k.tests_executed ?? 0}}</strong></div>
    <div class="kpi"><span>Proven</span><strong>${{k.proven_vulnerabilities ?? 0}}</strong></div>
  </div>${{warning}}
  <div class="links">
    ${{artifactLink(proofLinks.model, 'Security Model JSON')}}
    ${{artifactLink(proofLinks.contract, 'Security Contract JSON')}}
    ${{artifactLink(proofLinks.invariants, 'Invariant State JSON')}}
    ${{artifactLink(proofLinks.proofs, 'Security Proofs JSON')}}
    ${{artifactLink(proofLinks.sqlite, 'SQLite Model')}}
  </div>
  <h3>Proof Evidence</h3>
  ${{proofs || '<div class="empty"><p>No dynamic proof entries were generated. Check that the target app is running and the runtime config points to it.</p></div>'}}`;
}}
</script>
"""
    return page_shell(content)


def proofsec_run(data: dict) -> dict:
    target = Path(str(data.get("target", ""))).expanduser().resolve()
    output_dir = Path(str(data.get("output_dir", ""))).expanduser().resolve()
    config_path = Path(str(data.get("config", ""))).expanduser().resolve()
    stack = str(data.get("stack") or "auto")
    test_type = str(data.get("test_type") or "bola")
    run_dynamic = str(data.get("run_dynamic", "")) == "1"
    confirm_all = str(data.get("confirm_all", "")) == "1"
    if not target.exists() or not target.is_dir():
        raise ValueError("Project path does not exist or is not a folder.")
    if run_dynamic and (not config_path.exists() or not config_path.is_file()):
        raise ValueError("Runtime config does not exist.")
    assert_write_allowed(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    GENERATED_ARTIFACT_ROOTS.add(output_dir)

    model = build_security_model(target, stack)
    model_path = output_dir / "security-model.json"
    sqlite_path = output_dir / "proofsec.sqlite"
    write_model_json(model, model_path)
    write_model_sqlite(model, sqlite_path)

    contract = propose_security_contract(model)
    if confirm_all:
        contract = confirm_all_proposed(contract)
    contract_path = output_dir / "security-contract.json"
    write_contract(contract, contract_path)

    evaluations = evaluate_invariants(contract, model)
    invariant_payload = invariant_state_payload(contract, evaluations)
    invariant_path = output_dir / "invariant-state.json"
    write_invariant_state(invariant_payload, invariant_path)

    proof_payload = {"kpis": {"tests_executed": 0, "proven_vulnerabilities": 0}, "proofs": []}
    proof_path = output_dir / "security-proofs.json"
    dynamic_warning = ""
    if run_dynamic:
        proof_payload = run_dynamic_tests(model_path, contract_path, config_path, test_type)
        write_proofs(proof_payload, proof_path)
    else:
        dynamic_warning = "Dynamic validation was disabled for this run."

    model_kpis = model.kpis()
    contract_kpis = contract.kpis()
    proof_kpis = proof_payload.get("kpis", {})
    return {
        "kpis": {
            **model_kpis,
            "invariants": contract_kpis["invariants"],
            "confirmed_invariants": contract_kpis["confirmed_invariants"],
            "tests_executed": proof_kpis.get("tests_executed", 0),
            "proven_vulnerabilities": proof_kpis.get("proven_vulnerabilities", 0),
            "fixed_vulnerabilities": proof_kpis.get("fixed_vulnerabilities", 0),
            "inconclusive": proof_kpis.get("inconclusive", 0),
        },
        "proofs": proof_payload.get("proofs", []),
        "dynamic_warning": dynamic_warning,
        "files": {
            "model": str(model_path),
            "contract": str(contract_path),
            "invariants": str(invariant_path),
            "proofs": str(proof_path) if run_dynamic else "",
            "sqlite": str(sqlite_path),
        },
    }


def browse_path(path_value: str) -> dict:
    path = Path(path_value or str(Path.home())).expanduser().resolve()
    if not path.exists():
        raise ValueError("Path does not exist.")
    if path.is_file():
        path = path.parent
    entries = []
    for child in sorted(path.iterdir(), key=lambda item: (not item.is_dir(), item.name.lower()))[:300]:
        if child.name.startswith("."):
            continue
        entries.append({"name": child.name, "path": str(child), "is_dir": child.is_dir()})
    return {"path": str(path), "entries": entries}


class Handler(BaseHTTPRequestHandler):
    server_version = "ProofSecUI/0.1"

    def log_message(self, format: str, *args: object) -> None:
        return

    def secure_headers(self) -> None:
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")

    def validate_request_origin(self) -> bool:
        host = header_hostname(self.headers.get("Host", ""))
        if host not in LOOPBACK_HOSTS:
            return False
        origin = self.headers.get("Origin")
        if origin:
            origin_host = header_hostname(urlparse(origin).netloc)
            if origin_host not in LOOPBACK_HOSTS:
                return False
        return True

    def send_bytes(self, status: int, body: bytes, content_type: str = "text/html; charset=utf-8") -> None:
        self.send_response(status)
        self.secure_headers()
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, status: int, payload: dict) -> None:
        self.send_bytes(status, json.dumps(payload, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

    def do_GET(self) -> None:
        if not self.validate_request_origin():
            self.send_json(403, {"error": "Forbidden origin"})
            return
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self.send_bytes(200, render_home())
            return
        if parsed.path == "/browse":
            try:
                path = parse_qs(parsed.query).get("path", [""])[0]
                self.send_json(200, browse_path(unquote(path)))
            except Exception as exc:
                self.send_json(400, {"error": str(exc)})
            return
        if parsed.path == "/artifact":
            try:
                path = Path(unquote(parse_qs(parsed.query).get("path", [""])[0])).expanduser().resolve()
                if not any(is_within(path, root) for root in GENERATED_ARTIFACT_ROOTS):
                    raise ValueError("Artifact is outside generated ProofSec folders.")
                if not path.exists() or not path.is_file():
                    raise ValueError("Artifact not found.")
                content_type = "application/json; charset=utf-8" if path.suffix.lower() == ".json" else "application/octet-stream"
                self.send_bytes(200, path.read_bytes(), content_type)
            except Exception as exc:
                self.send_json(404, {"error": str(exc)})
            return
        self.send_json(404, {"error": "Not found"})

    def do_POST(self) -> None:
        if not self.validate_request_origin():
            self.send_json(403, {"error": "Forbidden origin"})
            return
        if self.headers.get("X-ProofSec-Token") != SESSION_TOKEN:
            self.send_json(403, {"error": "Invalid session token"})
            return
        if "application/json" not in self.headers.get("Content-Type", ""):
            self.send_json(415, {"error": "Expected application/json"})
            return
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length > MAX_POST_BYTES:
            self.send_json(413, {"error": "Request too large"})
            return
        try:
            data = json.loads(self.rfile.read(length).decode("utf-8"))
            if self.path == "/run":
                self.send_json(200, proofsec_run(data))
                return
            self.send_json(404, {"error": "Not found"})
        except Exception as exc:
            self.send_json(400, {"error": str(exc)})


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="ProofSec local web UI.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8795)
    parser.add_argument("--open", action="store_true")
    args = parser.parse_args(argv)
    if not is_loopback_bind(args.host):
        parser.error("ProofSec UI only supports loopback hosts.")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    url = f"http://{args.host}:{server.server_port}"
    print(f"ProofSec UI: {url}")
    if args.open:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
