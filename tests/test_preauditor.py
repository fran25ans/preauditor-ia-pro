import contextlib
import io
import plistlib
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib import error as urlerror
from urllib import request as urlrequest

import mobile_release_radar
import mobile_release_ui
import preauditor
import preauditor_ui
import proofsec_ui
from proofsec.security_model import build_security_model, write_model_sqlite
from proofsec.contract import contract_to_yaml, merge_invariants, propose_security_contract
from proofsec.invariants import (
    evaluate_invariants,
    invariant_state_payload,
    load_security_contract,
    update_invariant_status,
)
from proofsec.llm.invariant_suggestions import suggest_invariants_with_llm
from proofsec.llm.ollama import parse_json_object
from proofsec.attack_engine import run_authorization_tests, retest_proof, run_bola_tests


class PreauditorRuleTests(unittest.TestCase):
    def scan_fixture(self, files, profile="pro", ignore_text=None):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for relative, content in files.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            ignore_file = None
            if ignore_text is not None:
                ignore_file = root / ".preauditor-ignore"
                ignore_file.write_text(ignore_text, encoding="utf-8")
            return preauditor.scan(root, profile=profile, ignore_file=ignore_file)

    def rule_ids(self, findings):
        return {finding.rule_id for finding in findings}

    def test_detects_ai_trusted_workspace(self):
        findings = self.scan_fixture(
            {
                "pull_request.yml": "env:\n  GEMINI_CLI_TRUST_WORKSPACE: 'true'\n",
            }
        )
        self.assertIn("SEC-026", self.rule_ids(findings))
        finding = next(f for f in findings if f.rule_id == "SEC-026")
        self.assertEqual(finding.severity, "Critica")

    def test_detects_prompt_loaded_from_pr_workspace(self):
        findings = self.scan_fixture(
            {
                "pull_request.yml": "steps:\n  - run: cp .review/GEMINI.md GEMINI.md\n",
            }
        )
        self.assertIn("SEC-027", self.rule_ids(findings))

    def test_detects_exposed_secret(self):
        findings = self.scan_fixture(
            {
                "app.py": 'API_KEY = "demo_api_key_not_real_1234567890"\n',
            }
        )
        self.assertIn("SEC-001", self.rule_ids(findings))
        finding = next(f for f in findings if f.rule_id == "SEC-001")
        self.assertEqual(finding.severity, "Critica")
        self.assertNotIn("not_real_1234567890", finding.evidence)

    def test_detects_cors_composite(self):
        findings = self.scan_fixture(
            {
                "app.py": (
                    "app.add_middleware(\n"
                    "    CORSMiddleware,\n"
                    "    allow_origins=['*'],\n"
                    "    allow_credentials=True,\n"
                    ")\n"
                ),
            }
        )
        ids = self.rule_ids(findings)
        self.assertIn("SEC-003", ids)
        self.assertIn("SEC-053", ids)
        self.assertIn("CMP-002", ids)
        composite = next(f for f in findings if f.rule_id == "CMP-002")
        self.assertEqual(composite.line, 3)
        self.assertEqual([item["rule_id"] for item in composite.related_findings], ["SEC-003", "SEC-053"])
        self.assertEqual([item["line"] for item in composite.related_findings], [3, 4])
        self.assertIn("allow_origins", composite.related_findings[0]["evidence"])
        self.assertIn("allow_credentials", composite.related_findings[1]["evidence"])

    def test_composite_review_is_invalidated_when_evidence_changes(self):
        first = self.scan_fixture(
            {
                "app.py": "allow_origins=['*']\nallow_credentials=True\n",
            }
        )
        changed = self.scan_fixture(
            {
                "app.py": "# configuration moved\n\nallow_origins=['*']\nallow_credentials=True\n",
            }
        )
        first_composite = next(f for f in first if f.rule_id == "CMP-002")
        changed_composite = next(f for f in changed if f.rule_id == "CMP-002")
        reviews = {
            first_composite.fingerprint: {
                "fingerprint": first_composite.fingerprint,
                "status": "false_positive",
                "rationale": "Reviewed before the evidence changed",
            }
        }

        self.assertNotEqual(first_composite.fingerprint, changed_composite.fingerprint)
        self.assertEqual(preauditor.review_for_finding(changed_composite, reviews)["status"], "pending")

    def test_composite_review_persists_when_evidence_is_unchanged(self):
        findings = self.scan_fixture(
            {
                "app.py": "allow_origins=['*']\nallow_credentials=True\n",
            }
        )
        repeated = self.scan_fixture(
            {
                "app.py": "allow_origins=['*']\nallow_credentials=True\n",
            }
        )
        original = next(f for f in findings if f.rule_id == "CMP-002")
        unchanged = next(f for f in repeated if f.rule_id == "CMP-002")
        reviews = {original.fingerprint: {"fingerprint": original.fingerprint, "status": "confirmed"}}

        self.assertEqual(original.fingerprint, unchanged.fingerprint)
        self.assertEqual(preauditor.review_for_finding(unchanged, reviews)["status"], "confirmed")

    def test_detects_ai_pr_composite(self):
        findings = self.scan_fixture(
            {
                "pull_request.yml": (
                    "on: pull_request\n"
                    "jobs:\n"
                    "  ai-review:\n"
                    "    permissions:\n"
                    "      pull-requests: write\n"
                    "      issues: write\n"
                    "    steps:\n"
                    "      - run: cp .review/GEMINI.md GEMINI.md\n"
                    "      - run: echo ok\n"
                    "        env:\n"
                    "          GEMINI_CLI_TRUST_WORKSPACE: 'true'\n"
                    "          PRIVATE_KEY: ${{ secrets.PRIVATE_KEY }}\n"
                )
            }
        )
        self.assertIn("CMP-001", self.rule_ids(findings))
        composite = next(f for f in findings if f.rule_id == "CMP-001")
        self.assertEqual(composite.severity, "Critica")
        related_ids = {item["rule_id"] for item in composite.related_findings}
        self.assertTrue({"SEC-026", "SEC-027"} <= related_ids)
        self.assertTrue(related_ids & {"SEC-005", "SEC-029", "SEC-058", "SEC-059"})
        self.assertNotEqual(composite.context, "")

    def test_suppresses_rule_by_id(self):
        findings = self.scan_fixture(
            {
                "pull_request.yml": "env:\n  GEMINI_CLI_TRUST_WORKSPACE: 'true'\n",
            },
            ignore_text="SEC-026\n",
        )
        self.assertNotIn("SEC-026", self.rule_ids(findings))

    def test_ai_profile_limits_categories(self):
        rules = preauditor.rules_for_profile("ai")
        categories = {rule.category for rule in rules}
        self.assertEqual(categories, {"IA", "CI/CD", "Secretos", "Supply Chain"})

    def test_markdown_includes_client_metadata(self):
        findings = self.scan_fixture(
            {
                "app.py": 'API_KEY = "demo_api_key_not_real_1234567890"\n',
            }
        )
        meta = preauditor.ReportMeta(
            client="Cliente Test",
            auditor="Auditor Test",
            scope="Scope Test",
            version="v-test",
        )
        report = preauditor.render_markdown(findings, Path("/tmp/project"), "pro", meta)
        self.assertIn("**Cliente:** Cliente Test", report)
        self.assertIn("**Auditor:** Auditor Test", report)
        self.assertIn("SEC-001", report)

    def test_english_language_renders_reports(self):
        findings = self.scan_fixture(
            {
                "app.py": 'API_KEY = "demo_api_key_not_real_1234567890"\n',
            },
            profile="basic",
        )
        meta = preauditor.ReportMeta(
            client="Demo",
            auditor="Auditor",
            scope="Initial review",
            version="test",
            language="en",
        )
        markdown = preauditor.render_markdown(findings, Path("/tmp/project"), "basic", meta)
        html_report = preauditor.render_html(findings, Path("/tmp/project"), "basic", meta)
        dashboard = preauditor.render_dashboard(findings, Path("/tmp/project"), "basic", meta)
        with tempfile.TemporaryDirectory() as tmp:
            checklist = Path(tmp) / "checklist.md"
            findings_json = Path(tmp) / "findings.json"
            findings_sarif = Path(tmp) / "findings.sarif"
            preauditor.write_checklist(findings, checklist, "en")
            preauditor.write_json(findings, findings_json, "basic", meta)
            preauditor.write_sarif(findings, findings_sarif, "en")
            checklist_text = checklist.read_text(encoding="utf-8")
            json_text = findings_json.read_text(encoding="utf-8")
            sarif_text = findings_sarif.read_text(encoding="utf-8")
        self.assertIn("Preliminary Security Assessment Report", markdown)
        self.assertIn("Possible exposed secret or API key", markdown)
        self.assertNotIn("Posible secreto o API key expuesta", markdown)
        self.assertIn("Executive Summary", html_report)
        self.assertIn("Distribution by Severity", dashboard)
        self.assertIn("Remediation Checklist", checklist_text)
        self.assertIn("Possible exposed secret or API key", json_text)
        self.assertIn("Possible exposed secret or API key", sarif_text)

    def test_dashboard_reserves_space_for_long_file_labels(self):
        findings = self.scan_fixture(
            {
                ".github/workflows/deploy.yml": "permissions: write-all\n",
            }
        )
        meta = preauditor.ReportMeta(
            client="Demo",
            auditor="Auditor",
            scope="Dashboard layout",
            version="test",
        )
        dashboard = preauditor.render_dashboard(findings, Path("/tmp/project"), "pro", meta)

        self.assertIn("grid-template-columns:minmax(0,42%) minmax(80px,1fr) 32px", dashboard)
        self.assertIn('class="bar-label" title="${esc(label)}"', dashboard)
        self.assertIn("text-overflow:ellipsis", dashboard)

    def test_ui_home_includes_english_toggle_assets(self):
        html_text = preauditor_ui.render_home().decode("utf-8")
        self.assertIn('data-i18n="headerSubtitle"', html_text)
        self.assertIn("Interface and Report Language", html_text)
        self.assertIn("Generate Preliminary Analysis", html_text)
        self.assertIn("rulesCatalogEn", html_text)
        self.assertIn("UI_TRANSLATIONS", html_text)

    def test_parse_ollama_json_with_extra_text(self):
        parsed = preauditor.parse_ollama_json(
            'Respuesta:\n{"verdict":"probable_real","confidence":"Media","rationale":"coincide","auditor_validation":"validar contexto"}'
        )
        self.assertEqual(parsed["verdict"], "probable_real")
        self.assertEqual(parsed["confidence"], "Media")

    def test_ollama_false_positive_filter_is_explicit(self):
        findings = self.scan_fixture(
            {
                "app.py": 'API_KEY = "demo_api_key_not_real_1234567890"\n',
            }
        )
        finding = findings[0]
        assessments = {
            preauditor.finding_key(finding): {
                "verdict": "probable_falso_positivo",
                "confidence": "Media",
            }
        }
        filtered = preauditor.filter_ollama_false_positives(findings, assessments)
        self.assertEqual(filtered, [])

    def test_custom_yaml_rule_detects_internal_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.js").write_text("const mode = 'legacy-internal-risk';\n", encoding="utf-8")
            rules_file = root / "rules.yml"
            rules_file.write_text(
                """
rules:
  - id: ACME-001
    title: Politica interna incumplida
    severity: Alta
    category: Custom
    regex: legacy-internal-risk
    file_globs:
      - "*.js"
    recommendation: Sustituir por el patron aprobado.
""",
                encoding="utf-8",
            )
            custom_rules = preauditor.load_custom_rules(rules_file)
            findings = preauditor.scan(root, profile="basic", custom_rules=custom_rules)
        self.assertIn("ACME-001", self.rule_ids(findings))

    def test_ui_validates_and_saves_custom_rule_pack(self):
        rule_text = """
rules:
  - id: CLIENT-999
    title: Patron prohibido por cliente
    severity: Media
    category: Politica interna
    regex: forbidden-client-pattern
    file_globs:
      - "*.py"
    recommendation: Sustituir por el patron aprobado.
"""
        rules = preauditor_ui.validate_custom_rules_text(rule_text)
        self.assertEqual([rule.rule_id for rule in rules], ["CLIENT-999"])
        with tempfile.TemporaryDirectory(dir=preauditor_ui.APP_ROOT) as tmp:
            rules_file = Path(tmp) / "client-rules.yml"
            saved = preauditor_ui.save_custom_rules_text(str(rules_file), rule_text)
            loaded = preauditor_ui.load_custom_rules_text(str(rules_file))
        self.assertEqual(saved["count"], 1)
        self.assertEqual(saved["rules"], ["CLIENT-999"])
        self.assertIn("CLIENT-999", loaded["text"])

    def test_compare_with_baseline_tracks_before_after(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text('API_KEY = "demo_api_key_not_real_1234567890"\n', encoding="utf-8")
            before = preauditor.scan(root, profile="basic")
            meta = preauditor.ReportMeta(
                client="Demo",
                auditor="Test",
                scope="Comparativa",
                version="test",
            )
            baseline = root / "baseline.json"
            baseline.write_text(
                preauditor.json.dumps(
                    preauditor.baseline_payload(before, root, "basic", meta, preauditor.project_hash(root)),
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )
            (root / "app.py").write_text("print('fixed')\n", encoding="utf-8")
            after = preauditor.scan(root, profile="basic")
            comparison = preauditor.compare_with_baseline(after, baseline)
        self.assertIsNotNone(comparison)
        self.assertEqual(comparison["new"], 0)
        self.assertGreaterEqual(comparison["fixed"], 1)
        self.assertEqual(comparison["persistent"], 0)
        self.assertEqual(comparison["status"], "mejora")

    def test_ui_scan_auto_compares_previous_baseline(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "project"
            output = Path(tmp) / "out"
            root.mkdir()
            output.mkdir()
            (root / "app.py").write_text('API_KEY = "demo_api_key_not_real_1234567890"\n', encoding="utf-8")
            first = preauditor_ui.scan_project(
                {
                    "target": str(root),
                    "output_dir": str(output),
                    "profile": "basic",
                    "stack": "generic",
                    "client": "Demo",
                    "auto_compare": "1",
                    "allow_external_write": "1",
                }
            )
            self.assertIsNone(first["comparison"])
            (root / "app.py").write_text("print('fixed')\n", encoding="utf-8")
            second = preauditor_ui.scan_project(
                {
                    "target": str(root),
                    "output_dir": str(output),
                    "profile": "basic",
                    "stack": "generic",
                    "client": "Demo",
                    "auto_compare": "1",
                    "allow_external_write": "1",
                }
            )
        self.assertIsNotNone(second["comparison"])
        self.assertGreaterEqual(second["comparison"]["fixed"], 1)

    def test_review_records_are_applied_to_findings(self):
        findings = self.scan_fixture(
            {
                "app.py": 'API_KEY = "demo_api_key_not_real_1234567890"\n',
            },
            profile="basic",
        )
        finding = findings[0]
        reviews = {
            finding.fingerprint: {
                "fingerprint": finding.fingerprint,
                "status": "confirmed",
                "reviewed_by": "Francisco",
                "rationale": "Confirmado manualmente",
            }
        }
        payload = preauditor.finding_payload(finding, reviews)
        counts = preauditor.review_counts(findings, reviews)
        self.assertEqual(payload["review"]["status"], "confirmed")
        self.assertEqual(counts["confirmed"], 1)
        self.assertEqual(counts["pending"], 0)

    def test_ui_review_decision_persists_between_scans(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "project"
            output = Path(tmp) / "out"
            root.mkdir()
            output.mkdir()
            (root / "app.py").write_text('API_KEY = "demo_api_key_not_real_1234567890"\n', encoding="utf-8")
            first = preauditor_ui.scan_project(
                {
                    "target": str(root),
                    "output_dir": str(output),
                    "profile": "basic",
                    "stack": "generic",
                    "client": "Demo",
                    "allow_external_write": "1",
                }
            )
            finding = first["findings"][0]
            saved = preauditor_ui.save_review_decision(
                {
                    "review_path": first["review_path"],
                    "fingerprint": finding["fingerprint"],
                    "rule_id": finding["rule_id"],
                    "title": finding["title"],
                    "file": finding["file"],
                    "line": finding["line"],
                    "status": "confirmed",
                    "reviewed_by": "Francisco",
                    "rationale": "Validado en prueba",
                    "ticket": "SEC-1",
                }
            )
            second = preauditor_ui.scan_project(
                {
                    "target": str(root),
                    "output_dir": str(output),
                    "profile": "basic",
                    "stack": "generic",
                    "client": "Demo",
                    "allow_external_write": "1",
                }
            )
        self.assertEqual(saved["record"]["status"], "confirmed")
        self.assertEqual(second["findings"][0]["review"]["status"], "confirmed")
        self.assertEqual(second["review_counts"]["confirmed"], 1)

    def test_ui_rejects_post_without_session_token(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), preauditor_ui.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}/custom-rules/validate"
            request = urlrequest.Request(
                url,
                data=b'{"text":"rules: []"}',
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with self.assertRaises(urlerror.HTTPError) as raised:
                urlrequest.urlopen(request, timeout=5)
            self.assertEqual(raised.exception.code, 403)
            raised.exception.close()
        finally:
            server.shutdown()
            server.server_close()

    def test_ui_accepts_post_with_session_token(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), preauditor_ui.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}/custom-rules/validate"
            body = b'{"text":"rules:\\n  - id: TEAM-1\\n    title: Demo\\n    severity: Baja\\n    regex: demo\\n"}'
            request = urlrequest.Request(
                url,
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "X-Preauditor-Token": preauditor_ui.SESSION_TOKEN,
                },
                method="POST",
            )
            with urlrequest.urlopen(request, timeout=5) as response:
                payload = preauditor.json.loads(response.read().decode("utf-8"))
            self.assertEqual(payload["count"], 1)
            self.assertEqual(payload["rules"], ["TEAM-1"])
        finally:
            server.shutdown()
            server.server_close()

    def test_ui_cli_rejects_remote_mode(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                preauditor_ui.parse_args(["--host", "0.0.0.0", "--allow-remote"])

    def test_ui_cli_keeps_loopback_mode(self):
        args = preauditor_ui.parse_args(["--host", "127.0.0.1", "--port", "9876"])
        self.assertEqual(args.host, "127.0.0.1")
        self.assertEqual(args.port, 9876)


class MobileReleaseRadarTests(unittest.TestCase):
    def make_apk(self, root: Path, name: str, manifest: str, extra_files: dict[str, str] | None = None) -> Path:
        apk = root / name
        with zipfile.ZipFile(apk, "w") as archive:
            archive.writestr("AndroidManifest.xml", manifest)
            for filename, content in (extra_files or {}).items():
                archive.writestr(filename, content)
        return apk

    def make_ipa(self, root: Path, name: str, info: dict, extra_files: dict[str, str] | None = None) -> Path:
        ipa = root / name
        with zipfile.ZipFile(ipa, "w") as archive:
            archive.writestr("Payload/Demo.app/Info.plist", plistlib.dumps(info))
            for filename, content in (extra_files or {}).items():
                archive.writestr(f"Payload/Demo.app/{filename}", content)
        return ipa

    def test_android_artifact_detects_release_risks(self):
        manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.demo" android:versionName="1.0" android:versionCode="1">
  <uses-permission android:name="android.permission.CAMERA" />
  <application android:debuggable="true" android:allowBackup="true" android:usesCleartextTraffic="true">
    <activity android:name=".DeepLinkActivity" android:exported="true" />
  </application>
</manifest>
"""
        with tempfile.TemporaryDirectory() as tmp:
            apk = self.make_apk(Path(tmp), "demo.apk", manifest, {"assets/config.txt": "api=https://api.example.com\n"})
            profile = mobile_release_radar.analyze_artifact(apk)
        rule_ids = {finding.rule_id for finding in profile.findings}
        self.assertEqual(profile.platform, "android")
        self.assertIn("android.permission.CAMERA", profile.dangerous_permissions)
        self.assertIn("activity:.DeepLinkActivity", profile.exported_components)
        self.assertTrue({"AND-001", "AND-002", "AND-003", "AND-005"} <= rule_ids)

    def test_ios_artifact_detects_ats_risk_and_permissions(self):
        info = {
            "CFBundleIdentifier": "com.example.demo",
            "CFBundleShortVersionString": "1.0",
            "CFBundleVersion": "85",
            "CFBundleDisplayName": "Demo",
            "NSCameraUsageDescription": "Camera is used for scans.",
            "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True},
            "CFBundleURLTypes": [{"CFBundleURLSchemes": ["demoapp"]}],
        }
        with tempfile.TemporaryDirectory() as tmp:
            ipa = self.make_ipa(Path(tmp), "demo.ipa", info, {"config.txt": "url=https://api.example.com"})
            profile = mobile_release_radar.analyze_artifact(ipa)
        self.assertEqual(profile.platform, "ios")
        self.assertEqual(profile.bundle_id, "com.example.demo")
        self.assertIn("NSCameraUsageDescription", profile.permissions)
        self.assertIn("demoapp", profile.url_schemes)
        self.assertIn("IOS-001", {finding.rule_id for finding in profile.findings})

    def test_mobile_release_diff_marks_new_and_fixed_risks(self):
        previous_manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.demo">
  <application android:allowBackup="true" />
</manifest>
"""
        current_manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.demo">
  <uses-permission android:name="android.permission.READ_CONTACTS" />
  <application android:usesCleartextTraffic="true">
    <service android:name=".SyncService" android:exported="true" />
  </application>
</manifest>
"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            previous = mobile_release_radar.analyze_artifact(self.make_apk(root, "old.apk", previous_manifest))
            current = mobile_release_radar.analyze_artifact(self.make_apk(root, "new.apk", current_manifest))
            payload = mobile_release_radar.result_payload(current, previous)
        self.assertEqual(payload["decision"], "blocked")
        self.assertIn("Policy blocks releases with new findings", " ".join(payload["policy_violations"]))
        self.assertGreater(payload["comparison"]["new_findings"], 0)
        self.assertGreater(payload["comparison"]["fixed_findings"], 0)
        self.assertIn("android.permission.READ_CONTACTS", payload["comparison"]["added_dangerous_permissions"])
        self.assertIn("service:.SyncService", payload["comparison"]["added_exported_components"])

    def test_mobile_release_policy_blocks_regressions_only_with_previous_build(self):
        previous_manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.demo">
  <application />
</manifest>
"""
        current_manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.demo">
  <uses-permission android:name="android.permission.READ_CONTACTS" />
  <application>
    <receiver android:name=".PushReceiver" android:exported="true" />
  </application>
</manifest>
"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy_path = root / "mobile-policy.yml"
            policy_path.write_text(
                "block_on_new_dangerous_permissions: true\nmax_new_exported_components: 0\n",
                encoding="utf-8",
            )
            policy = mobile_release_radar.load_policy(policy_path)
            current = mobile_release_radar.analyze_artifact(self.make_apk(root, "current.apk", current_manifest))
            first_payload = mobile_release_radar.result_payload(current, None, policy=policy)
            previous = mobile_release_radar.analyze_artifact(self.make_apk(root, "previous.apk", previous_manifest))
            compared_payload = mobile_release_radar.result_payload(current, previous, policy=policy)

        first_statuses = {item["id"]: item["status"] for item in first_payload["store_readiness"]}
        self.assertEqual(first_statuses["REL-004"], "pass")
        self.assertEqual(first_statuses["REL-005"], "pass")
        self.assertEqual(first_payload["policy_violations"], [])
        self.assertEqual(compared_payload["decision"], "blocked")
        self.assertIn("Policy blocks new dangerous permissions.", compared_payload["policy_violations"])
        self.assertIn("Policy limit exceeded for new exported components.", compared_payload["policy_violations"])

    def test_mobile_release_history_is_persisted_per_app(self):
        manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.history">
  <application />
</manifest>
"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            current = mobile_release_radar.analyze_artifact(self.make_apk(root, "history.apk", manifest))
            history_root = root / "history"
            first = mobile_release_radar.result_payload(current, None, history_root=history_root)
            second = mobile_release_radar.result_payload(current, None, history_root=history_root)

        self.assertTrue(first["history_path"].endswith("com.example.history/history.jsonl"))
        self.assertEqual(len(first["history"]), 1)
        self.assertEqual(len(second["history"]), 2)
        self.assertEqual(second["history"][-1]["app"], "com.example.history")

    def test_mobile_release_ui_renders_home(self):
        html_text = mobile_release_ui.render_home().decode("utf-8")
        self.assertIn("Mobile Release Radar", html_text)
        self.assertIn("Analyze Mobile Release", html_text)
        self.assertIn("Current APK/AAB/IPA", html_text)
        self.assertIn("Store app release history", html_text)
        self.assertIn("Release policy JSON/YAML", html_text)
        self.assertIn("newest build as Current", html_text)
        self.assertIn("Remove Previous Build", html_text)
        self.assertIn("Check build order", html_text)
        self.assertNotIn("Use 85.apk Demo", html_text)
        self.assertNotIn("/Users/franciscojosegimenoesteban/Downloads/85.apk", html_text)
        self.assertIn("Comparison active", html_text)
        self.assertIn("No new risk findings were introduced", html_text)

    def test_mobile_release_ui_rejects_remote_host(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                mobile_release_ui.parse_args(["--host", "0.0.0.0"])

    def test_mobile_release_ui_scan_generates_outputs(self):
        manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.demo">
  <application android:allowBackup="true" />
</manifest>
"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            apk = self.make_apk(root, "demo.apk", manifest)
            output = root / "out"
            mobile_release_ui.GENERATED_ARTIFACT_ROOTS.add(output.resolve())
            result = mobile_release_ui.scan_mobile_release(
                {
                    "artifact": str(apk),
                    "output_dir": str(output),
                    "platform": "auto",
                }
            )
        self.assertEqual(result["platform"], "android")
        self.assertEqual(result["previous_artifact"], "")
        self.assertIn("store_readiness", result)
        self.assertIn("history", result)
        self.assertIn("HTML Report", result["files"])
        self.assertIn("Markdown Report", result["files"])
        self.assertIn("JSON Data", result["files"])


class ProofSecSecurityModelTests(unittest.TestCase):
    def write_spring_demo(self, root: Path) -> None:
        app = root / "src/main/java/com/example/DemoApplication.java"
        app.parent.mkdir(parents=True, exist_ok=True)
        app.write_text(
            """
package com.example;

import org.springframework.boot.SpringApplication;

public class DemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }
}
""",
            encoding="utf-8",
        )
        controller = root / "src/main/java/com/example/CustomerController.java"
        controller.write_text(
            """
package com.example;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/customers")
@PreAuthorize("hasRole('ADVISOR')")
public class CustomerController {
    @GetMapping("/{id}")
    public Customer getCustomer(@PathVariable Long id) {
        return service.findById(id);
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public void deleteCustomer(@PathVariable Long id) {
        service.delete(id);
    }
}
""",
            encoding="utf-8",
        )

    def test_proofsec_discovers_spring_security_model(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_spring_demo(root)
            model = build_security_model(root)

        self.assertEqual(model.framework, "spring-boot")
        self.assertEqual(len(model.endpoints), 2)
        endpoint_paths = {(endpoint.method, endpoint.path) for endpoint in model.endpoints}
        self.assertIn(("GET", "/api/customers/{id}"), endpoint_paths)
        self.assertIn(("DELETE", "/api/customers/{id}"), endpoint_paths)
        self.assertIn("ADVISOR", {role.name for role in model.roles})
        self.assertIn("ADMIN", {role.name for role in model.roles})
        self.assertIn("customers", {resource.name for resource in model.resources})
        get_endpoint = next(endpoint for endpoint in model.endpoints if endpoint.method == "GET")
        self.assertEqual(get_endpoint.action, "read")
        self.assertEqual(get_endpoint.parameters, ("id",))

    def test_proofsec_persists_security_model_to_sqlite(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_spring_demo(root)
            model = build_security_model(root)
            db_path = root / "proofsec.sqlite"
            model_id = write_model_sqlite(model, db_path)

            import sqlite3

            with contextlib.closing(sqlite3.connect(db_path)) as connection:
                endpoint_count = connection.execute("select count(*) from endpoints where model_id = ?", (model_id,)).fetchone()[0]
                edge_count = connection.execute("select count(*) from graph_edges where model_id = ?", (model_id,)).fetchone()[0]

        self.assertEqual(endpoint_count, 2)
        self.assertGreaterEqual(edge_count, 4)

    def test_proofsec_proposes_security_contract_from_model(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_spring_demo(root)
            model = build_security_model(root)
            contract = propose_security_contract(model)

        advisor = next(role for role in contract.roles if role.name == "ADVISOR")
        admin = next(role for role in contract.roles if role.name == "ADMIN")
        advisor_permissions = {permission.permission for permission in advisor.permissions}
        admin_permissions = {permission.permission for permission in admin.permissions}
        self.assertIn("customers.read:assigned", advisor_permissions)
        self.assertNotIn("customers.delete:any", advisor_permissions)
        self.assertIn("customers.delete:any", admin_permissions)
        self.assertEqual(contract.invariants[0].source, "inferred")
        self.assertEqual(contract.invariants[0].status, "proposed")
        self.assertIn("assigned_customers", contract.invariants[0].name)

    def test_proofsec_contract_yaml_is_human_reviewable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_spring_demo(root)
            contract = propose_security_contract(build_security_model(root))
            yaml_text = contract_to_yaml(contract)

        self.assertIn("roles:", yaml_text)
        self.assertIn("ADVISOR:", yaml_text)
        self.assertIn("permission: customers.read:assigned", yaml_text)
        self.assertIn("invariants:", yaml_text)
        self.assertIn("status: proposed", yaml_text)

    def test_proofsec_llm_suggestions_are_schema_validated_and_proposed(self):
        class FakeProvider:
            name = "fake"
            model = "unit-test"

            def chat_json(self, system, user, timeout=60):
                return {
                    "invariants": [
                        {
                            "name": "advisor_customer_region_matches",
                            "description": "Advisors should only read customers in their assigned region.",
                            "resource": "customers",
                            "action": "read",
                            "expected_behavior": "Cross-region reads should be forbidden.",
                            "confidence": 0.98,
                            "evidence": "customers read endpoint is role protected and takes an id.",
                        },
                        {
                            "name": "ignore_unknown_resource",
                            "description": "Invalid resource must be ignored.",
                            "resource": "payments",
                            "action": "read",
                            "expected_behavior": "ignored",
                            "confidence": 1.0,
                            "evidence": "not in model",
                        },
                    ]
                }

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_spring_demo(root)
            model = build_security_model(root)
            suggestions = suggest_invariants_with_llm(model, FakeProvider())

        self.assertEqual(len(suggestions), 1)
        self.assertEqual(suggestions[0].source, "inferred")
        self.assertEqual(suggestions[0].status, "proposed")
        self.assertEqual(suggestions[0].confidence, 0.65)
        self.assertIn("fake/unit-test", suggestions[0].evidence)

    def test_proofsec_merges_llm_invariants_without_duplicates(self):
        class DuplicateProvider:
            name = "fake"
            model = "unit-test"

            def chat_json(self, system, user, timeout=60):
                return {
                    "invariants": [
                        {
                            "name": "advisor_can_only_access_assigned_customers",
                            "description": "Duplicate deterministic invariant.",
                            "resource": "customers",
                            "action": "read",
                            "expected_behavior": "Forbidden.",
                            "confidence": 0.5,
                            "evidence": "duplicate",
                        }
                    ]
                }

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_spring_demo(root)
            model = build_security_model(root)
            contract = propose_security_contract(model)
            merged = merge_invariants(contract, suggest_invariants_with_llm(model, DuplicateProvider()))

        self.assertEqual(len(merged.invariants), 1)
        self.assertEqual(merged.invariants[0].name, "advisor_can_only_access_assigned_customers")

    def test_proofsec_ollama_parser_extracts_json_object(self):
        parsed = parse_json_object('Respuesta:\n{"invariants":[]}')
        self.assertEqual(parsed, {"invariants": []})

    def test_proofsec_invariant_engine_marks_proposed_as_needing_confirmation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_spring_demo(root)
            model = build_security_model(root)
            contract = propose_security_contract(model)
            evaluations = evaluate_invariants(contract, model)

        self.assertEqual(evaluations[0].status, "proposed")
        self.assertEqual(evaluations[0].readiness, "needs_confirmation")
        self.assertTrue(evaluations[0].requires_dynamic_test)
        self.assertIn("GET /api/customers/{id}", evaluations[0].matching_endpoints)

    def test_proofsec_invariant_engine_confirms_and_rejects_invariants(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_spring_demo(root)
            model = build_security_model(root)
            contract = propose_security_contract(model)
            invariant_id = contract.invariants[0].invariant_id
            confirmed = update_invariant_status(contract, invariant_id, "confirmed")
            confirmed_evaluation = evaluate_invariants(confirmed, model)[0]
            rejected = update_invariant_status(confirmed, invariant_id, "rejected")
            rejected_evaluation = evaluate_invariants(rejected, model)[0]

        self.assertEqual(confirmed_evaluation.status, "confirmed")
        self.assertEqual(confirmed_evaluation.readiness, "ready_for_testing")
        self.assertEqual(rejected_evaluation.status, "rejected")
        self.assertEqual(rejected_evaluation.readiness, "not_testable")

    def test_proofsec_invariant_engine_rejects_manual_dynamic_statuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_spring_demo(root)
            contract = propose_security_contract(build_security_model(root))
            invariant_id = contract.invariants[0].invariant_id

        with self.assertRaises(ValueError):
            update_invariant_status(contract, invariant_id, "violated")

    def test_proofsec_invariant_state_roundtrip_from_json_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_spring_demo(root)
            model = build_security_model(root)
            contract = propose_security_contract(model)
            contract_path = root / "contract.json"
            contract.write_json(contract_path)
            loaded = load_security_contract(contract_path)
            evaluations = evaluate_invariants(loaded, model)
            payload = invariant_state_payload(loaded, evaluations)

        self.assertEqual(payload["status_counts"]["proposed"], 1)
        self.assertEqual(payload["readiness_counts"]["needs_confirmation"], 1)
        self.assertEqual(payload["invariants"][0]["name"], "advisor_can_only_access_assigned_customers")

    def write_proofsec_runtime_files(self, root: Path, base_url: str) -> tuple[Path, Path, Path, str]:
        self.write_spring_demo(root)
        model = build_security_model(root)
        contract = propose_security_contract(model)
        invariant_id = contract.invariants[0].invariant_id
        contract = update_invariant_status(contract, invariant_id, "confirmed")
        model_path = root / "model.json"
        contract_path = root / "contract.json"
        config_path = root / "proofsec-runtime.json"
        model.write_json(model_path)
        contract.write_json(contract_path)
        config_path.write_text(
            preauditor.json.dumps(
                {
                    "target": {
                        "base_url": base_url,
                        "authorized": True,
                        "max_requests": 5,
                        "timeout_seconds": 3,
                    },
                    "identities": {
                        "advisor_a": {
                            "role": "ADVISOR",
                            "auth": {"type": "bearer", "token": "test-token-advisor-a"},
                        },
                        "advisor_b": {
                            "role": "ADVISOR",
                            "auth": {"type": "bearer", "token": "test-token-advisor-b"},
                        },
                    },
                    "resources": {
                        "customer_101": {
                            "resource": "customers",
                            "id": "101",
                            "owner_identity": "advisor_a",
                            "sensitive_markers": ["advisor_a"],
                        },
                        "customer_202": {
                            "resource": "customers",
                            "id": "202",
                            "owner_identity": "advisor_b",
                            "sensitive_markers": ["advisor_b"],
                        },
                    },
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        return model_path, contract_path, config_path, invariant_id

    def add_admin_controller(self, root: Path) -> None:
        controller = root / "src/main/java/com/example/AdminController.java"
        controller.write_text(
            """
package com.example;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/admin")
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {
    @GetMapping("/audit")
    public String auditLog() {
        return "audit";
    }

    @PostMapping("/reindex")
    public void reindex() {
    }
}
""",
            encoding="utf-8",
        )

    def run_customer_server(self, secure: bool):
        class CustomerHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                return

            def do_GET(self):
                authorization = self.headers.get("Authorization", "")
                cross_owner = (
                    (authorization.endswith("advisor-a") and self.path == "/api/customers/202")
                    or (authorization.endswith("advisor-b") and self.path == "/api/customers/101")
                )
                if cross_owner and secure:
                    self.send_response(403)
                    self.end_headers()
                    self.wfile.write(b'{"error":"forbidden"}')
                    return
                if self.path == "/api/admin/audit":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"entries":["admin-audit-visible"]}')
                    return
                if self.path == "/api/customers":
                    items = (
                        [{"id": "202", "owner": "advisor_b", "email": "customer202@example.test"}]
                        if authorization.endswith("advisor-b")
                        else [{"id": "101", "owner": "advisor_a", "email": "customer101@example.test"}]
                    )
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(preauditor.json.dumps({"data": items}).encode())
                    return
                if self.path in {"/api/customers/101", "/api/customers/202"}:
                    customer_id = self.path.rsplit("/", 1)[-1]
                    owner = "advisor_b" if customer_id == "202" else "advisor_a"
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(f'{{"id":"{customer_id}","owner":"{owner}","email":"customer{customer_id}@example.test"}}'.encode())
                    return
                self.send_response(404)
                self.end_headers()

            def do_POST(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"ok":true}')

        server = ThreadingHTTPServer(("127.0.0.1", 0), CustomerHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server

    def test_proofsec_bola_engine_generates_real_proven_security_proof(self):
        server = self.run_customer_server(secure=False)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                base_url = f"http://127.0.0.1:{server.server_port}"
                model_path, contract_path, config_path, invariant_id = self.write_proofsec_runtime_files(root, base_url)
                payload = run_bola_tests(model_path, contract_path, config_path)
        finally:
            server.shutdown()
            server.server_close()

        self.assertEqual(payload["kpis"]["proven_vulnerabilities"], 2)
        proof = payload["proofs"][0]
        self.assertEqual(proof["invariant_id"], invariant_id)
        self.assertEqual(proof["finding_state"], "PROVEN")
        self.assertEqual(proof["exploitability"], "PROVEN")
        self.assertEqual(proof["expected"], "403 Forbidden or equivalent denial")
        self.assertEqual(proof["actual"], "200")
        self.assertIn("SECURITY INVARIANT VIOLATED", proof["conclusion"])
        self.assertIn("Authorization", proof["evidence"]["request_headers"])
        self.assertEqual(proof["evidence"]["request_headers"]["Authorization"], "Bearer ****")
        self.assertNotIn("response_body", proof["evidence"])
        self.assertIn("response_body_preview", proof["evidence"])
        self.assertNotIn("test-token-advisor-a", preauditor.json.dumps(proof))
        self.assertIn("repository.findById", proof["suggested_fix"])
        self.assertIn("andExpect(status().isForbidden())", proof["regression_test"])

    def test_proofsec_bola_does_not_mark_generic_200_body_as_proven(self):
        class GenericHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                return

            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"message":"No information available"}')

        server = ThreadingHTTPServer(("127.0.0.1", 0), GenericHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                base_url = f"http://127.0.0.1:{server.server_port}"
                model_path, contract_path, config_path, _ = self.write_proofsec_runtime_files(root, base_url)
                payload = run_bola_tests(model_path, contract_path, config_path)
        finally:
            server.shutdown()
            server.server_close()

        self.assertEqual(payload["kpis"]["proven_vulnerabilities"], 0)
        self.assertEqual(payload["kpis"]["inconclusive"], 2)
        self.assertEqual(payload["proofs"][0]["finding_state"], "INCONCLUSIVE")
        self.assertEqual(payload["proofs"][0]["exploitability"], "UNKNOWN")
        self.assertIn("requested resource id was not confirmed", payload["proofs"][0]["conclusion"])

    def test_proofsec_bola_error_payload_with_resource_and_owner_is_not_proven(self):
        class ErrorPayloadHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                return

            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error":"customer 202 belongs to advisor_b and cannot be accessed"}')

        server = ThreadingHTTPServer(("127.0.0.1", 0), ErrorPayloadHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                base_url = f"http://127.0.0.1:{server.server_port}"
                model_path, contract_path, config_path, _ = self.write_proofsec_runtime_files(root, base_url)
                payload = run_bola_tests(model_path, contract_path, config_path)
        finally:
            server.shutdown()
            server.server_close()

        self.assertEqual(payload["kpis"]["proven_vulnerabilities"], 0)
        self.assertEqual(payload["proofs"][0]["finding_state"], "INCONCLUSIVE")
        self.assertIn("requested resource id was not confirmed", payload["proofs"][0]["conclusion"])

    def test_proofsec_bola_discovers_resources_before_cross_owner_test(self):
        server = self.run_customer_server(secure=False)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                self.write_spring_demo(root)
                model = build_security_model(root)
                contract = propose_security_contract(model)
                invariant_id = contract.invariants[0].invariant_id
                contract = update_invariant_status(contract, invariant_id, "confirmed")
                model_path = root / "model.json"
                contract_path = root / "contract.json"
                config_path = root / "runtime-discovery.json"
                model.write_json(model_path)
                contract.write_json(contract_path)
                config_path.write_text(
                    preauditor.json.dumps(
                        {
                            "target": {
                                "base_url": f"http://127.0.0.1:{server.server_port}",
                                "authorized": True,
                                "max_requests": 10,
                            },
                            "identities": {
                                "advisor_a": {
                                    "role": "ADVISOR",
                                    "auth": {"type": "bearer", "token": "test-token-advisor-a"},
                                },
                                "advisor_b": {
                                    "role": "ADVISOR",
                                    "auth": {"type": "bearer", "token": "test-token-advisor-b"},
                                },
                            },
                            "discovery": {
                                "customers": {
                                    "list_endpoint": "/api/customers",
                                    "items_path": "data",
                                    "id_field": "id",
                                    "owner_marker_fields": ["owner"],
                                }
                            },
                        },
                        indent=2,
                    ),
                    encoding="utf-8",
                )
                payload = run_bola_tests(model_path, contract_path, config_path)
        finally:
            server.shutdown()
            server.server_close()

        self.assertEqual(payload["kpis"]["proven_vulnerabilities"], 2)
        tested_resources = {proof["resource"] for proof in payload["proofs"]}
        self.assertEqual(tested_resources, {"customer_101", "customer_202"})
        self.assertIn("ownership marker", payload["proofs"][0]["conclusion"])

    def test_proofsec_bola_uses_dynamic_discovery_hypothesis_without_manual_invariant(self):
        server = self.run_customer_server(secure=False)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                from proofsec.models import EndpointNode, ProjectSecurityModel, ResourceNode, SecurityContract

                root = Path(tmp)
                model = ProjectSecurityModel(
                    project_path=str(root),
                    framework="spring-boot",
                    languages=("java",),
                    endpoints=[
                        EndpointNode(
                            method="GET",
                            path="/api/customers",
                            controller="CustomerController",
                            handler="list",
                            file=str(root / "CustomerController.java"),
                            line=10,
                            resource="customers",
                            action="read",
                        ),
                        EndpointNode(
                            method="GET",
                            path="/api/customers/{id}",
                            controller="CustomerController",
                            handler="detail",
                            file=str(root / "CustomerController.java"),
                            line=20,
                            resource="customers",
                            action="read",
                            parameters=("id",),
                        ),
                    ],
                    resources=[ResourceNode("customers")],
                )
                contract = SecurityContract(
                    project_path=str(root),
                    resources=["customers"],
                    invariants=[],
                    notes=["No human-confirmed invariants in this blind test."],
                )
                model_path = root / "model.json"
                contract_path = root / "contract.json"
                config_path = root / "runtime-discovery-empty-contract.json"
                model.write_json(model_path)
                contract.write_json(contract_path)
                config_path.write_text(
                    preauditor.json.dumps(
                        {
                            "target": {
                                "base_url": f"http://127.0.0.1:{server.server_port}",
                                "authorized": True,
                                "max_requests": 10,
                            },
                            "identities": {
                                "advisor_a": {
                                    "role": "ADVISOR",
                                    "auth": {"type": "bearer", "token": "test-token-advisor-a"},
                                },
                                "advisor_b": {
                                    "role": "ADVISOR",
                                    "auth": {"type": "bearer", "token": "test-token-advisor-b"},
                                },
                            },
                            "discovery": {
                                "customers": {
                                    "list_endpoint": "/api/customers",
                                    "items_path": "data",
                                    "id_field": "id",
                                    "owner_marker_fields": ["owner"],
                                }
                            },
                        },
                        indent=2,
                    ),
                    encoding="utf-8",
                )
                payload = run_bola_tests(model_path, contract_path, config_path)
        finally:
            server.shutdown()
            server.server_close()

        self.assertEqual(payload["kpis"]["proven_vulnerabilities"], 2)
        self.assertTrue(all(proof["invariant_id"].startswith("dyn_inv_") for proof in payload["proofs"]))
        self.assertIn("test hypothesis", payload["proofs"][0]["conclusion"])

    def test_proofsec_bola_discovery_resolves_owner_from_identity_attributes(self):
        class AttributeOwnerHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                return

            def do_GET(self):
                authorization = self.headers.get("Authorization", "")
                if self.path == "/api/customers":
                    items = (
                        [{"id": "202", "advisorId": "98371", "email": "customer202@example.test"}]
                        if authorization.endswith("advisor-b")
                        else [{"id": "101", "advisorId": "4001", "email": "customer101@example.test"}]
                    )
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(preauditor.json.dumps({"data": items}).encode())
                    return
                if self.path in {"/api/customers/101", "/api/customers/202"}:
                    customer_id = self.path.rsplit("/", 1)[-1]
                    advisor_id = "98371" if customer_id == "202" else "4001"
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(f'{{"id":"{customer_id}","advisorId":"{advisor_id}"}}'.encode())
                    return
                self.send_response(404)
                self.end_headers()

        server = ThreadingHTTPServer(("127.0.0.1", 0), AttributeOwnerHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                self.write_spring_demo(root)
                model = build_security_model(root)
                contract = propose_security_contract(model)
                invariant_id = contract.invariants[0].invariant_id
                contract = update_invariant_status(contract, invariant_id, "confirmed")
                model_path = root / "model.json"
                contract_path = root / "contract.json"
                config_path = root / "runtime-discovery-attributes.json"
                model.write_json(model_path)
                contract.write_json(contract_path)
                config_path.write_text(
                    preauditor.json.dumps(
                        {
                            "target": {
                                "base_url": f"http://127.0.0.1:{server.server_port}",
                                "authorized": True,
                                "max_requests": 10,
                            },
                            "identities": {
                                "advisor_a": {
                                    "role": "ADVISOR",
                                    "attributes": {"user_id": "4001", "email": "advisor-a@example.test"},
                                    "auth": {"type": "bearer", "token": "test-token-advisor-a"},
                                },
                                "advisor_b": {
                                    "role": "ADVISOR",
                                    "attributes": {"user_id": "98371", "email": "advisor-b@example.test"},
                                    "auth": {"type": "bearer", "token": "test-token-advisor-b"},
                                },
                            },
                            "discovery": {
                                "customers": {
                                    "list_endpoint": "/api/customers",
                                    "items_path": "data",
                                    "id_field": "id",
                                    "owner_marker_fields": ["advisorId"],
                                }
                            },
                        },
                        indent=2,
                    ),
                    encoding="utf-8",
                )
                payload = run_bola_tests(model_path, contract_path, config_path)
        finally:
            server.shutdown()
            server.server_close()

        self.assertEqual(payload["kpis"]["proven_vulnerabilities"], 2)
        owners = {proof["resource_owner"] for proof in payload["proofs"]}
        self.assertEqual(owners, {"advisor_a", "advisor_b"})
        suggested = payload["resource_discovery"]["suggested_owner_fields"]
        self.assertTrue(any(item["field"] == "advisorId" and item["identity_attribute"] == "user_id" for item in suggested))

    def test_proofsec_bola_discovery_skips_shared_resource_observed_by_attacker(self):
        class SharedHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                return

            def do_GET(self):
                if self.path == "/api/customers":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"data":[{"id":"500","owner":"advisor_b"}]}')
                    return
                if self.path == "/api/customers/500":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"id":"500","owner":"advisor_b","email":"shared@example.test"}')
                    return
                self.send_response(404)
                self.end_headers()

        server = ThreadingHTTPServer(("127.0.0.1", 0), SharedHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                self.write_spring_demo(root)
                model = build_security_model(root)
                contract = propose_security_contract(model)
                contract = update_invariant_status(contract, contract.invariants[0].invariant_id, "confirmed")
                model_path = root / "model.json"
                contract_path = root / "contract.json"
                config_path = root / "runtime-shared.json"
                model.write_json(model_path)
                contract.write_json(contract_path)
                config_path.write_text(
                    preauditor.json.dumps(
                        {
                            "target": {"base_url": f"http://127.0.0.1:{server.server_port}", "authorized": True},
                            "identities": {
                                "advisor_a": {"role": "ADVISOR", "auth": {"type": "bearer", "token": "test-token-advisor-a"}},
                                "advisor_b": {"role": "ADVISOR", "auth": {"type": "bearer", "token": "test-token-advisor-b"}},
                            },
                            "discovery": {
                                "customers": {
                                    "list_endpoint": "/api/customers",
                                    "items_path": "data",
                                    "id_field": "id",
                                    "owner_fields": ["owner"],
                                    "owner_marker_fields": ["owner"],
                                }
                            },
                        }
                    ),
                    encoding="utf-8",
                )
                payload = run_bola_tests(model_path, contract_path, config_path)
        finally:
            server.shutdown()
            server.server_close()

        self.assertEqual(payload["kpis"]["tests_executed"], 0)
        self.assertEqual(payload["kpis"]["proven_vulnerabilities"], 0)

    def test_proofsec_bola_discovery_skips_unknown_owner_resources(self):
        server = self.run_customer_server(secure=False)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                self.write_spring_demo(root)
                model = build_security_model(root)
                contract = propose_security_contract(model)
                contract = update_invariant_status(contract, contract.invariants[0].invariant_id, "confirmed")
                model_path = root / "model.json"
                contract_path = root / "contract.json"
                config_path = root / "runtime-unknown.json"
                model.write_json(model_path)
                contract.write_json(contract_path)
                config_path.write_text(
                    preauditor.json.dumps(
                        {
                            "target": {"base_url": f"http://127.0.0.1:{server.server_port}", "authorized": True},
                            "identities": {
                                "advisor_a": {"role": "ADVISOR", "auth": {"type": "bearer", "token": "test-token-advisor-a"}},
                                "advisor_b": {"role": "ADVISOR", "auth": {"type": "bearer", "token": "test-token-advisor-b"}},
                            },
                            "discovery": {
                                "customers": {
                                    "list_endpoint": "/api/customers",
                                    "items_path": "data",
                                    "id_field": "id",
                                    "owner_fields": ["missingOwner"],
                                    "owner_marker_fields": ["owner"],
                                }
                            },
                        }
                    ),
                    encoding="utf-8",
                )
                payload = run_bola_tests(model_path, contract_path, config_path)
        finally:
            server.shutdown()
            server.server_close()

        self.assertEqual(payload["kpis"]["tests_executed"], 0)
        self.assertEqual(payload["kpis"]["proven_vulnerabilities"], 0)

    def test_proofsec_dynamic_engine_requires_explicit_authorization(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            model_path, contract_path, config_path, _ = self.write_proofsec_runtime_files(root, "http://127.0.0.1:1")
            config = preauditor.json.loads(config_path.read_text(encoding="utf-8"))
            config["target"]["authorized"] = False
            config_path.write_text(preauditor.json.dumps(config), encoding="utf-8")

            with self.assertRaises(ValueError):
                run_bola_tests(model_path, contract_path, config_path)

    def test_proofsec_retest_marks_fixed_when_original_attack_is_denied(self):
        vulnerable = self.run_customer_server(secure=False)
        fixed = None
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                base_url = f"http://127.0.0.1:{vulnerable.server_port}"
                model_path, contract_path, config_path, _ = self.write_proofsec_runtime_files(root, base_url)
                first_payload = run_bola_tests(model_path, contract_path, config_path)
                proof_path = root / "proofs.json"
                proof_path.write_text(preauditor.json.dumps(first_payload), encoding="utf-8")
                vulnerable.shutdown()
                vulnerable.server_close()
                fixed = self.run_customer_server(secure=True)
                config = preauditor.json.loads(config_path.read_text(encoding="utf-8"))
                config["target"]["base_url"] = f"http://127.0.0.1:{fixed.server_port}"
                config_path.write_text(preauditor.json.dumps(config), encoding="utf-8")
                retest_payload = retest_proof(model_path, contract_path, config_path, proof_path)
        finally:
            if fixed:
                fixed.shutdown()
                fixed.server_close()

        self.assertEqual(first_payload["kpis"]["proven_vulnerabilities"], 2)
        self.assertEqual(retest_payload["kpis"]["fixed_vulnerabilities"], 2)
        self.assertEqual(retest_payload["proofs"][0]["finding_state"], "FIXED")
        self.assertIn("FIX VERIFIED", retest_payload["proofs"][0]["conclusion"])

    def test_proofsec_bfla_engine_proves_lower_role_can_access_admin_function(self):
        server = self.run_customer_server(secure=False)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                self.write_spring_demo(root)
                self.add_admin_controller(root)
                model = build_security_model(root)
                model_path = root / "model.json"
                config_path = root / "runtime.json"
                model.write_json(model_path)
                config_path.write_text(
                    preauditor.json.dumps(
                        {
                            "target": {
                                "base_url": f"http://127.0.0.1:{server.server_port}",
                                "authorized": True,
                                "max_requests": 5,
                            },
                            "identities": {
                                "advisor_a": {
                                    "role": "ADVISOR",
                                    "auth": {"type": "bearer", "token": "test-token-advisor-a"},
                                }
                            },
                            "resources": {
                                "customer_101": {
                                    "resource": "customers",
                                    "id": "101",
                                    "owner_identity": "advisor_a",
                                }
                            },
                            "authorization_validation": {
                                "functional_markers": {
                                    "GET /api/admin/audit": ["entries", "admin-audit-visible"]
                                }
                            },
                        }
                    ),
                    encoding="utf-8",
                )
                payload = run_authorization_tests(model_path, config_path, "bfla")
        finally:
            server.shutdown()
            server.server_close()

        self.assertEqual(payload["kpis"]["bfla"], 1)
        self.assertEqual(payload["kpis"]["proven_vulnerabilities"], 1)
        proof = payload["proofs"][0]
        self.assertEqual(proof["classification"], "BFLA")
        self.assertEqual(proof["vulnerability"], "Broken Function Level Authorization")
        self.assertEqual(proof["actual"], "200")
        self.assertIn("Lower-privileged identity", proof["conclusion"])

    def test_proofsec_bfla_2xx_without_functional_marker_is_validated_not_proven(self):
        server = self.run_customer_server(secure=False)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                self.write_spring_demo(root)
                self.add_admin_controller(root)
                model = build_security_model(root)
                model_path = root / "model.json"
                config_path = root / "runtime.json"
                model.write_json(model_path)
                config_path.write_text(
                    preauditor.json.dumps(
                        {
                            "target": {"base_url": f"http://127.0.0.1:{server.server_port}", "authorized": True},
                            "identities": {
                                "advisor_a": {
                                    "role": "ADVISOR",
                                    "auth": {"type": "bearer", "token": "test-token-advisor-a"},
                                }
                            },
                        }
                    ),
                    encoding="utf-8",
                )
                payload = run_authorization_tests(model_path, config_path, "bfla")
        finally:
            server.shutdown()
            server.server_close()

        self.assertEqual(payload["kpis"]["proven_vulnerabilities"], 0)
        self.assertEqual(payload["kpis"]["validated_findings"], 1)
        self.assertEqual(payload["proofs"][0]["finding_state"], "VALIDATED")

    def test_proofsec_bfla_2xx_authorization_error_payload_is_not_proven(self):
        class ErrorAdminHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                return

            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error":"You are not authorized"}')

        server = ThreadingHTTPServer(("127.0.0.1", 0), ErrorAdminHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                self.write_spring_demo(root)
                self.add_admin_controller(root)
                model = build_security_model(root)
                model_path = root / "model.json"
                config_path = root / "runtime.json"
                model.write_json(model_path)
                config_path.write_text(
                    preauditor.json.dumps(
                        {
                            "target": {"base_url": f"http://127.0.0.1:{server.server_port}", "authorized": True},
                            "identities": {
                                "advisor_a": {"role": "ADVISOR", "auth": {"type": "bearer", "token": "test-token-advisor-a"}}
                            },
                            "resources": {
                                "customer_101": {"resource": "customers", "id": "101", "owner_identity": "advisor_a"}
                            },
                        }
                    ),
                    encoding="utf-8",
                )
                payload = run_authorization_tests(model_path, config_path, "bfla")
        finally:
            server.shutdown()
            server.server_close()

        self.assertEqual(payload["kpis"]["proven_vulnerabilities"], 0)
        self.assertEqual(payload["kpis"]["inconclusive"], 1)
        self.assertEqual(payload["proofs"][0]["finding_state"], "INCONCLUSIVE")

    def test_proofsec_privilege_engine_skips_mutating_endpoints_by_default(self):
        server = self.run_customer_server(secure=False)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                self.write_spring_demo(root)
                self.add_admin_controller(root)
                model = build_security_model(root)
                model_path = root / "model.json"
                config_path = root / "runtime.json"
                model.write_json(model_path)
                config_path.write_text(
                    preauditor.json.dumps(
                        {
                            "target": {
                                "base_url": f"http://127.0.0.1:{server.server_port}",
                                "authorized": True,
                                "max_requests": 5,
                                "allow_mutating": False,
                            },
                            "identities": {
                                "advisor_a": {
                                    "role": "ADVISOR",
                                    "auth": {"type": "bearer", "token": "test-token-advisor-a"},
                                }
                            },
                            "resources": {
                                "customer_101": {
                                    "resource": "customers",
                                    "id": "101",
                                    "owner_identity": "advisor_a",
                                }
                            },
                        }
                    ),
                    encoding="utf-8",
                )
                skipped = run_authorization_tests(model_path, config_path, "privilege")
                config = preauditor.json.loads(config_path.read_text(encoding="utf-8"))
                config["target"]["allow_mutating"] = True
                config_path.write_text(preauditor.json.dumps(config), encoding="utf-8")
                executed = run_authorization_tests(model_path, config_path, "privilege")
        finally:
            server.shutdown()
            server.server_close()

        self.assertEqual(skipped["kpis"]["tests_executed"], 0)
        self.assertGreaterEqual(executed["kpis"]["privilege_escalation"], 1)
        self.assertEqual(executed["proofs"][0]["classification"], "PRIVILEGE_ESCALATION")

    def test_proofsec_ui_renders_dedicated_view(self):
        html_text = proofsec_ui.render_home().decode("utf-8")
        self.assertIn("ProofSec", html_text)
        self.assertIn("Generate ProofSec Analysis", html_text)
        self.assertIn("BOLA / IDOR", html_text)
        self.assertIn("Privilege escalation", html_text)
        self.assertIn("Security Proofs", html_text)

    def test_proofsec_ui_run_generates_model_contract_and_invariants_without_dynamic(self):
        with tempfile.TemporaryDirectory(dir=proofsec_ui.APP_ROOT) as tmp:
            root = Path(tmp) / "project"
            output = Path(tmp) / "out"
            self.write_spring_demo(root)
            result = proofsec_ui.proofsec_run(
                {
                    "target": str(root),
                    "output_dir": str(output),
                    "stack": "spring-boot",
                    "confirm_all": "1",
                    "run_dynamic": "0",
                    "test_type": "bola",
                    "config": str(Path(tmp) / "missing-runtime.json"),
                }
            )
            model_exists = Path(result["files"]["model"]).exists()
            contract_exists = Path(result["files"]["contract"]).exists()
            invariants_exists = Path(result["files"]["invariants"]).exists()

        self.assertEqual(result["kpis"]["endpoints_discovered"], 2)
        self.assertEqual(result["kpis"]["confirmed_invariants"], 1)
        self.assertEqual(result["kpis"]["tests_executed"], 0)
        self.assertTrue(model_exists)
        self.assertTrue(contract_exists)
        self.assertTrue(invariants_exists)

    def test_proofsec_ui_rejects_remote_host(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                proofsec_ui.parse_args(["--host", "0.0.0.0"])


if __name__ == "__main__":
    unittest.main()
