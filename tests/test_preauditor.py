import tempfile
import unittest
from pathlib import Path

import preauditor
import preauditor_ui


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
        with tempfile.TemporaryDirectory() as tmp:
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
                }
            )
        self.assertEqual(saved["record"]["status"], "confirmed")
        self.assertEqual(second["findings"][0]["review"]["status"], "confirmed")
        self.assertEqual(second["review_counts"]["confirmed"], 1)


if __name__ == "__main__":
    unittest.main()
