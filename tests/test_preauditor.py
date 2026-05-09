import tempfile
import unittest
from pathlib import Path

import preauditor


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


if __name__ == "__main__":
    unittest.main()
