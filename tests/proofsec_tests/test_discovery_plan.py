import unittest
import json
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from proofsec.discovery_plan import suggest_discovery_config, write_discovery_config_suggestions_with_runtime
from proofsec.models import EndpointNode, ProjectSecurityModel
from proofsec.response_shape import infer_response_shape


class ProofSecDiscoveryPlanTests(unittest.TestCase):
    def test_suggests_collection_discovery_from_security_model(self):
        model = ProjectSecurityModel(
            project_path="/workspace/demo",
            framework="spring-boot",
            endpoints=[
                EndpointNode(
                    method="GET",
                    path="/api/customers",
                    controller="CustomerController",
                    handler="listCustomers",
                    file="CustomerController.java",
                    line=20,
                    roles=("ADVISOR",),
                    resource="customers",
                    action="read",
                ),
                EndpointNode(
                    method="GET",
                    path="/api/customers/{id}",
                    controller="CustomerController",
                    handler="getCustomer",
                    file="CustomerController.java",
                    line=27,
                    roles=("ADVISOR",),
                    resource="customers",
                    action="read",
                    parameters=("id",),
                ),
            ],
        )

        payload = suggest_discovery_config(model)

        self.assertIn("customers", payload["discovery"])
        self.assertEqual(payload["discovery"]["customers"]["list_endpoint"], "/api/customers")
        self.assertEqual(payload["discovery"]["customers"]["id_field"], "auto")
        self.assertGreaterEqual(payload["suggestions"][0]["confidence"], 0.9)
        self.assertIn("GET /api/customers/{id}", payload["suggestions"][0]["related_detail_endpoints"])

    def test_response_shape_detects_content_and_customer_id(self):
        shape = infer_response_shape(
            "customers",
            {
                "content": [
                    {"customerId": "101", "advisorId": "4001", "name": "Ada"},
                    {"customerId": "202", "advisorId": "98371", "name": "Grace"},
                ]
            },
            has_detail_endpoint=True,
        )

        self.assertEqual(shape.items_path, "content")
        self.assertEqual(shape.id_field, "customerId")
        self.assertGreater(shape.id_candidates[0].confidence, shape.id_candidates[1].confidence)

    def test_runtime_discovery_enhances_shape_and_ownership_fields(self):
        class ContentHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                return

            def do_GET(self):
                auth = self.headers.get("Authorization", "")
                body = (
                    {"content": [{"customerId": "202", "advisorId": "98371", "name": "Grace"}]}
                    if auth.endswith("advisor-b")
                    else {"content": [{"customerId": "101", "advisorId": "4001", "name": "Ada"}]}
                )
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(body).encode())

        server = ThreadingHTTPServer(("127.0.0.1", 0), ContentHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                model = ProjectSecurityModel(
                    project_path="/workspace/demo",
                    framework="spring-boot",
                    endpoints=[
                        EndpointNode(
                            method="GET",
                            path="/api/customers",
                            controller="CustomerController",
                            handler="listCustomers",
                            file="CustomerController.java",
                            line=20,
                            roles=("ADVISOR",),
                            resource="customers",
                            action="read",
                        ),
                        EndpointNode(
                            method="GET",
                            path="/api/customers/{id}",
                            controller="CustomerController",
                            handler="getCustomer",
                            file="CustomerController.java",
                            line=27,
                            roles=("ADVISOR",),
                            resource="customers",
                            action="read",
                            parameters=("id",),
                        ),
                    ],
                )
                model_path = root / "model.json"
                runtime_path = root / "runtime.json"
                output_path = root / "discovery.json"
                model.write_json(model_path)
                runtime_path.write_text(
                    json.dumps(
                        {
                            "target": {"base_url": f"http://127.0.0.1:{server.server_port}", "authorized": True},
                            "identities": {
                                "advisor_a": {
                                    "role": "ADVISOR",
                                    "attributes": {"user_id": "4001"},
                                    "auth": {"type": "bearer", "token": "test-token-advisor-a"},
                                },
                                "advisor_b": {
                                    "role": "ADVISOR",
                                    "attributes": {"user_id": "98371"},
                                    "auth": {"type": "bearer", "token": "test-token-advisor-b"},
                                },
                            },
                        }
                    ),
                    encoding="utf-8",
                )
                payload = write_discovery_config_suggestions_with_runtime(model_path, runtime_path, output_path)
        finally:
            server.shutdown()
            server.server_close()

        entry = payload["discovery"]["customers"]
        self.assertEqual(entry["items_path"], "content")
        self.assertEqual(entry["id_field"], "customerId")
        self.assertIn("advisorId", entry["owner_fields"])
        suggestion = payload["suggestions"][0]
        self.assertTrue(suggestion["id_candidates"])
        self.assertTrue(suggestion["owner_field_suggestions"])


if __name__ == "__main__":
    unittest.main()
