import unittest
import json
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from proofsec.discovery_plan import suggest_discovery_config, write_discovery_config_suggestions_with_runtime
from proofsec.discovery.spring import infer_resource
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

    def test_response_shape_detects_reference_key_and_code_ids(self):
        clients = infer_response_shape(
            "clients",
            {"content": [{"clientRef": "C-1", "responsible": "E-1"}, {"clientRef": "C-2", "responsible": "E-2"}]},
            has_detail_endpoint=True,
        )
        notes = infer_response_shape(
            "notes",
            {"_embedded": {"notes": [{"noteKey": "N-A", "createdBy": "a"}, {"noteKey": "N-B", "createdBy": "b"}]}},
            has_detail_endpoint=True,
        )
        projects = infer_response_shape(
            "projects",
            [{"projectCode": "PR-A", "name": "A"}, {"projectCode": "PR-B", "name": "B"}],
            has_detail_endpoint=True,
        )

        self.assertEqual(clients.id_field, "clientRef")
        self.assertEqual(notes.id_field, "noteKey")
        self.assertEqual(projects.id_field, "projectCode")

    def test_response_shape_detects_graph_edges_nodes_entries_and_maps(self):
        assets = infer_response_shape(
            "assets",
            {
                "edges": [
                    {"node": {"assetCode": "AS-A", "binding": {"tenantRef": "tenant-red"}}},
                    {"node": {"assetCode": "AS-B", "binding": {"tenantRef": "tenant-blue"}}},
                ]
            },
            has_detail_endpoint=True,
        )
        secrets = infer_response_shape(
            "secrets",
            {"collection": {"entries": [{"secretRef": "SEC-A", "ownerSub": "usr-a"}, {"secretRef": "SEC-B", "ownerSub": "usr-b"}]}},
            has_detail_endpoint=True,
        )
        cases = infer_response_shape(
            "cases",
            {"payload": {"byId": {"CASE-A": {"caseRef": "CASE-A"}, "CASE-B": {"caseRef": "CASE-B"}}}},
            has_detail_endpoint=True,
        )

        self.assertEqual(assets.items_path, "edges.node")
        self.assertEqual(assets.id_field, "assetCode")
        self.assertEqual(secrets.items_path, "collection.entries")
        self.assertEqual(secrets.id_field, "secretRef")
        self.assertEqual(cases.items_path, "payload.byId")
        self.assertEqual(cases.id_field, "caseRef")

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

    def test_runtime_discovery_resolves_identity_path_variables(self):
        seen_paths = []

        class TenantHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                return

            def do_GET(self):
                seen_paths.append(self.path)
                auth = self.headers.get("Authorization", "")
                body = (
                    {"content": [{"recordKey": "REC-B", "scope": {"tenant": "TEN-B"}}]}
                    if auth.endswith("bravo")
                    else {"content": [{"recordKey": "REC-A", "scope": {"tenant": "TEN-A"}}]}
                )
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(body).encode())

        server = ThreadingHTTPServer(("127.0.0.1", 0), TenantHandler)
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
                            path="/v3/workspaces/{tenant}/records",
                            controller="RecordController",
                            handler="list",
                            file="RecordController.java",
                            line=10,
                            resource="records",
                            action="read",
                            parameters=("tenant",),
                        ),
                        EndpointNode(
                            method="GET",
                            path="/v3/workspaces/{tenant}/records/{recordKey}",
                            controller="RecordController",
                            handler="detail",
                            file="RecordController.java",
                            line=20,
                            resource="records",
                            action="read",
                            parameters=("recordKey", "tenant"),
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
                                "alpha": {
                                    "role": "MEMBER",
                                    "attributes": {"tenant_id": "TEN-A"},
                                    "auth": {"type": "bearer", "token": "token-alpha"},
                                },
                                "bravo": {
                                    "role": "MEMBER",
                                    "attributes": {"tenant_id": "TEN-B"},
                                    "auth": {"type": "bearer", "token": "token-bravo"},
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

        entry = payload["discovery"]["records"]
        self.assertEqual(entry["list_endpoint"], "/v3/workspaces/{tenant}/records")
        self.assertEqual(entry["detail_endpoint"], "/v3/workspaces/{tenant}/records/{recordKey}")
        self.assertEqual(entry["items_path"], "content")
        self.assertEqual(entry["id_field"], "recordKey")
        self.assertIn("/v3/workspaces/TEN-A/records", seen_paths)
        self.assertIn("/v3/workspaces/TEN-B/records", seen_paths)

    def test_runtime_discovery_bootstraps_from_openapi_when_static_model_is_empty(self):
        class OpenApiHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                return

            def do_GET(self):
                if self.path == "/openapi.json":
                    body = {
                        "openapi": "3.0.0",
                        "paths": {
                            "/gateway/assets": {"get": {"operationId": "listAssets"}},
                            "/gateway/assets/{asset_code}": {
                                "get": {
                                    "operationId": "getAsset",
                                    "parameters": [{"name": "asset_code", "in": "path"}],
                                }
                            },
                        },
                    }
                else:
                    auth = self.headers.get("Authorization", "")
                    body = (
                        {"edges": [{"node": {"assetCode": "AS-B", "binding": {"tenantRef": "tenant-blue"}}}]}
                        if auth.endswith("bravo")
                        else {"edges": [{"node": {"assetCode": "AS-A", "binding": {"tenantRef": "tenant-red"}}}]}
                    )
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(body).encode())

        server = ThreadingHTTPServer(("127.0.0.1", 0), OpenApiHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                model = ProjectSecurityModel(project_path="/workspace/fastapi", framework="unknown")
                model_path = root / "model.json"
                runtime_path = root / "runtime.json"
                output_path = root / "discovery.json"
                model.write_json(model_path)
                runtime_path.write_text(
                    json.dumps(
                        {
                            "target": {"base_url": f"http://127.0.0.1:{server.server_port}", "authorized": True},
                            "identities": {
                                "alpha": {
                                    "role": "ANALYST",
                                    "attributes": {"tenant": "tenant-red"},
                                    "auth": {"type": "bearer", "token": "token-alpha"},
                                },
                                "bravo": {
                                    "role": "ANALYST",
                                    "attributes": {"tenant": "tenant-blue"},
                                    "auth": {"type": "bearer", "token": "token-bravo"},
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

        self.assertIn("assets", payload["discovery"])
        entry = payload["discovery"]["assets"]
        self.assertEqual(entry["list_endpoint"], "/gateway/assets")
        self.assertEqual(entry["detail_endpoint"], "/gateway/assets/{asset_code}")
        self.assertEqual(entry["items_path"], "edges.node")
        self.assertEqual(entry["id_field"], "assetCode")
        self.assertIn("binding.tenantRef", entry["owner_fields"])

    def test_infers_versioned_and_assigned_resource_names(self):
        self.assertEqual(infer_resource("/api/v2/portfolio/clients"), "clients")
        self.assertEqual(infer_resource("/api/v2/portfolio/clients/{clientRef}"), "clients")
        self.assertEqual(infer_resource("/api/projects/assigned"), "projects")

    def test_suggests_assigned_collection_when_detail_endpoint_exists(self):
        model = ProjectSecurityModel(
            project_path="/workspace/demo",
            framework="spring-boot",
            endpoints=[
                EndpointNode(
                    method="GET",
                    path="/api/projects/assigned",
                    controller="ProjectController",
                    handler="assigned",
                    file="ProjectController.java",
                    line=10,
                    resource="projects",
                    action="read",
                ),
                EndpointNode(
                    method="GET",
                    path="/api/projects/{projectCode}",
                    controller="ProjectController",
                    handler="detail",
                    file="ProjectController.java",
                    line=20,
                    resource="projects",
                    action="read",
                    parameters=("projectCode",),
                ),
                EndpointNode(
                    method="GET",
                    path="/health",
                    controller="HealthController",
                    handler="health",
                    file="HealthController.java",
                    line=30,
                    resource="health",
                    action="read",
                ),
            ],
        )

        payload = suggest_discovery_config(model)

        self.assertIn("projects", payload["discovery"])
        self.assertEqual(payload["discovery"]["projects"]["list_endpoint"], "/api/projects/assigned")
        self.assertNotIn("health", payload["discovery"])


if __name__ == "__main__":
    unittest.main()
