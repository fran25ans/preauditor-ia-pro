import unittest

from proofsec.discovery_plan import suggest_discovery_config
from proofsec.models import EndpointNode, ProjectSecurityModel


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
        self.assertEqual(payload["discovery"]["customers"]["id_field"], "id")
        self.assertGreaterEqual(payload["suggestions"][0]["confidence"], 0.9)
        self.assertIn("GET /api/customers/{id}", payload["suggestions"][0]["related_detail_endpoints"])


if __name__ == "__main__":
    unittest.main()

