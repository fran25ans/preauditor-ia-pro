import json
import unittest

from proofsec.models import HttpExchangeEvidence, ProofSecResourceExample
from proofsec.proof_validator import validate_authorization_response, validate_bola_response
from proofsec.response_shape import infer_response_shape


def evidence(status: int, body: dict | list | str) -> HttpExchangeEvidence:
    text = body if isinstance(body, str) else json.dumps(body)
    return HttpExchangeEvidence(
        method="GET",
        url="http://127.0.0.1:8080/test",
        request_headers={},
        status=status,
        response_headers={},
        response_body_preview=text,
        response_body=text,
    )


def customer_202() -> ProofSecResourceExample:
    return ProofSecResourceExample(
        name="customer_202",
        resource="customers",
        resource_id="202",
        owner_identity="advisor_b",
        sensitive_markers=("advisor_b", "98371"),
    )


class ProofSecAdversarialTests(unittest.TestCase):
    def test_bola_metadata_id_and_owner_does_not_become_proven(self):
        result = validate_bola_response(
            evidence(
                200,
                {
                    "meta": {
                        "id": "202",
                        "owner": "advisor_b",
                        "requestId": "trace-123",
                    },
                    "data": [],
                },
            ),
            customer_202(),
        )

        self.assertNotEqual(result.state, "PROVEN")

    def test_bola_error_envelope_with_embedded_details_is_not_proven(self):
        result = validate_bola_response(
            evidence(
                200,
                {
                    "status": "denied",
                    "details": {
                        "id": "202",
                        "owner": "advisor_b",
                    },
                    "reason": "customer belongs to another advisor",
                },
            ),
            customer_202(),
        )

        self.assertEqual(result.state, "INCONCLUSIVE")

    def test_bola_shared_collection_payload_is_validated_not_proven(self):
        result = validate_bola_response(
            evidence(
                200,
                {
                    "data": [
                        {
                            "customerId": "202",
                            "managerId": "98371",
                            "visibility": "shared",
                        }
                    ]
                },
            ),
            customer_202(),
        )

        self.assertEqual(result.state, "VALIDATED")
        self.assertFalse(result.owner_confirmed)

    def test_bfla_success_with_error_text_and_functional_marker_is_not_proven(self):
        result = validate_authorization_response(
            evidence(200, {"error": "not allowed to list users", "users": []}),
            functional_markers=("users",),
        )

        self.assertEqual(result.state, "INCONCLUSIVE")

    def test_response_shape_prefers_content_over_pagination_links(self):
        shape = infer_response_shape(
            "customers",
            {
                "content": [
                    {"customerId": "101", "advisorId": "4001"},
                    {"customerId": "202", "advisorId": "98371"},
                ],
                "links": [
                    {"id": "next", "href": "/api/customers?page=2"},
                    {"id": "prev", "href": "/api/customers?page=0"},
                ],
                "page": {"number": 1, "size": 2},
            },
            has_detail_endpoint=True,
        )

        self.assertEqual(shape.items_path, "content")
        self.assertEqual(shape.id_field, "customerId")

    def test_response_shape_empty_content_does_not_select_links_as_resources(self):
        shape = infer_response_shape(
            "customers",
            {
                "content": [],
                "links": [
                    {"id": "next", "href": "/api/customers?page=2"},
                    {"id": "prev", "href": "/api/customers?page=0"},
                ],
                "page": {"number": 1, "size": 2, "totalElements": 0},
            },
            has_detail_endpoint=True,
        )

        self.assertEqual(shape.items_path, "content")
        self.assertNotEqual(shape.id_field, "href")

    def test_response_shape_avoids_owner_field_as_resource_id(self):
        shape = infer_response_shape(
            "customers",
            {
                "results": [
                    {"advisorId": "4001", "name": "Ada"},
                    {"advisorId": "98371", "name": "Grace"},
                ]
            },
            has_detail_endpoint=True,
        )

        self.assertNotEqual(shape.id_field, "advisorId")
        self.assertLess(shape.confidence, 0.7)


if __name__ == "__main__":
    unittest.main()
