import unittest

from proofsec.models import ProofSecIdentity
from proofsec.ownership_suggestions import suggest_owner_fields_from_observations


class ProofSecOwnershipSuggestionTests(unittest.TestCase):
    def identities(self):
        return {
            "advisor_a": ProofSecIdentity(
                name="advisor_a",
                role="ADVISOR",
                attributes={"name": "advisor_a", "user_id": "4001", "email": "a@example.test"},
            ),
            "advisor_b": ProofSecIdentity(
                name="advisor_b",
                role="ADVISOR",
                attributes={"name": "advisor_b", "user_id": "98371", "email": "b@example.test"},
            ),
        }

    def test_suggests_semantic_owner_field_by_correlation(self):
        identities = self.identities()
        suggestions = suggest_owner_fields_from_observations(
            "customers",
            [
                ({"id": "101", "managerId": "4001"}, identities["advisor_a"]),
                ({"id": "202", "managerId": "98371"}, identities["advisor_b"]),
            ],
            identities,
        )

        suggestion = next(item for item in suggestions if item.field == "managerId")
        self.assertEqual(suggestion.identity_attribute, "user_id")
        self.assertGreaterEqual(suggestion.confidence, 0.9)
        self.assertEqual(suggestion.observations, 2)
        self.assertEqual(suggestion.owner_matches, 2)
        self.assertEqual(suggestion.ambiguous_matches, 0)
        self.assertTrue(suggestion.semantic_match)

    def test_non_semantic_single_match_stays_lower_confidence(self):
        identities = self.identities()
        suggestions = suggest_owner_fields_from_observations(
            "customers",
            [
                ({"id": "101", "randomCounter": "4001"}, identities["advisor_a"]),
                ({"id": "202", "randomCounter": "7777"}, identities["advisor_b"]),
            ],
            identities,
        )

        self.assertFalse(any(item.field == "randomCounter" and item.confidence >= 0.85 for item in suggestions))

    def test_ambiguous_matches_are_penalized(self):
        identities = self.identities()
        suggestions = suggest_owner_fields_from_observations(
            "customers",
            [
                ({"id": "101", "assignedTo": "4001"}, identities["advisor_b"]),
                ({"id": "202", "assignedTo": "98371"}, identities["advisor_a"]),
            ],
            identities,
        )

        self.assertFalse(any(item.field == "assignedTo" and item.confidence >= 0.85 for item in suggestions))

    def test_multiple_identity_fields_in_same_object_are_ambiguous(self):
        identities = self.identities()
        suggestions = suggest_owner_fields_from_observations(
            "customers",
            [
                (
                    {
                        "id": "202",
                        "advisorId": "98371",
                        "createdBy": "4001",
                    },
                    identities["advisor_b"],
                )
            ],
            identities,
        )

        advisor = next(item for item in suggestions if item.field == "advisorId")
        self.assertGreaterEqual(advisor.ambiguous_matches, 1)
        self.assertLess(advisor.confidence, 0.85)

    def test_outlier_is_explained_and_does_not_look_perfect(self):
        identities = self.identities()
        observations = [({"id": str(index), "managerId": "4001"}, identities["advisor_a"]) for index in range(9)]
        observations.append(({"id": "10", "managerId": "98371"}, identities["advisor_a"]))

        suggestions = suggest_owner_fields_from_observations("customers", observations, identities)

        manager = next(item for item in suggestions if item.field == "managerId")
        self.assertEqual(manager.observations, 10)
        self.assertEqual(manager.owner_matches, 9)
        self.assertGreaterEqual(manager.ambiguous_matches, 1)
        self.assertLess(manager.confidence, 0.95)


if __name__ == "__main__":
    unittest.main()
