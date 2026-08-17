# ProofSec Adversarial Testing

This document records adversarial cases used to reduce false `PROVEN` results in ProofSec.

## Goals

- Detect JSON payloads that can trick BOLA validation.
- Detect response shapes that produce wrong `items_path` or `id_field`.
- Detect ambiguous ownership correlations.
- Keep `PROVEN` reserved for dynamic evidence that confirms the resource and ownership structurally.

## Current Adversarial Cases

| Area | Case | Expected result |
| --- | --- | --- |
| BOLA validation | `meta.id` and `meta.owner` match target resource | Not `PROVEN` |
| BOLA validation | Error envelope contains target id and owner | `INCONCLUSIVE` |
| BOLA validation | Shared payload confirms resource id but owner field is not structurally confirmed | `VALIDATED`, not `PROVEN` |
| BFLA validation | 2xx response contains error semantics and a functional marker | `INCONCLUSIVE` |
| Response shape | Spring-style `content` with pagination links | Select `content`, not `links` |
| Response shape | Empty `content` with pagination links | Select `content`, not `links` |
| Response shape | Only ownership-like fields exist, such as `advisorId` | Do not accept it as the resource id |
| Ownership | `managerId` correlates with `identity.attributes.user_id` | High-confidence suggestion |
| Ownership | One-off random match | Low confidence |
| Ownership | Crossed/ambiguous identity matches | Penalized confidence |

## Fixes Found By This Battery

- Metadata objects such as `meta.id` + `meta.owner` could be mistaken for a returned resource. The BOLA validator now ignores non-resource paths such as `meta`, `page`, `pagination`, `links`, `_links`, `debug` and `trace`.
- Empty paginated responses could select `links` as the collection path. Response shape discovery now penalizes link collections and prefers known resource collection keys such as `content`, `data`, `results` and `items`.

## Principle

When evidence is incomplete, ProofSec should prefer `VALIDATED` or `INCONCLUSIVE` over `PROVEN`.

