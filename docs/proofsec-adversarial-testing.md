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
| Response shape | No reliable id candidate exists | `id_field: null` / needs confirmation |
| BOLA validation | `context`, `extra`, `info`, `audit.requested` or `requestedResource` contain target id and owner | Not `PROVEN` |
| BOLA validation | `data.previous` contains target id and owner but current resource is null | Not `PROVEN` |
| BOLA validation | Root object contains `id`/`owner` but `allowed=false`, `accessible=false`, `result=null` or `data=null` | Not `PROVEN` |
| BOLA validation | GraphQL-style `data.customer` contains target id and owner without explicit response shape | Not `PROVEN` |
| BOLA validation | JSON:API relationship points to owner | `VALIDATED`, not `PROVEN` |
| BOLA validation | `204`, `206` and redirects | Not `PROVEN` unless structural ownership evidence exists |
| Ownership | Multiple identity-correlated fields in the same object point to different identities | Penalized as ambiguous |
| Ownership | `managerId` correlates with `identity.attributes.user_id` | High-confidence suggestion |
| Ownership | One-off random match | Low confidence |
| Ownership | Crossed/ambiguous identity matches | Penalized confidence |

## Fixes Found By This Battery

- Metadata objects such as `meta.id` + `meta.owner` could be mistaken for a returned resource. The BOLA validator now ignores non-resource paths such as `meta`, `page`, `pagination`, `links`, `_links`, `debug` and `trace`.
- Empty paginated responses could select `links` as the collection path. Response shape discovery now penalizes link collections and prefers known resource collection keys such as `content`, `data`, `results` and `items`.
- BOLA validation now requires positive structural context for the returned resource: root object, direct `data`/`result` wrappers, or items inside resource collection wrappers.
- Response shape discovery now fails closed with `id_field: null` when the best candidate is too weak.
- Root objects with access-decision semantics are not treated as returned resources.

## Principle

When evidence is incomplete, ProofSec should prefer `VALIDATED` or `INCONCLUSIVE` over `PROVEN`.
