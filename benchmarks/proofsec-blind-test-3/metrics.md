# ProofSec Blind Test #3 Metrics

Date: 2026-08-17
ProofSec mode: minimal runtime config + automatic discovery suggestions
Target: `http://127.0.0.1:8082`

## Frozen Result Before Ground Truth

- Static framework detected: `unknown`
- Static endpoints discovered: 0
- Static resources discovered: 0
- Runtime discovery suggestions: 0
- Dynamic validation: stopped safely because no resource examples or discovery config were available
- PROVEN vulnerabilities: 0

## Ground Truth Comparison

| Scenario | Ground truth | ProofSec result | Assessment |
| --- | --- | --- | --- |
| T3-01 Assets | Real BOLA, GraphQL-like `edges[].node` shape | Missed | False negative |
| T3-02 Reports | Protected, JSON:API-like `data[]` shape with readers | Not tested | Coverage gap |
| T3-03 Work items | Ambiguous ownership, no detail endpoint | Not tested | Safe by non-execution |
| T3-04 Secrets | Real BOLA, `collection.entries[]` shape | Missed | False negative |
| T3-05 Access decision trap | Echoes id/owner with `allowed=false` | Not tested | Safe by non-execution |
| T3-06 BFLA trap | 200 with blocked/error semantics | Not tested | Safe by non-execution |

## Metrics

- Real BOLA scenarios: 2
- BOLA PROVEN: 0
- BOLA missed: 2
- False PROVEN: 0
- PROVEN precision: not applicable, because no PROVEN result was emitted
- False PROVEN rate: 0%
- Main gap found: ProofSec does not yet discover FastAPI/OpenAPI routes and therefore cannot bootstrap cross-framework dynamic validation from only identities and target URL.

## Takeaway

Blind test #3 confirms the current product boundary: the Spring-oriented discovery pipeline is conservative outside Spring Boot. The next major capability should be OpenAPI/FastAPI discovery, including response shapes such as `edges[].node`, JSON:API `data[]` and `collection.entries[]`.
