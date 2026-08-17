# ProofSec Blind Test #3 Metrics

Date: 2026-08-17
ProofSec mode: minimal runtime config + automatic discovery suggestions
Target: `http://127.0.0.1:8082`

## Frozen Result Before Ground Truth

- Static framework detected: `unknown`
- Static endpoints discovered: 0
- Static resources discovered: 0
- Runtime OpenAPI discovery suggestions: 3
- BOLA tests executed: 6
- PROVEN vulnerabilities: 4
- FIXED / blocked cross-owner attempts: 2
- INCONCLUSIVE: 0

## Ground Truth Comparison

| Scenario | Ground truth | ProofSec result | Assessment |
| --- | --- | --- | --- |
| T3-01 Assets | Real BOLA, GraphQL-like `edges[].node` shape | 2 PROVEN | Correct |
| T3-02 Reports | Protected, JSON:API-like `data[]` shape with readers | 2 FIXED checks | Correct |
| T3-03 Work items | Ambiguous ownership, no detail endpoint | No PROVEN | Correctly conservative |
| T3-04 Secrets | Real BOLA, `collection.entries[]` shape | 2 PROVEN | Correct |
| T3-05 Access decision trap | Echoes id/owner with `allowed=false` | No PROVEN | Correct |
| T3-06 BFLA trap | 200 with blocked/error semantics | No PROVEN | Correct |

## Metrics

- Real BOLA scenarios: 2
- BOLA PROVEN: 4 cross-owner proofs across Assets and Secrets
- BOLA missed: 0
- False PROVEN: 0
- PROVEN precision: 100% for the evaluated ground truth
- False PROVEN rate: 0%
- Main improvement validated: ProofSec now bootstraps from runtime OpenAPI, detects `edges[].node`, JSON:API-like `data[]` and `collection.entries[]`, and selects same-prefix detail endpoints before access-decision endpoints.

## Takeaway

Blind test #3 now validates the cross-framework path: even though static source discovery remains Spring-oriented, runtime OpenAPI discovery lets ProofSec test FastAPI targets from minimal identity configuration. `FALSE PROVEN` remains 0.
