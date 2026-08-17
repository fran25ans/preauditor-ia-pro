# ProofSec Blind Test #2 Metrics

Date: 2026-08-17
ProofSec mode: minimal runtime config + automatic discovery suggestions
Target: `http://127.0.0.1:18081`

## Frozen Result Before Ground Truth

- Static endpoints discovered: 11
- Static resources discovered: 8
- Runtime discovery suggestions: 2
- BOLA tests executed: 2
- PROVEN vulnerabilities: 0
- FIXED / blocked cross-owner attempts: 2
- INCONCLUSIVE: 0

## Ground Truth Comparison

| Scenario | Ground truth | ProofSec result | Assessment |
| --- | --- | --- | --- |
| T2-01 Records | Real BOLA in `/v3/workspaces/{tenant}/records/{recordKey}` | Missed | False negative |
| T2-02 Cases | Protected, map-shaped collection | No PROVEN | Correctly conservative |
| T2-03 Vault | Owner + legitimate delegate, protected detail | 2 FIXED checks | Correct |
| T2-04 Tickets | Ambiguous ownership, no detail endpoint | No PROVEN | Correctly conservative |
| T2-05 Decision trap | Response echoes access decision, not resource | No PROVEN | Correct |
| T2-06 BFLA trap | 200 with blocked/error semantics | No PROVEN | Correct |

## Metrics

- Real BOLA scenarios: 1
- BOLA PROVEN: 0
- BOLA missed: 1
- False PROVEN: 0
- PROVEN precision: not applicable, because no PROVEN result was emitted
- False PROVEN rate: 0%
- Main gap found: ProofSec did not infer tenant-scoped collection/detail URLs that require substituting identity attributes such as `tenant_id` into `{tenant}` path variables.

## Takeaway

ProofSec behaved fail-closed in this blind target: it preferred missing a real BOLA over declaring exploitability without enough evidence. The next precision-safe improvement is tenant/path-variable aware discovery, not broader vulnerability coverage.
