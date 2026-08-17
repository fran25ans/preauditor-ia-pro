# Que mirar primero

## Entregables reales

- `deliverables/miapp/informe-miapp.pdf`: informe PDF para leer o enviar.
- `deliverables/miapp/dashboard-miapp.html`: dashboard local con filtros.
- `deliverables/miapp/informe-miapp.html`: informe tecnico en HTML.
- `deliverables/miapp/hallazgos-miapp.json`: datos estructurados.

## Herramienta

- `preauditor.py`: motor principal.
- `preauditor_ui.py`: interfaz web local.
- `mobile_release_radar.py`: comparador de releases moviles Android/iOS.
- `mobile_release_ui.py`: interfaz web local para Mobile Release Radar.
- `proofsec/`: base ProofSec para modelo de seguridad, invariantes, BOLA dinámico, Security Proof y retest.
- `README.md`: documentacion de uso.
- `install.sh`: instalador local.
- `dist/preauditor_ia-0.1.0-py3-none-any.whl`: paquete instalable.
- `tests/test_preauditor.py`: tests automaticos.
- `examples/custom-rules.yml`: ejemplo de reglas custom para clientes.

## Demos

- `examples/reports/`: informes de ejemplo.
- `sample-vulnerable/`: proyecto vulnerable de prueba.

## Comandos utiles

```bash
preauditor --profile pro --list-rules
preauditor-ui
mobile-release-ui
mobile-release-radar /Users/franciscojosegimenoesteban/Downloads/85.apk --history-dir deliverables/mobile-history --out deliverables/mobile-85/mobile-report.md --html deliverables/mobile-85/mobile-report.html --json deliverables/mobile-85/mobile-report.json
proofsec analyze ./examples/proofsec-spring-demo --out deliverables/proofsec/security-model.json
proofsec contract ./examples/proofsec-spring-demo --out deliverables/proofsec/security-contract.yml
proofsec contract ./examples/proofsec-spring-demo --out deliverables/proofsec/security-contract.json
proofsec invariants --contract deliverables/proofsec/security-contract.json --model deliverables/proofsec/security-model.json --confirm-all --updated-contract deliverables/proofsec/security-contract-reviewed.json --out deliverables/proofsec/invariant-state.json
proofsec test --type bola --model deliverables/proofsec/security-model.json --contract deliverables/proofsec/security-contract-reviewed.json --config examples/proofsec-runtime.example.json --out deliverables/proofsec/security-proofs.json
proofsec test --type all --model deliverables/proofsec/security-model.json --contract deliverables/proofsec/security-contract-reviewed.json --config examples/proofsec-runtime.example.json --out deliverables/proofsec/security-proofs-all.json
preauditor ./sample-vulnerable --profile pro --ollama --fail-on never
preauditor ./sample-vulnerable --profile pro --rules-file examples/custom-rules.yml --fail-on never
python3 -m unittest discover -s tests
sh install.sh
```
