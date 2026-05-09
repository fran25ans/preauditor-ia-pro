# Que mirar primero

## Entregables reales

- `deliverables/miapp/informe-miapp.pdf`: informe PDF para leer o enviar.
- `deliverables/miapp/dashboard-miapp.html`: dashboard local con filtros.
- `deliverables/miapp/informe-miapp.html`: informe tecnico en HTML.
- `deliverables/miapp/hallazgos-miapp.json`: datos estructurados.

## Herramienta

- `preauditor.py`: motor principal.
- `preauditor_ui.py`: interfaz web local.
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
preauditor ./sample-vulnerable --profile pro --ollama --fail-on never
preauditor ./sample-vulnerable --profile pro --rules-file examples/custom-rules.yml --fail-on never
python3 -m unittest discover -s tests
sh install.sh
```
