# Caso práctico: de dos riesgos a cero hallazgos

Este ejemplo usa dos proyectos mínimos incluidos en el repositorio:

- `examples/case-study-before`: contiene una API key de demostración y CORS abierto.
- `examples/case-study-after`: representa el estado remediado, sin secretos ni configuración CORS permisiva.

Los valores son deliberadamente ficticios y no contienen credenciales reales.

## 1. Crear el baseline

```bash
preauditor examples/case-study-before \
  --profile basic \
  --baseline /tmp/preauditor-case-baseline.json \
  --out /tmp/preauditor-case-before.md \
  --fail-on never
```

Resultado reproducible:

| Métrica | Antes |
|---|---:|
| Hallazgos totales | 2 |
| Críticos | 1 |
| Altos | 1 |
| Riesgo global | Alto |

Los hallazgos son `SEC-001` — posible secreto expuesto — y `SEC-003` — CORS abierto.

## 2. Comparar el estado remediado

```bash
preauditor examples/case-study-after \
  --profile basic \
  --compare /tmp/preauditor-case-baseline.json \
  --out /tmp/preauditor-case-after.md \
  --fail-on never
```

Resultado reproducible:

| Métrica | Después |
|---|---:|
| Hallazgos nuevos | 0 |
| Hallazgos corregidos | 2 |
| Hallazgos persistentes | 0 |
| Hallazgos actuales | 0 |
| Riesgo global | Sin hallazgos automáticos relevantes |

## Qué demuestra

El caso permite enseñar a un cliente un flujo completo y verificable:

1. Detectar y guardar el estado inicial.
2. Corregir el código o la configuración.
3. Volver a analizar con el mismo criterio.
4. Demostrar qué riesgos desaparecieron y cuáles siguen presentes.

El resultado continúa siendo un análisis preliminar. La validación humana en `review.json` aporta la decisión profesional y la trazabilidad necesarias para una entrega real.
