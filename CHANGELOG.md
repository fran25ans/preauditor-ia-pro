# Changelog

## Unreleased

- Añade `mobile-release-radar`, una herramienta para analizar y comparar releases móviles Android (`.apk`, `.aab`) e iOS (`.ipa`).
- Añade `mobile-release-ui`, una interfaz web local separada para analizar APK/AAB/IPA y ver la decisión de release.
- Detecta permisos, componentes exportados, configuraciones móviles inseguras, dominios, endpoints, secretos y cambios entre builds.
- Genera decisión preliminar de release: `APPROVED`, `NEEDS_REVIEW` o `BLOCKED`.
- Añade checklist de preparación para tienda, política de release configurable y timeline histórico por aplicación.
- Amplía ProofSec con configuración de target autorizado, identidades de prueba, motor BOLA/IDOR seguro, BFLA, privilege escalation controlado, Security Proof, propuesta de remediación, test de regresión conceptual y retest de fixes.
- Añade guardrails dinámicos: `target.authorized: true`, localhost por defecto, límite de requests, timeout y evidencias con tokens redactados.
- Endurece el criterio `PROVEN` de BOLA/IDOR con validador de recurso y ownership; `HTTP 200` con body genérico queda como `INCONCLUSIVE`.
- Añade validación estructural de BOLA/IDOR para evitar `PROVEN` en payloads de error que solo mencionan recurso y owner como texto.
- Añade Resource Discovery configurado para aprender recursos por identidad desde endpoints de listado antes de construir la matriz de ataque cruzado.

## 0.2.0

- Añade validación humana persistente mediante `review.json`.
- Añade comparación automática antes/después con baseline.
- Añade evidencia relacionada y fingerprints vinculados a los constituyentes de hallazgos compuestos.
- Endurece la UI local y elimina la posibilidad de escuchar fuera de loopback.
- Añade interfaz e informes en inglés.
- Mejora el posicionamiento y la redacción en español.
- Añade CI para Python 3.10, 3.11 y 3.12.
- Añade un caso práctico reproducible antes/después.
