# Changelog

## Unreleased

- Añade `mobile-release-radar`, una herramienta para analizar y comparar releases móviles Android (`.apk`, `.aab`) e iOS (`.ipa`).
- Añade `mobile-release-ui`, una interfaz web local separada para analizar APK/AAB/IPA y ver la decisión de release.
- Detecta permisos, componentes exportados, configuraciones móviles inseguras, dominios, endpoints, secretos y cambios entre builds.
- Genera decisión preliminar de release: `APPROVED`, `NEEDS_REVIEW` o `BLOCKED`.
- Añade checklist de preparación para tienda, política de release configurable y timeline histórico por aplicación.

## 0.2.0

- Añade validación humana persistente mediante `review.json`.
- Añade comparación automática antes/después con baseline.
- Añade evidencia relacionada y fingerprints vinculados a los constituyentes de hallazgos compuestos.
- Endurece la UI local y elimina la posibilidad de escuchar fuera de loopback.
- Añade interfaz e informes en inglés.
- Mejora el posicionamiento y la redacción en español.
- Añade CI para Python 3.10, 3.11 y 3.12.
- Añade un caso práctico reproducible antes/después.
