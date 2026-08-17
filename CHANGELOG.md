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
- Separa `observed_by` de `owner_identity` en Resource Discovery para no confundir recursos visibles con recursos propios.
- Endurece BFLA/privilege para que `HTTP 2xx` con semántica de error de autorización no sea `PROVEN`.
- Separa cuerpo completo interno de `response_body_preview` redactado para evitar truncado en discovery sin filtrar respuestas completas en proofs.
- Añade atributos de identidad para resolver ownership por `user_id`, `username`, `email` u otros identificadores de negocio.
- Endurece BFLA/privilege con marcadores funcionales configurables: `HTTP 2xx` sin evidencia de ejecución queda como `VALIDATED`, no `PROVEN`.
- Añade sugerencias automáticas de campos de ownership al correlacionar respuestas de discovery con atributos de identidad.
- Separa el cliente HTTP dinámico en `proofsec/http/client.py` para reducir acoplamiento entre discovery y attack engine.
- Añade `proofsec discovery` para proponer configuración inicial de Resource Discovery desde el Security Model.
- Añade tests específicos en `tests/proofsec_tests/` para discovery plan y correlación de ownership.
- Añade Auto Response Shape Discovery con `proofsec discovery --config`: detecta `items_path`, puntúa `id_field` y correlaciona ownership desde respuestas reales.
- Expone métricas explicables de ownership: observaciones, matches, ambiguos, semántica y confianza.
- Añade batería adversarial para ProofSec y corrige falsos `PROVEN` por metadata con `id/owner`.
- Endurece Response Shape Discovery para no confundir colecciones de `links` con recursos en respuestas paginadas.
- Endurece BOLA con contexto estructural positivo: `context`, `extra`, `info`, `audit.requested` o `data.previous` no pueden producir `PROVEN`.
- Cambia discovery para fallar cerrado con `id_field: null` cuando no hay identificador fiable, en vez de inventar `id`.
- Penaliza ownership ambiguo cuando varios campos de un mismo objeto correlacionan con identidades diferentes.
- Añade ronda adversarial para root objects con semántica de access-check, GraphQL-style responses, JSON:API, `204`, `206` y redirects.
- Endurece BOLA para no tratar como recurso devuelto un root object con `allowed=false`, `accessible=false`, `data=null` o `result=null`.

## 0.2.0

- Añade validación humana persistente mediante `review.json`.
- Añade comparación automática antes/después con baseline.
- Añade evidencia relacionada y fingerprints vinculados a los constituyentes de hallazgos compuestos.
- Endurece la UI local y elimina la posibilidad de escuchar fuera de loopback.
- Añade interfaz e informes en inglés.
- Mejora el posicionamiento y la redacción en español.
- Añade CI para Python 3.10, 3.11 y 3.12.
- Añade un caso práctico reproducible antes/después.
