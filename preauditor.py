#!/usr/bin/env python3
"""Local security pre-auditor for codebases using AI and API surfaces."""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import html
import json
import os
import re
import zipfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from html import unescape
from pathlib import Path
from typing import Iterable
from urllib import error as urlerror
from urllib import request as urlrequest


SEVERITY_ORDER = {
    "Critica": 4,
    "Alta": 3,
    "Media": 2,
    "Baja": 1,
}

SEVERITY_LABELS = {
    "Critica": "Critica",
    "Alta": "Alta",
    "Media": "Media",
    "Baja": "Baja",
}

REVIEW_STATUSES = {
    "pending": "Pendiente",
    "confirmed": "Confirmado manualmente",
    "false_positive": "Falso positivo",
    "accepted_risk": "Riesgo aceptado",
    "fixed": "Corregido",
    "revalidated": "Revalidado",
}

REVIEW_STATUS_LABELS_EN = {
    "pending": "Pending",
    "confirmed": "Manually confirmed",
    "false_positive": "False positive",
    "accepted_risk": "Accepted risk",
    "fixed": "Fixed",
    "revalidated": "Revalidated",
}

SEVERITY_LABELS_EN = {
    "Critica": "Critical",
    "Alta": "High",
    "Media": "Medium",
    "Baja": "Low",
}

RISK_LABELS_EN = {
    "Alto": "High",
    "Medio": "Medium",
    "Bajo": "Low",
    "Sin hallazgos automáticos relevantes": "No relevant automated findings",
}

COMPARISON_STATUS_EN = {
    "mejora": "improved",
    "regresion": "regression",
    "estable": "stable",
}

LEVEL_LABELS_EN = {
    "Crítico": "Critical",
    "Alto": "High",
    "Medio": "Medium",
    "Bajo": "Low",
}

LANGUAGES = {
    "es": "Español",
    "en": "English",
}

PROFILES = {
    "basic": {
        "SEC-001",
        "SEC-002",
        "SEC-003",
        "SEC-004",
        "SEC-005",
        "SEC-006",
        "SEC-007",
        "SEC-008",
        "SEC-009",
        "SEC-010",
        "SEC-011",
        "SEC-012",
    },
    "pro": "all",
    "ai": "category:IA,CI/CD,Secretos,Supply Chain",
    "api": "category:API,Autenticacion,Sesion,Frontend,Privacidad,Inyeccion,Transporte",
    "cloud": "category:Cloud,Infraestructura,Kubernetes,Contenedores,Secretos,Resiliencia",
    "cicd": "category:CI/CD,Supply Chain,Secretos,IA",
    "fintech": "category:API,Autenticacion,Sesion,Privacidad,Criptografia,Secretos,CI/CD,IA,Cloud",
}

STACKS = {
    "generic": "Stack generico",
    "codeigniter": "CodeIgniter/PHP",
    "springboot": "Spring Boot/JVM",
    "react": "React/frontend",
    "node": "Node.js",
    "flutter": "Flutter/mobile",
    "wordpress": "WordPress/PHP",
}

DEFAULT_EXCLUDES = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "dist",
    "build",
    "__pycache__",
    ".next",
    ".turbo",
    "coverage",
    ".pytest_cache",
}

TEXT_EXTENSIONS = {
    ".bat",
    ".c",
    ".cfg",
    ".conf",
    ".cpp",
    ".cs",
    ".css",
    ".docx",
    ".env",
    ".go",
    ".gradle",
    ".graphql",
    ".h",
    ".hcl",
    ".html",
    ".ini",
    ".java",
    ".js",
    ".json",
    ".jsx",
    ".kt",
    ".md",
    ".mjs",
    ".php",
    ".properties",
    ".py",
    ".rb",
    ".rs",
    ".sh",
    ".sql",
    ".swift",
    ".tf",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    category: str
    cvss: float
    confidence: str
    remediation_effort: str
    file: str
    line: int
    evidence: str
    context: str
    fingerprint: str
    description: str
    why_dangerous: str
    exploit_concept: str
    recommendation: str
    secure_example: str
    reference: str
    related_findings: tuple[dict[str, object], ...] = ()


@dataclass(frozen=True)
class ReportMeta:
    client: str
    auditor: str
    scope: str
    version: str
    stack: str = "generic"
    language: str = "es"


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    severity: str
    category: str
    cvss: float
    confidence: str
    remediation_effort: str
    patterns: tuple[re.Pattern[str], ...]
    file_globs: tuple[str, ...]
    description: str
    why_dangerous: str
    exploit_concept: str
    recommendation: str
    secure_example: str
    reference: str

    def applies_to(self, relative_path: str) -> bool:
        if not self.file_globs:
            return True
        return any(fnmatch.fnmatch(relative_path, glob) for glob in self.file_globs)


def compile_rule(
    rule_id: str,
    title: str,
    severity: str,
    category: str,
    cvss: float,
    confidence: str,
    remediation_effort: str,
    regexes: list[str],
    file_globs: list[str] | None,
    description: str,
    why_dangerous: str,
    exploit_concept: str,
    recommendation: str,
    secure_example: str,
    reference: str,
) -> Rule:
    return Rule(
        rule_id=rule_id,
        title=title,
        severity=severity,
        category=category,
        cvss=cvss,
        confidence=confidence,
        remediation_effort=remediation_effort,
        patterns=tuple(re.compile(regex, re.IGNORECASE) for regex in regexes),
        file_globs=tuple(file_globs or []),
        description=description,
        why_dangerous=why_dangerous,
        exploit_concept=exploit_concept,
        recommendation=recommendation,
        secure_example=secure_example,
        reference=reference,
    )


def yaml_scalar(value: object) -> str:
    text = str(value).strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {"'", '"'}:
        text = text[1:-1]
    return text


def report_language(meta: ReportMeta | None = None, language: str | None = None) -> str:
    value = language or (meta.language if meta else "es")
    return "en" if value == "en" else "es"


def severity_label(severity: str, lang: str = "es") -> str:
    if lang == "en":
        return SEVERITY_LABELS_EN.get(severity, severity)
    return "Crítica" if severity == "Critica" else severity


def review_status_label(status: str, lang: str = "es") -> str:
    if lang == "en":
        return REVIEW_STATUS_LABELS_EN.get(status, status)
    return REVIEW_STATUSES.get(status, status)


def risk_label(risk: str, lang: str = "es") -> str:
    if lang == "en":
        return RISK_LABELS_EN.get(risk, risk)
    return risk


def comparison_status_label(status: str, lang: str = "es") -> str:
    if lang == "en":
        return COMPARISON_STATUS_EN.get(status, status)
    return status


def level_label(level: str, lang: str = "es") -> str:
    if lang == "en":
        return LEVEL_LABELS_EN.get(level, level)
    return level


def stack_label(stack: str, lang: str = "es") -> str:
    label = STACKS.get(stack, stack)
    if lang == "en" and label == "Stack generico":
        return "Generic stack"
    return label


def parse_inline_list(value: str) -> list[str]:
    value = value.strip()
    if value.startswith("[") and value.endswith("]"):
        raw_items = value[1:-1].split(",")
        return [yaml_scalar(item) for item in raw_items if yaml_scalar(item)]
    return [yaml_scalar(value)] if value else []


def parse_simple_yaml_rules(text: str) -> list[dict]:
    rules: list[dict] = []
    current: dict | None = None
    list_key: str | None = None

    for raw_line in text.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        line = raw_line.strip()
        if line == "rules:":
            continue
        if line.startswith("- "):
            item = line[2:].strip()
            if indent <= 2 and ":" in item:
                current = {}
                rules.append(current)
                list_key = None
                key, value = item.split(":", 1)
                current[key.strip()] = yaml_scalar(value)
                continue
            if current is not None and list_key:
                current.setdefault(list_key, []).append(yaml_scalar(item))
            continue
        if current is None or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        if value:
            current[key] = parse_inline_list(value) if key in {"regexes", "file_globs"} else yaml_scalar(value)
            list_key = None
        else:
            current[key] = []
            list_key = key
    return rules


def load_custom_rules(path: Path | None) -> list[Rule]:
    if not path:
        return []
    if not path.exists():
        raise ValueError(f"Archivo de reglas custom no encontrado: {path}")

    text = path.read_text(encoding="utf-8", errors="replace")
    if path.suffix.lower() == ".json":
        data = json.loads(text)
    else:
        try:
            import yaml  # type: ignore

            data = yaml.safe_load(text)
        except Exception:
            data = {"rules": parse_simple_yaml_rules(text)}

    raw_rules = data.get("rules", data) if isinstance(data, dict) else data
    if not isinstance(raw_rules, list):
        raise ValueError("El archivo de reglas custom debe contener una lista 'rules'.")

    custom_rules: list[Rule] = []
    for index, raw_rule in enumerate(raw_rules, start=1):
        if not isinstance(raw_rule, dict):
            raise ValueError(f"Regla custom #{index} invalida.")
        rule_id = yaml_scalar(raw_rule.get("id") or raw_rule.get("rule_id") or f"CUSTOM-{index:03d}")
        severity = yaml_scalar(raw_rule.get("severity", "Media"))
        if severity not in SEVERITY_ORDER:
            raise ValueError(f"Regla custom {rule_id}: severidad invalida '{severity}'.")
        regexes_value = raw_rule.get("regexes", raw_rule.get("regex", []))
        if isinstance(regexes_value, str):
            regexes = [regexes_value]
        else:
            regexes = [yaml_scalar(item) for item in regexes_value]
        if not regexes:
            raise ValueError(f"Regla custom {rule_id}: falta regex o regexes.")
        file_globs_value = raw_rule.get("file_globs", raw_rule.get("files", []))
        if isinstance(file_globs_value, str):
            file_globs = parse_inline_list(file_globs_value)
        else:
            file_globs = [yaml_scalar(item) for item in file_globs_value]
        custom_rules.append(
            compile_rule(
                rule_id,
                yaml_scalar(raw_rule.get("title", "Regla custom")),
                severity,
                yaml_scalar(raw_rule.get("category", "Custom")),
                float(raw_rule.get("cvss", 6.0)),
                yaml_scalar(raw_rule.get("confidence", "Media")),
                yaml_scalar(raw_rule.get("remediation_effort", "Media")),
                regexes,
                file_globs,
                yaml_scalar(raw_rule.get("description", "Patron definido por reglas custom del cliente.")),
                yaml_scalar(raw_rule.get("why_dangerous", "Puede incumplir una politica interna o introducir riesgo contextual.")),
                yaml_scalar(raw_rule.get("exploit_concept", "Depende del contexto; requiere validacion del auditor.")),
                yaml_scalar(raw_rule.get("recommendation", "Revisar el patron y aplicar la politica interna correspondiente.")),
                yaml_scalar(raw_rule.get("secure_example", "Definir una alternativa aprobada por la politica interna.")),
                yaml_scalar(raw_rule.get("reference", "Politica interna / OWASP")),
            )
        )
    return custom_rules


RULES = [
    compile_rule(
        "SEC-001",
        "Posible secreto o API key expuesta",
        "Critica",
        "Secretos",
        9.1,
        "Alta",
        "Media",
        [
            r"\b(api[_-]?key|secret|token|password|passwd|pwd)\b\s*[:=]\s*['\"][^'\"\s]{12,}['\"]",
            r"\b(sk-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{20,})\b",
            r"\b(AKIA|ASIA)[A-Z0-9]{16}\b",
        ],
        None,
        "Se ha encontrado un patrón compatible con una credencial embebida en el código.",
        "Una credencial comprometida puede permitir acceso directo a servicios, datos o infraestructura sin pasar por controles de aplicación.",
        "Un atacante con acceso al repositorio o a un artefacto publicado podría reutilizar la clave para consultar APIs, exfiltrar datos o desplegar cambios.",
        "Revoca la credencial, elimínala del historial si procede y usa un gestor de secretos o variables de entorno gestionadas.",
        "API_KEY = os.environ['SERVICE_API_KEY']",
        "OWASP Top 10 A02 Cryptographic Failures / OWASP API Security API8 Security Misconfiguration",
    ),
    compile_rule(
        "SEC-002",
        "Archivo de entorno o credenciales incluido",
        "Alta",
        "Secretos",
        8.1,
        "Media",
        "Baja",
        [r".+"],
        ["*.env", "*.env.*", "*credentials*", "*secrets*", "id_rsa", "*.pem", "*.key"],
        "El repositorio contiene un archivo cuyo nombre sugiere secretos, claves privadas o configuración sensible.",
        "Estos archivos suelen contener tokens, passwords o claves privadas que no deben distribuirse con el código.",
        "Un atacante puede buscar estos nombres de archivo y extraer credenciales aunque no conozca la estructura interna del proyecto.",
        "Mantén solo plantillas sin secretos, como .env.example, y excluye los ficheros reales mediante .gitignore.",
        "DATABASE_URL=postgres://user:password@host/db  # solo en gestor seguro, nunca en repo",
        "OWASP Top 10 A05 Security Misconfiguration",
    ),
    compile_rule(
        "SEC-003",
        "CORS abierto",
        "Alta",
        "API",
        8.0,
        "Alta",
        "Media",
        [
            r"Access-Control-Allow-Origin['\"]?\s*[:,]\s*['\"]\*['\"]",
            r"cors\(\s*\{?[^}\n]*(origin\s*:\s*['\"]\*['\"]|origin\s*:\s*true)",
            r"allow_origins\s*=\s*\[\s*['\"]\*['\"]\s*\]",
        ],
        None,
        "La configuración permite peticiones cross-origin desde cualquier dominio.",
        "CORS abierto puede exponer endpoints sensibles a abuso desde navegadores de terceros, sobre todo si hay cookies o tokens implicados.",
        "Una web controlada por un atacante podría invocar la API desde el navegador de una víctima y leer respuestas si la configuración lo permite.",
        "Restringe los orígenes a dominios explícitos por entorno y evita combinar comodines con credenciales.",
        "app.use(cors({ origin: ['https://app.example.com'], credentials: true }))",
        "OWASP API Security API7 Security Misconfiguration",
    ),
    compile_rule(
        "SEC-004",
        "Endpoint aparentemente sin autenticacion",
        "Media",
        "API",
        6.8,
        "Media",
        "Media",
        [
            r"@(app|router)\.(get|post|put|delete|patch)\([^)]*\)\s*\n\s*(async\s+)?def\s+\w+",
            r"(app|router)\.(get|post|put|delete|patch)\([^)]*\)\s*=>",
            r"(app|router)\.(get|post|put|delete|patch)\([^,\n]+,\s*(async\s*)?\(",
        ],
        ["*.py", "*.js", "*.ts", "*.tsx", "*.jsx"],
        "Se ha localizado una ruta o endpoint sin evidencia cercana de middleware o dependencia de autenticacion.",
        "Los endpoints sin autenticacion pueden exponer datos o acciones internas si no se separan claramente las rutas publicas.",
        "Un atacante podria enumerar rutas y llamar directamente a operaciones no protegidas.",
        "Declara autenticacion por defecto y documenta explicitamente las rutas publicas.",
        "router.get('/profile', requireAuth, getProfile)",
        "OWASP API Security API1 Broken Object Level Authorization / API2 Broken Authentication",
    ),
    compile_rule(
        "SEC-005",
        "Permisos excesivos en GitHub Actions",
        "Alta",
        "CI/CD",
        8.2,
        "Alta",
        "Baja",
        [
            r"permissions:\s*(write-all|read-all)",
            r"pull-requests:\s*write",
            r"issues:\s*write",
            r"contents:\s*write",
            r"id-token:\s*write",
        ],
        ["*.yml", "*.yaml", "*.docx", ".github/workflows/*.yml", ".github/workflows/*.yaml"],
        "El workflow solicita permisos amplios o sensibles.",
        "Permisos excesivos aumentan el impacto de una ejecucion maliciosa, una dependencia comprometida o un pull request inseguro.",
        "Un atacante que consiga ejecutar codigo en CI podria publicar paquetes, modificar el repositorio o solicitar tokens OIDC.",
        "Aplica minimo privilegio por job y limita permisos write a los jobs que los necesitan.",
        "permissions:\n  contents: read",
        "OWASP Top 10 A05 Security Misconfiguration / OWASP CI/CD Security",
    ),
    compile_rule(
        "SEC-006",
        "Ejecucion dinamica de codigo o comandos",
        "Alta",
        "Ejecucion",
        8.8,
        "Alta",
        "Media",
        [
            r"\beval\s*\(",
            r"\bexec\s*\(",
            r"\bshell_exec\s*\(",
            r"\bsystem\s*\(",
            r"subprocess\.(run|Popen|call)\([^)]*shell\s*=\s*True",
            r"child_process\.(exec|execSync)\s*\(",
        ],
        None,
        "Se ha detectado ejecucion dinamica de codigo o comandos del sistema.",
        "Si la entrada del usuario alcanza estas llamadas, puede derivar en ejecucion remota de codigo o inyeccion de comandos.",
        "Un atacante podria manipular parametros para ejecutar instrucciones arbitrarias en el servidor.",
        "Evita eval/exec, usa APIs tipadas y pasa argumentos como listas sin shell.",
        "subprocess.run(['git', 'status'], check=True)",
        "OWASP Top 10 A03 Injection",
    ),
    compile_rule(
        "SEC-007",
        "Prompt de sistema visible o embebido",
        "Media",
        "IA",
        5.9,
        "Media",
        "Media",
        [
            r"system[_ -]?prompt\s*[:=]",
            r"role\s*[:=]\s*['\"]system['\"]",
            r"You are ChatGPT|You are an AI assistant",
        ],
        None,
        "Hay instrucciones de sistema o prompts sensibles definidos directamente en el codigo.",
        "Los prompts pueden revelar politica interna, herramientas disponibles o restricciones de seguridad que facilitan ataques de prompt injection.",
        "Un atacante podria extraer o adaptar sus entradas para saltarse instrucciones conocidas.",
        "Mantén prompts sensibles fuera del cliente, versiona plantillas con cuidado y filtra lo que se expone al usuario.",
        "messages=[{'role': 'system', 'content': load_server_side_policy()}]",
        "OWASP LLM01 Prompt Injection / LLM07 System Prompt Leakage",
    ),
    compile_rule(
        "SEC-008",
        "Salida de IA sin validacion estructural",
        "Alta",
        "IA",
        8.0,
        "Media",
        "Media",
        [
            r"openai\.(chat\.completions|responses)\.create\(",
            r"client\.(chat\.completions|responses)\.create\(",
            r"generateContent\(",
        ],
        None,
        "Se ha encontrado una llamada a un modelo de IA; revise si la salida se valida antes de ejecutar acciones o persistir datos.",
        "Las salidas de IA pueden contener instrucciones, datos malformados o contenido manipulado por prompt injection.",
        "Un atacante podria introducir contenido que el modelo transforme en comandos, SQL, JSON invalido o decisiones no autorizadas.",
        "Usa esquemas estrictos, validacion de tipos, listas de permitidos y aprobacion humana para acciones sensibles.",
        "result = schema.parse_raw(model_output)",
        "OWASP LLM02 Insecure Output Handling",
    ),
    compile_rule(
        "SEC-009",
        "Agente con autonomia elevada",
        "Alta",
        "IA",
        8.3,
        "Media",
        "Media",
        [
            r"auto[_-]?approve\s*[:=]\s*true",
            r"allow[_-]?all[_-]?tools\s*[:=]\s*true",
            r"max[_-]?iterations\s*[:=]\s*(?:[5-9]|\d{2,})",
            r"human[_-]?approval\s*[:=]\s*false",
        ],
        None,
        "La configuracion sugiere que un agente puede actuar con poca supervision.",
        "Los agentes autonomos amplifican errores, prompt injection y abuso de herramientas cuando no existen limites claros.",
        "Un atacante podria inducir al agente a ejecutar operaciones encadenadas, consultar secretos o modificar recursos.",
        "Define permisos por herramienta, limites de iteracion, confirmacion humana y registros auditables.",
        "agent = Agent(tools=[read_docs], require_approval=['write_file', 'deploy'])",
        "OWASP LLM06 Excessive Agency",
    ),
    compile_rule(
        "SEC-010",
        "Herramienta IA con permisos demasiado amplios",
        "Alta",
        "IA",
        8.4,
        "Media",
        "Media",
        [
            r"tools\s*[:=]\s*\[?[^\n]*(shell|browser|filesystem|write_file|delete_file)",
            r"permissions\s*[:=]\s*['\"]?(all|admin|write)['\"]?",
        ],
        ["*.py", "*.js", "*.ts", "*.tsx", "*.jsx", "*.json", "*.toml"],
        "Se detectan herramientas o permisos sensibles accesibles desde un flujo de IA.",
        "Una herramienta poderosa expuesta al modelo sin control granular puede convertir una manipulacion de prompt en una accion real.",
        "Un atacante podria hacer que la IA lea archivos, escriba cambios o invoque comandos fuera del caso de uso previsto.",
        "Aplica minimo privilegio, separa herramientas por contexto y exige confirmacion para acciones destructivas.",
        "tools = [SearchDocsTool(read_only=True)]",
        "OWASP LLM06 Excessive Agency / LLM08 Vector and Embedding Weaknesses",
    ),
    compile_rule(
        "SEC-011",
        "Logs con posible informacion sensible",
        "Media",
        "Privacidad",
        6.5,
        "Media",
        "Baja",
        [
            r"(console\.log|logger\.(info|debug|error)|print)\([^)]*(password|token|secret|authorization|cookie|api[_-]?key)",
            r"(request|req|headers|body|cookies)\b[^;\n]*(console\.log|print|logger)",
        ],
        None,
        "Un log podria estar registrando datos sensibles, cabeceras, cookies o cuerpos de peticion.",
        "Los logs se replican y retienen en multiples sistemas; exponer secretos ahi aumenta mucho la superficie de fuga.",
        "Un usuario interno, proveedor o intruso con acceso a observabilidad podria recuperar tokens o datos personales.",
        "Enmascara secretos, evita registrar cuerpos completos y aplica politicas de retencion.",
        "logger.info('login failed', extra={'user_id': user.id})",
        "OWASP Top 10 A09 Security Logging and Monitoring Failures",
    ),
    compile_rule(
        "SEC-012",
        "Subida de archivos sin validacion evidente",
        "Alta",
        "Archivos",
        8.1,
        "Media",
        "Media",
        [
            r"(multer|upload\.single|upload\.array|File\(|UploadFile|request\.files|move_uploaded_file)",
            r"formidable\(|busboy\(",
        ],
        None,
        "Hay manejo de subida de archivos; revise si existe validacion de tipo, tamano, extension y almacenamiento seguro.",
        "Las subidas inseguras pueden permitir malware, sobrescritura de archivos, ejecucion de contenido o consumo de recursos.",
        "Un atacante podria subir un archivo ejecutable, un payload con extension doble o un archivo enorme para degradar el servicio.",
        "Valida MIME real, extension permitida, tamano maximo, antivirus si aplica y guarda fuera del webroot.",
        "if file.content_type not in ALLOWED_TYPES: raise HTTPException(400)",
        "OWASP Top 10 A05 Security Misconfiguration / A03 Injection",
    ),
    compile_rule(
        "SEC-013",
        "Consulta SQL construida por concatenacion",
        "Alta",
        "Inyeccion",
        8.6,
        "Media",
        "Media",
        [
            r"(SELECT|INSERT|UPDATE|DELETE).*(\+|%|f['\"]|\$\{)",
            r"(cursor\.execute|db\.query|sequelize\.query)\([^)]*(\+|%|f['\"]|\$\{)",
        ],
        ["*.py", "*.js", "*.ts", "*.php", "*.java", "*.rb"],
        "La consulta parece construirse con interpolacion o concatenacion de valores.",
        "La construccion dinamica de SQL puede permitir inyeccion si cualquier fragmento proviene del usuario.",
        "Un atacante podria alterar filtros, extraer datos o ejecutar operaciones no previstas modificando parametros.",
        "Usa consultas parametrizadas, ORM seguro o query builders con binding de parametros.",
        "cursor.execute('SELECT * FROM users WHERE id = ?', [user_id])",
        "OWASP Top 10 A03 Injection / OWASP API Security API8 Security Misconfiguration",
    ),
    compile_rule(
        "SEC-014",
        "Verificacion TLS desactivada",
        "Alta",
        "Transporte",
        7.5,
        "Alta",
        "Baja",
        [
            r"verify\s*=\s*False",
            r"rejectUnauthorized\s*:\s*false",
            r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0",
            r"curl\s+.*-k\b",
        ],
        None,
        "El codigo o configuracion desactiva la validacion de certificados TLS.",
        "Sin verificacion TLS, una conexion puede ser interceptada o manipulada por un atacante en red.",
        "Un atacante con posicion de red podria presentar un certificado falso y leer o alterar trafico sensible.",
        "Mantén la verificacion TLS activa y configura certificados de confianza por entorno cuando sea necesario.",
        "requests.get(url, timeout=10)  # verify=True por defecto",
        "OWASP Top 10 A02 Cryptographic Failures",
    ),
    compile_rule(
        "SEC-015",
        "Modo debug activo",
        "Media",
        "Configuracion",
        6.4,
        "Alta",
        "Baja",
        [
            r"debug\s*[:=]\s*true",
            r"DEBUG\s*=\s*True",
            r"app\.run\([^)]*debug\s*=\s*True",
            r"ENV\s*=\s*['\"]development['\"]",
        ],
        None,
        "El modo debug o entorno de desarrollo parece estar activo en codigo o configuracion.",
        "El debug puede exponer trazas, variables, rutas internas y consolas interactivas.",
        "Un atacante podria provocar errores para obtener informacion de arquitectura o secretos en trazas.",
        "Activa debug solo localmente y controla el entorno mediante configuracion externa segura.",
        "DEBUG = os.getenv('APP_ENV') == 'local'",
        "OWASP Top 10 A05 Security Misconfiguration",
    ),
    compile_rule(
        "SEC-016",
        "Deserializacion insegura",
        "Alta",
        "Inyeccion",
        8.7,
        "Alta",
        "Media",
        [
            r"pickle\.loads?\(",
            r"yaml\.load\([^)]*Loader\s*=\s*yaml\.Loader",
            r"yaml\.load\(",
            r"unserialize\s*\(",
            r"Marshal\.load\(",
        ],
        ["*.py", "*.php", "*.rb"],
        "Se ha detectado una API de deserializacion peligrosa.",
        "Deserializar datos no confiables puede ejecutar codigo o instanciar objetos peligrosos.",
        "Un atacante podria enviar un payload serializado que ejecute acciones al ser cargado.",
        "Usa formatos de datos simples y loaders seguros; nunca deserialices objetos de entrada no confiable.",
        "yaml.safe_load(user_supplied_yaml)",
        "OWASP Top 10 A08 Software and Data Integrity Failures",
    ),
    compile_rule(
        "SEC-017",
        "JWT decodificado sin verificacion",
        "Alta",
        "Autenticacion",
        8.2,
        "Alta",
        "Media",
        [
            r"jwt\.decode\([^)]*verify\s*[:=]\s*False",
            r"jwt\.decode\([^)]*options\s*=\s*\{[^}]*verify_signature[^}]*False",
            r"verify_signature\s*[:=]\s*false",
        ],
        ["*.py", "*.js", "*.ts"],
        "El token JWT parece decodificarse sin verificar firma.",
        "Aceptar tokens sin firma valida rompe la autenticacion y permite suplantacion.",
        "Un atacante podria fabricar un JWT con claims arbitrarios y ser tratado como otro usuario o rol.",
        "Verifica firma, algoritmo esperado, expiracion, audiencia e issuer.",
        "jwt.decode(token, public_key, algorithms=['RS256'], audience='api')",
        "OWASP API Security API2 Broken Authentication",
    ),
    compile_rule(
        "SEC-018",
        "Criptografia debil",
        "Media",
        "Criptografia",
        6.1,
        "Alta",
        "Media",
        [
            r"\b(md5|sha1)\s*\(",
            r"hashlib\.(md5|sha1)\(",
            r"Crypto\.Hash\.(MD5|SHA1)",
        ],
        None,
        "Se usa un algoritmo hash considerado debil para seguridad moderna.",
        "MD5 y SHA1 son vulnerables a colisiones y no son adecuados para integridad o passwords.",
        "Un atacante podria aprovechar colisiones o hashes rapidos para evadir controles o crackear credenciales.",
        "Usa SHA-256/512 para integridad y Argon2, bcrypt o scrypt para passwords.",
        "password_hash = argon2.hash(password)",
        "OWASP Top 10 A02 Cryptographic Failures",
    ),
    compile_rule(
        "SEC-019",
        "CSP permisiva o insegura",
        "Media",
        "Frontend",
        6.2,
        "Media",
        "Media",
        [
            r"Content-Security-Policy.*(unsafe-inline|unsafe-eval|\*)",
            r"script-src[^;\n]*(unsafe-inline|unsafe-eval|\*)",
        ],
        ["*.html", "*.js", "*.ts", "*.jsx", "*.tsx", "*.conf", "*.nginx"],
        "La politica CSP contiene comodines o directivas inseguras.",
        "Una CSP debil reduce la proteccion frente a XSS y ejecucion de scripts no autorizados.",
        "Un atacante que consiga inyectar HTML tendria mas opciones para ejecutar JavaScript en el navegador.",
        "Define origenes explicitos, elimina unsafe-inline/unsafe-eval y usa nonces o hashes.",
        "Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{value}'",
        "OWASP Top 10 A03 Injection / A05 Security Misconfiguration",
    ),
    compile_rule(
        "SEC-020",
        "Docker ejecutandose como root o privilegiado",
        "Alta",
        "Contenedores",
        7.8,
        "Media",
        "Media",
        [
            r"privileged\s*:\s*true",
            r"--privileged",
            r"USER\s+root",
        ],
        ["Dockerfile", "docker-compose*.yml", "docker-compose*.yaml", "*.yaml", "*.yml"],
        "La configuracion de contenedor parece usar privilegios elevados o usuario root.",
        "Los contenedores privilegiados aumentan el impacto de una vulnerabilidad dentro de la aplicacion.",
        "Un atacante que comprometa la app podria pivotar con mas permisos sobre el contenedor o el host.",
        "Ejecuta con usuario no root, capabilities minimas y filesystem de solo lectura si es viable.",
        "USER appuser",
        "OWASP Top 10 A05 Security Misconfiguration",
    ),
    compile_rule(
        "SEC-021",
        "Exposicion de red amplia en infraestructura",
        "Alta",
        "Infraestructura",
        8.0,
        "Media",
        "Media",
        [
            r"0\.0\.0\.0/0",
            r"::/0",
            r"cidr_blocks\s*=\s*\[[^\]]*0\.0\.0\.0/0",
        ],
        ["*.tf", "*.yaml", "*.yml", "*.json"],
        "La infraestructura permite acceso desde cualquier origen de red.",
        "Reglas abiertas pueden exponer administracion, bases de datos o servicios internos a Internet.",
        "Un atacante podria escanear y atacar servicios accesibles desde cualquier IP.",
        "Limita rangos por necesidad real, usa redes privadas y controles de acceso por capa.",
        "cidr_blocks = [var.office_cidr]",
        "OWASP API Security API7 Security Misconfiguration",
    ),
    compile_rule(
        "SEC-022",
        "SSRF potencial por URL controlada",
        "Media",
        "API",
        6.9,
        "Baja",
        "Media",
        [
            r"(requests\.get|requests\.post|fetch|axios\.get|axios\.post)\([^)]*(url|uri|request|req|input)",
            r"net/http.*Get\([^)]*(url|input|target)",
        ],
        ["*.py", "*.js", "*.ts", "*.go"],
        "Una peticion HTTP saliente parece depender de una URL variable o de entrada.",
        "Si no hay lista de permitidos, puede permitir SSRF contra servicios internos o metadata endpoints.",
        "Un atacante podria forzar al servidor a consultar recursos internos no accesibles desde Internet.",
        "Valida esquema, host y puerto contra una allowlist y bloquea rangos internos.",
        "if parsed.hostname not in ALLOWED_HOSTS: raise ValueError('host not allowed')",
        "OWASP API Security API7 Server Side Request Forgery",
    ),
    compile_rule(
        "SEC-023",
        "Secretos definidos en Dockerfile",
        "Alta",
        "Secretos",
        8.0,
        "Alta",
        "Baja",
        [
            r"^(ENV|ARG)\s+(API_KEY|TOKEN|SECRET|PASSWORD|AWS_|OPENAI_)",
        ],
        ["Dockerfile", "*.dockerfile"],
        "El Dockerfile define posibles secretos mediante ENV o ARG.",
        "Los secretos en capas de imagen pueden quedar en historiales, caches y registros.",
        "Un atacante con acceso a la imagen podria inspeccionar capas y recuperar credenciales.",
        "Inyecta secretos en runtime con secret managers y evita ARG/ENV para credenciales.",
        "docker run --env-file <(secret-manager export app/prod) image",
        "OWASP Top 10 A02 Cryptographic Failures",
    ),
    compile_rule(
        "SEC-024",
        "Script de instalacion remoto ejecutado por shell",
        "Alta",
        "Supply Chain",
        8.1,
        "Alta",
        "Baja",
        [
            r"(curl|wget).*(\|\s*(sh|bash|zsh))",
            r"(sh|bash)\s+-c\s+['\"].*(curl|wget)",
        ],
        ["*.sh", "Dockerfile", "*.yaml", "*.yml", "Makefile"],
        "Se ejecuta un script remoto directamente en shell.",
        "Este patron confia en contenido remoto mutable y aumenta el riesgo de compromiso de supply chain.",
        "Un atacante que controle DNS, red, CDN o el repositorio remoto podria ejecutar codigo en el entorno.",
        "Fija versiones, verifica firmas o checksums y descarga artefactos antes de ejecutarlos.",
        "curl -fsSLO https://example.com/tool.tgz && echo '<sha256> tool.tgz' | sha256sum -c -",
        "OWASP Top 10 A08 Software and Data Integrity Failures",
    ),
    compile_rule(
        "SEC-025",
        "Cookies sin atributos de seguridad",
        "Media",
        "Sesion",
        6.4,
        "Media",
        "Baja",
        [
            r"set_cookie\([^)]*(secure\s*=\s*False|httponly\s*=\s*False|samesite\s*=\s*['\"]?none)",
            r"Set-Cookie[^;\n]*(?!.*HttpOnly)(?!.*Secure)",
            r"res\.cookie\([^)]*\{[^}]*(secure\s*:\s*false|httpOnly\s*:\s*false)",
        ],
        ["*.py", "*.js", "*.ts", "*.java", "*.php"],
        "Una cookie parece configurarse sin atributos de seguridad suficientes.",
        "Cookies sin Secure, HttpOnly o SameSite adecuado son mas vulnerables a robo o abuso cross-site.",
        "Un atacante podria aprovechar XSS o trafico no cifrado para obtener o reutilizar sesiones.",
        "Configura Secure, HttpOnly y SameSite=Lax/Strict salvo necesidad justificada.",
        "response.set_cookie('sid', value, secure=True, httponly=True, samesite='Lax')",
        "OWASP Top 10 A07 Identification and Authentication Failures",
    ),
    compile_rule(
        "SEC-026",
        "Workspace de agente IA marcado como confiable",
        "Critica",
        "IA",
        9.0,
        "Alta",
        "Baja",
        [
            r"GEMINI_CLI_TRUST_WORKSPACE\s*[:=]\s*['\"]?true['\"]?",
            r"GEMINI[_\s-]*CLI[_\s-]*TRUST[_\s-]*WORKSPACE\s*[:=]\s*['\"]?true['\"]?",
            r"TRUST_WORKSPACE\s*[:=]\s*['\"]?true['\"]?",
            r"trust\s*:\s*true",
            r"trust_workspace\s*[:=]\s*true",
        ],
        ["*.yml", "*.yaml", "*.json", "*.toml", "*.md", "*.docx"],
        "El workflow o configuracion indica que el workspace controlado por el repositorio debe tratarse como confiable para un agente IA.",
        "Si una Pull Request puede modificar archivos del workspace, el agente puede aceptar instrucciones controladas por el atacante como si fueran de confianza.",
        "Un atacante podria abrir una PR que modifique instrucciones del agente para saltarse controles, crear comentarios falsos o abusar de herramientas autorizadas.",
        "Desactiva la confianza plena del workspace y carga prompts/politicas desde una fuente no modificable por PRs externas.",
        "GEMINI_CLI_TRUST_WORKSPACE: 'false'",
        "OWASP LLM01 Prompt Injection / OWASP LLM06 Excessive Agency",
    ),
    compile_rule(
        "SEC-027",
        "Prompt de agente cargado desde el workspace del PR",
        "Critica",
        "IA",
        9.2,
        "Alta",
        "Media",
        [
            r"cp\s+\.review/GEMINI\.md\s+GEMINI\.md",
            r"cp\s+\.\s*review\s*/GEMINI\.md\s+GEMINI\.md",
            r"cat\s+\.review/GEMINI\.md",
            r"prompt:\s*\|",
        ],
        ["*.yml", "*.yaml", "*.docx"],
        "El workflow parece cargar instrucciones del agente desde archivos presentes en el workspace del repositorio.",
        "En workflows de Pull Request, esos archivos pueden ser modificados por el propio cambio revisado y convertirse en un vector de prompt injection.",
        "Un atacante podria cambiar el prompt del agente para aprobar codigo malicioso, filtrar contexto o usar herramientas con permisos del bot.",
        "Carga el prompt desde secrets, repositorio base bloqueado o configuracion externa inmutable para colaboradores externos.",
        "run: echo \"$GEMINI_PROMPT\" > GEMINI.md",
        "OWASP LLM01 Prompt Injection / OWASP LLM07 System Prompt Leakage",
    ),
    compile_rule(
        "SEC-028",
        "Token de GitHub usado en comando visible",
        "Alta",
        "CI/CD",
        8.0,
        "Alta",
        "Baja",
        [
            r"curl\s+.*Authorization:\s*Bearer\s*\$\{\{[^}]*token[^}]*\}\}",
            r"curl\s+.*Authorization\s*:\s*Bearer\s*\$\s*\{\{[^}]*token[^}]*\}\}",
            r"Authorization:\s*Bearer\s*\$\{\{[^}]*GITHUB_TOKEN[^}]*\}\}",
            r"echo\s+.*\$\{\{[^}]*token[^}]*\}\}",
        ],
        ["*.yml", "*.yaml", "*.sh", "*.docx"],
        "Un token parece interpolarse en un comando shell que puede acabar expuesto en logs o historiales.",
        "Aunque GitHub enmascara muchos secretos, interpolar tokens en comandos aumenta el riesgo de fuga por errores, debug o salidas no previstas.",
        "Una persona con acceso a logs podria reutilizar un token efimero durante su ventana de validez para operar con permisos del bot.",
        "Usa acciones oficiales o github-script, evita imprimir cabeceras y aplica add-mask antes de cualquier uso shell inevitable.",
        "echo \"::add-mask::$TOKEN\"",
        "OWASP Top 10 A09 Security Logging and Monitoring Failures / OWASP LLM06 Excessive Agency",
    ),
    compile_rule(
        "SEC-029",
        "Agente IA con permisos de escritura sobre PRs o issues",
        "Alta",
        "IA",
        8.5,
        "Media",
        "Media",
        [
            r"google-github-actions/run-gemini-cli",
            r"GITHUB_PERSONAL_ACCESS_TOKEN",
            r"mcp_github_create_issue",
            r"mcp_github_pull_request_review_write",
            r"mcp_github_add_comment_to_pending_review",
        ],
        ["*.yml", "*.yaml", "*.md", "*.docx"],
        "El agente IA tiene capacidad para interactuar con GitHub escribiendo comentarios, reviews o issues.",
        "Estas capacidades son utiles, pero si se combinan con prompt injection o workspace confiable pueden producir acciones no autorizadas.",
        "Un atacante podria influir en el agente para crear issues falsos, manipular revisiones o publicar contenido no deseado.",
        "Separa lectura y escritura, exige aprobacion humana para acciones de escritura y limita permisos por job.",
        "permissions:\n  contents: read\n  pull-requests: read",
        "OWASP LLM06 Excessive Agency",
    ),
    compile_rule(
        "SEC-030",
        "Instrucciones absolutas del agente frente a contenido no confiable",
        "Media",
        "IA",
        6.7,
        "Media",
        "Media",
        [
            r"\bMUST\b.*\b(call|use|create|write|submit)\b",
            r"DO NOT EVER",
            r"STRICTLY FORBIDDEN",
            r"adherence to instructions is absolute",
        ],
        ["*.md", "*.txt", "*.docx"],
        "El prompt contiene instrucciones absolutas que pueden ser fragiles si se mezclan con contenido no confiable.",
        "Los prompts imperativos no son un control de seguridad por si solos; deben complementarse con permisos tecnicos y validaciones externas.",
        "Un atacante podria introducir instrucciones competidoras o explotar ambiguedades para inducir acciones fuera de politica.",
        "Convierte requisitos criticos en controles de herramienta, validaciones de servidor y aprobaciones humanas, no solo texto de prompt.",
        "require_human_approval(['create_issue', 'submit_review'])",
        "OWASP LLM01 Prompt Injection / OWASP LLM06 Excessive Agency",
    ),
    compile_rule(
        "SEC-031",
        "Workflow ejecutado con pull_request_target",
        "Alta",
        "CI/CD",
        8.4,
        "Alta",
        "Media",
        [r"pull_request_target\s*:"],
        ["*.yml", "*.yaml"],
        "El workflow se ejecuta con el evento pull_request_target.",
        "Este evento corre con contexto del repositorio base y puede exponer permisos o secretos si se combina con checkout de codigo no confiable.",
        "Un atacante podria abrir una PR y conseguir que el workflow ejecute codigo controlado con permisos elevados.",
        "Usa pull_request para codigo no confiable y reserva pull_request_target para flujos sin checkout ni ejecucion del contenido del PR.",
        "on: pull_request",
        "OWASP Top 10 A05 Security Misconfiguration / OWASP CI/CD Security",
    ),
    compile_rule(
        "SEC-032",
        "GitHub Action sin fijar a commit",
        "Media",
        "Supply Chain",
        6.8,
        "Media",
        "Media",
        [r"uses:\s*['\"]?[^@\s]+@(?:v\d+|main|master|latest)['\"]?"],
        ["*.yml", "*.yaml"],
        "Una accion de GitHub se referencia por version flotante, rama o tag mutable.",
        "Tags y ramas pueden cambiar; si una accion o dependencia se compromete, el workflow podria ejecutar codigo distinto al revisado.",
        "Un atacante sobre la cadena de suministro podria modificar una accion referenciada por tag/rama para ejecutar codigo en CI.",
        "Fija acciones a SHA de commit y usa herramientas de actualizacion controlada.",
        "uses: actions/checkout@f43a0e5ff2bd294095638e18286ca9a3d1956744",
        "OWASP Top 10 A08 Software and Data Integrity Failures",
    ),
    compile_rule(
        "SEC-033",
        "Checkout de codigo de PR con persist-credentials activo",
        "Media",
        "CI/CD",
        6.6,
        "Media",
        "Baja",
        [r"persist-credentials\s*:\s*true"],
        ["*.yml", "*.yaml"],
        "actions/checkout mantiene credenciales Git disponibles para pasos posteriores.",
        "Si un paso ejecuta codigo no confiable, esas credenciales podrian usarse para operaciones Git no previstas.",
        "Un atacante podria modificar scripts de build para leer o reutilizar credenciales persistidas.",
        "Establece persist-credentials: false salvo que el job necesite escribir explicitamente al repositorio.",
        "persist-credentials: false",
        "OWASP CI/CD Security / OWASP Top 10 A05 Security Misconfiguration",
    ),
    compile_rule(
        "SEC-034",
        "Dependencia instalada sin version fija",
        "Media",
        "Supply Chain",
        6.5,
        "Media",
        "Media",
        [
            r"\b(npm|pnpm|yarn)\s+(install|add)\s+[A-Za-z0-9@/_-]+(?:\s|$)",
            r"\bpip\s+install\s+[A-Za-z0-9_.-]+(?:\s|$)",
            r"\bgo\s+get\s+[A-Za-z0-9_./-]+(?:\s|$)",
        ],
        ["*.yml", "*.yaml", "*.sh", "Dockerfile", "Makefile"],
        "Una dependencia se instala sin version o digest fijado.",
        "Instalaciones flotantes reducen reproducibilidad y amplian el riesgo de supply chain.",
        "Un atacante o paquete comprometido podria introducir una version maliciosa que CI instale automaticamente.",
        "Fija versiones, usa lockfiles y valida integridad con hashes o firmas cuando sea posible.",
        "pip install package==1.2.3 --require-hashes",
        "OWASP Top 10 A08 Software and Data Integrity Failures",
    ),
    compile_rule(
        "SEC-035",
        "Imagen Docker con tag latest",
        "Media",
        "Contenedores",
        6.2,
        "Alta",
        "Baja",
        [r"FROM\s+[^\s:]+:latest", r"image\s*:\s*[^\s:]+:latest"],
        ["Dockerfile", "*.dockerfile", "*.yml", "*.yaml"],
        "Una imagen de contenedor usa el tag latest.",
        "latest es mutable y puede cambiar sin revision, rompiendo reproducibilidad o introduciendo vulnerabilidades nuevas.",
        "Un despliegue podria ejecutar una imagen distinta de la probada originalmente.",
        "Fija tags inmutables o digest SHA y revisa actualizaciones por pipeline controlado.",
        "FROM python:3.12.3-slim@sha256:<digest>",
        "OWASP Top 10 A08 Software and Data Integrity Failures",
    ),
    compile_rule(
        "SEC-036",
        "Kubernetes permite contenedor privilegiado",
        "Alta",
        "Kubernetes",
        8.0,
        "Alta",
        "Media",
        [r"privileged\s*:\s*true", r"allowPrivilegeEscalation\s*:\s*true"],
        ["*.yml", "*.yaml"],
        "Un manifiesto Kubernetes permite privilegios elevados o escalada de privilegios.",
        "Esto aumenta el impacto de un compromiso de contenedor y puede facilitar acceso a recursos del nodo.",
        "Un atacante que comprometa el pod podria intentar escapar o abusar de capacidades del host.",
        "Desactiva privilegios, define securityContext restrictivo y aplica Pod Security Standards.",
        "allowPrivilegeEscalation: false",
        "OWASP Kubernetes Top 10 K01 Insecure Workload Configurations",
    ),
    compile_rule(
        "SEC-037",
        "Kubernetes monta hostPath",
        "Alta",
        "Kubernetes",
        8.1,
        "Alta",
        "Media",
        [r"hostPath\s*:", r"mountPath\s*:\s*/var/run/docker\.sock"],
        ["*.yml", "*.yaml"],
        "Un pod monta rutas del host o el socket de Docker.",
        "hostPath puede exponer archivos del nodo y convertir un compromiso de pod en compromiso del host.",
        "Un atacante podria leer archivos sensibles del nodo o controlar Docker mediante el socket montado.",
        "Evita hostPath; usa volúmenes gestionados y permisos minimos.",
        "# Evitar hostPath; usar persistentVolumeClaim con acceso restringido",
        "OWASP Kubernetes Top 10 K01 Insecure Workload Configurations",
    ),
    compile_rule(
        "SEC-038",
        "Kubernetes ejecuta como root",
        "Media",
        "Kubernetes",
        6.8,
        "Media",
        "Baja",
        [r"runAsUser\s*:\s*0", r"runAsNonRoot\s*:\s*false"],
        ["*.yml", "*.yaml"],
        "El contenedor Kubernetes parece ejecutarse como root.",
        "Ejecutar como root aumenta el impacto de vulnerabilidades dentro del contenedor.",
        "Un atacante con ejecucion en el contenedor tendria mas permisos internos y mejores opciones de pivotaje.",
        "Define runAsNonRoot: true y un usuario no privilegiado.",
        "securityContext:\n  runAsNonRoot: true\n  runAsUser: 10001",
        "OWASP Kubernetes Top 10 K01 Insecure Workload Configurations",
    ),
    compile_rule(
        "SEC-039",
        "RBAC con cluster-admin",
        "Alta",
        "Kubernetes",
        8.6,
        "Alta",
        "Media",
        [r"name\s*:\s*cluster-admin", r"ClusterRoleBinding"],
        ["*.yml", "*.yaml"],
        "El manifiesto contiene referencias a ClusterRoleBinding o cluster-admin.",
        "Permisos cluster-wide amplios elevan mucho el impacto de una credencial o service account comprometida.",
        "Un atacante con acceso al service account podria operar sobre todo el cluster.",
        "Usa Roles namespace-scoped y permisos minimos por recurso/verbo.",
        "kind: Role\nrules:\n- apiGroups: ['']\n  resources: ['pods']\n  verbs: ['get', 'list']",
        "OWASP Kubernetes Top 10 K03 Overly Permissive RBAC",
    ),
    compile_rule(
        "SEC-040",
        "Terraform IAM wildcard",
        "Alta",
        "Cloud",
        8.5,
        "Alta",
        "Media",
        [r"Action\s*=\s*['\"]\*['\"]", r"actions\s*=\s*\[[^\]]*['\"]\*['\"]", r"Resource\s*=\s*['\"]\*['\"]"],
        ["*.tf", "*.json", "*.hcl"],
        "Una politica IAM contiene comodines amplios en acciones o recursos.",
        "Los comodines rompen el principio de minimo privilegio y aumentan el impacto de una credencial comprometida.",
        "Un atacante podria usar permisos no previstos para moverse lateralmente o modificar recursos criticos.",
        "Limita acciones y recursos a los estrictamente necesarios.",
        "actions = ['s3:GetObject']\nresources = [aws_s3_bucket.app.arn]",
        "OWASP Top 10 A05 Security Misconfiguration",
    ),
    compile_rule(
        "SEC-041",
        "S3 publico o ACL abierta",
        "Alta",
        "Cloud",
        8.2,
        "Alta",
        "Baja",
        [r"acl\s*=\s*['\"]public-read", r"block_public_acls\s*=\s*false", r"block_public_policy\s*=\s*false"],
        ["*.tf", "*.json", "*.hcl"],
        "La configuracion de almacenamiento parece permitir acceso publico.",
        "Buckets publicos pueden filtrar datos internos, backups o artefactos de cliente.",
        "Un atacante podria listar o descargar objetos si la politica queda expuesta.",
        "Bloquea acceso publico por defecto y concede acceso mediante roles o URLs firmadas.",
        "block_public_acls = true\nblock_public_policy = true",
        "OWASP Top 10 A01 Broken Access Control",
    ),
    compile_rule(
        "SEC-042",
        "Base de datos expuesta publicamente",
        "Alta",
        "Cloud",
        8.4,
        "Media",
        "Media",
        [r"publicly_accessible\s*=\s*true", r"assign_public_ip\s*=\s*true"],
        ["*.tf", "*.json", "*.hcl"],
        "Un recurso cloud parece configurado con exposicion publica.",
        "Bases de datos o workloads con IP publica aumentan superficie de ataque y riesgo de fuerza bruta o explotacion remota.",
        "Un atacante podria descubrir el servicio desde Internet e intentar credenciales o vulnerabilidades conocidas.",
        "Usa subredes privadas, security groups restrictivos y acceso por bastion/VPN.",
        "publicly_accessible = false",
        "OWASP API Security API7 Security Misconfiguration",
    ),
    compile_rule(
        "SEC-043",
        "Firewall permite administracion desde Internet",
        "Alta",
        "Infraestructura",
        8.5,
        "Alta",
        "Media",
        [r"(from_port|port)\s*=\s*(22|3389|5432|3306|6379)", r"(22|3389|5432|3306|6379)/tcp"],
        ["*.tf", "*.yml", "*.yaml", "*.json"],
        "Se ha detectado un puerto administrativo o de base de datos en reglas de red.",
        "Si se combina con origen abierto, expone servicios sensibles a Internet.",
        "Un atacante podria escanear puertos administrativos y probar credenciales o exploits.",
        "Restringe estos puertos a redes privadas o rangos administrativos aprobados.",
        "cidr_blocks = [var.vpn_cidr]",
        "OWASP Top 10 A05 Security Misconfiguration",
    ),
    compile_rule(
        "SEC-044",
        "Autenticacion o autorizacion desactivada",
        "Critica",
        "Autenticacion",
        9.0,
        "Media",
        "Media",
        [
            r"auth\s*[:=]\s*false",
            r"disable[_-]?auth\s*[:=]\s*true",
            r"permitAll\(\)",
            r"csrf\(\)\.disable\(\)",
            r"anonymous\s*:\s*true",
        ],
        ["*.py", "*.js", "*.ts", "*.java", "*.kt", "*.yml", "*.yaml", "*.json"],
        "La autenticacion, autorizacion o proteccion CSRF parece estar desactivada.",
        "Desactivar controles de acceso puede exponer operaciones o datos protegidos.",
        "Un atacante podria invocar endpoints sin identidad valida o abusar de sesiones existentes.",
        "Aplica autenticacion por defecto, autoriza por recurso y documenta excepciones publicas.",
        "authorizeHttpRequests().requestMatchers('/public/**').permitAll().anyRequest().authenticated()",
        "OWASP Top 10 A01 Broken Access Control / A07 Identification and Authentication Failures",
    ),
    compile_rule(
        "SEC-045",
        "Password o credenciales por defecto",
        "Critica",
        "Secretos",
        9.0,
        "Alta",
        "Baja",
        [
            r"(password|passwd|pwd)\s*[:=]\s*['\"]?(admin|password|changeme|123456|root|toor)['\"]?",
            r"(username|user)\s*[:=]\s*['\"]?(admin|root)['\"]?",
        ],
        ["*.yml", "*.yaml", "*.json", "*.env", "*.properties", "*.ini", "*.py", "*.js", "*.ts"],
        "Se ha detectado una credencial por defecto o debil.",
        "Credenciales por defecto son uno de los primeros vectores probados por atacantes y scanners.",
        "Un atacante podria autenticarse directamente si la credencial llega a un entorno real.",
        "Elimina valores por defecto, obliga rotacion y usa secretos gestionados por entorno.",
        "ADMIN_PASSWORD = os.environ['ADMIN_PASSWORD']",
        "OWASP Top 10 A07 Identification and Authentication Failures",
    ),
    compile_rule(
        "SEC-046",
        "Password hashing inseguro o ausente",
        "Alta",
        "Criptografia",
        8.0,
        "Media",
        "Media",
        [r"password\s*[:=]\s*hashlib\.(md5|sha1)", r"createHash\(['\"](md5|sha1)['\"]\)", r"password\s*==\s*"],
        ["*.py", "*.js", "*.ts", "*.java", "*.kt"],
        "El tratamiento de passwords parece usar hashing debil o comparacion directa.",
        "Passwords deben almacenarse con KDF lenta y sal; hashes rapidos o comparaciones directas facilitan compromiso.",
        "Un atacante con acceso a la base de datos podria crackear credenciales rapidamente.",
        "Usa Argon2, bcrypt o scrypt con parametros adecuados.",
        "argon2.verify(stored_hash, password)",
        "OWASP Top 10 A02 Cryptographic Failures",
    ),
    compile_rule(
        "SEC-047",
        "Redirect abierto potencial",
        "Media",
        "API",
        6.3,
        "Media",
        "Baja",
        [r"(redirect|RedirectResponse|res\.redirect)\([^)]*(url|next|redirect_uri|returnUrl|target)"],
        ["*.py", "*.js", "*.ts", "*.java", "*.kt", "*.php"],
        "Un redirect parece depender de un parametro variable.",
        "Redirects abiertos facilitan phishing, robo de tokens en flujos OAuth o bypass de allowlists.",
        "Un atacante podria enviar a usuarios a un dominio malicioso usando una URL legitima como trampolin.",
        "Valida destinos contra una allowlist de rutas internas u origenes permitidos.",
        "if target not in ALLOWED_REDIRECTS: target = '/'",
        "OWASP Top 10 A01 Broken Access Control",
    ),
    compile_rule(
        "SEC-048",
        "XXE potencial en parser XML",
        "Alta",
        "Inyeccion",
        8.1,
        "Media",
        "Media",
        [r"DocumentBuilderFactory\.newInstance\(", r"etree\.XMLParser\(", r"resolve_entities\s*=\s*True", r"simplexml_load_string\("],
        ["*.py", "*.java", "*.kt", "*.php"],
        "Se usa un parser XML que requiere revisar configuracion contra XXE.",
        "Parsers XML inseguros pueden leer archivos locales o realizar peticiones internas.",
        "Un atacante podria enviar XML con entidades externas para exfiltrar archivos o provocar SSRF.",
        "Desactiva DTDs y entidades externas, o usa parsers seguros por defecto.",
        "XMLParser(resolve_entities=False, no_network=True)",
        "OWASP Top 10 A05 Security Misconfiguration / A03 Injection",
    ),
    compile_rule(
        "SEC-049",
        "Path traversal potencial",
        "Alta",
        "Archivos",
        8.0,
        "Media",
        "Media",
        [r"(open|readFile|writeFile|send_file|FileResponse)\([^)]*(filename|filepath|path|req\.|request\.)", r"\.\./"],
        ["*.py", "*.js", "*.ts", "*.java", "*.kt", "*.php"],
        "Operaciones de archivo parecen depender de rutas controlables.",
        "Sin normalizacion y allowlist, puede permitir leer o escribir fuera del directorio esperado.",
        "Un atacante podria usar secuencias ../ para acceder a archivos sensibles.",
        "Normaliza rutas, valida que permanezcan dentro del directorio permitido y usa IDs logicos.",
        "safe = base_dir.joinpath(name).resolve(); assert safe.is_relative_to(base_dir)",
        "OWASP Top 10 A01 Broken Access Control",
    ),
    compile_rule(
        "SEC-050",
        "XSS potencial por HTML sin escapar",
        "Media",
        "Frontend",
        6.7,
        "Media",
        "Media",
        [r"dangerouslySetInnerHTML", r"innerHTML\s*=", r"v-html\s*=", r"\|\s*safe\b"],
        ["*.js", "*.ts", "*.jsx", "*.tsx", "*.vue", "*.html", "*.py"],
        "El codigo inserta HTML sin evidencia de sanitizacion.",
        "Renderizar HTML no confiable puede permitir XSS y robo de sesiones o acciones en nombre del usuario.",
        "Un atacante podria inyectar scripts mediante contenido almacenado o reflejado.",
        "Evita HTML crudo o sanitiza con una libreria robusta y politica CSP.",
        "DOMPurify.sanitize(userHtml)",
        "OWASP Top 10 A03 Injection",
    ),
    compile_rule(
        "SEC-051",
        "Rate limiting ausente o desactivado",
        "Media",
        "API",
        6.4,
        "Baja",
        "Media",
        [r"rate[_-]?limit\s*[:=]\s*false", r"throttle\s*[:=]\s*false", r"limiter\s*=\s*None"],
        ["*.py", "*.js", "*.ts", "*.yml", "*.yaml", "*.json"],
        "La limitacion de frecuencia parece desactivada.",
        "Sin rate limiting, endpoints sensibles son mas vulnerables a fuerza bruta, scraping o abuso automatizado.",
        "Un atacante podria automatizar intentos de login o llamadas costosas hasta degradar el servicio.",
        "Aplica limites por IP/usuario/ruta y backoff en operaciones sensibles.",
        "limiter.limit('10/minute')(login_handler)",
        "OWASP API Security API4 Unrestricted Resource Consumption",
    ),
    compile_rule(
        "SEC-052",
        "Webhook sin verificacion de firma",
        "Alta",
        "API",
        8.0,
        "Media",
        "Media",
        [r"webhook", r"X-Hub-Signature", r"stripe-signature"],
        ["*.py", "*.js", "*.ts", "*.java", "*.kt"],
        "Hay manejo de webhooks; revise si se verifica firma, timestamp y replay protection.",
        "Webhooks sin verificacion permiten que terceros simulen eventos de proveedores.",
        "Un atacante podria enviar eventos falsos de pago, despliegue o integracion.",
        "Verifica HMAC/firma del proveedor antes de procesar el cuerpo.",
        "stripe.Webhook.construct_event(payload, sig_header, endpoint_secret)",
        "OWASP API Security API2 Broken Authentication",
    ),
    compile_rule(
        "SEC-053",
        "CORS con credenciales y wildcard",
        "Critica",
        "API",
        9.0,
        "Alta",
        "Baja",
        [r"allow_credentials\s*=\s*True", r"credentials\s*:\s*true"],
        None,
        "La configuracion CORS permite credenciales; debe revisarse junto con los origenes permitidos.",
        "Credenciales con CORS amplio pueden exponer sesiones o tokens a sitios no confiables.",
        "Una web atacante podria realizar peticiones autenticadas y leer respuestas si el origen tambien es laxo.",
        "Usa origenes explicitos y evita credenciales salvo necesidad clara.",
        "cors({ origin: ['https://app.example.com'], credentials: true })",
        "OWASP API Security API7 Security Misconfiguration",
    ),
    compile_rule(
        "SEC-054",
        "Modelo IA puede recibir secretos o contexto sensible",
        "Alta",
        "IA",
        8.0,
        "Baja",
        "Media",
        [r"(api[_-]?key|secret|token|password|authorization).*(prompt|messages|input|context)", r"(prompt|messages|input|context).*(api[_-]?key|secret|token|password|authorization)"],
        ["*.py", "*.js", "*.ts", "*.md", "*.docx"],
        "Datos sensibles parecen mezclarse con prompts, mensajes o contexto de IA.",
        "Enviar secretos a modelos o proveedores externos puede violar politicas internas y ampliar superficie de fuga.",
        "Un atacante podria inducir al sistema a revelar contexto sensible o dejarlo registrado en trazas de proveedor.",
        "Redacta secretos antes de construir prompts y aplica data loss prevention en entradas a IA.",
        "safe_context = redact_secrets(context)",
        "OWASP LLM02 Insecure Output Handling / LLM07 System Prompt Leakage",
    ),
    compile_rule(
        "SEC-055",
        "RAG o embeddings sin control de fuente",
        "Media",
        "IA",
        6.8,
        "Baja",
        "Media",
        [r"(vectorstore|embedding|retriever|similarity_search|rag)", r"chunk"],
        ["*.py", "*.js", "*.ts", "*.md"],
        "Se detectan componentes RAG/embeddings; revise control de fuentes, permisos y aislamiento por tenant.",
        "RAG sin filtros de autorizacion puede mezclar documentos entre usuarios o introducir contenido malicioso recuperado.",
        "Un atacante podria inyectar documentos que el modelo recupere como instrucciones confiables.",
        "Filtra por permisos, firma fuentes confiables y separa indices por tenant o dominio de confianza.",
        "retriever.search(query, filter={'tenant_id': user.tenant_id})",
        "OWASP LLM08 Vector and Embedding Weaknesses / LLM01 Prompt Injection",
    ),
    compile_rule(
        "SEC-056",
        "Ejecucion de codigo generada por IA",
        "Critica",
        "IA",
        9.3,
        "Media",
        "Alta",
        [r"(eval|exec|subprocess|child_process).*(model|llm|assistant|completion|response)", r"(model|llm|assistant|completion|response).*(eval|exec|subprocess|child_process)"],
        ["*.py", "*.js", "*.ts"],
        "La salida o contexto de IA parece conectado a ejecucion de codigo o comandos.",
        "Ejecutar contenido influido por un modelo puede convertir prompt injection en ejecucion real.",
        "Un atacante podria manipular la entrada al modelo para producir comandos que luego se ejecutan.",
        "Nunca ejecutes salida de IA directamente; usa esquemas, allowlists, sandbox y aprobacion humana.",
        "command = approved_commands[result.action]",
        "OWASP LLM02 Insecure Output Handling / LLM06 Excessive Agency",
    ),
    compile_rule(
        "SEC-057",
        "Logs o telemetria de IA activados con contenido sensible",
        "Media",
        "IA",
        6.6,
        "Media",
        "Baja",
        [r"telemetry\s*:\s*\{?", r"outfile\s*:\s*['\"].*\.log", r"log[_-]?prompts\s*[:=]\s*true", r"store\s*[:=]\s*true"],
        ["*.yml", "*.yaml", "*.json", "*.py", "*.js", "*.ts"],
        "La configuracion registra telemetria, prompts o salidas de IA.",
        "Prompts y respuestas pueden contener datos sensibles, secretos o informacion de clientes.",
        "Un atacante o usuario interno con acceso a logs podria recuperar contexto sensible.",
        "Desactiva logging de prompts por defecto, redacta datos y define retencion corta.",
        "log_prompts: false",
        "OWASP LLM07 System Prompt Leakage / OWASP Top 10 A09",
    ),
    compile_rule(
        "SEC-058",
        "OAuth client secret o private key en variables de CI",
        "Alta",
        "CI/CD",
        8.3,
        "Media",
        "Media",
        [r"(CLIENT_SECRET|PRIVATE_KEY|APP_ID|TOKEN)\s*:\s*['\"]?\$\{\{\s*secrets\.", r"private-key\s*:\s*['\"]?\$\{\{\s*secrets\."],
        ["*.yml", "*.yaml"],
        "El workflow inyecta secretos sensibles en jobs de CI.",
        "No siempre es incorrecto, pero en jobs que ejecutan codigo de PR aumenta mucho el impacto de un bypass.",
        "Un atacante podria modificar pasos para exfiltrar secretos si el workflow ejecuta contenido no confiable.",
        "Aisla secretos en jobs sin codigo de PR, limita eventos y usa entornos protegidos.",
        "if: github.event.pull_request.head.repo.full_name == github.repository",
        "OWASP Top 10 A02 Cryptographic Failures / OWASP CI/CD Security",
    ),
    compile_rule(
        "SEC-059",
        "Permisos OIDC write en CI",
        "Alta",
        "CI/CD",
        8.2,
        "Alta",
        "Media",
        [r"id-token\s*:\s*write"],
        ["*.yml", "*.yaml"],
        "El workflow puede solicitar tokens OIDC.",
        "OIDC write permite obtener credenciales federadas cloud si la configuracion de confianza es laxa.",
        "Un atacante que controle el job podria intentar asumir roles cloud asociados al repositorio.",
        "Restringe OIDC a jobs concretos y condiciones de branch/environment en el proveedor cloud.",
        "permissions:\n  id-token: none",
        "OWASP CI/CD Security / OWASP Top 10 A05",
    ),
    compile_rule(
        "SEC-060",
        "Uso de sudo en pipeline",
        "Media",
        "CI/CD",
        6.3,
        "Media",
        "Baja",
        [r"\bsudo\s+"],
        ["*.yml", "*.yaml", "*.sh"],
        "El pipeline ejecuta comandos con sudo.",
        "sudo en CI amplifica el impacto de scripts o dependencias comprometidas dentro del runner.",
        "Un atacante que modifique un script ejecutado en CI podria alterar el entorno con privilegios elevados.",
        "Evita sudo salvo necesidad justificada y usa contenedores/runners aislados.",
        "run: ./scripts/check.sh",
        "OWASP CI/CD Security",
    ),
    compile_rule(
        "SEC-061",
        "Cabecera HSTS ausente o desactivada",
        "Media",
        "Transporte",
        6.1,
        "Media",
        "Baja",
        [r"Strict-Transport-Security\s*:\s*['\"]?$", r"max-age\s*=\s*0", r"hsts\s*[:=]\s*false"],
        ["*.conf", "*.nginx", "*.yml", "*.yaml", "*.js", "*.ts", "*.py", "*.java"],
        "La configuracion sugiere HSTS ausente o desactivado.",
        "Sin HSTS, los usuarios pueden ser degradados a HTTP en ciertos escenarios de red.",
        "Un atacante en red podria intentar downgrade o interceptacion antes de que el navegador fuerce HTTPS.",
        "Activa HSTS con max-age suficiente, includeSubDomains y preload si aplica.",
        "Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "OWASP Top 10 A02 Cryptographic Failures",
    ),
    compile_rule(
        "SEC-062",
        "Cabecera de clickjacking permisiva",
        "Media",
        "Frontend",
        5.8,
        "Media",
        "Baja",
        [r"X-Frame-Options\s*:\s*ALLOWALL", r"frame-ancestors\s+\*", r"frameOptions\s*[:=]\s*false"],
        ["*.conf", "*.nginx", "*.html", "*.js", "*.ts", "*.py", "*.java", "*.yml", "*.yaml"],
        "La configuracion permite embeber la aplicacion en frames no confiables.",
        "Clickjacking puede inducir acciones del usuario sobre la aplicacion desde un sitio atacante.",
        "Un atacante podria superponer la interfaz legitima en un iframe y capturar clicks de la victima.",
        "Usa frame-ancestors con origenes concretos o X-Frame-Options DENY/SAMEORIGIN.",
        "Content-Security-Policy: frame-ancestors 'self'",
        "OWASP Top 10 A05 Security Misconfiguration",
    ),
    compile_rule(
        "SEC-063",
        "Cookies con SameSite=None",
        "Media",
        "Sesion",
        6.2,
        "Alta",
        "Baja",
        [r"samesite\s*[:=]\s*['\"]?none", r"SameSite=None"],
        ["*.py", "*.js", "*.ts", "*.java", "*.php", "*.conf"],
        "Una cookie se configura con SameSite=None.",
        "SameSite=None permite envio cross-site y requiere una justificacion clara junto a Secure.",
        "Un atacante podria abusar de flujos cross-site si existen endpoints con efectos laterales.",
        "Usa SameSite=Lax o Strict salvo integraciones que requieran None, siempre con Secure.",
        "sameSite: 'lax', secure: true, httpOnly: true",
        "OWASP Top 10 A07 Identification and Authentication Failures",
    ),
    compile_rule(
        "SEC-064",
        "JWT con algoritmo none o secreto debil",
        "Critica",
        "Autenticacion",
        9.1,
        "Alta",
        "Media",
        [r"algorithms?\s*[:=]\s*\[[^\]]*['\"]none['\"]", r"algorithm\s*[:=]\s*['\"]none['\"]", r"jwt[_-]?secret\s*[:=]\s*['\"]?(secret|changeme|password|123456)"],
        ["*.py", "*.js", "*.ts", "*.java", "*.kt", "*.yml", "*.yaml", "*.json", "*.env"],
        "La configuracion JWT permite algoritmo none o usa un secreto debil.",
        "JWT con algoritmo none o claves triviales permite falsificar tokens.",
        "Un atacante podria crear tokens con claims arbitrarios y suplantar usuarios o roles.",
        "Fija algoritmos fuertes y usa claves largas gestionadas como secretos.",
        "jwt.decode(token, key, algorithms=['RS256'], audience='api')",
        "OWASP API Security API2 Broken Authentication",
    ),
    compile_rule(
        "SEC-065",
        "OAuth redirect URI comodin o localhost",
        "Alta",
        "Autenticacion",
        8.0,
        "Media",
        "Baja",
        [r"redirect_uris?\s*[:=].*(\*|localhost|127\.0\.0\.1)", r"redirect-uri\s*[:=].*(\*|localhost|127\.0\.0\.1)"],
        ["*.json", "*.yml", "*.yaml", "*.tf", "*.env", "*.properties"],
        "La configuracion OAuth/OIDC contiene redirect URIs comodin o locales.",
        "Redirect URIs laxas pueden permitir robo de codigos de autorizacion o tokens.",
        "Un atacante podria registrar un destino compatible y capturar el codigo OAuth.",
        "Declara redirect URIs exactas por entorno y evita comodines.",
        "redirect_uris = ['https://app.example.com/oauth/callback']",
        "OWASP API Security API2 Broken Authentication",
    ),
    compile_rule(
        "SEC-066",
        "OAuth state/nonce ausente o desactivado",
        "Alta",
        "Autenticacion",
        7.8,
        "Baja",
        "Media",
        [r"state\s*[:=]\s*None", r"useState\s*[:=]\s*false", r"nonce\s*[:=]\s*None", r"useNonce\s*[:=]\s*false"],
        ["*.py", "*.js", "*.ts", "*.java", "*.kt", "*.json", "*.yml", "*.yaml"],
        "El flujo OAuth/OIDC parece desactivar state o nonce.",
        "state y nonce protegen contra CSRF, replay y mezcla de respuestas en flujos de login.",
        "Un atacante podria enlazar respuestas OAuth no solicitadas o reutilizadas.",
        "Genera state/nonce aleatorios por transaccion y validalos al retorno.",
        "state = secrets.token_urlsafe(32)",
        "OWASP API Security API2 Broken Authentication",
    ),
    compile_rule(
        "SEC-067",
        "TLS antiguo permitido",
        "Media",
        "Transporte",
        6.5,
        "Alta",
        "Baja",
        [r"TLSv1(\.0|\.1)?", r"ssl_protocols\s+.*TLSv1(\s|;)", r"minVersion\s*[:=]\s*['\"]TLSv1"],
        ["*.conf", "*.nginx", "*.yml", "*.yaml", "*.js", "*.ts", "*.java", "*.tf"],
        "La configuracion permite versiones TLS antiguas.",
        "TLS 1.0/1.1 esta obsoleto y puede incumplir requisitos de seguridad o compliance.",
        "Un atacante podria explotar clientes o configuraciones debiles para degradar la seguridad del canal.",
        "Permite TLS 1.2+ o TLS 1.3 segun compatibilidad.",
        "ssl_protocols TLSv1.2 TLSv1.3;",
        "OWASP Top 10 A02 Cryptographic Failures",
    ),
    compile_rule(
        "SEC-068",
        "Cifrado en reposo desactivado",
        "Alta",
        "Cloud",
        8.0,
        "Alta",
        "Media",
        [r"encrypted\s*=\s*false", r"server_side_encryption\s*=\s*false", r"enable_encryption\s*=\s*false"],
        ["*.tf", "*.json", "*.hcl", "*.yml", "*.yaml"],
        "Un recurso de almacenamiento o base de datos parece tener cifrado en reposo desactivado.",
        "Sin cifrado en reposo, una fuga de snapshots, discos o backups tiene mayor impacto.",
        "Un atacante con acceso a medios de almacenamiento podria leer datos sensibles sin una capa adicional de proteccion.",
        "Activa cifrado gestionado por KMS o claves administradas por cliente segun sensibilidad.",
        "encrypted = true\nkms_key_id = aws_kms_key.app.arn",
        "OWASP Top 10 A02 Cryptographic Failures",
    ),
    compile_rule(
        "SEC-069",
        "Backups o retencion desactivados",
        "Media",
        "Resiliencia",
        6.0,
        "Media",
        "Baja",
        [r"backup_retention_period\s*=\s*0", r"skip_final_snapshot\s*=\s*true", r"deletion_protection\s*=\s*false"],
        ["*.tf", "*.json", "*.hcl", "*.yml", "*.yaml"],
        "La configuracion reduce backups, snapshot final o proteccion contra borrado.",
        "Aunque no siempre es explotable directamente, empeora recuperacion ante ransomware, error humano o compromiso.",
        "Un atacante con permisos cloud podria borrar recursos y dificultar recuperacion.",
        "Activa retencion, snapshots finales y proteccion contra borrado en recursos criticos.",
        "backup_retention_period = 7\ndeletion_protection = true",
        "OWASP Top 10 A05 Security Misconfiguration",
    ),
    compile_rule(
        "SEC-070",
        "Datos personales en logs",
        "Media",
        "Privacidad",
        6.7,
        "Media",
        "Media",
        [r"(console\.log|print|logger\.(info|debug|error))\([^)]*(email|phone|dni|ssn|iban|credit|card|address)", r"(email|phone|dni|ssn|iban|credit_card).*log"],
        ["*.py", "*.js", "*.ts", "*.java", "*.kt", "*.php"],
        "Los logs podrian incluir datos personales o financieros.",
        "Registrar PII aumenta el impacto de accesos internos, brechas de observabilidad y retenciones excesivas.",
        "Un atacante o usuario con acceso a logs podria extraer datos personales sin acceder a la base principal.",
        "Minimiza logs, enmascara PII y aplica retencion/acceso restringido.",
        "logger.info('payment failed', extra={'payment_id': payment.id})",
        "OWASP Top 10 A09 Security Logging and Monitoring Failures",
    ),
    compile_rule(
        "SEC-071",
        "Cache de dependencias incluye secretos o env",
        "Media",
        "CI/CD",
        6.4,
        "Media",
        "Baja",
        [r"path:\s*\|[\s\S]*\.env", r"path:\s*.*(\.env|\.npmrc|\.pypirc|credentials|secrets)"],
        ["*.yml", "*.yaml"],
        "La configuracion de cache puede incluir archivos de entorno o credenciales.",
        "Caches de CI pueden persistir y reutilizar archivos sensibles entre jobs o ramas.",
        "Un atacante podria recuperar secretos cacheados si controla un job posterior o una clave de cache.",
        "Excluye secretos de caches y usa claves separadas por confianza/branch.",
        "path: ~/.m2/repository",
        "OWASP Top 10 A02 Cryptographic Failures / OWASP CI/CD Security",
    ),
    compile_rule(
        "SEC-072",
        "Docker copia todo el contexto",
        "Media",
        "Contenedores",
        6.3,
        "Media",
        "Baja",
        [r"^(COPY|ADD)\s+\.\s+"],
        ["Dockerfile", "*.dockerfile"],
        "El Dockerfile copia todo el contexto de build.",
        "Sin .dockerignore estricto, pueden entrar secretos, historiales, tests o artefactos innecesarios en la imagen.",
        "Un atacante con acceso a la imagen podria encontrar archivos no previstos incluidos por accidente.",
        "Usa .dockerignore y copia solo los archivos necesarios.",
        "COPY pyproject.toml poetry.lock ./",
        "OWASP Top 10 A05 Security Misconfiguration",
    ),
    compile_rule(
        "SEC-073",
        "Docker ADD con URL remota",
        "Media",
        "Supply Chain",
        6.9,
        "Alta",
        "Baja",
        [r"^ADD\s+https?://"],
        ["Dockerfile", "*.dockerfile"],
        "Dockerfile usa ADD para descargar contenido remoto.",
        "Descargas remotas en build dificultan verificacion de integridad y reproducibilidad.",
        "Un atacante que comprometa el origen remoto podria introducir contenido malicioso en la imagen.",
        "Descarga artefactos con checksum/firma o incorpora dependencias por gestor controlado.",
        "RUN curl -fsSLO URL && echo '<sha256> file' | sha256sum -c -",
        "OWASP Top 10 A08 Software and Data Integrity Failures",
    ),
    compile_rule(
        "SEC-074",
        "Kubernetes service account token automontado",
        "Media",
        "Kubernetes",
        6.6,
        "Media",
        "Baja",
        [r"automountServiceAccountToken\s*:\s*true"],
        ["*.yml", "*.yaml"],
        "El pod monta automaticamente el token del service account.",
        "Tokens innecesarios amplian el impacto de una ejecucion dentro del pod.",
        "Un atacante que comprometa el contenedor podria usar el token para consultar o modificar recursos del cluster.",
        "Desactiva automount salvo que la workload necesite hablar con la API de Kubernetes.",
        "automountServiceAccountToken: false",
        "OWASP Kubernetes Top 10 K03 Overly Permissive RBAC",
    ),
    compile_rule(
        "SEC-075",
        "Capabilities Linux amplias en contenedor",
        "Alta",
        "Contenedores",
        7.9,
        "Media",
        "Media",
        [r"cap_add\s*:", r"add:\s*\[[^\]]*(SYS_ADMIN|NET_ADMIN|ALL)", r"capabilities\s*:"],
        ["*.yml", "*.yaml", "Dockerfile", "*.dockerfile"],
        "La configuracion de contenedor modifica capabilities Linux.",
        "Capabilities amplias como SYS_ADMIN o NET_ADMIN incrementan el impacto de una vulnerabilidad.",
        "Un atacante dentro del contenedor podria manipular red, mounts u operaciones privilegiadas.",
        "Elimina capabilities por defecto y añade solo las imprescindibles.",
        "cap_drop:\n  - ALL",
        "OWASP Kubernetes Top 10 K01 Insecure Workload Configurations",
    ),
    compile_rule(
        "SEC-076",
        "Read-only root filesystem no definido",
        "Baja",
        "Contenedores",
        4.8,
        "Baja",
        "Media",
        [r"readOnlyRootFilesystem\s*:\s*false", r"read_only\s*:\s*false"],
        ["*.yml", "*.yaml"],
        "El filesystem raiz escribible puede facilitar persistencia o alteracion dentro del contenedor.",
        "No es una vulnerabilidad por si sola, pero reduce hardening de workloads.",
        "Un atacante con ejecucion podria escribir herramientas o modificar archivos dentro del contenedor.",
        "Usa root filesystem de solo lectura y monta volumenes especificos para escritura necesaria.",
        "readOnlyRootFilesystem: true",
        "OWASP Kubernetes Top 10 K01 Insecure Workload Configurations",
    ),
    compile_rule(
        "SEC-077",
        "GraphQL introspection habilitada",
        "Media",
        "API",
        6.1,
        "Media",
        "Baja",
        [r"introspection\s*[:=]\s*true", r"graphiql\s*[:=]\s*true", r"playground\s*[:=]\s*true"],
        ["*.py", "*.js", "*.ts", "*.java", "*.kt", "*.yml", "*.yaml", "*.json"],
        "GraphQL introspection, GraphiQL o playground parecen habilitados.",
        "En produccion pueden facilitar enumeracion de esquemas y operaciones sensibles.",
        "Un atacante podria descubrir tipos, mutaciones y campos internos para preparar abuso de API.",
        "Desactiva introspection/playground en produccion o restringelos a usuarios internos.",
        "introspection: process.env.NODE_ENV !== 'production'",
        "OWASP API Security API9 Improper Inventory Management",
    ),
    compile_rule(
        "SEC-078",
        "Errores detallados expuestos",
        "Media",
        "Configuracion",
        6.0,
        "Media",
        "Baja",
        [r"show_stacktrace\s*[:=]\s*true", r"include-stacktrace\s*:\s*always", r"trace\s*[:=]\s*true", r"expose_errors\s*[:=]\s*true"],
        ["*.yml", "*.yaml", "*.properties", "*.json", "*.py", "*.js", "*.ts", "*.java"],
        "La aplicacion parece exponer trazas o errores detallados.",
        "Errores detallados revelan rutas, clases, queries, versiones o secretos accidentales.",
        "Un atacante podria provocar errores para mapear arquitectura y preparar ataques.",
        "Devuelve mensajes genericos al cliente y registra detalles solo en logs protegidos.",
        "server.error.include-stacktrace=never",
        "OWASP Top 10 A05 Security Misconfiguration",
    ),
    compile_rule(
        "SEC-079",
        "CORS refleja origen dinamico",
        "Alta",
        "API",
        7.8,
        "Media",
        "Media",
        [r"Access-Control-Allow-Origin.*(req\.headers\.origin|request\.headers|origin)", r"origin\s*:\s*(origin|req\.headers\.origin|true)"],
        ["*.js", "*.ts", "*.py", "*.java", "*.kt"],
        "La configuracion CORS parece reflejar el origen de la peticion.",
        "Reflejar origenes equivale a aceptar dominios arbitrarios si no hay allowlist previa.",
        "Una web atacante podria recibir respuestas de API desde el navegador de una victima.",
        "Valida origin contra una allowlist exacta antes de devolverlo.",
        "if origin in ALLOWED_ORIGINS: set_header('Access-Control-Allow-Origin', origin)",
        "OWASP API Security API7 Security Misconfiguration",
    ),
    compile_rule(
        "SEC-080",
        "Politica de moderacion o validacion de salida IA ausente",
        "Media",
        "IA",
        6.9,
        "Baja",
        "Media",
        [r"(moderation|guardrail|safety|validate_output)\s*[:=]\s*(false|None|null)", r"skip[_-]?moderation\s*[:=]\s*true"],
        ["*.py", "*.js", "*.ts", "*.json", "*.yml", "*.yaml"],
        "La configuracion sugiere que controles de moderacion, guardrails o validacion de salida estan desactivados.",
        "Sin validacion de salida, el sistema puede ejecutar o mostrar contenido inseguro generado o inducido por el modelo.",
        "Un atacante podria provocar respuestas malformadas, instrucciones peligrosas o contenido que altere flujos posteriores.",
        "Activa validacion estructural, politicas de salida y controles especificos por caso de uso.",
        "validated = OutputSchema.model_validate_json(response_text)",
        "OWASP LLM02 Insecure Output Handling",
    ),
    compile_rule(
        "SEC-081",
        "Swagger o documentacion API expuesta",
        "Media",
        "API",
        6.2,
        "Media",
        "Baja",
        [r"swagger-ui", r"api-docs", r"openapi\.json", r"docs_url\s*=\s*['\"]/", r"redoc_url\s*=\s*['\"]/"],
        ["*.py", "*.js", "*.ts", "*.java", "*.kt", "*.yml", "*.yaml", "*.json"],
        "La documentacion interactiva de API parece estar expuesta.",
        "No siempre es un fallo, pero en entornos productivos facilita enumeracion de endpoints, modelos y operaciones.",
        "Un atacante podria usar la documentacion para identificar rutas sensibles o payloads validos.",
        "Restringe documentacion a entornos internos o usuarios autenticados.",
        "docs_url = None if ENV == 'production' else '/docs'",
        "OWASP API Security API9 Improper Inventory Management",
    ),
    compile_rule(
        "SEC-082",
        "Endpoint Actuator o health detallado expuesto",
        "Media",
        "Configuracion",
        6.3,
        "Media",
        "Baja",
        [r"management\.endpoints\.web\.exposure\.include\s*=\s*\*", r"show-details\s*:\s*always", r"/actuator"],
        ["*.properties", "*.yml", "*.yaml", "*.java", "*.kt", "*.md", "*.docx"],
        "La configuracion sugiere exposicion amplia de endpoints de diagnostico.",
        "Actuator/health detallado puede revelar variables, dependencias, rutas internas o estado de componentes.",
        "Un atacante podria enumerar tecnologia y estado interno para preparar ataques mas precisos.",
        "Expone solo health basico publicamente y protege endpoints administrativos.",
        "management.endpoints.web.exposure.include=health,info",
        "OWASP Top 10 A05 Security Misconfiguration",
    ),
    compile_rule(
        "SEC-083",
        "Elasticsearch o Kibana sin autenticacion",
        "Critica",
        "Infraestructura",
        9.0,
        "Media",
        "Media",
        [r"xpack\.security\.enabled\s*:\s*false", r"ELASTIC_PASSWORD\s*=\s*['\"]?changeme", r"elasticsearch.*9200.*0\.0\.0\.0"],
        ["*.yml", "*.yaml", "*.env", "*.properties", "*.tf", "*.json"],
        "La configuracion de Elasticsearch/Kibana parece desactivar seguridad o exponer el servicio.",
        "Buscadores y dashboards suelen contener logs, datos personales y trazas sensibles.",
        "Un atacante podria consultar indices, borrar datos o extraer informacion de clientes.",
        "Activa autenticacion, TLS, roles minimos y limita red a subredes privadas.",
        "xpack.security.enabled: true",
        "OWASP Top 10 A01 Broken Access Control",
    ),
    compile_rule(
        "SEC-084",
        "Redis sin autenticacion o expuesto",
        "Alta",
        "Infraestructura",
        8.5,
        "Media",
        "Media",
        [r"requirepass\s*['\"]?$", r"protected-mode\s+no", r"REDIS_PASSWORD\s*=\s*['\"]?$", r"6379:6379"],
        ["*.conf", "*.env", "*.yml", "*.yaml", "docker-compose*.yml", "docker-compose*.yaml"],
        "Redis parece estar expuesto o sin password.",
        "Redis sin autenticacion puede permitir lectura, escritura, borrado de datos o abuso para RCE en configuraciones vulnerables.",
        "Un atacante podria conectarse al puerto y manipular cache, sesiones o colas.",
        "Activa autenticacion, TLS si aplica y limita acceso por red privada.",
        "requirepass ${REDIS_PASSWORD}",
        "OWASP Top 10 A05 Security Misconfiguration",
    ),
    compile_rule(
        "SEC-085",
        "MongoDB sin autenticacion o bind abierto",
        "Alta",
        "Infraestructura",
        8.5,
        "Media",
        "Media",
        [r"authorization\s*:\s*disabled", r"bindIp\s*:\s*0\.0\.0\.0", r"27017:27017"],
        ["*.conf", "*.yml", "*.yaml", "docker-compose*.yml", "docker-compose*.yaml"],
        "MongoDB parece estar sin autorizacion o expuesto a todas las interfaces.",
        "Bases documentales expuestas son un vector frecuente de fuga y borrado de datos.",
        "Un atacante podria conectarse, extraer colecciones o ejecutar operaciones destructivas.",
        "Activa auth, limita bindIp y usa redes privadas/security groups.",
        "security:\n  authorization: enabled",
        "OWASP Top 10 A01 Broken Access Control",
    ),
    compile_rule(
        "SEC-086",
        "RabbitMQ o broker con credenciales por defecto",
        "Alta",
        "Infraestructura",
        8.2,
        "Alta",
        "Baja",
        [r"RABBITMQ_DEFAULT_USER\s*[:=]\s*guest", r"RABBITMQ_DEFAULT_PASS\s*[:=]\s*guest", r"guest:guest", r"amqp://guest:guest"],
        ["*.env", "*.yml", "*.yaml", "docker-compose*.yml", "docker-compose*.yaml", "*.properties"],
        "El broker parece usar credenciales por defecto.",
        "Credenciales por defecto en colas permiten leer mensajes, publicar eventos falsos o degradar sistemas.",
        "Un atacante podria consumir mensajes sensibles o inyectar tareas maliciosas.",
        "Usa usuarios unicos por entorno, passwords fuertes y permisos por vhost/cola.",
        "RABBITMQ_DEFAULT_USER=app_user\nRABBITMQ_DEFAULT_PASS=${RABBITMQ_PASSWORD}",
        "OWASP Top 10 A07 Identification and Authentication Failures",
    ),
    compile_rule(
        "SEC-087",
        "Kafka PLAINTEXT o sin autenticacion",
        "Alta",
        "Infraestructura",
        8.0,
        "Media",
        "Media",
        [r"PLAINTEXT://", r"security\.protocol\s*=\s*PLAINTEXT", r"ALLOW_PLAINTEXT_LISTENER\s*=\s*yes"],
        ["*.properties", "*.yml", "*.yaml", "*.env"],
        "Kafka parece configurado con listeners PLAINTEXT.",
        "Sin TLS/SASL, mensajes y credenciales pueden viajar sin proteccion o sin autenticacion fuerte.",
        "Un atacante con acceso de red podria leer, producir o manipular eventos.",
        "Usa SASL_SSL/SSL, ACLs por topic y redes privadas.",
        "security.protocol=SASL_SSL",
        "OWASP Top 10 A02 Cryptographic Failures",
    ),
    compile_rule(
        "SEC-088",
        "MinIO o S3 compatible con credenciales por defecto",
        "Critica",
        "Secretos",
        9.0,
        "Alta",
        "Baja",
        [r"MINIO_ROOT_USER\s*[:=]\s*minioadmin", r"MINIO_ROOT_PASSWORD\s*[:=]\s*minioadmin", r"minioadmin:minioadmin"],
        ["*.env", "*.yml", "*.yaml", "docker-compose*.yml", "docker-compose*.yaml"],
        "MinIO parece usar credenciales administrativas por defecto.",
        "Almacenamiento de objetos suele contener adjuntos, backups o datos de cliente.",
        "Un atacante podria autenticarse como admin y listar, descargar o borrar objetos.",
        "Cambia credenciales por entorno y limita acceso con politicas de minimo privilegio.",
        "MINIO_ROOT_PASSWORD=${MINIO_ROOT_PASSWORD}",
        "OWASP Top 10 A07 Identification and Authentication Failures",
    ),
    compile_rule(
        "SEC-089",
        "Archivo de lock ausente en proyecto Node",
        "Media",
        "Supply Chain",
        6.1,
        "Baja",
        "Baja",
        [r"\"dependencies\"\s*:", r"\"devDependencies\"\s*:"],
        ["package.json"],
        "El proyecto Node declara dependencias; revise que exista lockfile versionado.",
        "Sin lockfile, instalaciones pueden resolver versiones distintas y dificultar reproducibilidad.",
        "Una version transitoria comprometida podria entrar en CI sin cambio explicito de package.json.",
        "Versiona package-lock.json, pnpm-lock.yaml o yarn.lock y usa npm ci/pnpm install --frozen-lockfile.",
        "npm ci",
        "OWASP Top 10 A08 Software and Data Integrity Failures",
    ),
    compile_rule(
        "SEC-090",
        "Uso de npm install en CI en vez de npm ci",
        "Media",
        "Supply Chain",
        6.2,
        "Alta",
        "Baja",
        [r"\bnpm\s+install\b(?!\s+-g)"],
        ["*.yml", "*.yaml", "*.sh", "Dockerfile", "Makefile"],
        "CI usa npm install en lugar de npm ci.",
        "npm install puede modificar lockfiles o resolver dependencias de forma menos reproducible.",
        "Una dependencia inesperada podria entrar en build sin control estricto.",
        "Usa npm ci en CI y falla si package-lock no coincide.",
        "npm ci",
        "OWASP Top 10 A08 Software and Data Integrity Failures",
    ),
    compile_rule(
        "SEC-091",
        "Version de dependencia comodin",
        "Media",
        "Supply Chain",
        6.4,
        "Media",
        "Media",
        [r"\"[^\"]+\"\s*:\s*\"(\*|latest|file:|git\+|github:)\"", r"==\s*\*", r"version\s*=\s*['\"]latest['\"]"],
        ["package.json", "requirements.txt", "pyproject.toml", "pom.xml", "build.gradle", "*.gradle"],
        "Una dependencia usa version comodin, latest o fuente directa no fijada.",
        "Versiones flotantes o fuentes Git directas reducen reproducibilidad y control de supply chain.",
        "Un atacante que comprometa el origen o publique una version nueva podria afectar builds futuros.",
        "Fija versiones concretas y usa lockfiles o checksums.",
        "\"library\": \"1.2.3\"",
        "OWASP Top 10 A08 Software and Data Integrity Failures",
    ),
    compile_rule(
        "SEC-092",
        "Dependencia local por ruta en manifiesto",
        "Media",
        "Supply Chain",
        5.9,
        "Media",
        "Media",
        [r"\"[^\"]+\"\s*:\s*\"file:", r"path\s*=\s*['\"]\.\.", r"implementation\s+files\("],
        ["package.json", "pyproject.toml", "build.gradle", "*.gradle"],
        "El manifiesto referencia dependencias locales por ruta.",
        "Dependencias por ruta pueden romper reproducibilidad y esconder codigo no auditado en CI.",
        "Un atacante podria alterar una ruta local incluida en el build sin pasar por el gestor de paquetes esperado.",
        "Publica paquetes internos versionados o usa workspaces con controles claros.",
        "\"@org/lib\": \"workspace:*\"",
        "OWASP Top 10 A08 Software and Data Integrity Failures",
    ),
    compile_rule(
        "SEC-093",
        "Desactivacion de verificacion de integridad en gestor de paquetes",
        "Alta",
        "Supply Chain",
        7.8,
        "Media",
        "Baja",
        [r"strict-ssl\s*=\s*false", r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*0", r"pip\s+.*--trusted-host", r"npm\s+config\s+set\s+strict-ssl\s+false"],
        ["*.npmrc", "pip.conf", "*.yml", "*.yaml", "*.sh", "Dockerfile"],
        "La configuracion desactiva validaciones TLS o confia explicitamente en hosts de paquetes.",
        "Esto debilita la integridad de descargas de dependencias.",
        "Un atacante en red podria interceptar o suplantar repositorios de paquetes.",
        "Mantén TLS estricto y usa repositorios internos con certificados correctos.",
        "strict-ssl=true",
        "OWASP Top 10 A08 Software and Data Integrity Failures",
    ),
    compile_rule(
        "SEC-094",
        "Comando destructivo en pipeline",
        "Media",
        "CI/CD",
        6.5,
        "Media",
        "Baja",
        [r"\brm\s+-rf\s+(/|\$HOME|~|\*)", r"\bdocker\s+system\s+prune\s+-a", r"\bkubectl\s+delete\s+.*--all"],
        ["*.yml", "*.yaml", "*.sh", "Makefile"],
        "El pipeline contiene comandos destructivos amplios.",
        "Comandos destructivos en CI pueden causar perdida de datos o afectar runners compartidos si variables se expanden mal.",
        "Un atacante que controle variables o contexto podria amplificar el alcance del borrado.",
        "Restringe rutas, valida variables y evita comodines destructivos.",
        "rm -rf \"$BUILD_DIR\" && test -n \"$BUILD_DIR\"",
        "OWASP CI/CD Security",
    ),
    compile_rule(
        "SEC-095",
        "Terraform backend sin cifrado o lock",
        "Media",
        "Cloud",
        6.5,
        "Media",
        "Baja",
        [r"encrypt\s*=\s*false", r"dynamodb_table\s*=\s*['\"]\s*['\"]", r"backend\s+\"s3\""],
        ["*.tf", "*.hcl"],
        "El backend Terraform requiere revisar cifrado y bloqueo de estado.",
        "El state puede contener secretos y el lock evita corrupcion por ejecuciones concurrentes.",
        "Un atacante con acceso al state podria extraer credenciales o endpoints internos.",
        "Activa cifrado, bloqueo y acceso minimo al bucket de state.",
        "encrypt = true\ndynamodb_table = 'terraform-locks'",
        "OWASP Top 10 A02 Cryptographic Failures",
    ),
    compile_rule(
        "SEC-096",
        "Terraform output sensible no marcado",
        "Media",
        "Secretos",
        6.6,
        "Media",
        "Baja",
        [r"output\s+\"[^\"]*(password|secret|token|key)[^\"]*\"", r"value\s*=.*(password|secret|token|key)"],
        ["*.tf"],
        "Un output de Terraform parece contener informacion sensible.",
        "Outputs no marcados como sensitive pueden aparecer en CLI, logs o sistemas de CI.",
        "Un usuario con acceso a logs del pipeline podria recuperar secretos.",
        "Marca outputs sensibles y evita exponer secretos como outputs si no es necesario.",
        "sensitive = true",
        "OWASP Top 10 A02 Cryptographic Failures",
    ),
    compile_rule(
        "SEC-097",
        "Azure storage permite acceso publico",
        "Alta",
        "Cloud",
        8.1,
        "Media",
        "Baja",
        [r"allow_blob_public_access\s*=\s*true", r"container_access_type\s*=\s*['\"](blob|container)"],
        ["*.tf", "*.json", "*.bicep", "*.yml", "*.yaml"],
        "Azure Storage parece permitir acceso publico a blobs o contenedores.",
        "Contenedores publicos pueden filtrar adjuntos, backups o datos internos.",
        "Un atacante podria enumerar o descargar objetos si conoce el nombre del contenedor.",
        "Desactiva acceso publico y usa SAS/roles con minimo privilegio.",
        "allow_blob_public_access = false",
        "OWASP Top 10 A01 Broken Access Control",
    ),
    compile_rule(
        "SEC-098",
        "GCP bucket publico",
        "Alta",
        "Cloud",
        8.1,
        "Media",
        "Baja",
        [r"allUsers", r"allAuthenticatedUsers", r"roles/storage\.objectViewer"],
        ["*.tf", "*.json", "*.yaml", "*.yml"],
        "Una politica GCP parece conceder acceso amplio a almacenamiento.",
        "Permisos allUsers/allAuthenticatedUsers pueden exponer datos a Internet o a cualquier cuenta Google.",
        "Un atacante podria leer objetos si la politica se aplica a buckets sensibles.",
        "Evita miembros publicos y concede acceso mediante service accounts especificas.",
        "member = 'serviceAccount:app@example.iam.gserviceaccount.com'",
        "OWASP Top 10 A01 Broken Access Control",
    ),
    compile_rule(
        "SEC-099",
        "MFA desactivado o no requerido",
        "Alta",
        "Autenticacion",
        7.8,
        "Media",
        "Media",
        [r"mfa\s*[:=]\s*false", r"multi[_-]?factor\s*[:=]\s*false", r"require_mfa\s*[:=]\s*false"],
        ["*.py", "*.js", "*.ts", "*.java", "*.kt", "*.yml", "*.yaml", "*.json"],
        "La configuracion sugiere que MFA no es requerido.",
        "Sin MFA, el compromiso de password tiene mayor probabilidad de convertirse en acceso real.",
        "Un atacante con credenciales filtradas podria iniciar sesion sin segundo factor.",
        "Requiere MFA para administradores y operaciones sensibles.",
        "require_mfa: true",
        "OWASP Top 10 A07 Identification and Authentication Failures",
    ),
    compile_rule(
        "SEC-100",
        "Proteccion anti-replay ausente",
        "Media",
        "API",
        6.6,
        "Baja",
        "Media",
        [r"timestamp\s*[:=]\s*None", r"nonce\s*[:=]\s*None", r"replay[_-]?protection\s*[:=]\s*false", r"verify_timestamp\s*[:=]\s*false"],
        ["*.py", "*.js", "*.ts", "*.java", "*.kt", "*.yml", "*.yaml", "*.json"],
        "La configuracion sugiere ausencia de timestamp, nonce o proteccion anti-replay.",
        "APIs firmadas o webhooks sin anti-replay pueden aceptar mensajes capturados previamente.",
        "Un atacante podria reutilizar una peticion valida para repetir una accion sensible.",
        "Valida timestamp, nonce unico y ventana temporal corta.",
        "if abs(now - timestamp) > 300: reject()",
        "OWASP API Security API2 Broken Authentication",
    ),
]


def should_skip(path: Path, root: Path) -> bool:
    rel_parts = path.relative_to(root).parts
    return any(part in DEFAULT_EXCLUDES for part in rel_parts)


def is_probably_text(path: Path) -> bool:
    if path.name in {"Dockerfile", "Makefile", ".gitignore"}:
        return True
    return path.suffix.lower() in TEXT_EXTENSIONS or ".env" in path.name


def iter_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        if should_skip(path, root):
            continue
        if path.is_file() and is_probably_text(path):
            yield path


def read_lines(path: Path) -> list[str]:
    if path.suffix.lower() == ".docx":
        return read_docx_lines(path)
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def read_docx_lines(path: Path) -> list[str]:
    try:
        with zipfile.ZipFile(path) as archive:
            xml_files = [
                name
                for name in archive.namelist()
                if name.startswith("word/") and name.endswith(".xml")
            ]
            paragraphs: list[str] = []
            for name in xml_files:
                xml = archive.read(name).decode("utf-8", errors="replace")
                xml = re.sub(r"</w:p>", "\n", xml)
                xml = re.sub(r"</w:tr>", "\n", xml)
                text = re.sub(r"<[^>]+>", " ", xml)
                text = unescape(text)
                for line in text.splitlines():
                    cleaned = re.sub(r"\s+", " ", line).strip()
                    if cleaned:
                        paragraphs.append(cleaned)
            return paragraphs
    except (OSError, zipfile.BadZipFile, KeyError):
        return []


def masked_evidence(text: str) -> str:
    compact = text.strip()
    if len(compact) > 180:
        compact = compact[:177] + "..."
    compact = re.sub(
        r"((?:api[_-]?key|secret|token|password|passwd|pwd|OPENAI_API_KEY|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*)([^\s'\"\]]{8,})",
        lambda match: f"{match.group(1)}{match.group(2)[:4]}...{match.group(2)[-4:]}",
        compact,
        flags=re.IGNORECASE,
    )
    compact = re.sub(
        r"(['\"])([^'\"]{4})([^'\"]{8,})([^'\"]{4})(['\"])",
        lambda match: f"{match.group(1)}{match.group(2)}...{match.group(4)}{match.group(5)}",
        compact,
    )
    return compact


def context_for(lines: list[str], line_number: int, radius: int = 2) -> str:
    start = max(1, line_number - radius)
    end = min(len(lines), line_number + radius)
    excerpt = []
    for current in range(start, end + 1):
        prefix = ">" if current == line_number else " "
        excerpt.append(f"{prefix} {current}: {masked_evidence(lines[current - 1])}")
    return "\n".join(excerpt)


def rules_for_profile(profile: str) -> list[Rule]:
    selected = PROFILES[profile]
    if selected == "all":
        return RULES
    if isinstance(selected, str) and selected.startswith("category:"):
        categories = {category.strip() for category in selected.removeprefix("category:").split(",")}
        return [rule for rule in RULES if rule.category in categories]
    return [rule for rule in RULES if rule.rule_id in selected]


def load_suppressions(root: Path, ignore_file: Path | None = None) -> list[str]:
    candidates = []
    if ignore_file:
        candidates.append(ignore_file)
    candidates.append(root / ".preauditor-ignore")

    suppressions: list[str] = []
    for candidate in candidates:
        if not candidate.exists():
            continue
        try:
            for line in candidate.read_text(encoding="utf-8", errors="replace").splitlines():
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    suppressions.append(stripped)
        except OSError:
            continue
    return suppressions


def is_suppressed(finding: Finding, suppressions: list[str]) -> bool:
    location = f"{finding.file}:{finding.line}"
    for suppression in suppressions:
        if suppression == finding.rule_id:
            return True
        if suppression == finding.fingerprint or suppression == f"fingerprint:{finding.fingerprint}":
            return True
        if suppression == location or suppression == f"{finding.rule_id}:{location}":
            return True
        if " " in suppression:
            rule_id, pattern = suppression.split(None, 1)
            if rule_id == finding.rule_id and fnmatch.fnmatch(finding.file, pattern):
                return True
        if ":" in suppression:
            rule_id, pattern = suppression.split(":", 1)
            if rule_id == finding.rule_id and fnmatch.fnmatch(finding.file, pattern):
                return True
        if suppression.startswith("file:") and fnmatch.fnmatch(finding.file, suppression.removeprefix("file:")):
            return True
    return False


def make_finding(rule: Rule, relative: str, line_number: int, line: str, lines: list[str]) -> Finding:
    severity = rule.severity
    cvss = rule.cvss
    description = rule.description

    if rule.rule_id in {"SEC-032", "SEC-058", "SEC-059"} and "pull_request" in "\n".join(lines[:40]):
        if severity == "Media":
            severity = "Alta"
            cvss = max(cvss, 7.5)
            description += " Ajuste contextual: aparece en un workflow asociado a Pull Requests."

    fingerprint = hashlib.sha256(
        f"{rule.rule_id}:{relative}:{line_number}:{line.strip()}".encode()
    ).hexdigest()
    return Finding(
        rule_id=rule.rule_id,
        title=rule.title,
        severity=severity,
        category=rule.category,
        cvss=cvss,
        confidence=rule.confidence,
        remediation_effort=rule.remediation_effort,
        file=relative,
        line=line_number,
        evidence=masked_evidence(line),
        context=context_for(lines, line_number),
        fingerprint=fingerprint[:12],
        description=description,
        why_dangerous=rule.why_dangerous,
        exploit_concept=rule.exploit_concept,
        recommendation=rule.recommendation,
        secure_example=rule.secure_example,
        reference=rule.reference,
    )


def related_finding_entry(finding: Finding) -> dict[str, object]:
    return {
        "rule_id": finding.rule_id,
        "title": finding.title,
        "file": finding.file,
        "line": finding.line,
        "evidence": finding.evidence,
    }


def composite_related(file_findings: list[Finding], rule_ids: set[str]) -> tuple[dict[str, object], ...]:
    related = [
        finding
        for finding in file_findings
        if finding.rule_id in rule_ids
    ]
    related.sort(key=lambda finding: (finding.line, finding.rule_id))
    return tuple(related_finding_entry(finding) for finding in related)


def composite_context(related: tuple[dict[str, object], ...]) -> str:
    return "\n".join(
        f"{item['file']}:{item['line']} [{item['rule_id']}] {item['evidence']}"
        for item in related
    )


def add_composite_findings(findings: list[Finding]) -> list[Finding]:
    composites: list[Finding] = []
    by_file = sorted({finding.file for finding in findings})
    for file in by_file:
        file_findings = [finding for finding in findings if finding.file == file]
        rule_ids = {finding.rule_id for finding in file_findings}

        if {"SEC-026", "SEC-027"} <= rule_ids and rule_ids.intersection({"SEC-005", "SEC-029", "SEC-058", "SEC-059"}):
            related = composite_related(file_findings, {"SEC-005", "SEC-026", "SEC-027", "SEC-029", "SEC-058", "SEC-059"})
            first_line = min(int(item["line"]) for item in related)
            fingerprint = hashlib.sha256(f"CMP-001:{file}".encode()).hexdigest()[:12]
            composites.append(
                Finding(
                    rule_id="CMP-001",
                    title="Cadena critica de agente IA en Pull Request",
                    severity="Critica",
                    category="IA",
                    cvss=9.6,
                    confidence="Alta",
                    remediation_effort="Alta",
                    file=file,
                    line=first_line,
                    evidence=" + ".join(item["rule_id"] for item in related),
                    context=composite_context(related),
                    fingerprint=fingerprint,
                    description="Se combinan workspace confiable, prompt cargado desde el PR y permisos/capacidades de escritura o secretos en CI.",
                    why_dangerous="La combinacion permite que una PR modifique instrucciones del agente y que el agente opere con permisos reales sobre GitHub o secretos.",
                    exploit_concept="Un atacante podria abrir una PR que altera el prompt y empuja al agente a crear comentarios, issues o acciones no autorizadas.",
                    recommendation="Separar prompt confiable del workspace, desactivar trust_workspace, reducir permisos a lectura y exigir aprobacion humana para escritura.",
                    secure_example="GEMINI_CLI_TRUST_WORKSPACE: 'false'\npermissions:\n  contents: read\n  pull-requests: read",
                    reference="OWASP LLM01 Prompt Injection / OWASP LLM06 Excessive Agency / OWASP CI/CD Security",
                    related_findings=related,
                )
            )

        if {"SEC-003", "SEC-053"} <= rule_ids:
            related = composite_related(file_findings, {"SEC-003", "SEC-053"})
            first_line = min(int(item["line"]) for item in related)
            fingerprint = hashlib.sha256(f"CMP-002:{file}".encode()).hexdigest()[:12]
            composites.append(
                Finding(
                    rule_id="CMP-002",
                    title="CORS abierto con credenciales",
                    severity="Critica",
                    category="API",
                    cvss=9.1,
                    confidence="Alta",
                    remediation_effort="Baja",
                    file=file,
                    line=first_line,
                    evidence=" + ".join(item["rule_id"] for item in related),
                    context=composite_context(related),
                    fingerprint=fingerprint,
                    description="Se detecta una combinacion de origen CORS abierto y credenciales habilitadas.",
                    why_dangerous="Permite que navegadores envien credenciales a la API desde origenes no confiables si la configuracion efectiva lo permite.",
                    exploit_concept="Una web atacante podria realizar peticiones autenticadas y leer respuestas desde el navegador de la victima.",
                    recommendation="Usa allowlist exacta de origenes y evita credenciales salvo necesidad justificada.",
                    secure_example="cors({ origin: ['https://app.example.com'], credentials: true })",
                    reference="OWASP API Security API7 Security Misconfiguration",
                    related_findings=related,
                )
            )
    return findings + composites


def scan(root: Path, profile: str = "pro", ignore_file: Path | None = None, custom_rules: list[Rule] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    active_rules = rules_for_profile(profile) + list(custom_rules or [])
    suppressions = load_suppressions(root, ignore_file)

    for path in iter_files(root):
        relative = path.relative_to(root).as_posix()
        lines = read_lines(path)
        if not lines:
            continue

        for rule in active_rules:
            if not rule.applies_to(relative):
                continue
            for line_number, line in enumerate(lines, start=1):
                if any(pattern.search(line) for pattern in rule.patterns):
                    finding = make_finding(rule, relative, line_number, line, lines)
                    if finding.fingerprint in seen or is_suppressed(finding, suppressions):
                        continue
                    seen.add(finding.fingerprint)
                    findings.append(finding)
                    break

    findings = [
        finding
        for finding in add_composite_findings(findings)
        if not is_suppressed(finding, suppressions)
    ]
    return sorted(
        findings,
        key=lambda finding: (
            -SEVERITY_ORDER[finding.severity],
            finding.file,
            finding.line,
            finding.rule_id,
        ),
    )


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    return {severity: sum(1 for f in findings if f.severity == severity) for severity in SEVERITY_ORDER}


def category_counts(findings: list[Finding]) -> dict[str, int]:
    categories = sorted({finding.category for finding in findings})
    return {category: sum(1 for f in findings if f.category == category) for category in categories}


def average_cvss(findings: list[Finding]) -> float:
    if not findings:
        return 0.0
    return round(sum(finding.cvss for finding in findings) / len(findings), 1)


def top_files(findings: list[Finding], limit: int = 5) -> list[tuple[str, int]]:
    files = sorted({finding.file for finding in findings})
    ranked = [(file, sum(1 for finding in findings if finding.file == file)) for file in files]
    return sorted(ranked, key=lambda item: (-item[1], item[0]))[:limit]


def remediation_sla(finding: Finding) -> str:
    if finding.severity == "Critica":
        return "24-48 horas"
    if finding.severity == "Alta":
        return "7 dias"
    if finding.severity == "Media":
        return "30 dias"
    return "Backlog controlado"


def impact_for(finding: Finding) -> str:
    if finding.severity in {"Critica", "Alta"} or finding.cvss >= 8:
        return "Alto"
    if finding.cvss >= 6:
        return "Medio"
    return "Bajo"


def likelihood_for(finding: Finding) -> str:
    if finding.confidence == "Alta" and finding.severity in {"Critica", "Alta"}:
        return "Alta"
    if finding.confidence in {"Alta", "Media"}:
        return "Media"
    return "Baja"


def priority_for(finding: Finding) -> str:
    if finding.severity == "Critica" or finding.cvss >= 9:
        return "P1"
    if finding.severity == "Alta" or finding.cvss >= 7:
        return "P2"
    if finding.severity == "Media":
        return "P3"
    return "P4"


def manual_validation_points(findings: list[Finding]) -> list[str]:
    points: list[str] = []
    ids = {finding.rule_id for finding in findings}
    if {"SEC-003", "SEC-053", "CMP-002"} & ids:
        points.append("Confirmar si la configuracion CORS aplica a produccion o solo a entornos locales/controlados.")
    if {"SEC-004"} & ids:
        points.append("Validar si los endpoints marcados como sin autenticacion estan protegidos por middleware externo, gateway o proxy.")
    if {"SEC-026", "SEC-027", "CMP-001"} & ids:
        points.append("Confirmar si el workflow de agente IA procesa Pull Requests de contribuidores externos o ramas no confiables.")
    if {"SEC-055"} & ids:
        points.append("Revisar si el RAG filtra documentos por usuario, tenant, permisos y fuente de confianza.")
    if {"SEC-058", "SEC-059"} & ids:
        points.append("Validar condiciones de uso de secretos/OIDC en CI y si pueden ejecutarse con codigo procedente de PR.")
    if not points and findings:
        points.append("Validar manualmente los hallazgos criticos y altos para confirmar explotabilidad, alcance real e impacto de negocio.")
    return points


def ai_agent_risk_score(findings: list[Finding]) -> tuple[int, str, list[str]]:
    ids = {finding.rule_id for finding in findings}
    score = 0
    reasons = []
    weights = {
        "SEC-010": (15, "herramientas sensibles disponibles"),
        "SEC-026": (20, "workspace marcado como confiable"),
        "SEC-027": (20, "prompt cargado desde workspace/PR"),
        "SEC-029": (15, "permisos de escritura sobre GitHub"),
        "SEC-058": (10, "secretos inyectados en CI"),
        "SEC-059": (10, "OIDC write en CI"),
        "SEC-009": (10, "autonomia elevada"),
        "SEC-056": (20, "posible ejecucion de codigo influida por IA"),
        "CMP-001": (25, "cadena critica de agente IA"),
    }
    for rule_id, (weight, reason) in weights.items():
        if rule_id in ids:
            score += weight
            reasons.append(reason)
    score = min(score, 100)
    if score >= 80:
        level = "Critico"
    elif score >= 55:
        level = "Alto"
    elif score >= 30:
        level = "Medio"
    else:
        level = "Bajo"
    return score, level, reasons


def project_hash(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(iter_files(root), key=lambda p: p.relative_to(root).as_posix()):
        try:
            relative = path.relative_to(root).as_posix()
            digest.update(relative.encode())
            digest.update(b"\0")
            digest.update(path.read_bytes())
            digest.update(b"\0")
        except OSError:
            continue
    return digest.hexdigest()


def finding_key(finding: Finding) -> str:
    return f"{finding.rule_id}:{finding.file}:{finding.line}:{finding.fingerprint}"


def load_review_records(path: Path | None) -> dict[str, dict]:
    if not path or not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    raw_items = data.get("reviews", data) if isinstance(data, dict) else data
    records: dict[str, dict] = {}
    if isinstance(raw_items, list):
        for item in raw_items:
            if isinstance(item, dict) and item.get("fingerprint"):
                records[str(item["fingerprint"])] = item
    elif isinstance(raw_items, dict):
        for fingerprint, item in raw_items.items():
            if isinstance(item, dict):
                normalized = dict(item)
                normalized.setdefault("fingerprint", fingerprint)
                records[str(fingerprint)] = normalized
    return records


def normalize_review_record(record: dict | None, finding: Finding | None = None) -> dict:
    record = dict(record or {})
    status = str(record.get("status", "pending"))
    if status not in REVIEW_STATUSES:
        status = "pending"
    normalized = {
        "fingerprint": str(record.get("fingerprint") or (finding.fingerprint if finding else "")),
        "status": status,
        "reviewed_by": str(record.get("reviewed_by", "")),
        "reviewed_at": str(record.get("reviewed_at", "")),
        "rationale": str(record.get("rationale", "")),
        "ticket": str(record.get("ticket", "")),
        "fix_commit": str(record.get("fix_commit", "")),
        "verification": str(record.get("verification", "")),
    }
    if finding:
        normalized.update(
            {
                "rule_id": finding.rule_id,
                "title": finding.title,
                "file": finding.file,
                "line": finding.line,
            }
        )
    else:
        for key in ("rule_id", "title", "file", "line"):
            if key in record:
                normalized[key] = record[key]
    return normalized


def review_for_finding(finding: Finding, review_records: dict[str, dict] | None = None) -> dict:
    return normalize_review_record((review_records or {}).get(finding.fingerprint), finding)


def review_counts(findings: list[Finding], review_records: dict[str, dict] | None = None) -> dict[str, int]:
    counts = {status: 0 for status in REVIEW_STATUSES}
    for finding in findings:
        counts[review_for_finding(finding, review_records)["status"]] += 1
    return counts


def finding_payload(finding: Finding, review_records: dict[str, dict] | None = None) -> dict:
    payload = asdict(finding)
    payload["review"] = review_for_finding(finding, review_records)
    return payload


def baseline_payload(
    findings: list[Finding],
    target: Path,
    profile: str,
    meta: ReportMeta,
    project_sha: str,
    review_records: dict[str, dict] | None = None,
) -> dict:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": str(target),
        "profile": profile,
        "meta": asdict(meta),
        "project_sha256": project_sha,
        "findings": [
            {
                "key": finding_key(finding),
                "rule_id": finding.rule_id,
                "title": finding.title,
                "severity": finding.severity,
                "file": finding.file,
                "line": finding.line,
                "fingerprint": finding.fingerprint,
                "review": review_for_finding(finding, review_records),
            }
            for finding in findings
        ],
    }


def compare_with_baseline(findings: list[Finding], baseline_path: Path | None) -> dict | None:
    if not baseline_path:
        return None
    try:
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    previous = {item["key"]: item for item in baseline.get("findings", []) if "key" in item}
    current = {finding_key(finding): finding for finding in findings}
    new_keys = sorted(set(current) - set(previous))
    fixed_keys = sorted(set(previous) - set(current))
    persistent_keys = sorted(set(current) & set(previous))
    previous_counts = {severity: 0 for severity in SEVERITY_ORDER}
    for item in previous.values():
        severity = item.get("severity")
        if severity in previous_counts:
            previous_counts[severity] += 1
    current_counts = severity_counts(findings)
    previous_total = len(previous)
    current_total = len(current)
    improvement_percent = round((len(fixed_keys) / previous_total) * 100, 1) if previous_total else 0.0
    if len(fixed_keys) > len(new_keys):
        status = "mejora"
    elif len(new_keys) > len(fixed_keys):
        status = "regresion"
    else:
        status = "estable"
    return {
        "baseline": str(baseline_path),
        "new": len(new_keys),
        "fixed": len(fixed_keys),
        "persistent": len(persistent_keys),
        "previous_total": previous_total,
        "current_total": current_total,
        "previous_counts": previous_counts,
        "current_counts": current_counts,
        "critical_delta": current_counts["Critica"] - previous_counts["Critica"],
        "high_delta": current_counts["Alta"] - previous_counts["Alta"],
        "improvement_percent": improvement_percent,
        "status": status,
        "new_findings": [asdict(current[key]) for key in new_keys],
        "fixed_findings": [previous[key] for key in fixed_keys],
    }


def related_findings_markdown(finding: Finding) -> list[str]:
    if not finding.related_findings:
        return []
    lines = [
        "**Hallazgo compuesto:** la severidad procede de la combinación de varias evidencias relacionadas.",
        "",
        "| Regla | Ubicación | Evidencia |",
        "|---|---|---|",
    ]
    for item in finding.related_findings:
        lines.append(
            f"| `{item['rule_id']}` | `{item['file']}:{item['line']}` | `{item['evidence']}` |"
        )
    lines.append("")
    return lines


def related_findings_markdown_en(finding: Finding) -> list[str]:
    if not finding.related_findings:
        return []
    lines = [
        "**Composite finding:** severity comes from the combination of related evidence.",
        "",
        "| Rule | Location | Evidence |",
        "|---|---|---|",
    ]
    for item in finding.related_findings:
        lines.append(
            f"| `{item['rule_id']}` | `{item['file']}:{item['line']}` | `{item['evidence']}` |"
        )
    lines.append("")
    return lines


def related_findings_html(finding: Finding) -> str:
    if not finding.related_findings:
        return ""
    rows = "".join(
        (
            "<tr>"
            f"<td><code>{html.escape(str(item['rule_id']))}</code></td>"
            f"<td><code>{html.escape(str(item['file']))}:{html.escape(str(item['line']))}</code></td>"
            f"<td><code>{html.escape(str(item['evidence']))}</code></td>"
            "</tr>"
        )
        for item in finding.related_findings
    )
    return f"""
        <div class="related-findings">
          <p><strong>Hallazgo compuesto:</strong> la severidad procede de la combinación de varias evidencias relacionadas.</p>
          <table>
            <thead><tr><th>Regla</th><th>Ubicación</th><th>Evidencia</th></tr></thead>
            <tbody>{rows}</tbody>
          </table>
        </div>
"""


def related_findings_html_en(finding: Finding) -> str:
    if not finding.related_findings:
        return ""
    rows = "".join(
        (
            "<tr>"
            f"<td><code>{html.escape(str(item['rule_id']))}</code></td>"
            f"<td><code>{html.escape(str(item['file']))}:{html.escape(str(item['line']))}</code></td>"
            f"<td><code>{html.escape(str(item['evidence']))}</code></td>"
            "</tr>"
        )
        for item in finding.related_findings
    )
    return f"""
        <div class="related-findings">
          <p><strong>Composite finding:</strong> severity comes from the combination of related evidence.</p>
          <table>
            <thead><tr><th>Rule</th><th>Location</th><th>Evidence</th></tr></thead>
            <tbody>{rows}</tbody>
          </table>
        </div>
"""


def severity_at_least(severity: str, threshold: str) -> bool:
    return SEVERITY_ORDER[severity] >= SEVERITY_ORDER[threshold]


def ollama_prompt(finding: Finding, meta: ReportMeta) -> str:
    return f"""Eres un analista senior de AppSec ayudando a hacer triage de un análisis preliminar automático.

Tu tarea NO es cerrar el hallazgo. Debes estimar si parece:
- probable_real
- requiere_revision
- probable_falso_positivo

Responde SOLO JSON válido con estas claves:
{{
  "verdict": "probable_real|requiere_revision|probable_falso_positivo",
  "confidence": "Alta|Media|Baja",
  "rationale": "explicación breve",
  "auditor_validation": "qué debe comprobar el auditor humano"
}}

Contexto del informe:
- Cliente: {meta.client}
- Stack declarado: {meta.stack}

Hallazgo:
- ID: {finding.rule_id}
- Título: {finding.title}
- Severidad: {finding.severity}
- Categoría: {finding.category}
- Archivo: {finding.file}:{finding.line}
- Evidencia enmascarada: {finding.evidence}
- Contexto:
{finding.context}
- Descripción: {finding.description}
- Riesgo: {finding.why_dangerous}
- Recomendación: {finding.recommendation}

Criterios:
- Si falta contexto para confirmar, usa requiere_revision.
- No asumas que es falso positivo solo porque la evidencia está incompleta.
- Los secretos están enmascarados intencionadamente.
- Mantén la respuesta concisa."""


def parse_ollama_json(text: str) -> dict:
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, flags=re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError:
                pass
    return {
        "verdict": "requiere_revision",
        "confidence": "Baja",
        "rationale": "Ollama no devolvió JSON válido.",
        "auditor_validation": "Revisar manualmente el hallazgo.",
    }


def analyze_with_ollama(
    findings: list[Finding],
    meta: ReportMeta,
    base_url: str,
    model: str,
    limit: int,
    min_severity: str,
    timeout: int = 60,
) -> dict[str, dict]:
    selected = [
        finding
        for finding in findings
        if severity_at_least(finding.severity, min_severity)
    ][:limit]
    assessments: dict[str, dict] = {}
    endpoint = base_url.rstrip("/") + "/api/chat"

    for finding in selected:
        payload = {
            "model": model,
            "stream": False,
            "format": "json",
            "messages": [
                {
                    "role": "system",
                    "content": "Eres un analista AppSec. Responde exclusivamente JSON válido.",
                },
                {"role": "user", "content": ollama_prompt(finding, meta)},
            ],
        }
        try:
            req = urlrequest.Request(
                endpoint,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlrequest.urlopen(req, timeout=timeout) as response:
                data = json.loads(response.read().decode("utf-8"))
            content = data.get("message", {}).get("content", "")
            assessment = parse_ollama_json(content)
        except (OSError, urlerror.URLError, json.JSONDecodeError) as exc:
            assessment = {
                "verdict": "requiere_revision",
                "confidence": "Baja",
                "rationale": f"No se pudo consultar Ollama: {exc}",
                "auditor_validation": "Arrancar Ollama o revisar manualmente.",
            }

        if assessment.get("verdict") not in {"probable_real", "requiere_revision", "probable_falso_positivo"}:
            assessment["verdict"] = "requiere_revision"
        if assessment.get("confidence") not in {"Alta", "Media", "Baja"}:
            assessment["confidence"] = "Baja"
        assessment["model"] = model
        assessments[finding_key(finding)] = assessment
    return assessments


def filter_ollama_false_positives(findings: list[Finding], assessments: dict[str, dict]) -> list[Finding]:
    kept = []
    for finding in findings:
        assessment = assessments.get(finding_key(finding))
        if assessment and assessment.get("verdict") == "probable_falso_positivo" and assessment.get("confidence") in {"Alta", "Media"}:
            continue
        kept.append(finding)
    return kept


def global_risk(findings: list[Finding]) -> str:
    counts = severity_counts(findings)
    if counts["Critica"] > 0 or counts["Alta"] >= 4:
        return "Alto"
    if counts["Alta"] > 0 or counts["Media"] >= 5:
        return "Medio"
    if findings:
        return "Bajo"
    return "Sin hallazgos automáticos relevantes"


def business_impact(findings: list[Finding], lang: str = "es") -> str:
    categories = {finding.category for finding in findings}
    if lang == "en":
        impacts_en = []
        if "Secretos" in categories:
            impacts_en.append("possible credential compromise and access to external services")
        if "API" in categories:
            impacts_en.append("exposure of endpoints or data to unauthorized clients")
        if "IA" in categories:
            impacts_en.append("risk of prompt injection, unauthorized actions, or unsafe AI output handling")
        if "CI/CD" in categories:
            impacts_en.append("higher impact if pipelines or dependencies are compromised")
        if "Privacidad" in categories:
            impacts_en.append("possible leakage of sensitive data into logging systems")
        if "Archivos" in categories:
            impacts_en.append("risk of abuse in file upload workflows")
        if not impacts_en:
            return "No business impact was identified with the current automated rules."
        return "; ".join(impacts_en) + "."

    impacts = []
    if "Secretos" in categories:
        impacts.append("posible compromiso de credenciales y acceso a servicios externos")
    if "API" in categories:
        impacts.append("exposición de endpoints o datos a clientes no autorizados")
    if "IA" in categories:
        impacts.append("riesgo de prompt injection, acciones no autorizadas o manejo inseguro de salidas de IA")
    if "CI/CD" in categories:
        impacts.append("mayor impacto ante compromiso de pipeline o dependencias")
    if "Privacidad" in categories:
        impacts.append("posible fuga de datos sensibles a sistemas de logging")
    if "Archivos" in categories:
        impacts.append("riesgo de abuso en subidas de archivos")
    if not impacts:
        return "No se han identificado impactos de negocio con las reglas automáticas actuales."
    return "; ".join(impacts) + "."


def render_markdown(
    findings: list[Finding],
    target: Path,
    profile: str,
    meta: ReportMeta,
    project_sha: str = "",
    comparison: dict | None = None,
    ollama_assessments: dict[str, dict] | None = None,
    review_records: dict[str, dict] | None = None,
) -> str:
    counts = severity_counts(findings)
    categories = category_counts(findings)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    disclaimer = (
        "Esta auditoría automática no sustituye una revisión experta. "
        "Los hallazgos deben ser validados por un consultor especializado, "
        "ya que pueden existir falsos positivos, falsos negativos y riesgos contextuales "
        "no detectables automáticamente."
    )
    lang = report_language(meta)
    if lang == "en":
        disclaimer_en = (
            "This automated assessment does not replace expert review. "
            "Findings must be validated by a specialist because false positives, "
            "false negatives, and contextual risks may exist."
        )
        lines = [
            "# Preliminary Security Assessment Report",
            "",
            f"**Client:** {meta.client}",
            f"**Auditor:** {meta.auditor}",
            f"**Scope:** {meta.scope}",
            f"**Report version:** {meta.version}",
            f"**Declared stack:** {stack_label(meta.stack, lang)}",
            f"**Scanned project:** `{target}`",
            f"**Project SHA256:** `{project_sha or 'not calculated'}`",
            f"**Date:** {now}",
            f"**Profile:** {profile}",
            f"**Active rules:** {len(rules_for_profile(profile))}",
            f"**Overall risk:** {risk_label(global_risk(findings), lang)}",
            f"**Approximate average CVSS:** {average_cvss(findings)}",
            "",
            f"> {disclaimer_en}",
            "",
            "## Executive Summary",
            "",
            f"- Critical findings: {counts['Critica']}",
            f"- High findings: {counts['Alta']}",
            f"- Medium findings: {counts['Media']}",
            f"- Low findings: {counts['Baja']}",
            f"- Approximate average CVSS: {average_cvss(findings)}",
            f"- Business impact: {business_impact(findings, lang)}",
            "",
            "### Prioritization Model",
            "",
            "- P1: fix immediately.",
            "- P2: fix within 7 days.",
            "- P3: fix within 30 days.",
            "- P4: review in the next iteration.",
            "",
        ]
        ai_score, ai_level, ai_reasons = ai_agent_risk_score(findings)
        lines.extend(
            [
                "### AI Agent Risk Score",
                "",
                f"- AI agent risk: **{ai_score}/100 — {level_label(ai_level, lang)}**",
                f"- Factors: {', '.join(ai_reasons) if ai_reasons else 'No specific AI agent risk factors were detected.'}",
                "",
            ]
        )
        if comparison:
            lines.extend(
                [
                    "### Baseline Comparison",
                    "",
                    f"- Baseline: `{comparison['baseline']}`",
                    f"- New findings: {comparison['new']}",
                    f"- Fixed findings: {comparison['fixed']}",
                    f"- Persistent findings: {comparison['persistent']}",
                    "",
                ]
            )
        if ollama_assessments:
            verdict_counts: dict[str, int] = {}
            for assessment in ollama_assessments.values():
                verdict = assessment.get("verdict", "requiere_revision")
                verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
            model = next(iter(ollama_assessments.values())).get("model", "unknown")
            lines.extend(
                [
                    "### Local Ollama Triage",
                    "",
                    f"- Model: {model}",
                    f"- Likely real: {verdict_counts.get('probable_real', 0)}",
                    f"- Needs review: {verdict_counts.get('requiere_revision', 0)}",
                    f"- Likely false positives: {verdict_counts.get('probable_falso_positivo', 0)}",
                    "",
                ]
            )
        validation_points = manual_validation_points(findings)
        reviews = review_counts(findings, review_records)
        lines.extend(
            [
                "### Persistent Human Review",
                "",
                f"- Pending: {reviews['pending']}",
                f"- Manually confirmed: {reviews['confirmed']}",
                f"- False positives: {reviews['false_positive']}",
                f"- Accepted risks: {reviews['accepted_risk']}",
                f"- Fixed: {reviews['fixed']}",
                f"- Revalidated: {reviews['revalidated']}",
                "",
            ]
        )
        if validation_points:
            lines.extend(["### Items Requiring Manual Validation", ""])
            for point in validation_points:
                lines.append(f"- {point}")
            lines.append("")
        lines.extend(["### Distribution by Category", ""])
        if categories:
            for category, count in categories.items():
                lines.append(f"- {category}: {count}")
        else:
            lines.append("- No affected categories.")
        lines.extend(["", "### Files with Most Findings", ""])
        ranked_files = top_files(findings)
        if ranked_files:
            for file, count in ranked_files:
                lines.append(f"- `{file}`: {count}")
        else:
            lines.append("- No affected files.")
        lines.extend(["", "### Priorities", ""])
        priority_findings = [f for f in findings if f.severity in {"Critica", "Alta"}][:10]
        if priority_findings:
            for finding in priority_findings:
                lines.append(
                    f"- **{severity_label(finding.severity, lang)}** - {finding.title} in `{finding.file}:{finding.line}`"
                )
        else:
            lines.append("- No critical or high findings were identified with the current rules.")
        lines.extend(["", "## Technical Report", ""])
        if not findings:
            lines.extend(
                [
                    "No findings were detected with the current rule set.",
                    "",
                    "This does not guarantee the absence of vulnerabilities; it only means known patterns were not identified in this automated scan.",
                ]
            )
            return "\n".join(lines) + "\n"
        for index, finding in enumerate(findings, start=1):
            review = review_for_finding(finding, review_records)
            lines.extend(
                [
                    f"### {index}. {finding.title}",
                    "",
                    f"- **ID:** {finding.rule_id}",
                    f"- **Severity:** {severity_label(finding.severity, lang)}",
                    f"- **Approximate CVSS:** {finding.cvss}",
                    f"- **Confidence:** {finding.confidence}",
                    f"- **Impact:** {impact_for(finding)}",
                    f"- **Likelihood:** {likelihood_for(finding)}",
                    f"- **Priority:** {priority_for(finding)}",
                    f"- **Remediation effort:** {finding.remediation_effort}",
                    f"- **Suggested SLA:** {remediation_sla(finding)}",
                    f"- **Category:** {finding.category}",
                    f"- **File:** `{finding.file}:{finding.line}`",
                    f"- **Fingerprint:** `{finding.fingerprint}`",
                    f"- **Evidence:** `{finding.evidence}`",
                    f"- **Human review:** {review_status_label(review['status'], lang)}",
                    "",
                ]
            )
            assessment = (ollama_assessments or {}).get(finding_key(finding))
            if assessment:
                lines.extend(
                    [
                        "**Ollama triage:**",
                        "",
                        f"- **Verdict:** {assessment.get('verdict', 'requiere_revision')}",
                        f"- **Confidence:** {assessment.get('confidence', 'Baja')}",
                        f"- **Rationale:** {assessment.get('rationale', '')}",
                        f"- **Human validation:** {assessment.get('auditor_validation', '')}",
                        "",
                    ]
                )
            lines.extend(related_findings_markdown_en(finding))
            lines.extend(
                [
                    "**Context:**",
                    "",
                    "```",
                    finding.context,
                    "```",
                    "",
                    f"**Description:** {finding.description}",
                    "",
                    f"**Why this is dangerous:** {finding.why_dangerous}",
                    "",
                    f"**Conceptual exploitation:** {finding.exploit_concept}",
                    "",
                    f"**How to fix:** {finding.recommendation}",
                    "",
                    "**Secure code example:**",
                    "",
                    "```",
                    finding.secure_example,
                    "```",
                    "",
                    f"**Reference:** {finding.reference}",
                    "",
                    "**Remediation checklist:**",
                    "",
                    "- [ ] Validate whether the finding applies in the real context.",
                    "- [ ] Fix the root cause, not only the isolated evidence.",
                    "- [ ] Add a preventive test or control.",
                    "- [ ] Review deployments, history, and affected secrets.",
                    "",
                ]
            )
        lines.extend(
            [
                "## Recommended Next Steps",
                "",
                "1. Manually validate critical and high findings.",
                "2. Prioritize fixes based on exposure, affected data, and exploitability.",
                "3. Run the scan again after remediation.",
                "4. Complete an expert review for business logic, architecture, and contextual risks.",
            ]
        )
        return "\n".join(lines) + "\n"

    lines = [
        "# Informe de análisis preliminar de seguridad",
        "",
        f"**Cliente:** {meta.client}",
        f"**Auditor:** {meta.auditor}",
        f"**Alcance:** {meta.scope}",
        f"**Versión del informe:** {meta.version}",
        f"**Stack declarado:** {STACKS.get(meta.stack, meta.stack)}",
        f"**Proyecto escaneado:** `{target}`",
        f"**SHA256 del proyecto:** `{project_sha or 'no calculado'}`",
        f"**Fecha:** {now}",
        f"**Perfil:** {profile}",
        f"**Reglas activas:** {len(rules_for_profile(profile))}",
        f"**Riesgo global:** {global_risk(findings)}",
        f"**CVSS medio aproximado:** {average_cvss(findings)}",
        "",
        f"> {disclaimer}",
        "",
        "## Resumen para dirección",
        "",
        f"- Hallazgos críticos: {counts['Critica']}",
        f"- Hallazgos altos: {counts['Alta']}",
        f"- Hallazgos medios: {counts['Media']}",
        f"- Hallazgos bajos: {counts['Baja']}",
        f"- CVSS medio aproximado: {average_cvss(findings)}",
        f"- Impacto de negocio: {business_impact(findings)}",
        "",
        "### Scoring profesional",
        "",
        "- P1: corregir inmediatamente.",
        "- P2: corregir en 7 días.",
        "- P3: corregir en 30 días.",
        "- P4: revisar en la próxima iteración.",
        "",
    ]

    ai_score, ai_level, ai_reasons = ai_agent_risk_score(findings)
    lines.extend(
        [
            "### AI Agent Risk Score",
            "",
            f"- Riesgo del agente IA: **{ai_score}/100 — {ai_level}**",
            f"- Factores: {', '.join(ai_reasons) if ai_reasons else 'No se detectaron factores específicos de agente IA.'}",
            "",
        ]
    )

    if comparison:
        lines.extend(
            [
                "### Comparativa contra baseline",
                "",
                f"- Baseline: `{comparison['baseline']}`",
                f"- Nuevos hallazgos: {comparison['new']}",
                f"- Hallazgos corregidos: {comparison['fixed']}",
                f"- Hallazgos persistentes: {comparison['persistent']}",
                "",
            ]
        )

    if ollama_assessments:
        verdict_counts: dict[str, int] = {}
        for assessment in ollama_assessments.values():
            verdict = assessment.get("verdict", "requiere_revision")
            verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
        model = next(iter(ollama_assessments.values())).get("model", "desconocido")
        lines.extend(
            [
                "### Triage local con Ollama",
                "",
                f"- Modelo usado: {model}",
                f"- Probables reales: {verdict_counts.get('probable_real', 0)}",
                f"- Requieren revisión: {verdict_counts.get('requiere_revision', 0)}",
                f"- Probables falsos positivos: {verdict_counts.get('probable_falso_positivo', 0)}",
                "",
            ]
        )

    validation_points = manual_validation_points(findings)
    reviews = review_counts(findings, review_records)
    lines.extend(
        [
            "### Validación humana persistente",
            "",
            f"- Pendientes: {reviews['pending']}",
            f"- Confirmados manualmente: {reviews['confirmed']}",
            f"- Falsos positivos: {reviews['false_positive']}",
            f"- Riesgos aceptados: {reviews['accepted_risk']}",
            f"- Corregidos: {reviews['fixed']}",
            f"- Revalidados: {reviews['revalidated']}",
            "",
        ]
    )
    if validation_points:
        lines.extend(["### Puntos que requieren validación manual", ""])
        for point in validation_points:
            lines.append(f"- {point}")
        lines.append("")

    lines.extend(
        [
        "### Distribución por categoría",
        "",
        ]
    )

    if categories:
        for category, count in categories.items():
            lines.append(f"- {category}: {count}")
    else:
        lines.append("- Sin categorías afectadas.")

    lines.extend(
        [
            "",
            "### Archivos con más hallazgos",
            "",
        ]
    )

    ranked_files = top_files(findings)
    if ranked_files:
        for file, count in ranked_files:
            lines.append(f"- `{file}`: {count}")
    else:
        lines.append("- Sin archivos afectados.")

    lines.extend(
        [
            "",
            "### Prioridades",
            "",
        ]
    )

    priority_findings = [f for f in findings if f.severity in {"Critica", "Alta"}][:10]
    if priority_findings:
        for finding in priority_findings:
            lines.append(
                f"- **{finding.severity}** - {finding.title} en `{finding.file}:{finding.line}`"
            )
    else:
        lines.append("- No hay hallazgos críticos o altos con las reglas actuales.")

    lines.extend(
        [
            "",
            "## Informe técnico",
            "",
        ]
    )

    if not findings:
        lines.extend(
            [
                "No se han detectado hallazgos con el conjunto de reglas actual.",
                "",
                "Esto no garantiza ausencia de vulnerabilidades; solo indica que no se han identificado patrones conocidos en este escaneo automático.",
            ]
        )
        return "\n".join(lines) + "\n"

    for index, finding in enumerate(findings, start=1):
        lines.extend(
            [
                f"### {index}. {finding.title}",
                "",
                f"- **ID:** {finding.rule_id}",
                f"- **Severidad:** {finding.severity}",
                f"- **CVSS aproximado:** {finding.cvss}",
                f"- **Confianza:** {finding.confidence}",
                f"- **Impacto:** {impact_for(finding)}",
                f"- **Probabilidad:** {likelihood_for(finding)}",
                f"- **Prioridad:** {priority_for(finding)}",
                f"- **Esfuerzo de corrección:** {finding.remediation_effort}",
                f"- **SLA sugerido:** {remediation_sla(finding)}",
                f"- **Categoría:** {finding.category}",
                f"- **Archivo:** `{finding.file}:{finding.line}`",
                f"- **Fingerprint:** `{finding.fingerprint}`",
                f"- **Evidencia:** `{finding.evidence}`",
                f"- **Validación humana:** {REVIEW_STATUSES[review_for_finding(finding, review_records)['status']]}",
                "",
            ]
        )
        assessment = (ollama_assessments or {}).get(finding_key(finding))
        if assessment:
            lines.extend(
                [
                    "**Triage Ollama:**",
                    "",
                    f"- **Veredicto:** {assessment.get('verdict', 'requiere_revision')}",
                    f"- **Confianza:** {assessment.get('confidence', 'Baja')}",
                    f"- **Razonamiento:** {assessment.get('rationale', '')}",
                    f"- **Validación humana:** {assessment.get('auditor_validation', '')}",
                    "",
                ]
            )
        lines.extend(related_findings_markdown(finding))
        lines.extend(
            [
                "**Contexto:**",
                "",
                "```",
                finding.context,
                "```",
                "",
                f"**Descripción:** {finding.description}",
                "",
                f"**Por qué es peligroso:** {finding.why_dangerous}",
                "",
                f"**Cómo explotarlo conceptualmente:** {finding.exploit_concept}",
                "",
                f"**Cómo corregirlo:** {finding.recommendation}",
                "",
                "**Ejemplo de código seguro:**",
                "",
                "```",
                finding.secure_example,
                "```",
                "",
                f"**Referencia:** {finding.reference}",
                "",
                "**Checklist de corrección:**",
                "",
                "- [ ] Validar si el hallazgo aplica en el contexto real.",
                "- [ ] Corregir la causa raíz, no solo la evidencia puntual.",
                "- [ ] Añadir prueba o control preventivo.",
                "- [ ] Revisar despliegues, historiales y secretos afectados.",
                "",
            ]
        )

    lines.extend(
        [
            "## Próximos pasos recomendados",
            "",
            "1. Validar manualmente los hallazgos críticos y altos.",
            "2. Priorizar correcciones según exposición, datos afectados y facilidad de explotación.",
            "3. Repetir el escaneo tras las correcciones.",
            "4. Completar una auditoría experta para riesgos de lógica de negocio, arquitectura y contexto.",
        ]
    )
    return "\n".join(lines) + "\n"


def badge_class(severity: str) -> str:
    return {
        "Critica": "critical",
        "Alta": "high",
        "Media": "medium",
        "Baja": "low",
    }[severity]


def render_html_en(
    findings: list[Finding],
    target: Path,
    profile: str,
    meta: ReportMeta,
    project_sha: str = "",
    comparison: dict | None = None,
    ollama_assessments: dict[str, dict] | None = None,
    review_records: dict[str, dict] | None = None,
) -> str:
    counts = severity_counts(findings)
    categories = category_counts(findings)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    risk = risk_label(global_risk(findings), "en")
    disclaimer = (
        "This automated assessment does not replace expert review. Findings must be "
        "validated by a specialist because false positives, false negatives, and contextual risks may exist."
    )
    category_rows = "\n".join(
        f"<tr><td>{html.escape(category)}</td><td>{count}</td></tr>"
        for category, count in categories.items()
    ) or "<tr><td>No affected categories</td><td>0</td></tr>"
    file_rows = "\n".join(
        f"<tr><td><code>{html.escape(file)}</code></td><td>{count}</td></tr>"
        for file, count in top_files(findings)
    ) or "<tr><td>No affected files</td><td>0</td></tr>"
    priority_items = "\n".join(
        (
            f"<li><span class='badge {badge_class(f.severity)}'>{html.escape(severity_label(f.severity, 'en'))}</span>"
            f"<strong>{html.escape(f.title)}</strong>"
            f"<span><code>{html.escape(f.file)}:{f.line}</code></span></li>"
        )
        for f in [finding for finding in findings if finding.severity in {"Critica", "Alta"}][:10]
    ) or "<li>No critical or high findings were identified with the current rules.</li>"
    ai_score, ai_level, ai_reasons = ai_agent_risk_score(findings)
    comparison_html = ""
    if comparison:
        comparison_html = f"""
    <section class="panel">
      <h2>Baseline Comparison</h2>
      <p><strong>New:</strong> {comparison['new']} · <strong>Fixed:</strong> {comparison['fixed']} · <strong>Persistent:</strong> {comparison['persistent']} · <strong>Status:</strong> {html.escape(comparison_status_label(comparison['status'], 'en'))}</p>
      <p><code>{html.escape(comparison['baseline'])}</code></p>
    </section>
"""
    review_summary = review_counts(findings, review_records)
    review_html = f"""
    <section class="panel">
      <h2>Persistent Human Review</h2>
      <p><strong>Pending:</strong> {review_summary['pending']} · <strong>Confirmed:</strong> {review_summary['confirmed']} · <strong>False positives:</strong> {review_summary['false_positive']} · <strong>Accepted risks:</strong> {review_summary['accepted_risk']} · <strong>Fixed:</strong> {review_summary['fixed']} · <strong>Revalidated:</strong> {review_summary['revalidated']}</p>
    </section>
"""
    ollama_html = ""
    if ollama_assessments:
        verdict_counts: dict[str, int] = {}
        for assessment in ollama_assessments.values():
            verdict = assessment.get("verdict", "requiere_revision")
            verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
        ollama_html = f"""
    <section class="panel">
      <h2>Local Ollama Triage</h2>
      <p><strong>Likely real:</strong> {verdict_counts.get('probable_real', 0)} · <strong>Needs review:</strong> {verdict_counts.get('requiere_revision', 0)} · <strong>Likely false positives:</strong> {verdict_counts.get('probable_falso_positivo', 0)}</p>
    </section>
"""
    manual_html = "".join(f"<li>{html.escape(point)}</li>" for point in manual_validation_points(findings))
    finding_cards = []
    for index, finding in enumerate(findings, start=1):
        assessment = (ollama_assessments or {}).get(finding_key(finding))
        review = review_for_finding(finding, review_records)
        finding_cards.append(
            f"""
      <article class="finding{' composite' if finding.rule_id.startswith('CMP-') else ''}">
        <div class="finding-head">
          <div>
            <p class="eyebrow">{html.escape(finding.rule_id)} · {html.escape(finding.category)}</p>
            <h3>{index}. {html.escape(finding.title)}</h3>
            <p><code>{html.escape(finding.file)}:{finding.line}</code> · fingerprint <code>{html.escape(finding.fingerprint)}</code></p>
          </div>
          <div class="scorebox">
            <span class="badge {badge_class(finding.severity)}">{html.escape(severity_label(finding.severity, 'en'))}</span>
            <strong>{finding.cvss}</strong>
            <span>Approx. CVSS</span>
          </div>
        </div>
        <div class="meta-grid">
          <div><span>Confidence</span><strong>{html.escape(finding.confidence)}</strong></div>
          <div><span>Effort</span><strong>{html.escape(finding.remediation_effort)}</strong></div>
          <div><span>Suggested SLA</span><strong>{html.escape(remediation_sla(finding))}</strong></div>
          <div><span>Human review</span><strong>{html.escape(review_status_label(review['status'], 'en'))}</strong></div>
        </div>
        {related_findings_html_en(finding)}
        <pre>{html.escape(finding.context)}</pre>
        {f"<div class='meta-grid'><div><span>Ollama</span><strong>{html.escape(assessment.get('verdict', 'requiere_revision'))}</strong></div><div><span>AI confidence</span><strong>{html.escape(assessment.get('confidence', 'Baja'))}</strong></div><div><span>Validation</span><strong>{html.escape(assessment.get('auditor_validation', 'Manual review required'))}</strong></div></div><p>{html.escape(assessment.get('rationale', ''))}</p>" if assessment else ""}
        <dl>
          <dt>Description</dt><dd>{html.escape(finding.description)}</dd>
          <dt>Why this is dangerous</dt><dd>{html.escape(finding.why_dangerous)}</dd>
          <dt>Conceptual exploitation</dt><dd>{html.escape(finding.exploit_concept)}</dd>
          <dt>Recommended fix</dt><dd>{html.escape(finding.recommendation)}</dd>
          <dt>Secure example</dt><dd><code>{html.escape(finding.secure_example)}</code></dd>
          <dt>Reference</dt><dd>{html.escape(finding.reference)}</dd>
        </dl>
      </article>
"""
        )
    findings_html = "\n".join(finding_cards) or "<p>No findings were detected with the current rule set.</p>"
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Preliminary Security Assessment</title>
  <style>
    :root {{ --ink:#18212f; --muted:#5b6472; --line:#d8dee8; --panel:#f7f9fc; --critical:#a31925; --high:#c2410c; --medium:#9a6700; --low:#176f4d; --brand:#0f766e; }}
    * {{ box-sizing:border-box; }} body {{ margin:0; font-family:Arial,sans-serif; line-height:1.55; color:var(--ink); background:#fff; }} main {{ max-width:1120px; margin:0 auto; padding:36px 28px 56px; }}
    header {{ border-bottom:1px solid var(--line); padding-bottom:24px; margin-bottom:28px; }} h1 {{ margin:0 0 10px; font-size:34px; line-height:1.1; }} h2 {{ margin:34px 0 14px; font-size:22px; }} h3 {{ margin:0; font-size:18px; }}
    p {{ margin:0 0 10px; }} code {{ background:#eef2f7; padding:2px 5px; border-radius:4px; }} pre {{ margin:16px 0; background:#101828; color:#f8fafc; padding:14px; border-radius:8px; overflow-x:auto; font-size:13px; }}
    table {{ width:100%; border-collapse:collapse; background:#fff; }} td,th {{ border-bottom:1px solid var(--line); padding:10px 8px; text-align:left; }} .subtitle {{ color:var(--muted); max-width:780px; }}
    .kpis {{ display:grid; grid-template-columns:repeat(5,minmax(0,1fr)); gap:12px; margin-top:24px; }} .kpi,.panel,.finding {{ border:1px solid var(--line); border-radius:8px; }} .kpi {{ padding:14px; background:var(--panel); }} .kpi span {{ display:block; color:var(--muted); font-size:12px; text-transform:uppercase; }} .kpi strong {{ display:block; margin-top:6px; font-size:24px; }}
    .notice {{ border-left:4px solid var(--brand); background:#eefdf9; padding:14px 16px; border-radius:6px; margin:22px 0; }} .grid {{ display:grid; grid-template-columns:1fr 1fr; gap:18px; }} .panel {{ padding:16px; background:#fff; }}
    .priority {{ list-style:none; padding:0; margin:0; }} .priority li {{ display:grid; grid-template-columns:86px 1fr auto; gap:12px; align-items:center; border-bottom:1px solid var(--line); padding:10px 0; }}
    .badge {{ display:inline-block; border-radius:999px; padding:4px 9px; color:#fff; font-size:12px; font-weight:700; text-align:center; }} .critical {{ background:var(--critical); }} .high {{ background:var(--high); }} .medium {{ background:var(--medium); }} .low {{ background:var(--low); }}
    .finding {{ padding:18px; margin:18px 0; page-break-inside:avoid; }} .finding.composite {{ border-color:var(--critical); box-shadow:0 0 0 2px rgba(163,25,37,.12), 0 0 24px rgba(163,25,37,.18); }} .finding-head {{ display:flex; justify-content:space-between; gap:18px; align-items:flex-start; }}
    .eyebrow {{ color:var(--brand); font-size:12px; font-weight:700; text-transform:uppercase; margin-bottom:4px; }} .scorebox {{ min-width:120px; text-align:right; }} .scorebox strong {{ display:block; font-size:28px; margin-top:8px; }} .scorebox span:last-child {{ color:var(--muted); font-size:12px; }}
    .meta-grid {{ display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:10px; margin-top:16px; }} .meta-grid div {{ background:var(--panel); border:1px solid var(--line); border-radius:6px; padding:10px; }} .meta-grid span {{ display:block; color:var(--muted); font-size:12px; }}
    .related-findings {{ border:1px solid #f2b8bd; background:#fff7f8; border-radius:8px; padding:12px; margin-top:16px; }} dl {{ display:grid; grid-template-columns:210px 1fr; gap:8px 18px; }} dt {{ font-weight:700; color:#263244; }} dd {{ margin:0; }}
    @media(max-width:820px) {{ .kpis,.grid,.meta-grid {{ grid-template-columns:1fr; }} .priority li {{ grid-template-columns:1fr; }} .finding-head {{ display:block; }} .scorebox {{ text-align:left; margin-top:12px; }} dl {{ grid-template-columns:1fr; }} }}
  </style>
</head>
<body>
  <main>
    <header>
      <p class="eyebrow">Pre-Auditor IA · local preliminary assessment</p>
      <h1>Preliminary Security Assessment Report</h1>
      <p class="subtitle">Local automated scan designed to detect risk patterns, prioritize evidence, and prepare expert validation.</p>
      <div class="kpis">
        <div class="kpi"><span>Overall risk</span><strong>{html.escape(risk)}</strong></div>
        <div class="kpi"><span>Critical</span><strong>{counts['Critica']}</strong></div>
        <div class="kpi"><span>High</span><strong>{counts['Alta']}</strong></div>
        <div class="kpi"><span>Total</span><strong>{len(findings)}</strong></div>
        <div class="kpi"><span>Avg. CVSS</span><strong>{average_cvss(findings)}</strong></div>
      </div>
    </header>
    <section class="notice">{html.escape(disclaimer)}</section>
    <section>
      <h2>Executive Summary</h2>
      <p><strong>Client:</strong> {html.escape(meta.client)} · <strong>Auditor:</strong> {html.escape(meta.auditor)}</p>
      <p><strong>Scope:</strong> {html.escape(meta.scope)} · <strong>Version:</strong> {html.escape(meta.version)} · <strong>Stack:</strong> {html.escape(stack_label(meta.stack, 'en'))}</p>
      <p><strong>Project:</strong> <code>{html.escape(str(target))}</code></p>
      <p><strong>Project SHA256:</strong> <code>{html.escape(project_sha or 'not calculated')}</code></p>
      <p><strong>Date:</strong> {html.escape(now)} · <strong>Profile:</strong> {html.escape(profile)} · <strong>Active rules:</strong> {len(rules_for_profile(profile))}</p>
      <p><strong>Business impact:</strong> {html.escape(business_impact(findings, 'en'))}</p>
    </section>
    <section class="panel"><h2>AI Agent Risk Score</h2><p><strong>{ai_score}/100 — {html.escape(level_label(ai_level, 'en'))}</strong></p><p>{html.escape(', '.join(ai_reasons) if ai_reasons else 'No specific AI agent risk factors were detected.')}</p></section>
    {comparison_html}
    {ollama_html}
    {review_html}
    <section class="panel"><h2>Items Requiring Manual Validation</h2><ul>{manual_html or '<li>Manually validate critical and high findings.</li>'}</ul></section>
    <section class="grid"><div class="panel"><h2>Distribution by Category</h2><table>{category_rows}</table></div><div class="panel"><h2>Files with Most Findings</h2><table>{file_rows}</table></div></section>
    <section><h2>Priorities</h2><ul class="priority">{priority_items}</ul></section>
    <section><h2>Technical Report</h2>{findings_html}</section>
    <section><h2>Recommended Next Steps</h2><ol><li>Manually validate critical and high findings.</li><li>Confirm real exploitability, exposure, and affected data.</li><li>Fix root causes and add preventive controls.</li><li>Run the scan again and close evidence through expert review.</li></ol></section>
  </main>
</body>
</html>
"""


def render_html(
    findings: list[Finding],
    target: Path,
    profile: str,
    meta: ReportMeta,
    project_sha: str = "",
    comparison: dict | None = None,
    ollama_assessments: dict[str, dict] | None = None,
    review_records: dict[str, dict] | None = None,
) -> str:
    if report_language(meta) == "en":
        return render_html_en(findings, target, profile, meta, project_sha, comparison, ollama_assessments, review_records)

    counts = severity_counts(findings)
    categories = category_counts(findings)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    risk = global_risk(findings)
    disclaimer = (
        "Esta auditoría automática no sustituye una revisión experta. "
        "Los hallazgos deben ser validados por un consultor especializado, "
        "ya que pueden existir falsos positivos, falsos negativos y riesgos contextuales "
        "no detectables automáticamente."
    )

    category_rows = "\n".join(
        f"<tr><td>{html.escape(category)}</td><td>{count}</td></tr>"
        for category, count in categories.items()
    ) or "<tr><td>Sin categorías afectadas</td><td>0</td></tr>"
    file_rows = "\n".join(
        f"<tr><td><code>{html.escape(file)}</code></td><td>{count}</td></tr>"
        for file, count in top_files(findings)
    ) or "<tr><td>Sin archivos afectados</td><td>0</td></tr>"
    priority_items = "\n".join(
        (
            f"<li><span class='badge {badge_class(f.severity)}'>{html.escape(f.severity)}</span>"
            f"<strong>{html.escape(f.title)}</strong>"
            f"<span><code>{html.escape(f.file)}:{f.line}</code></span></li>"
        )
        for f in [finding for finding in findings if finding.severity in {"Critica", "Alta"}][:10]
    ) or "<li>No hay hallazgos críticos o altos con las reglas actuales.</li>"
    ai_score, ai_level, ai_reasons = ai_agent_risk_score(findings)
    comparison_html = ""
    if comparison:
        comparison_html = f"""
    <section class="panel">
      <h2>Comparativa contra baseline</h2>
      <p><strong>Nuevos:</strong> {comparison['new']} · <strong>Corregidos:</strong> {comparison['fixed']} · <strong>Persistentes:</strong> {comparison['persistent']}</p>
      <p><code>{html.escape(comparison['baseline'])}</code></p>
    </section>
"""
    manual_html = "".join(f"<li>{html.escape(point)}</li>" for point in manual_validation_points(findings))
    review_summary = review_counts(findings, review_records)
    review_html = f"""
    <section class="panel">
      <h2>Validación humana persistente</h2>
      <p><strong>Pendientes:</strong> {review_summary['pending']} · <strong>Confirmados:</strong> {review_summary['confirmed']} · <strong>Falsos positivos:</strong> {review_summary['false_positive']} · <strong>Riesgos aceptados:</strong> {review_summary['accepted_risk']} · <strong>Corregidos:</strong> {review_summary['fixed']} · <strong>Revalidados:</strong> {review_summary['revalidated']}</p>
    </section>
"""
    ollama_html = ""
    if ollama_assessments:
        verdict_counts: dict[str, int] = {}
        for assessment in ollama_assessments.values():
            verdict = assessment.get("verdict", "requiere_revision")
            verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
        ollama_html = f"""
    <section class="panel">
      <h2>Triage local con Ollama</h2>
      <p><strong>Probables reales:</strong> {verdict_counts.get('probable_real', 0)} · <strong>Revisión:</strong> {verdict_counts.get('requiere_revision', 0)} · <strong>Probables falsos positivos:</strong> {verdict_counts.get('probable_falso_positivo', 0)}</p>
    </section>
"""

    finding_cards = []
    for index, finding in enumerate(findings, start=1):
        finding_cards.append(
            (lambda assessment: 
            f"""
      <article class="finding{' composite' if finding.rule_id.startswith('CMP-') else ''}">
        <div class="finding-head">
          <div>
            <p class="eyebrow">{html.escape(finding.rule_id)} · {html.escape(finding.category)}</p>
            <h3>{index}. {html.escape(finding.title)}</h3>
            <p><code>{html.escape(finding.file)}:{finding.line}</code> · fingerprint <code>{html.escape(finding.fingerprint)}</code></p>
          </div>
          <div class="scorebox">
            <span class="badge {badge_class(finding.severity)}">{html.escape(finding.severity)}</span>
            <strong>{finding.cvss}</strong>
            <span>CVSS aprox.</span>
          </div>
        </div>
        <div class="meta-grid">
          <div><span>Confianza</span><strong>{html.escape(finding.confidence)}</strong></div>
          <div><span>Esfuerzo</span><strong>{html.escape(finding.remediation_effort)}</strong></div>
          <div><span>SLA sugerido</span><strong>{html.escape(remediation_sla(finding))}</strong></div>
          <div><span>Validación humana</span><strong>{html.escape(REVIEW_STATUSES[review_for_finding(finding, review_records)['status']])}</strong></div>
        </div>
        {related_findings_html(finding)}
        <pre>{html.escape(finding.context)}</pre>
        {f"<div class='meta-grid'><div><span>Ollama</span><strong>{html.escape(assessment.get('verdict', 'requiere_revision'))}</strong></div><div><span>Confianza IA</span><strong>{html.escape(assessment.get('confidence', 'Baja'))}</strong></div><div><span>Validación</span><strong>{html.escape(assessment.get('auditor_validation', 'Revisar manualmente'))}</strong></div></div><p>{html.escape(assessment.get('rationale', ''))}</p>" if assessment else ""}
        <dl>
          <dt>Descripción</dt><dd>{html.escape(finding.description)}</dd>
          <dt>Por qué es peligroso</dt><dd>{html.escape(finding.why_dangerous)}</dd>
          <dt>Explotación conceptual</dt><dd>{html.escape(finding.exploit_concept)}</dd>
          <dt>Corrección recomendada</dt><dd>{html.escape(finding.recommendation)}</dd>
          <dt>Ejemplo seguro</dt><dd><code>{html.escape(finding.secure_example)}</code></dd>
          <dt>Referencia</dt><dd>{html.escape(finding.reference)}</dd>
        </dl>
      </article>
"""
            )((ollama_assessments or {}).get(finding_key(finding)))
        )
    findings_html = "\n".join(finding_cards) or "<p>No se han detectado hallazgos con el conjunto de reglas actual.</p>"

    return f"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Informe de análisis preliminar</title>
  <style>
    :root {{
      --ink: #18212f;
      --muted: #5b6472;
      --line: #d8dee8;
      --panel: #f7f9fc;
      --critical: #a31925;
      --high: #c2410c;
      --medium: #9a6700;
      --low: #176f4d;
      --brand: #0f766e;
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; font-family: Arial, sans-serif; line-height: 1.55; color: var(--ink); background: #ffffff; }}
    main {{ max-width: 1120px; margin: 0 auto; padding: 36px 28px 56px; }}
    header {{ border-bottom: 1px solid var(--line); padding-bottom: 24px; margin-bottom: 28px; }}
    h1 {{ margin: 0 0 10px; font-size: 34px; line-height: 1.1; letter-spacing: 0; }}
    h2 {{ margin: 34px 0 14px; font-size: 22px; }}
    h3 {{ margin: 0; font-size: 18px; }}
    p {{ margin: 0 0 10px; }}
    code {{ background: #eef2f7; padding: 2px 5px; border-radius: 4px; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }}
    pre {{ margin: 16px 0; background: #101828; color: #f8fafc; padding: 14px; border-radius: 8px; overflow-x: auto; font-size: 13px; }}
    table {{ width: 100%; border-collapse: collapse; background: #fff; }}
    td, th {{ border-bottom: 1px solid var(--line); padding: 10px 8px; text-align: left; }}
    .subtitle {{ color: var(--muted); max-width: 780px; }}
    .kpis {{ display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 12px; margin-top: 24px; }}
    .kpi {{ border: 1px solid var(--line); border-radius: 8px; padding: 14px; background: var(--panel); }}
    .kpi span {{ display: block; color: var(--muted); font-size: 12px; text-transform: uppercase; }}
    .kpi strong {{ display: block; margin-top: 6px; font-size: 24px; }}
    .notice {{ border-left: 4px solid var(--brand); background: #eefdf9; padding: 14px 16px; border-radius: 6px; margin: 22px 0; }}
    .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 18px; }}
    .panel {{ border: 1px solid var(--line); border-radius: 8px; padding: 16px; background: #fff; }}
    .priority {{ list-style: none; padding: 0; margin: 0; }}
    .priority li {{ display: grid; grid-template-columns: 86px 1fr auto; gap: 12px; align-items: center; border-bottom: 1px solid var(--line); padding: 10px 0; }}
    .badge {{ display: inline-block; border-radius: 999px; padding: 4px 9px; color: #fff; font-size: 12px; font-weight: 700; text-align: center; }}
    .critical {{ background: var(--critical); }}
    .high {{ background: var(--high); }}
    .medium {{ background: var(--medium); }}
    .low {{ background: var(--low); }}
    .finding {{ border: 1px solid var(--line); border-radius: 8px; padding: 18px; margin: 18px 0; page-break-inside: avoid; }}
    .finding.composite {{ border-color: var(--critical); box-shadow: 0 0 0 2px rgba(163,25,37,.12), 0 0 24px rgba(163,25,37,.18); }}
    .finding-head {{ display: flex; justify-content: space-between; gap: 18px; align-items: flex-start; }}
    .eyebrow {{ color: var(--brand); font-size: 12px; font-weight: 700; text-transform: uppercase; margin-bottom: 4px; }}
    .scorebox {{ min-width: 120px; text-align: right; }}
    .scorebox strong {{ display: block; font-size: 28px; margin-top: 8px; }}
    .scorebox span:last-child {{ color: var(--muted); font-size: 12px; }}
    .meta-grid {{ display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; margin-top: 16px; }}
    .meta-grid div {{ background: var(--panel); border: 1px solid var(--line); border-radius: 6px; padding: 10px; }}
    .meta-grid span {{ display: block; color: var(--muted); font-size: 12px; }}
    .related-findings {{ border: 1px solid #f2b8bd; background: #fff7f8; border-radius: 8px; padding: 12px; margin-top: 16px; }}
    .related-findings table {{ margin-top: 8px; }}
    dl {{ display: grid; grid-template-columns: 210px 1fr; gap: 8px 18px; }}
    dt {{ font-weight: 700; color: #263244; }}
    dd {{ margin: 0; }}
    @media print {{
      main {{ max-width: none; padding: 18mm; }}
      .finding {{ break-inside: avoid; }}
    }}
    @media (max-width: 820px) {{
      .kpis, .grid, .meta-grid {{ grid-template-columns: 1fr; }}
      .priority li {{ grid-template-columns: 1fr; }}
      .finding-head {{ display: block; }}
      .scorebox {{ text-align: left; margin-top: 12px; }}
      dl {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body>
  <main>
    <header>
      <p class="eyebrow">Pre-Auditor IA · análisis preliminar local</p>
      <h1>Informe de análisis preliminar de seguridad</h1>
      <p class="subtitle">Escaneo automático local orientado a detectar patrones de riesgo, priorizar evidencias y preparar una revisión experta.</p>
      <div class="kpis">
        <div class="kpi"><span>Riesgo global</span><strong>{html.escape(risk)}</strong></div>
        <div class="kpi"><span>Críticos</span><strong>{counts['Critica']}</strong></div>
        <div class="kpi"><span>Altos</span><strong>{counts['Alta']}</strong></div>
        <div class="kpi"><span>Total</span><strong>{len(findings)}</strong></div>
        <div class="kpi"><span>CVSS medio</span><strong>{average_cvss(findings)}</strong></div>
      </div>
    </header>

    <section class="notice">{html.escape(disclaimer)}</section>

    <section>
      <h2>Resumen ejecutivo</h2>
      <p><strong>Cliente:</strong> {html.escape(meta.client)} · <strong>Auditor:</strong> {html.escape(meta.auditor)}</p>
      <p><strong>Alcance:</strong> {html.escape(meta.scope)} · <strong>Versión:</strong> {html.escape(meta.version)} · <strong>Stack:</strong> {html.escape(STACKS.get(meta.stack, meta.stack))}</p>
      <p><strong>Proyecto:</strong> <code>{html.escape(str(target))}</code></p>
      <p><strong>SHA256 del proyecto:</strong> <code>{html.escape(project_sha or 'no calculado')}</code></p>
      <p><strong>Fecha:</strong> {html.escape(now)} · <strong>Perfil:</strong> {html.escape(profile)} · <strong>Reglas activas:</strong> {len(rules_for_profile(profile))}</p>
      <p><strong>Impacto de negocio:</strong> {html.escape(business_impact(findings))}</p>
    </section>
    <section class="panel">
      <h2>AI Agent Risk Score</h2>
      <p><strong>{ai_score}/100 — {html.escape(ai_level)}</strong></p>
      <p>{html.escape(', '.join(ai_reasons) if ai_reasons else 'No se detectaron factores específicos de agente IA.')}</p>
    </section>
    {comparison_html}
    {ollama_html}
    {review_html}
    <section class="panel">
      <h2>Puntos que requieren validación manual</h2>
      <ul>{manual_html or '<li>Validar manualmente hallazgos críticos y altos.</li>'}</ul>
    </section>

    <section class="grid">
      <div class="panel">
        <h2>Distribución por categoría</h2>
        <table>{category_rows}</table>
      </div>
      <div class="panel">
        <h2>Archivos con más hallazgos</h2>
        <table>{file_rows}</table>
      </div>
    </section>

    <section>
      <h2>Prioridades de validación</h2>
      <ul class="priority">{priority_items}</ul>
    </section>

    <section>
      <h2>Informe técnico</h2>
      {findings_html}
    </section>

    <section>
      <h2>Próximos pasos recomendados</h2>
      <ol>
        <li>Validar manualmente hallazgos críticos y altos.</li>
        <li>Confirmar explotabilidad real, exposición y datos afectados.</li>
        <li>Corregir causas raíz y añadir controles preventivos.</li>
        <li>Repetir escaneo y cerrar evidencias con una revisión experta.</li>
      </ol>
    </section>
  </main>
</body>
</html>
"""


def render_dashboard(
    findings: list[Finding],
    target: Path,
    profile: str,
    meta: ReportMeta,
    project_sha: str = "",
    comparison: dict | None = None,
    ollama_assessments: dict[str, dict] | None = None,
    review_records: dict[str, dict] | None = None,
) -> str:
    lang = report_language(meta)
    dashboard_text = {
        "html_lang": "en" if lang == "en" else "es",
        "risk": "Risk" if lang == "en" else "Riesgo",
        "critical": "Critical" if lang == "en" else "Críticos",
        "high": "High" if lang == "en" else "Altos",
        "total": "Total",
        "severity_distribution": "Distribution by Severity" if lang == "en" else "Distribución por severidad",
        "composite_findings": "Composite Findings" if lang == "en" else "Hallazgos compuestos",
        "top_categories": "Top Categories" if lang == "en" else "Categorías principales",
        "risky_files": "Files with Most Risk" if lang == "en" else "Archivos con más riesgo",
        "search_placeholder": "Search by file, rule, description..." if lang == "en" else "Buscar por archivo, regla, descripción...",
        "all_severities": "All severities" if lang == "en" else "Todas las severidades",
        "all_categories": "All categories" if lang == "en" else "Todas las categorías",
        "clear": "Clear" if lang == "en" else "Limpiar",
        "categories": "Categories" if lang == "en" else "Categorías",
        "before_after": "Before/after comparison" if lang == "en" else "Comparativa antes/después",
        "before": "Before" if lang == "en" else "Antes",
        "now": "Now" if lang == "en" else "Ahora",
        "new": "New" if lang == "en" else "Nuevos",
        "fixed": "Fixed" if lang == "en" else "Corregidos",
        "improvement": "Improvement" if lang == "en" else "Mejora",
        "composite_label": "Composite finding" if lang == "en" else "Hallazgo compuesto",
        "composite_text": "severity comes from the combination of related evidence." if lang == "en" else "la severidad procede de la combinación de varias evidencias relacionadas.",
        "rule": "Rule" if lang == "en" else "Regla",
        "location": "Location" if lang == "en" else "Ubicación",
        "evidence": "Evidence" if lang == "en" else "Evidencia",
        "no_composites": "No composite risk chains detected." if lang == "en" else "No se han detectado cadenas de riesgo compuestas.",
        "visible_findings": "visible findings" if lang == "en" else "hallazgos visibles",
        "human_review": "Human review" if lang == "en" else "Validación humana",
        "risk_detail": "Risk" if lang == "en" else "Riesgo",
        "fix": "Fix" if lang == "en" else "Corrección",
    }
    ai_score, ai_level, ai_reasons = ai_agent_risk_score(findings)
    payload = json.dumps(
        {
            "target": str(target),
            "profile": profile,
            "meta": asdict(meta),
            "language": lang,
            "severity_labels": SEVERITY_LABELS_EN if lang == "en" else {"Critica": "Crítica", "Alta": "Alta", "Media": "Media", "Baja": "Baja"},
            "review_status_labels": REVIEW_STATUS_LABELS_EN if lang == "en" else REVIEW_STATUSES,
            "risk_label": risk_label(global_risk(findings), lang),
            "comparison_status_label": comparison_status_label(comparison["status"], lang) if comparison else None,
            "project_sha256": project_sha,
            "comparison": comparison,
            "ollama_triage": ollama_assessments or {},
            "review_counts": review_counts(findings, review_records),
            "ai_agent_risk": {"score": ai_score, "level": level_label(ai_level, lang), "raw_level": ai_level, "reasons": ai_reasons},
            "risk": global_risk(findings),
            "counts": severity_counts(findings),
            "categories": category_counts(findings),
            "average_cvss": average_cvss(findings),
            "findings": [finding_payload(finding, review_records) for finding in findings],
        },
        ensure_ascii=False,
    )
    safe_payload = payload.replace("</", "<\\/")
    return f"""<!doctype html>
<html lang="{dashboard_text['html_lang']}">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Pre-Auditor IA Pro Dashboard</title>
  <style>
    :root {{ --ink:#172033; --muted:#657083; --line:#d9e0ea; --panel:#f7f9fc; --critical:#a31925; --high:#c2410c; --medium:#9a6700; --low:#176f4d; --brand:#0f766e; }}
    * {{ box-sizing: border-box; }}
    body {{ margin:0; font-family: Arial, sans-serif; color:var(--ink); background:#f4f7fb; }}
    header {{ background:#fff; border-bottom:1px solid var(--line); padding:24px; position:sticky; top:0; z-index:2; }}
    main {{ max-width:1180px; margin:0 auto; padding:24px; }}
    h1 {{ margin:0 0 8px; font-size:28px; }}
    h2 {{ margin:0 0 14px; font-size:18px; }}
    p {{ margin:0 0 8px; color:var(--muted); }}
    .top {{ max-width:1180px; margin:0 auto; }}
    .kpis {{ display:grid; grid-template-columns:repeat(5,minmax(0,1fr)); gap:12px; margin-top:18px; }}
    .kpi, .panel, .finding {{ background:#fff; border:1px solid var(--line); border-radius:8px; }}
    .kpi {{ padding:14px; }}
    .kpi span {{ color:var(--muted); font-size:12px; text-transform:uppercase; display:block; }}
    .kpi strong {{ font-size:24px; display:block; margin-top:4px; }}
    .toolbar {{ display:grid; grid-template-columns:1.2fr 180px 180px 120px; gap:10px; margin:0 0 18px; }}
    input, select, button {{ border:1px solid var(--line); border-radius:6px; padding:10px; font-size:14px; background:#fff; color:var(--ink); }}
    button {{ cursor:pointer; }}
    button.active {{ background:var(--brand); color:#fff; border-color:var(--brand); }}
    .layout {{ display:grid; grid-template-columns:280px 1fr; gap:18px; }}
    .panel {{ padding:16px; }}
    .insights {{ display:grid; grid-template-columns:1fr 1fr; gap:14px; margin:0 0 18px; }}
    .bar-row {{ display:grid; grid-template-columns:96px 1fr 42px; gap:8px; align-items:center; margin:9px 0; }}
    .bar-track {{ height:10px; background:#edf2f7; border-radius:999px; overflow:hidden; }}
    .bar-fill {{ height:100%; background:var(--brand); border-radius:999px; }}
    .bar-fill.Critica {{ background:var(--critical); }} .bar-fill.Alta {{ background:var(--high); }} .bar-fill.Media {{ background:var(--medium); }} .bar-fill.Baja {{ background:var(--low); }}
    .compound-list {{ display:grid; gap:8px; }}
    .compound-item {{ border:1px solid #f2b8bd; border-left:4px solid var(--critical); border-radius:8px; padding:10px; background:#fff7f8; }}
    .comparison-panel {{ margin:0 0 18px; padding:18px; background:#ecfdf5; border:1px solid #99f6e4; border-radius:8px; }}
    .comparison-panel.regresion {{ background:#fef2f2; border-color:#fecaca; }}
    .comparison-panel.estable {{ background:#f8fafc; border-color:var(--line); }}
    .comparison-grid {{ display:grid; grid-template-columns:repeat(5,1fr); gap:10px; margin-top:10px; }}
    .comparison-grid div {{ background:#fff; border:1px solid var(--line); border-radius:8px; padding:12px; }}
    .comparison-grid span {{ color:var(--muted); font-size:12px; text-transform:uppercase; display:block; }}
    .comparison-grid strong {{ display:block; margin-top:4px; font-size:22px; }}
    .finding {{ padding:16px; margin-bottom:14px; }}
    .finding.composite {{ border-color:#a31925; box-shadow:0 0 0 2px rgba(163,25,37,.18), 0 0 24px rgba(163,25,37,.22); }}
    .finding-head {{ display:flex; justify-content:space-between; gap:12px; }}
    .badge {{ display:inline-block; border-radius:999px; padding:4px 9px; color:#fff; font-size:12px; font-weight:700; }}
    .Critica {{ background:var(--critical); }} .Alta {{ background:var(--high); }} .Media {{ background:var(--medium); }} .Baja {{ background:var(--low); }}
    code {{ background:#eef2f7; padding:2px 5px; border-radius:4px; }}
    .composite-tag {{ display:inline-block; margin-left:8px; border:1px solid #a31925; color:#a31925; border-radius:999px; padding:3px 8px; font-size:11px; font-weight:700; text-transform:uppercase; }}
    pre {{ background:#101828; color:#f8fafc; padding:12px; border-radius:8px; overflow:auto; font-size:12px; }}
    .muted {{ color:var(--muted); }}
    .category-row {{ display:flex; justify-content:space-between; border-bottom:1px solid var(--line); padding:8px 0; }}
    .related-findings {{ border:1px solid #f2b8bd; background:#fff7f8; border-radius:8px; padding:12px; margin:12px 0; }}
    .related-findings table {{ width:100%; border-collapse:collapse; background:#fff; }}
    .related-findings td, .related-findings th {{ border-bottom:1px solid var(--line); padding:8px; text-align:left; }}
    @media (max-width:900px) {{ .kpis,.toolbar,.layout,.insights,.comparison-grid {{ grid-template-columns:1fr; }} header {{ position:static; }} }}
  </style>
</head>
<body>
  <header>
    <div class="top">
      <h1>Pre-Auditor IA Pro</h1>
      <p><strong id="client"></strong> · <span id="scope"></span></p>
      <p><code id="target"></code></p>
      <div class="kpis">
        <div class="kpi"><span>{dashboard_text['risk']}</span><strong id="risk"></strong></div>
        <div class="kpi"><span>{dashboard_text['critical']}</span><strong id="crit"></strong></div>
        <div class="kpi"><span>{dashboard_text['high']}</span><strong id="high"></strong></div>
        <div class="kpi"><span>{dashboard_text['total']}</span><strong id="total"></strong></div>
        <div class="kpi"><span>AI Agent</span><strong id="ai"></strong></div>
      </div>
    </div>
  </header>
  <main>
    <section id="comparison-panel"></section>
    <div class="insights">
      <section class="panel">
        <h2>{dashboard_text['severity_distribution']}</h2>
        <div id="severity-chart"></div>
      </section>
      <section class="panel">
        <h2>{dashboard_text['composite_findings']}</h2>
        <div id="compound-list"></div>
      </section>
      <section class="panel">
        <h2>{dashboard_text['top_categories']}</h2>
        <div id="category-chart"></div>
      </section>
      <section class="panel">
        <h2>{dashboard_text['risky_files']}</h2>
        <div id="file-chart"></div>
      </section>
    </div>
    <div class="toolbar">
      <input id="search" placeholder="{dashboard_text['search_placeholder']}">
      <select id="severity"><option value="">{dashboard_text['all_severities']}</option></select>
      <select id="category"><option value="">{dashboard_text['all_categories']}</option></select>
      <button id="reset">{dashboard_text['clear']}</button>
    </div>
    <div class="layout">
      <aside class="panel">
        <h2>{dashboard_text['categories']}</h2>
        <div id="categories"></div>
      </aside>
      <section>
        <div id="result-count" class="muted"></div>
        <div id="findings"></div>
      </section>
    </div>
  </main>
  <script id="data" type="application/json">{safe_payload}</script>
  <script>
    const data = JSON.parse(document.getElementById('data').textContent);
    const findings = data.findings;
    const severityOrder = ['Critica','Alta','Media','Baja'];
    const severityLabel = value => data.severity_labels[value] || value;
    const reviewStatusLabel = value => data.review_status_labels[value] || value;
    const esc = value => String(value ?? '').replace(/[&<>"']/g, ch => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[ch]));
    document.getElementById('client').textContent = data.meta.client;
    document.getElementById('scope').textContent = data.meta.scope;
    document.getElementById('target').textContent = data.target;
    document.getElementById('risk').textContent = data.risk_label || data.risk;
    document.getElementById('crit').textContent = data.counts.Critica;
    document.getElementById('high').textContent = data.counts.Alta;
    document.getElementById('total').textContent = findings.length;
    document.getElementById('ai').textContent = `${{data.ai_agent_risk.score}}/100`;
    if (data.comparison) {{
      document.getElementById('comparison-panel').innerHTML = `
        <div class="comparison-panel ${{esc(data.comparison.status)}}">
          <h2>{dashboard_text['before_after']} · ${{esc(data.comparison_status_label || data.comparison.status)}}</h2>
          <p><code>${{esc(data.comparison.baseline)}}</code></p>
          <div class="comparison-grid">
            <div><span>{dashboard_text['before']}</span><strong>${{data.comparison.previous_total}}</strong></div>
            <div><span>{dashboard_text['now']}</span><strong>${{data.comparison.current_total}}</strong></div>
            <div><span>{dashboard_text['new']}</span><strong>${{data.comparison.new}}</strong></div>
            <div><span>{dashboard_text['fixed']}</span><strong>${{data.comparison.fixed}}</strong></div>
            <div><span>{dashboard_text['improvement']}</span><strong>${{data.comparison.improvement_percent}}%</strong></div>
          </div>
        </div>
      `;
    }}
    function barRows(entries, maxValue, classByLabel = false) {{
      return entries.map(([label, value]) => `
        <div class="bar-row">
          <span>${{esc(label)}}</span>
          <div class="bar-track"><div class="bar-fill ${{classByLabel ? esc(label) : ''}}" style="width:${{maxValue ? Math.max(4, value / maxValue * 100) : 0}}%"></div></div>
          <strong>${{value}}</strong>
        </div>
      `).join('');
    }}
    function relatedRows(f) {{
      if (!f.related_findings || !f.related_findings.length) return '';
      return `
        <div class="related-findings">
          <p><strong>{dashboard_text['composite_label']}:</strong> {dashboard_text['composite_text']}</p>
          <table>
            <thead><tr><th>{dashboard_text['rule']}</th><th>{dashboard_text['location']}</th><th>{dashboard_text['evidence']}</th></tr></thead>
            <tbody>
              ${{f.related_findings.map(r => `<tr><td><code>${{esc(r.rule_id)}}</code></td><td><code>${{esc(r.file)}}:${{esc(r.line)}}</code></td><td><code>${{esc(r.evidence)}}</code></td></tr>`).join('')}}
            </tbody>
          </table>
        </div>
      `;
    }}
    const severityEntries = severityOrder.map(s => [s, data.counts[s] || 0]);
    document.getElementById('severity-chart').innerHTML = barRows(severityEntries, Math.max(...severityEntries.map(([,v]) => v), 1), true);
    const categoryEntries = Object.entries(data.categories).sort((a,b) => b[1] - a[1]).slice(0, 6);
    document.getElementById('category-chart').innerHTML = barRows(categoryEntries, Math.max(...categoryEntries.map(([,v]) => v), 1));
    const fileCounts = findings.reduce((acc, f) => {{ acc[f.file] = (acc[f.file] || 0) + 1; return acc; }}, {{}});
    const fileEntries = Object.entries(fileCounts).sort((a,b) => b[1] - a[1]).slice(0, 6);
    document.getElementById('file-chart').innerHTML = barRows(fileEntries, Math.max(...fileEntries.map(([,v]) => v), 1));
    const compounds = findings.filter(f => f.rule_id.startsWith('CMP-'));
    document.getElementById('compound-list').innerHTML = compounds.length ? compounds.map(f => `
      <div class="compound-item">
        <strong>${{esc(f.rule_id)}} · ${{esc(f.title)}}</strong>
        <p><code>${{esc(f.file)}}:${{esc(f.line)}}</code> · ${{esc(severityLabel(f.severity))}} · CVSS ${{esc(f.cvss)}}</p>
      </div>
    `).join('') : '<p>{dashboard_text['no_composites']}</p>';
    const sev = document.getElementById('severity');
    severityOrder.forEach(s => sev.append(new Option(severityLabel(s), s)));
    const cat = document.getElementById('category');
    Object.keys(data.categories).sort().forEach(c => cat.append(new Option(c, c)));
    document.getElementById('categories').innerHTML = Object.entries(data.categories).sort().map(([k,v]) => `<div class="category-row"><span>${{k}}</span><strong>${{v}}</strong></div>`).join('');
    function render() {{
      const q = document.getElementById('search').value.toLowerCase();
      const s = sev.value;
      const c = cat.value;
      const filtered = findings.filter(f => (!s || f.severity === s) && (!c || f.category === c) && (!q || JSON.stringify(f).toLowerCase().includes(q)));
      document.getElementById('result-count').textContent = `${{filtered.length}} {dashboard_text['visible_findings']}`;
      document.getElementById('findings').innerHTML = filtered.map(f => `
        <article class="finding ${{f.rule_id.startsWith('CMP-') ? 'composite' : ''}}">
          <div class="finding-head">
            <div>
              <span class="badge ${{esc(f.severity)}}">${{esc(severityLabel(f.severity))}}</span>
              ${{f.rule_id.startsWith('CMP-') ? '<span class="composite-tag">{dashboard_text['composite_label']}</span>' : ''}}
              <h2>${{esc(f.rule_id)}} · ${{esc(f.title)}}</h2>
              <p><code>${{esc(f.file)}}:${{esc(f.line)}}</code> · CVSS ${{esc(f.cvss)}} · ${{esc(f.category)}} · fingerprint <code>${{esc(f.fingerprint)}}</code></p>
            </div>
          </div>
          ${{relatedRows(f)}}
          <pre>${{esc(f.context)}}</pre>
          <p><strong>{dashboard_text['human_review']}:</strong> ${{esc(reviewStatusLabel(f.review?.status || 'pending'))}} ${{f.review?.reviewed_by ? '· ' + esc(f.review.reviewed_by) : ''}}</p>
          ${{data.ollama_triage[`${{f.rule_id}}:${{f.file}}:${{f.line}}:${{f.fingerprint}}`] ? `<p><strong>Ollama:</strong> ${{esc(data.ollama_triage[`${{f.rule_id}}:${{f.file}}:${{f.line}}:${{f.fingerprint}}`].verdict)}} · ${{esc(data.ollama_triage[`${{f.rule_id}}:${{f.file}}:${{f.line}}:${{f.fingerprint}}`].confidence)}}. ${{esc(data.ollama_triage[`${{f.rule_id}}:${{f.file}}:${{f.line}}:${{f.fingerprint}}`].rationale)}}</p>` : ''}}
          <p><strong>{dashboard_text['risk_detail']}:</strong> ${{esc(f.why_dangerous)}}</p>
          <p><strong>{dashboard_text['fix']}:</strong> ${{esc(f.recommendation)}}</p>
        </article>`).join('');
    }}
    ['search','severity','category'].forEach(id => document.getElementById(id).addEventListener('input', render));
    document.getElementById('reset').addEventListener('click', () => {{ document.getElementById('search').value=''; sev.value=''; cat.value=''; render(); }});
    render();
  </script>
</body>
</html>
"""


def write_pdf_report(
    findings: list[Finding],
    target: Path,
    profile: str,
    meta: ReportMeta,
    pdf_output: Path,
    project_sha: str = "",
    comparison: dict | None = None,
    ollama_assessments: dict[str, dict] | None = None,
    review_records: dict[str, dict] | None = None,
) -> bool:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except Exception:
        return False

    pdf_output.parent.mkdir(parents=True, exist_ok=True)
    styles = getSampleStyleSheet()
    story = []
    counts = severity_counts(findings)
    lang = report_language(meta)

    def p(text: str, style: str = "BodyText") -> Paragraph:
        return Paragraph(html.escape(str(text)).replace("\n", "<br/>"), styles[style])

    story.append(p("Preliminary Security Assessment Report" if lang == "en" else "Informe de análisis preliminar de seguridad", "Title"))
    story.append(p(f"{'Client' if lang == 'en' else 'Cliente'}: {meta.client}", "Heading2"))
    story.append(p(f"{'Auditor' if lang == 'en' else 'Auditor'}: {meta.auditor}"))
    story.append(p(f"{'Scope' if lang == 'en' else 'Alcance'}: {meta.scope}"))
    story.append(p(f"{'Version' if lang == 'en' else 'Versión'}: {meta.version}"))
    story.append(p(f"Stack: {stack_label(meta.stack, lang)}"))
    story.append(p(f"{'Project' if lang == 'en' else 'Proyecto'}: {target}"))
    story.append(p(f"{'Project SHA256' if lang == 'en' else 'SHA256 proyecto'}: {project_sha or ('not calculated' if lang == 'en' else 'no calculado')}"))
    story.append(p(f"{'Profile' if lang == 'en' else 'Perfil'}: {profile} · {'Active rules' if lang == 'en' else 'Reglas activas'}: {len(rules_for_profile(profile))}"))
    story.append(Spacer(1, 14))

    summary = Table(
        [
            (["Overall risk", "Critical", "High", "Medium", "Avg. CVSS"] if lang == "en" else ["Riesgo global", "Críticos", "Altos", "Medios", "CVSS medio"]),
            [risk_label(global_risk(findings), lang), counts["Critica"], counts["Alta"], counts["Media"], average_cvss(findings)],
        ],
        hAlign="LEFT",
    )
    summary.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#172033")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d9e0ea")),
                ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f7f9fc")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("PADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    story.append(summary)
    story.append(Spacer(1, 14))
    story.append(p(
        "This automated assessment does not replace expert review. Findings must be validated by a specialist."
        if lang == "en"
        else "Esta auditoría automática no sustituye una revisión experta. Los hallazgos deben ser validados por un consultor especializado.",
        "Italic",
    ))
    story.append(Spacer(1, 18))
    ai_score, ai_level, ai_reasons = ai_agent_risk_score(findings)
    story.append(p("AI Agent Risk Score", "Heading1"))
    story.append(p(f"{ai_score}/100 — {level_label(ai_level, lang)}"))
    story.append(p(", ".join(ai_reasons) if ai_reasons else ("No specific AI agent risk factors were detected." if lang == "en" else "No se detectaron factores específicos de agente IA.")))
    story.append(Spacer(1, 12))
    if comparison:
        story.append(p("Baseline Comparison" if lang == "en" else "Comparativa contra baseline", "Heading1"))
        if lang == "en":
            story.append(p(f"New: {comparison['new']} · Fixed: {comparison['fixed']} · Persistent: {comparison['persistent']}"))
        else:
            story.append(p(f"Nuevos: {comparison['new']} · Corregidos: {comparison['fixed']} · Persistentes: {comparison['persistent']}"))
        story.append(Spacer(1, 12))
    reviews = review_counts(findings, review_records)
    story.append(p("Persistent Human Review" if lang == "en" else "Validación humana persistente", "Heading1"))
    story.append(
        p(
            (
                f"Pending: {reviews['pending']} · Confirmed: {reviews['confirmed']} · "
                f"False positives: {reviews['false_positive']} · Accepted risks: {reviews['accepted_risk']} · "
                f"Fixed: {reviews['fixed']} · Revalidated: {reviews['revalidated']}"
            )
            if lang == "en"
            else (
                f"Pendientes: {reviews['pending']} · Confirmados: {reviews['confirmed']} · "
                f"Falsos positivos: {reviews['false_positive']} · Riesgos aceptados: {reviews['accepted_risk']} · "
                f"Corregidos: {reviews['fixed']} · Revalidados: {reviews['revalidated']}"
            )
        )
    )
    story.append(Spacer(1, 12))
    if ollama_assessments:
        verdict_counts: dict[str, int] = {}
        for assessment in ollama_assessments.values():
            verdict = assessment.get("verdict", "requiere_revision")
            verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
        story.append(p("Local Ollama Triage" if lang == "en" else "Triage local con Ollama", "Heading1"))
        story.append(
            p(
                (
                    f"Likely real: {verdict_counts.get('probable_real', 0)} · "
                    f"Needs review: {verdict_counts.get('requiere_revision', 0)} · "
                    f"Likely false positives: {verdict_counts.get('probable_falso_positivo', 0)}"
                )
                if lang == "en"
                else (
                    f"Probables reales: {verdict_counts.get('probable_real', 0)} · "
                    f"Revisión: {verdict_counts.get('requiere_revision', 0)} · "
                    f"Probables falsos positivos: {verdict_counts.get('probable_falso_positivo', 0)}"
                )
            )
        )
        story.append(Spacer(1, 12))
    story.append(p("Validation Priorities" if lang == "en" else "Prioridades de validación", "Heading1"))

    priority_rows = [["Severity", "Finding", "Location", "CVSS"]] if lang == "en" else [["Severidad", "Hallazgo", "Ubicación", "CVSS"]]
    for finding in findings[:12]:
        priority_rows.append([severity_label(finding.severity, lang), finding.title, f"{finding.file}:{finding.line}", finding.cvss])
    priority_table = Table(priority_rows, colWidths=[58, 220, 170, 45], hAlign="LEFT")
    priority_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f766e")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d9e0ea")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("PADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.append(priority_table)
    story.append(Spacer(1, 18))
    story.append(p("Technical Detail" if lang == "en" else "Detalle técnico", "Heading1"))

    for finding in findings:
        story.append(p(f"{finding.rule_id} · {finding.title}", "Heading2"))
        if lang == "en":
            story.append(p(f"Severity: {severity_label(finding.severity, lang)} · CVSS: {finding.cvss} · Category: {finding.category} · Location: {finding.file}:{finding.line}"))
            story.append(p(f"Human review: {review_status_label(review_for_finding(finding, review_records)['status'], lang)}"))
        else:
            story.append(p(f"Severidad: {severity_label(finding.severity, lang)} · CVSS: {finding.cvss} · Categoría: {finding.category} · Ubicación: {finding.file}:{finding.line}"))
            story.append(p(f"Validación humana: {review_status_label(review_for_finding(finding, review_records)['status'], lang)}"))
        if finding.related_findings:
            story.append(p("Composite finding: severity comes from the combination of related evidence." if lang == "en" else "Hallazgo compuesto: la severidad procede de la combinación de varias evidencias relacionadas."))
            for item in finding.related_findings:
                story.append(
                    p(
                        f"- {item['rule_id']} en {item['file']}:{item['line']} · {item['evidence']}"
                    )
                )
        assessment = (ollama_assessments or {}).get(finding_key(finding))
        if assessment:
            story.append(
                p(
                    "Triage Ollama: "
                    f"{assessment.get('verdict', 'requiere_revision')} · "
                    f"{assessment.get('confidence', 'Baja')} · "
                    f"{assessment.get('rationale', '')}"
                )
            )
        story.append(p(f"{'Description' if lang == 'en' else 'Descripción'}: {finding.description}"))
        story.append(p(f"{'Risk' if lang == 'en' else 'Riesgo'}: {finding.why_dangerous}"))
        story.append(p(f"{'Fix' if lang == 'en' else 'Corrección'}: {finding.recommendation}"))
        story.append(p(f"{'Reference' if lang == 'en' else 'Referencia'}: {finding.reference}"))
        story.append(Spacer(1, 10))

    try:
        doc = SimpleDocTemplate(str(pdf_output), pagesize=A4, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
        doc.build(story)
        return True
    except Exception:
        return False


def write_report(
    markdown: str,
    output: Path,
    html_output: Path | None,
    findings: list[Finding],
    target: Path,
    profile: str,
    meta: ReportMeta,
    pdf_output: Path | None,
    dashboard_output: Path | None,
    project_sha: str = "",
    comparison: dict | None = None,
    ollama_assessments: dict[str, dict] | None = None,
    review_records: dict[str, dict] | None = None,
) -> bool:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(markdown, encoding="utf-8")
    html_content = render_html(findings, target, profile, meta, project_sha, comparison, ollama_assessments, review_records)
    if html_output:
        html_output.parent.mkdir(parents=True, exist_ok=True)
        html_output.write_text(html_content, encoding="utf-8")
    pdf_written = False
    if pdf_output:
        pdf_written = write_pdf_report(findings, target, profile, meta, pdf_output, project_sha, comparison, ollama_assessments, review_records)
    if dashboard_output:
        dashboard_output.parent.mkdir(parents=True, exist_ok=True)
        dashboard_output.write_text(render_dashboard(findings, target, profile, meta, project_sha, comparison, ollama_assessments, review_records), encoding="utf-8")
    return pdf_written


def write_json(
    findings: list[Finding],
    output: Path,
    profile: str,
    meta: ReportMeta,
    project_sha: str = "",
    comparison: dict | None = None,
    ollama_assessments: dict[str, dict] | None = None,
    review_records: dict[str, dict] | None = None,
) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "profile": profile,
        "meta": asdict(meta),
        "project_sha256": project_sha,
        "comparison": comparison,
        "ollama_triage": ollama_assessments or {},
        "review_counts": review_counts(findings, review_records),
        "ai_agent_risk": {
            "score": ai_agent_risk_score(findings)[0],
            "level": ai_agent_risk_score(findings)[1],
            "reasons": ai_agent_risk_score(findings)[2],
        },
        "risk": global_risk(findings),
        "average_cvss": average_cvss(findings),
        "counts": severity_counts(findings),
        "categories": category_counts(findings),
        "findings": [finding_payload(finding, review_records) for finding in findings],
    }
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def write_checklist(findings: list[Finding], output: Path, language: str = "es") -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    lang = report_language(language=language)
    lines = ["# Remediation Checklist" if lang == "en" else "# Checklist de remediación", ""]
    for finding in findings:
        lines.extend(
            [
                f"- [ ] **{priority_for(finding)} / {severity_label(finding.severity, lang)}** `{finding.rule_id}` {finding.title}",
                f"  - {'Location' if lang == 'en' else 'Ubicación'}: `{finding.file}:{finding.line}`",
                f"  - SLA: {remediation_sla(finding)}",
                f"  - {'Fix' if lang == 'en' else 'Corrección'}: {finding.recommendation}",
                "",
            ]
        )
    output.write_text("\n".join(lines), encoding="utf-8")


def write_sarif(findings: list[Finding], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    rules = {}
    for finding in findings:
        rules[finding.rule_id] = {
            "id": finding.rule_id,
            "name": finding.title,
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.description},
            "help": {
                "text": (
                    f"{finding.why_dangerous}\n\n"
                    f"Recomendación: {finding.recommendation}\n\n"
                    f"Referencia: {finding.reference}"
                )
            },
            "properties": {
                "category": finding.category,
                "severity": finding.severity,
                "cvss": finding.cvss,
                "confidence": finding.confidence,
            },
        }

    level_map = {
        "Critica": "error",
        "Alta": "error",
        "Media": "warning",
        "Baja": "note",
    }
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Pre-Auditor IA",
                        "informationUri": "https://owasp.org/",
                        "rules": list(rules.values()),
                    }
                },
                "results": [
                    {
                        "ruleId": finding.rule_id,
                        "level": level_map[finding.severity],
                        "message": {"text": finding.title},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": finding.file},
                                    "region": {"startLine": finding.line},
                                }
                            }
                        ],
                        "partialFingerprints": {"preauditor": finding.fingerprint},
                    }
                    for finding in findings
                ],
            }
        ],
    }
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Análisis preliminar local de seguridad para detectar patrones de riesgo y generar entregables revisables."
    )
    parser.add_argument("target", nargs="?", default=".", help="Carpeta de código a escanear.")
    parser.add_argument(
        "--out",
        default="preaudit-report.md",
        help="Ruta del informe Markdown generado.",
    )
    parser.add_argument(
        "--html",
        default=None,
        help="Ruta opcional para generar también un informe HTML.",
    )
    parser.add_argument(
        "--pdf",
        default=None,
        help="Ruta opcional para generar PDF desde el informe HTML usando cupsfilter si está disponible.",
    )
    parser.add_argument(
        "--dashboard",
        default=None,
        help="Ruta opcional para generar un dashboard HTML local con filtros y búsqueda.",
    )
    parser.add_argument(
        "--json",
        default=None,
        help="Ruta opcional para exportar hallazgos en JSON.",
    )
    parser.add_argument(
        "--sarif",
        default=None,
        help="Ruta opcional para exportar hallazgos en SARIF 2.1.0.",
    )
    parser.add_argument(
        "--profile",
        choices=sorted(PROFILES),
        default="pro",
        help="Perfil de reglas: basic, pro, ai, api, cloud, cicd o fintech.",
    )
    parser.add_argument(
        "--fail-on",
        choices=["Critica", "Alta", "Media", "Baja", "never"],
        default="Alta",
        help="Devuelve código 1 si hay hallazgos de esta severidad o superior.",
    )
    parser.add_argument(
        "--list-rules",
        action="store_true",
        help="Muestra las reglas disponibles para el perfil seleccionado y termina.",
    )
    parser.add_argument("--client", default="Cliente no especificado", help="Nombre del cliente para el informe.")
    parser.add_argument("--auditor", default="Consultor especializado", help="Nombre del auditor o empresa auditora.")
    parser.add_argument("--scope", default="Análisis preliminar automático local", help="Alcance declarado del informe.")
    parser.add_argument("--report-version", default="1.0", help="Versión visible del informe entregado.")
    parser.add_argument("--ignore-file", default=None, help="Ruta opcional a un archivo de supresiones.")
    parser.add_argument("--rules-file", default=None, help="Ruta opcional a reglas custom YAML/JSON.")
    parser.add_argument("--stack", choices=sorted(STACKS), default="generic", help="Stack tecnológico declarado para contextualizar el informe.")
    parser.add_argument("--language", choices=sorted(LANGUAGES), default="es", help="Idioma de informes y dashboard: es o en.")
    parser.add_argument("--baseline", default=None, help="Ruta para guardar un baseline JSON del escaneo actual.")
    parser.add_argument("--compare", default=None, help="Ruta a un baseline JSON previo para comparar nuevos/corregidos/persistentes.")
    parser.add_argument("--deliverable", nargs="?", const="auto", default=None, help="Genera una carpeta de entrega completa. Opcionalmente indica la ruta.")
    parser.add_argument("--ollama", action="store_true", help="Activa triage local con Ollama para hallazgos complejos.")
    parser.add_argument("--ollama-url", default="http://127.0.0.1:11434", help="URL base de Ollama.")
    parser.add_argument("--ollama-model", default="llama3.1", help="Modelo local de Ollama a usar para el triage.")
    parser.add_argument("--ollama-limit", type=int, default=20, help="Número máximo de hallazgos que se enviarán a Ollama.")
    parser.add_argument(
        "--ollama-min-severity",
        choices=["Critica", "Alta", "Media", "Baja"],
        default="Alta",
        help="Severidad mínima que se enviará a Ollama.",
    )
    parser.add_argument(
        "--ollama-filter-fp",
        action="store_true",
        help="Oculta del informe hallazgos que Ollama marque como probable falso positivo con confianza Alta o Media.",
    )
    return parser.parse_args()


def print_rule_catalog(profile: str) -> None:
    rules = rules_for_profile(profile)
    print(f"Perfil: {profile}")
    print(f"Reglas activas: {len(rules)}")
    for category in sorted({rule.category for rule in rules}):
        category_rules = [rule for rule in rules if rule.category == category]
        print(f"\n[{category}] {len(category_rules)} reglas")
        for rule in category_rules:
            print(
                f"- {rule.rule_id} {rule.severity} CVSS~{rule.cvss}: {rule.title}"
            )


def slugify(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_-]+", "-", value.strip().lower()).strip("-")
    return cleaned or "cliente"


def main() -> int:
    args = parse_args()
    if args.list_rules:
        print_rule_catalog(args.profile)
        return 0

    target = Path(args.target).expanduser().resolve()
    if not target.exists() or not target.is_dir():
        print(f"Target invalido: {target}")
        return 2

    meta = ReportMeta(
        client=args.client,
        auditor=args.auditor,
        scope=args.scope,
        version=args.report_version,
        stack=args.stack,
        language=args.language,
    )
    ignore_file = Path(args.ignore_file).expanduser().resolve() if args.ignore_file else None
    try:
        custom_rules = load_custom_rules(Path(args.rules_file).expanduser().resolve() if args.rules_file else None)
    except (OSError, ValueError, re.error, json.JSONDecodeError) as exc:
        print(f"Error cargando reglas custom: {exc}")
        return 2
    findings = scan(target, args.profile, ignore_file, custom_rules)
    ollama_assessments: dict[str, dict] = {}
    if args.ollama:
        ollama_assessments = analyze_with_ollama(
            findings,
            meta,
            args.ollama_url,
            args.ollama_model,
            max(args.ollama_limit, 0),
            args.ollama_min_severity,
        )
        if args.ollama_filter_fp:
            findings = filter_ollama_false_positives(findings, ollama_assessments)
    project_sha = project_hash(target)
    comparison = compare_with_baseline(findings, Path(args.compare).expanduser().resolve() if args.compare else None)

    out_path = Path(args.out)
    html_path = Path(args.html) if args.html else None
    pdf_path = Path(args.pdf) if args.pdf else None
    dashboard_path = Path(args.dashboard) if args.dashboard else None
    json_path = Path(args.json) if args.json else None
    sarif_path = Path(args.sarif) if args.sarif else None
    baseline_path = Path(args.baseline) if args.baseline else None
    checklist_path = None

    if args.deliverable:
        if args.deliverable == "auto":
            stamp = datetime.now().strftime("%Y-%m-%d")
            deliverable_dir = Path(f"{slugify(args.client)}-preauditoria-{stamp}")
        else:
            deliverable_dir = Path(args.deliverable)
        deliverable_dir.mkdir(parents=True, exist_ok=True)
        out_path = deliverable_dir / "informe-tecnico.md"
        html_path = deliverable_dir / "informe-tecnico.html"
        pdf_path = deliverable_dir / "resumen-direccion.pdf"
        dashboard_path = deliverable_dir / "dashboard.html"
        json_path = deliverable_dir / "hallazgos.json"
        sarif_path = deliverable_dir / "hallazgos.sarif"
        baseline_path = deliverable_dir / "baseline.json"
        checklist_path = deliverable_dir / "checklist-remediacion.md"

    markdown = render_markdown(findings, target, args.profile, meta, project_sha, comparison, ollama_assessments)
    pdf_written = write_report(
        markdown,
        out_path,
        html_path,
        findings,
        target,
        args.profile,
        meta,
        pdf_path,
        dashboard_path,
        project_sha,
        comparison,
        ollama_assessments,
    )
    if json_path:
        write_json(findings, json_path, args.profile, meta, project_sha, comparison, ollama_assessments)
    if sarif_path:
        write_sarif(findings, sarif_path)
    if baseline_path:
        baseline_path.parent.mkdir(parents=True, exist_ok=True)
        baseline_path.write_text(
            json.dumps(baseline_payload(findings, target, args.profile, meta, project_sha), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    if checklist_path:
        write_checklist(findings, checklist_path, meta.language)

    counts = severity_counts(findings)
    if meta.language == "en":
        print(f"Preliminary assessment completed: {len(findings)} findings.")
        print(
            "Severity: "
            f"Critical={counts['Critica']} High={counts['Alta']} "
            f"Medium={counts['Media']} Low={counts['Baja']}"
        )
        print(f"Overall risk: {risk_label(global_risk(findings), 'en')}")
        print(f"Approximate average CVSS: {average_cvss(findings)}")
        print(f"AI Agent Risk Score: {ai_agent_risk_score(findings)[0]}/100 ({level_label(ai_agent_risk_score(findings)[1], 'en')})")
        print(f"Project SHA256: {project_sha}")
    else:
        print(f"Análisis preliminar completado: {len(findings)} hallazgos.")
        print(
            "Severidad: "
            f"Critica={counts['Critica']} Alta={counts['Alta']} "
            f"Media={counts['Media']} Baja={counts['Baja']}"
        )
        print(f"Riesgo global: {global_risk(findings)}")
        print(f"CVSS medio aproximado: {average_cvss(findings)}")
        print(f"AI Agent Risk Score: {ai_agent_risk_score(findings)[0]}/100 ({ai_agent_risk_score(findings)[1]})")
        print(f"SHA256 proyecto: {project_sha}")
    if comparison:
        if meta.language == "en":
            print(
                "Comparison: "
                f"new={comparison['new']} fixed={comparison['fixed']} persistent={comparison['persistent']}"
            )
        else:
            print(
                "Comparativa: "
                f"nuevos={comparison['new']} corregidos={comparison['fixed']} persistentes={comparison['persistent']}"
            )
    if args.ollama:
        verdict_counts: dict[str, int] = {}
        for assessment in ollama_assessments.values():
            verdict = assessment.get("verdict", "requiere_revision")
            verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
        if meta.language == "en":
            print(
                "Ollama triage: "
                f"likely_real={verdict_counts.get('probable_real', 0)} "
                f"needs_review={verdict_counts.get('requiere_revision', 0)} "
                f"likely_fp={verdict_counts.get('probable_falso_positivo', 0)}"
            )
        else:
            print(
                "Ollama triage: "
                f"probables_reales={verdict_counts.get('probable_real', 0)} "
                f"revision={verdict_counts.get('requiere_revision', 0)} "
                f"probables_fp={verdict_counts.get('probable_falso_positivo', 0)}"
            )
        if args.ollama_filter_fp:
            print("Ollama FP filter: enabled" if meta.language == "en" else "Filtro Ollama FP: activado")
    print(f"{'Profile' if meta.language == 'en' else 'Perfil'}: {args.profile}")
    if custom_rules:
        print(f"{'Custom rules' if meta.language == 'en' else 'Reglas custom'}: {len(custom_rules)}")
    print(f"{'Report' if meta.language == 'en' else 'Informe'}: {out_path.resolve()}")
    if html_path:
        print(f"HTML: {html_path.resolve()}")
    if pdf_path:
        if pdf_written:
            print(f"PDF: {pdf_path.resolve()}")
        else:
            print("PDF: no generado; cupsfilter no esta disponible o fallo la conversion.")
    if dashboard_path:
        print(f"Dashboard: {dashboard_path.resolve()}")
    if json_path:
        print(f"JSON: {json_path.resolve()}")
    if sarif_path:
        print(f"SARIF: {sarif_path.resolve()}")
    if baseline_path:
        print(f"Baseline: {baseline_path.resolve()}")
    if checklist_path:
        print(f"Checklist: {checklist_path.resolve()}")
    if args.fail_on == "never":
        return 0
    threshold = SEVERITY_ORDER[args.fail_on]
    return 1 if any(SEVERITY_ORDER[f.severity] >= threshold for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
