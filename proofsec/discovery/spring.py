"""Deterministic Spring Boot REST discovery for ProofSec."""

from __future__ import annotations

import re
from pathlib import Path

from proofsec.models import EndpointNode, ProjectSecurityModel, ResourceNode, RoleNode, SecurityEdge


JAVA_EXTENSIONS = {".java"}
CONTROLLER_RE = re.compile(r"@(RestController|Controller)\b")
CLASS_RE = re.compile(r"\bclass\s+([A-Za-z_][A-Za-z0-9_]*)")
METHOD_RE = re.compile(
    r"\b(public|private|protected)?\s*(?:[\w<>\[\], ?]+\s+)+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)"
)
REQUEST_MAPPING_RE = re.compile(r"@(RequestMapping|GetMapping|PostMapping|PutMapping|PatchMapping|DeleteMapping)\s*(?:\((.*?)\))?", re.DOTALL)
PREAUTHORIZE_RE = re.compile(r"@PreAuthorize\s*\(\s*\"([^\"]+)\"", re.DOTALL)
SECURED_RE = re.compile(r"@Secured\s*\((.*?)\)", re.DOTALL)
ROLE_RE = re.compile(r"(?:hasRole|hasAnyRole)\s*\(([^)]*)\)|ROLE_([A-Za-z0-9_]+)|['\"]([A-Z][A-Z0-9_]*)['\"]")
PATH_VARIABLE_RE = re.compile(r"@PathVariable(?:\([^)]*\))?\s+(?:[\w<>\[\]]+\s+)?([A-Za-z_][A-Za-z0-9_]*)")


HTTP_METHOD_BY_ANNOTATION = {
    "GetMapping": "GET",
    "PostMapping": "POST",
    "PutMapping": "PUT",
    "PatchMapping": "PATCH",
    "DeleteMapping": "DELETE",
}


def iter_java_files(root: Path) -> list[Path]:
    return sorted(path for path in root.rglob("*") if path.is_file() and path.suffix in JAVA_EXTENSIONS)


def annotation_window(lines: list[str], index: int, max_back: int = 8) -> tuple[int, str]:
    start = index
    for cursor in range(index - 1, max(-1, index - max_back - 1), -1):
        stripped = lines[cursor].strip()
        if stripped.startswith("@") or stripped == "":
            start = cursor
            continue
        break
    return start + 1, "\n".join(lines[start:index + 1])


def annotation_path(args: str | None) -> str:
    if not args:
        return ""
    match = re.search(r"(?:value\s*=\s*|path\s*=\s*)?[\{]?\s*\"([^\"]+)\"", args)
    return match.group(1) if match else ""


def annotation_method(annotation: str, args: str | None) -> str:
    if annotation in HTTP_METHOD_BY_ANNOTATION:
        return HTTP_METHOD_BY_ANNOTATION[annotation]
    if args:
        match = re.search(r"RequestMethod\.([A-Z]+)", args)
        if match:
            return match.group(1)
    return "ANY"


def normalize_path(*parts: str) -> str:
    cleaned = []
    for part in parts:
        if not part:
            continue
        cleaned.append(part.strip("/"))
    path = "/" + "/".join(part for part in cleaned if part)
    return re.sub(r"/+", "/", path)


def extract_roles(text: str) -> tuple[str, ...]:
    roles: set[str] = set()
    for auth_match in PREAUTHORIZE_RE.finditer(text):
        expression = auth_match.group(1)
        for role_match in ROLE_RE.finditer(expression):
            for group in role_match.groups():
                if group:
                    for role in re.findall(r"[A-Z][A-Z0-9_]+", group):
                        roles.add(role.removeprefix("ROLE_"))
    for secured_match in SECURED_RE.finditer(text):
        for role in re.findall(r"ROLE_([A-Za-z0-9_]+)|['\"]([A-Z][A-Z0-9_]*)['\"]", secured_match.group(1)):
            value = next((part for part in role if part), "")
            if value:
                roles.add(value.removeprefix("ROLE_"))
    return tuple(sorted(roles))


def infer_resource(path: str) -> str:
    parts = [part for part in path.strip("/").split("/") if part and not part.startswith("{")]
    if parts and parts[0] == "api" and len(parts) > 1:
        parts = parts[1:]
    if not parts:
        return "unknown"
    return parts[0].replace("-", "_").lower()


def infer_action(method: str) -> str:
    return {
        "GET": "read",
        "POST": "create",
        "PUT": "update",
        "PATCH": "update",
        "DELETE": "delete",
    }.get(method.upper(), "unknown")


def path_parameters(path: str, method_signature: str) -> tuple[str, ...]:
    params = set(re.findall(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", path))
    params.update(PATH_VARIABLE_RE.findall(method_signature))
    return tuple(sorted(params))


def discover_controller(root: Path, path: Path) -> tuple[list[EndpointNode], list[RoleNode], list[ResourceNode], list[SecurityEdge], list[str]]:
    relative = path.relative_to(root).as_posix()
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        return [], [], [], [], [f"Could not read {relative}: {exc}"]
    text = "\n".join(lines)
    if not CONTROLLER_RE.search(text):
        return [], [], [], [], []

    class_name = CLASS_RE.search(text).group(1) if CLASS_RE.search(text) else path.stem
    class_mapping = ""
    class_roles: tuple[str, ...] = ()
    for index, line in enumerate(lines):
        if "class " in line:
            _, window = annotation_window(lines, index)
            mapping = REQUEST_MAPPING_RE.search(window)
            if mapping:
                class_mapping = annotation_path(mapping.group(2))
            class_roles = extract_roles(window)
            break

    endpoints: list[EndpointNode] = []
    roles: dict[str, RoleNode] = {}
    resources: dict[str, ResourceNode] = {}
    edges: list[SecurityEdge] = []

    for index, line in enumerate(lines):
        if "(" not in line or ")" not in line:
            continue
        method_match = METHOD_RE.search(line.strip())
        if not method_match:
            continue
        start_line, window = annotation_window(lines, index)
        mapping = REQUEST_MAPPING_RE.search(window)
        if not mapping:
            continue
        annotation, args = mapping.group(1), mapping.group(2)
        http_method = annotation_method(annotation, args)
        method_path = annotation_path(args)
        full_path = normalize_path(class_mapping, method_path)
        handler = method_match.group(2)
        method_roles = extract_roles(window)
        endpoint_roles = method_roles or class_roles
        authorization = "role-based" if endpoint_roles else "unknown"
        resource_name = infer_resource(full_path)
        endpoint = EndpointNode(
            method=http_method,
            path=full_path,
            controller=class_name,
            handler=handler,
            file=relative,
            line=start_line,
            authorization=authorization,
            roles=endpoint_roles,
            resource=resource_name,
            action=infer_action(http_method),
            parameters=path_parameters(full_path, line),
        )
        endpoints.append(endpoint)
        resource = ResourceNode(resource_name, evidence=full_path)
        resources[resource.id] = resource
        edges.append(SecurityEdge(endpoint.id, resource.id, "accesses_resource", evidence=full_path))
        edges.append(SecurityEdge(endpoint.id, f"controller:{class_name}", "declares", evidence=relative))
        for role_name in endpoint_roles:
            role = RoleNode(role_name, evidence=window.strip())
            roles[role.id] = role
            edges.append(SecurityEdge(role.id, endpoint.id, "requires_role", evidence=window.strip()))

    notes = []
    if endpoints and not any(endpoint.roles for endpoint in endpoints):
        notes.append(f"{relative}: endpoints detected but no role annotations were found.")
    return endpoints, list(roles.values()), list(resources.values()), edges, notes


def discover_spring_boot(root: Path) -> ProjectSecurityModel:
    endpoints: list[EndpointNode] = []
    roles: dict[str, RoleNode] = {}
    resources: dict[str, ResourceNode] = {}
    edges: dict[str, SecurityEdge] = {}
    notes: list[str] = []

    java_files = iter_java_files(root)
    spring_boot_detected = False
    for path in java_files[:200]:
        try:
            if "SpringApplication.run" in path.read_text(encoding="utf-8", errors="ignore"):
                spring_boot_detected = True
                break
        except OSError as exc:
            notes.append(f"Could not inspect {path.relative_to(root).as_posix()}: {exc}")
    framework = "spring-boot" if spring_boot_detected else "spring"
    for path in java_files:
        found_endpoints, found_roles, found_resources, found_edges, found_notes = discover_controller(root, path)
        endpoints.extend(found_endpoints)
        for role in found_roles:
            roles[role.id] = role
        for resource in found_resources:
            resources[resource.id] = resource
        for edge in found_edges:
            edges[edge.id] = edge
        notes.extend(found_notes)

    return ProjectSecurityModel(
        project_path=str(root),
        framework=framework if endpoints else "unknown",
        languages=("java",) if java_files else (),
        endpoints=sorted(endpoints, key=lambda item: (item.path, item.method, item.file, item.line)),
        roles=sorted(roles.values(), key=lambda item: item.name),
        resources=sorted(resources.values(), key=lambda item: item.name),
        edges=sorted(edges.values(), key=lambda item: (item.source, item.type, item.target)),
        notes=notes,
    )
