"""OpenAPI route discovery for ProofSec runtime-assisted analysis."""

from __future__ import annotations

from typing import Any

from proofsec.discovery.spring import infer_action, infer_resource
from proofsec.models import EndpointNode, ProjectSecurityModel, ResourceNode, SecurityEdge


HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head"}


def path_parameters(path: str, operation: dict[str, Any]) -> tuple[str, ...]:
    params = set()
    import re

    params.update(re.findall(r"\{([^}]+)\}", path))
    for parameter in operation.get("parameters") or []:
        if isinstance(parameter, dict) and parameter.get("in") == "path" and parameter.get("name"):
            params.add(str(parameter["name"]))
    return tuple(sorted(params))


def model_from_openapi(spec: dict[str, Any], project_path: str = "runtime-openapi") -> ProjectSecurityModel:
    endpoints: list[EndpointNode] = []
    resources: dict[str, ResourceNode] = {}
    edges: dict[str, SecurityEdge] = {}
    paths = spec.get("paths") or {}
    if not isinstance(paths, dict):
        paths = {}
    for path, operations in paths.items():
        if not isinstance(path, str) or not isinstance(operations, dict):
            continue
        for method, operation in operations.items():
            method_text = str(method).lower()
            if method_text not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            http_method = method_text.upper()
            resource_name = infer_resource(path)
            endpoint = EndpointNode(
                method=http_method,
                path=path,
                controller="OpenAPI",
                handler=str(operation.get("operationId") or f"{method_text}_{path.strip('/').replace('/', '_')}"),
                file="openapi.json",
                line=1,
                authorization="unknown",
                roles=(),
                resource=resource_name,
                action=infer_action(http_method),
                parameters=path_parameters(path, operation),
            )
            endpoints.append(endpoint)
            resource = ResourceNode(resource_name, source="detected", evidence=path)
            resources[resource.id] = resource
            edge = SecurityEdge(endpoint.id, resource.id, "accesses_resource", evidence=path)
            edges[edge.id] = edge
    return ProjectSecurityModel(
        project_path=project_path,
        framework="openapi",
        languages=(),
        endpoints=sorted(endpoints, key=lambda item: (item.path, item.method)),
        resources=sorted(resources.values(), key=lambda item: item.name),
        edges=sorted(edges.values(), key=lambda item: (item.source, item.type, item.target)),
        notes=["Runtime OpenAPI document was used for endpoint discovery."],
    )
