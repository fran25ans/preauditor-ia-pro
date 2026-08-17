"""Security model orchestration and persistence."""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import contextlib

from proofsec.discovery import discover_spring_boot
from proofsec.models import ProjectSecurityModel


def build_security_model(root: Path, stack: str = "auto") -> ProjectSecurityModel:
    root = root.expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise ValueError(f"Project path not found: {root}")
    if stack in {"auto", "spring", "spring-boot"}:
        return discover_spring_boot(root)
    raise ValueError(f"Unsupported ProofSec stack: {stack}")


def write_model_json(model: ProjectSecurityModel, output: Path) -> None:
    model.write_json(output.expanduser().resolve())


def init_sqlite(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        create table if not exists security_models (
            id integer primary key autoincrement,
            project_path text not null,
            generated_at text not null,
            framework text not null,
            payload_json text not null
        );
        create table if not exists endpoints (
            model_id integer not null,
            endpoint_id text not null,
            method text not null,
            path text not null,
            controller text not null,
            handler text not null,
            file text not null,
            line integer not null,
            authorization text not null,
            roles_json text not null,
            resource text not null,
            action text not null,
            parameters_json text not null,
            foreign key(model_id) references security_models(id)
        );
        create table if not exists graph_edges (
            model_id integer not null,
            edge_id text not null,
            source text not null,
            target text not null,
            edge_type text not null,
            evidence text not null,
            foreign key(model_id) references security_models(id)
        );
        """
    )


def write_model_sqlite(model: ProjectSecurityModel, db_path: Path) -> int:
    db_path = db_path.expanduser().resolve()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with contextlib.closing(sqlite3.connect(db_path)) as connection:
        init_sqlite(connection)
        cursor = connection.execute(
            "insert into security_models(project_path, generated_at, framework, payload_json) values (?, ?, ?, ?)",
            (model.project_path, model.generated_at, model.framework, model.to_json()),
        )
        model_id = int(cursor.lastrowid)
        connection.executemany(
            """
            insert into endpoints(
                model_id, endpoint_id, method, path, controller, handler, file, line,
                authorization, roles_json, resource, action, parameters_json
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    model_id,
                    endpoint.id,
                    endpoint.method,
                    endpoint.path,
                    endpoint.controller,
                    endpoint.handler,
                    endpoint.file,
                    endpoint.line,
                    endpoint.authorization,
                    json.dumps(endpoint.roles, ensure_ascii=False),
                    endpoint.resource,
                    endpoint.action,
                    json.dumps(endpoint.parameters, ensure_ascii=False),
                )
                for endpoint in model.endpoints
            ],
        )
        connection.executemany(
            """
            insert into graph_edges(model_id, edge_id, source, target, edge_type, evidence)
            values (?, ?, ?, ?, ?, ?)
            """,
            [(model_id, edge.id, edge.source, edge.target, edge.type, edge.evidence) for edge in model.edges],
        )
        connection.commit()
    return model_id
