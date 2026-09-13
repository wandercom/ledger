"""HTTP API Server — FastAPI application exposing all Ledger operations as REST endpoints."""

from __future__ import annotations

import hashlib
import random
import uuid
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Optional

import uvicorn
import yaml
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, field_validator


# ── Enums ──────────────────────────────────────────────


class HttpMethod(str, Enum):
    GET = "GET"
    POST = "POST"


class Severity(str, Enum):
    error = "error"
    warning = "warning"
    info = "info"


class ExportFormat(str, Enum):
    json = "json"
    csv = "csv"
    yaml = "yaml"


class PlanStatus(str, Enum):
    pending = "pending"
    approved = "approved"
    expired = "expired"


# ── Config Model ──────────────────────────────────────


class LedgerConfig(BaseModel):
    port: int = 7701
    schema_dir: str = ""
    plan_ttl_seconds: int = 3600
    arbiter_url: str = ""


# ── Request/Response Models ───────────────────────────


class RegisterBackendRequest(BaseModel):
    backend_id: str
    display_name: str
    description: str = ""


class RegisterSchemaRequest(BaseModel):
    backend_id: str
    table_name: str
    yaml_content: str
    version: str = "1.0.0"


class ValidateSchemaRequest(BaseModel):
    yaml_content: str


class MigrationPlanRequest(BaseModel):
    backend_id: str
    table_name: str
    sql_content: str


class MockGenerationRequest(BaseModel):
    row_count: int
    seed: int = 42

    @field_validator("row_count")
    @classmethod
    def validate_row_count(cls, v: int) -> int:
        if v < 1 or v > 10000:
            raise ValueError("row_count must be between 1 and 10000")
        return v


class ErrorResponse(BaseModel):
    error: str
    detail: str
    violations: list = []


# ── In-Memory Registry ────────────────────────────────


class InMemoryRegistry:
    """Simple in-memory registry for backends, schemas, and plans."""

    def __init__(self):
        self.backends: dict[str, dict] = {}
        self.schemas: dict[str, dict[str, dict]] = {}  # backend_id -> {table_name -> schema_data}
        self.plans: dict[str, dict] = {}  # plan_id -> plan

    def register_backend(self, backend_id: str, display_name: str, description: str) -> tuple[dict, bool]:
        """Register or re-register a backend. Returns (data, is_new)."""
        if backend_id in self.backends:
            existing = self.backends[backend_id]
            if existing["display_name"] == display_name and existing["description"] == description:
                return existing, False
            else:
                return existing, None  # conflict
        data = {
            "backend_id": backend_id,
            "display_name": display_name,
            "description": description,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        self.backends[backend_id] = data
        return data, True

    def register_schema(self, backend_id: str, table_name: str, yaml_content: str,
                        version: str) -> tuple[dict, bool]:
        """Register a schema. Returns (data, is_new). None for conflict."""
        if backend_id not in self.backends:
            raise KeyError(f"Backend '{backend_id}' not found")

        if backend_id not in self.schemas:
            self.schemas[backend_id] = {}

        key = table_name
        if key in self.schemas[backend_id]:
            existing = self.schemas[backend_id][key]
            if existing["yaml_content"] == yaml_content:
                return existing, False
            else:
                return existing, None  # conflict

        # Parse the YAML to extract columns and annotations
        parsed = yaml.safe_load(yaml_content)
        columns = []
        annotations = []
        if isinstance(parsed, dict):
            table = parsed.get("table", parsed)
            raw_columns = table.get("columns", []) if isinstance(table, dict) else parsed.get("columns", [])
            if isinstance(raw_columns, list):
                for col in raw_columns:
                    if isinstance(col, dict):
                        columns.append(col)
                        col_anns = col.get("annotations", [])
                        if isinstance(col_anns, list):
                            for ann in col_anns:
                                annotations.append({
                                    "field": col.get("name", ""),
                                    "annotation": ann,
                                    "propagated": False,
                                })

        data = {
            "backend_id": backend_id,
            "table_name": table_name,
            "yaml_content": yaml_content,
            "version": version,
            "columns": columns,
            "annotations": annotations,
            "stored_at": datetime.now(timezone.utc).isoformat(),
        }
        self.schemas[backend_id][key] = data
        return data, True

    def get_schemas(self, backend_id: str) -> list[dict]:
        if backend_id not in self.backends:
            raise KeyError(f"Backend '{backend_id}' not found")
        schemas = self.schemas.get(backend_id, {})
        return [
            {"table_name": k, "version": v.get("version", ""), "stored_at": v.get("stored_at", ""),
             "column_count": len(v.get("columns", [])),
             "annotation_count": len(v.get("annotations", []))}
            for k, v in sorted(schemas.items())
        ]

    def get_schema_detail(self, backend_id: str, table_name: str) -> Optional[dict]:
        if backend_id not in self.backends:
            raise KeyError(f"Backend '{backend_id}' not found")
        schemas = self.schemas.get(backend_id, {})
        return schemas.get(table_name)

    def get_all_annotations(self) -> list[dict]:
        """Return all annotations across all schemas."""
        all_anns = []
        for backend_id, schemas in self.schemas.items():
            for table_name, schema_data in schemas.items():
                for ann in schema_data.get("annotations", []):
                    all_anns.append({
                        "backend_id": backend_id,
                        "table_name": table_name,
                        "field": ann.get("field", ""),
                        "annotation": ann.get("annotation", ""),
                        "propagated": ann.get("propagated", False),
                    })
        return all_anns


# ── Registry dependency ───────────────────────────────

_registry_cache: dict[int, InMemoryRegistry] = {}


def get_registry(config: LedgerConfig) -> InMemoryRegistry:
    """Get or create a cached registry for the given config."""
    config_id = id(config)
    if config_id not in _registry_cache:
        _registry_cache[config_id] = InMemoryRegistry()
    return _registry_cache[config_id]


# ── Exception handlers ────────────────────────────────


class BackendNotFoundError(Exception):
    def __init__(self, message: str):
        self.message = message
        super().__init__(message)


class SchemaNotFoundError(Exception):
    def __init__(self, message: str):
        self.message = message
        super().__init__(message)


class ConflictError(Exception):
    def __init__(self, message: str, violations: list = None):
        self.message = message
        self.violations = violations or []
        super().__init__(message)


class ValidationError(Exception):
    def __init__(self, message: str, violations: list = None):
        self.message = message
        self.violations = violations or []
        super().__init__(message)


class PlanNotFoundError(Exception):
    def __init__(self, message: str):
        self.message = message
        super().__init__(message)


class InvalidTransitionError(Exception):
    def __init__(self, message: str, violations: list = None):
        self.message = message
        self.violations = violations or []
        super().__init__(message)


# ── Handler functions ─────────────────────────────────


def handle_health(config: LedgerConfig) -> dict:
    return {
        "status": "ok",
        "version": "1.0.0",
        "port": config.port,
    }


def handle_register_backend(registry: InMemoryRegistry, req: RegisterBackendRequest) -> tuple[dict, int]:
    data, is_new = registry.register_backend(req.backend_id, req.display_name, req.description)
    if is_new is None:
        raise ConflictError(
            f"Backend '{req.backend_id}' already registered with different properties",
            violations=[{"message": f"Backend '{req.backend_id}' conflict", "severity": "error"}],
        )
    if is_new:
        return {
            "backend_id": data["backend_id"],
            "display_name": data["display_name"],
            "created": True,
        }, 201
    else:
        return {
            "backend_id": data["backend_id"],
            "display_name": data["display_name"],
            "created": False,
        }, 200


def handle_register_schema(registry: InMemoryRegistry, req: RegisterSchemaRequest) -> tuple[dict, int]:
    try:
        # Validate YAML is parseable
        parsed = yaml.safe_load(req.yaml_content)
        if parsed is None and req.yaml_content.strip():
            pass  # empty yaml is fine
    except yaml.YAMLError as e:
        raise ValidationError(
            f"Invalid YAML: {e}",
            violations=[{"message": f"YAML parse error: {e}", "severity": "error"}],
        )

    try:
        data, is_new = registry.register_schema(
            req.backend_id, req.table_name, req.yaml_content, req.version
        )
    except KeyError:
        raise BackendNotFoundError(f"Backend '{req.backend_id}' not found")

    if is_new is None:
        raise ConflictError(
            f"Schema '{req.table_name}' already registered with different content",
            violations=[{
                "message": f"Schema '{req.table_name}' conflict",
                "severity": "error",
            }],
        )
    if is_new:
        return {
            "backend_id": data["backend_id"],
            "table_name": data["table_name"],
            "created": True,
        }, 201
    else:
        return {
            "backend_id": data["backend_id"],
            "table_name": data["table_name"],
            "created": False,
        }, 200


def handle_get_schemas_for_backend(registry: InMemoryRegistry, backend_id: str) -> dict:
    try:
        schemas = registry.get_schemas(backend_id)
    except KeyError:
        raise BackendNotFoundError(f"Backend '{backend_id}' not found")
    return {
        "backend_id": backend_id,
        "schemas": schemas,
    }


def handle_get_schema_detail(registry: InMemoryRegistry, backend_id: str, table: str) -> dict:
    try:
        detail = registry.get_schema_detail(backend_id, table)
    except KeyError:
        raise BackendNotFoundError(f"Backend '{backend_id}' not found")
    if detail is None:
        raise SchemaNotFoundError(f"Schema '{table}' not found in backend '{backend_id}'")
    return detail


def handle_validate_schema(yaml_content: str) -> dict:
    if not yaml_content or not yaml_content.strip():
        raise ValidationError(
            "YAML content is empty",
            violations=[{"message": "YAML content is empty", "severity": "error"}],
        )

    try:
        parsed = yaml.safe_load(yaml_content)
    except yaml.YAMLError as e:
        return {
            "valid": False,
            "violations": [{"message": f"YAML parse error: {e}", "severity": "error"}],
        }

    violations = []

    # Structural validation
    if not isinstance(parsed, dict):
        violations.append({"message": "Schema must be a YAML mapping", "severity": "error"})
    else:
        if "table" not in parsed and "columns" not in parsed:
            violations.append({
                "message": "Schema missing 'table' or 'columns' field",
                "severity": "warning",
            })
        columns = parsed.get("columns", None)
        if columns is not None and not isinstance(columns, list):
            violations.append({
                "message": "'columns' must be a list",
                "severity": "error",
            })

    has_errors = any(v.get("severity") == "error" for v in violations)
    return {
        "valid": not has_errors,
        "violations": violations,
    }


def handle_create_migration_plan(
    registry: InMemoryRegistry,
    config: LedgerConfig,
    req: MigrationPlanRequest,
) -> tuple[dict, int]:
    if req.backend_id not in registry.backends:
        raise BackendNotFoundError(f"Backend '{req.backend_id}' not found")

    schemas = registry.schemas.get(req.backend_id, {})
    if req.table_name not in schemas:
        raise SchemaNotFoundError(
            f"Schema '{req.table_name}' not found in backend '{req.backend_id}'"
        )

    # Parse SQL
    sql = req.sql_content.strip()
    if not sql:
        raise ValidationError(
            "SQL content is empty",
            violations=[{"message": "SQL content is empty", "severity": "error"}],
        )

    # Check for recognizable SQL
    import re
    alter_pattern = re.compile(r"ALTER\s+TABLE", re.IGNORECASE)
    drop_pattern = re.compile(r"DROP\s+TABLE", re.IGNORECASE)

    if not alter_pattern.search(sql) and not drop_pattern.search(sql):
        raise ValidationError(
            "SQL does not contain recognizable migration statements",
            violations=[{"message": "Unrecognized SQL statement", "severity": "error"}],
        )

    # Compute diffs
    diffs = []
    violations = []

    # Simple ADD COLUMN detection
    add_col_pattern = re.compile(
        r"ALTER\s+TABLE\s+\S+\s+ADD\s+(?:COLUMN\s+)?(\S+)\s+(\S+)",
        re.IGNORECASE,
    )
    for m in add_col_pattern.finditer(sql):
        diffs.append({
            "operation": "ADD_COLUMN",
            "column": m.group(1),
            "type": m.group(2).rstrip(";"),
        })

    # Simple DROP TABLE detection -> gate failure
    gate_passed = True
    if drop_pattern.search(sql):
        gate_passed = False
        violations.append({
            "rule": "destructive_operation",
            "severity": "error",
            "message": "DROP TABLE is a destructive operation",
        })

    plan_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=config.plan_ttl_seconds)

    plan = {
        "plan_id": plan_id,
        "backend_id": req.backend_id,
        "table_name": req.table_name,
        "status": PlanStatus.pending.value,
        "diffs": diffs,
        "gate_result": {
            "passed": gate_passed,
            "violations": violations,
        },
        "expires_at": expires_at.isoformat(),
        "created_at": now.isoformat(),
    }

    registry.plans[plan_id] = plan
    return plan, 201


def handle_approve_migration_plan(
    registry: InMemoryRegistry,
    plan_id: str,
) -> dict:
    if plan_id not in registry.plans:
        raise PlanNotFoundError(f"Plan '{plan_id}' not found")

    plan = registry.plans[plan_id]

    if datetime.fromisoformat(plan["expires_at"]) <= datetime.now(timezone.utc):
        plan["status"] = PlanStatus.expired.value
        raise PlanNotFoundError(f"Plan '{plan_id}' has expired")

    if plan["status"] != PlanStatus.pending.value:
        raise InvalidTransitionError(
            f"Plan '{plan_id}' is already approved",
            violations=[{"message": "Plan already approved", "severity": "error"}],
        )

    if not plan["gate_result"]["passed"]:
        raise InvalidTransitionError(
            f"Plan '{plan_id}' has failing gate checks",
            violations=[{"message": "Gate checks failed", "severity": "error"}],
        )

    plan["status"] = PlanStatus.approved.value
    plan["approved_at"] = datetime.now(timezone.utc).isoformat()

    return {
        "plan_id": plan_id,
        "status": PlanStatus.approved.value,
        "approved_at": plan["approved_at"],
    }


def handle_export(
    registry: InMemoryRegistry,
    format_name: str,
) -> Any:
    # Collect all schemas
    all_schemas = []
    for backend_id, schemas in registry.schemas.items():
        for table_name, schema_data in schemas.items():
            all_schemas.append({
                "backend_id": backend_id,
                "table_name": table_name,
                "yaml_content": schema_data.get("yaml_content", ""),
                "columns": schema_data.get("columns", []),
            })

    if format_name == "json":
        return {
            "format": "json",
            "schema_count": len(all_schemas),
            "schemas": all_schemas,
        }
    elif format_name == "csv":
        # Generate CSV
        lines = ["backend_id,table_name,column_name,column_type"]
        for s in all_schemas:
            for col in s.get("columns", []):
                name = col.get("name", "")
                ctype = col.get("type", "")
                lines.append(f"{s['backend_id']},{s['table_name']},{name},{ctype}")
        return "\n".join(lines)
    elif format_name == "yaml":
        return yaml.dump(
            {"schemas": all_schemas},
            sort_keys=False,
            allow_unicode=True,
            default_flow_style=False,
        )
    else:
        raise ValidationError(
            f"Invalid export format: {format_name}",
            violations=[{"message": f"Unsupported format: {format_name}", "severity": "error"}],
        )


def handle_generate_mock(
    registry: InMemoryRegistry,
    backend_id: str,
    table_name: str,
    row_count: int,
    seed: int,
) -> dict:
    if backend_id not in registry.backends:
        raise BackendNotFoundError(f"Backend '{backend_id}' not found")

    schemas = registry.schemas.get(backend_id, {})
    if table_name not in schemas:
        raise SchemaNotFoundError(
            f"Schema '{table_name}' not found in backend '{backend_id}'"
        )

    schema_data = schemas[table_name]
    columns = schema_data.get("columns", [])
    column_names = [col.get("name", f"col_{i}") for i, col in enumerate(columns)]

    # Generate mock rows using seed
    rng = random.Random(seed)
    rows = []
    for _ in range(row_count):
        row = {}
        for col in columns:
            col_name = col.get("name", "")
            col_type = col.get("type", "text").lower()
            if "int" in col_type:
                row[col_name] = rng.randint(1, 1000000)
            elif "bool" in col_type:
                row[col_name] = rng.choice([True, False])
            elif "varchar" in col_type or "text" in col_type or "char" in col_type:
                row[col_name] = "".join(
                    rng.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=rng.randint(5, 20))
                )
            else:
                row[col_name] = "".join(
                    rng.choices("abcdefghijklmnopqrstuvwxyz", k=rng.randint(5, 12))
                )
        rows.append(row)

    return {
        "backend_id": backend_id,
        "table_name": table_name,
        "row_count": row_count,
        "columns": column_names,
        "rows": rows,
        "seed": seed,
    }


def handle_get_annotations(registry: InMemoryRegistry) -> dict:
    annotations = registry.get_all_annotations()
    return {
        "annotations": [
            {**ann, "propagated": ann.get("propagated", False)}
            for ann in annotations
        ],
        "total_count": len(annotations),
    }


# ── Application factory ──────────────────────────────


def create_app(config: LedgerConfig) -> FastAPI:
    """Application factory: create a configured FastAPI app."""
    app = FastAPI(title="Ledger API", version="1.0.0")

    # Store config on app state
    app.state.config = config
    app.state.registry = None  # Lazy init

    def _get_registry() -> InMemoryRegistry:
        if app.state.registry is None:
            app.state.registry = InMemoryRegistry()
        return app.state.registry

    # ── Exception handlers ──────────────────────────

    @app.exception_handler(BackendNotFoundError)
    def _handle_backend_not_found(request: Request, exc: BackendNotFoundError):
        return JSONResponse(
            status_code=404,
            content=ErrorResponse(error=exc.message, detail=exc.message).model_dump(),
        )

    @app.exception_handler(SchemaNotFoundError)
    def _handle_schema_not_found(request: Request, exc: SchemaNotFoundError):
        return JSONResponse(
            status_code=404,
            content=ErrorResponse(error=exc.message, detail=exc.message).model_dump(),
        )

    @app.exception_handler(ConflictError)
    def _handle_conflict(request: Request, exc: ConflictError):
        return JSONResponse(
            status_code=409,
            content=ErrorResponse(error=exc.message, detail=exc.message, violations=exc.violations).model_dump(),
        )

    @app.exception_handler(ValidationError)
    def _handle_validation(request: Request, exc: ValidationError):
        return JSONResponse(
            status_code=400,
            content=ErrorResponse(error=exc.message, detail=exc.message, violations=exc.violations).model_dump(),
        )

    @app.exception_handler(InvalidTransitionError)
    def _handle_invalid_transition(request: Request, exc: InvalidTransitionError):
        return JSONResponse(
            status_code=409,
            content=ErrorResponse(error=exc.message, detail=exc.message, violations=exc.violations).model_dump(),
        )

    @app.exception_handler(PlanNotFoundError)
    def _handle_plan_not_found(request: Request, exc: PlanNotFoundError):
        return JSONResponse(
            status_code=404,
            content=ErrorResponse(error=exc.message, detail=exc.message).model_dump(),
        )

    # ── Routes ──────────────────────────────────────

    @app.get("/health")
    def health():
        return handle_health(config)

    @app.post("/backends")
    def register_backend(req: RegisterBackendRequest):
        reg = _get_registry()
        data, status_code = handle_register_backend(reg, req)
        resp = JSONResponse(content=data, status_code=status_code)
        if status_code == 201:
            resp.headers["location"] = f"/backends/{req.backend_id}"
        return resp

    @app.post("/schemas")
    def register_schema(req: RegisterSchemaRequest):
        reg = _get_registry()
        data, status_code = handle_register_schema(reg, req)
        resp = JSONResponse(content=data, status_code=status_code)
        if status_code == 201:
            resp.headers["location"] = f"/schemas/{req.backend_id}/{req.table_name}"
        return resp

    @app.get("/schemas/{backend_id}")
    def get_schemas(backend_id: str):
        reg = _get_registry()
        return handle_get_schemas_for_backend(reg, backend_id)

    @app.get("/schemas/{backend_id}/{table}")
    def get_schema_detail(backend_id: str, table: str):
        reg = _get_registry()
        return handle_get_schema_detail(reg, backend_id, table)

    @app.post("/schemas/validate")
    def validate_schema(req: ValidateSchemaRequest):
        if not req.yaml_content or not req.yaml_content.strip():
            return JSONResponse(
                status_code=400,
                content={"error": "YAML content is empty", "violations": [
                    {"message": "YAML content is empty", "severity": "error"}
                ]},
            )
        return handle_validate_schema(req.yaml_content)

    @app.post("/migrations/plan")
    def create_migration_plan(req: MigrationPlanRequest):
        reg = _get_registry()
        plan, status_code = handle_create_migration_plan(reg, config, req)
        return JSONResponse(content=plan, status_code=status_code)

    @app.post("/migrations/{plan_id}/approve")
    def approve_migration_plan(plan_id: str):
        reg = _get_registry()
        return handle_approve_migration_plan(reg, plan_id)

    @app.get("/export/{format_name}")
    def export_data(format_name: str):
        valid_formats = {"json", "csv", "yaml"}
        if format_name not in valid_formats:
            return JSONResponse(
                status_code=422,
                content={"error": f"Invalid format: {format_name}", "violations": [
                    {"message": f"Supported formats: {sorted(valid_formats)}", "severity": "error"}
                ]},
            )
        reg = _get_registry()
        result = handle_export(reg, format_name)
        if format_name == "json":
            return result
        elif format_name == "csv":
            return PlainTextResponse(content=result, media_type="text/csv")
        elif format_name == "yaml":
            return PlainTextResponse(content=result, media_type="text/yaml")

    @app.post("/mock/{backend_id}/{table_name}")
    def generate_mock(backend_id: str, table_name: str, req: MockGenerationRequest):
        reg = _get_registry()
        return handle_generate_mock(reg, backend_id, table_name, req.row_count, req.seed)

    @app.get("/annotations")
    def get_annotations():
        reg = _get_registry()
        return handle_get_annotations(reg)

    return app


# ── serve_cli ─────────────────────────────────────────


def serve_cli(port: int = 7701, host: str = "0.0.0.0", config_path: str = "ledger.yaml"):
    """Start the Ledger API server from CLI."""
    import yaml as _yaml

    if not config_path:
        raise FileNotFoundError("Config path is required")

    try:
        with open(config_path, "r") as f:
            raw = f.read()
    except FileNotFoundError:
        raise

    try:
        data = _yaml.safe_load(raw)
    except _yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML in config: {e}")

    if not isinstance(data, dict):
        raise ValueError("Config must be a YAML mapping")

    cfg = LedgerConfig(
        port=data.get("port", port),
        schema_dir=data.get("schema_dir", ""),
        plan_ttl_seconds=data.get("plan_ttl_seconds", 3600),
        arbiter_url=data.get("arbiter_url", ""),
    )

    app = create_app(cfg)
    uvicorn.run(app, host=host, port=cfg.port, workers=1)


# ── start_server (used by CLI) ────────────────────────


def start_server(config_obj):
    """Start the server from a loaded config object (called by CLI serve command)."""
    port = getattr(config_obj, "port", 7701)
    if isinstance(config_obj, dict):
        port = config_obj.get("port", 7701)
    cfg = LedgerConfig(port=port)
    app = create_app(cfg)
    uvicorn.run(app, host="0.0.0.0", port=port, workers=1)
