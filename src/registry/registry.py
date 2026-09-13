"""Registry & Schema Store — manages .ledger/ directory, backend registration, schema storage."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, ConfigDict, field_validator


# ── Enums ─────────────────────────────────────────────

class BackendType(str, Enum):
    postgres = "postgres"
    mysql = "mysql"
    sqlite = "sqlite"
    redis = "redis"
    s3 = "s3"
    dynamodb = "dynamodb"
    kafka = "kafka"
    custom = "custom"


class ViolationSeverity(str, Enum):
    error = "error"
    warning = "warning"


class ChangeType(str, Enum):
    backend_registered = "backend_registered"
    schema_added = "schema_added"


# ── Exceptions ────────────────────────────────────────

class LedgerError(Exception):
    def __init__(self, message: str):
        self.message = message
        super().__init__(message)


class LedgerNotInitializedError(LedgerError):
    def __init__(self, message: str, root: str):
        self.root = root
        super().__init__(message)


class LedgerCorruptedError(LedgerError):
    def __init__(self, message: str, missing_paths: list[str]):
        self.missing_paths = missing_paths
        super().__init__(message)


class DuplicateBackendError(LedgerError):
    def __init__(self, message: str, backend_id: str):
        self.backend_id = backend_id
        super().__init__(message)


class OwnershipConflictError(LedgerError):
    def __init__(self, message: str, backend_id: str, existing_owner: str, attempted_owner: str):
        self.backend_id = backend_id
        self.existing_owner = existing_owner
        self.attempted_owner = attempted_owner
        super().__init__(message)


class BackendNotFoundError(LedgerError):
    def __init__(self, message: str, backend_id: str):
        self.backend_id = backend_id
        super().__init__(message)


class SchemaParseError(LedgerError):
    def __init__(self, message: str, backend_id: str, table: str, parse_error: str):
        self.backend_id = backend_id
        self.table = table
        self.parse_error = parse_error
        super().__init__(message)


# ── Models ────────────────────────────────────────────

BACKEND_ID_RE = re.compile(r"^[a-z][a-z0-9_-]{1,62}[a-z0-9]$")


class BackendMetadata(BaseModel):
    model_config = ConfigDict(frozen=True)

    backend_id: str
    backend_type: BackendType
    owner_component: str
    registered_at: datetime

    @field_validator("backend_id")
    @classmethod
    def _validate_backend_id(cls, v: str) -> str:
        if not BACKEND_ID_RE.match(v):
            raise ValueError(f"backend_id must match {BACKEND_ID_RE.pattern}, got {v!r}")
        return v


class SchemaRecord(BaseModel):
    backend_id: str
    table_name: str
    raw_content: bytes
    parsed_content: dict
    stored_at: datetime


class Violation(BaseModel):
    model_config = ConfigDict(frozen=True)

    severity: ViolationSeverity
    rule: str
    backend_id: str
    table: Optional[str] = None
    field: Optional[str] = None
    message: str


class ValidationResult(BaseModel):
    violations: list[Violation]
    valid: bool


class ChangelogEntry(BaseModel):
    model_config = ConfigDict(frozen=True)

    timestamp: datetime
    sequence: int
    actor: str
    change_type: ChangeType
    backend_id: str
    table: Optional[str] = None
    field: Optional[str] = None
    detail: Optional[str] = None


# ── Helpers ───────────────────────────────────────────

def _ledger_dir(root: Path) -> Path:
    return Path(root) / ".ledger"


def _require_initialized(root: Path) -> Path:
    """Return .ledger/ path or raise LedgerNotInitializedError."""
    ld = _ledger_dir(root)
    if not ld.is_dir():
        raise LedgerNotInitializedError(
            message=f".ledger/ directory not found at {root}",
            root=str(root),
        )
    return ld


def _changelog_path(ld: Path) -> Path:
    return ld / "changelog.jsonl"


def _next_sequence(ld: Path) -> int:
    """Compute next sequence number by counting existing lines."""
    cl = _changelog_path(ld)
    if not cl.exists() or cl.stat().st_size == 0:
        return 1
    count = 0
    with open(cl, "r") as f:
        for _ in f:
            count += 1
    return count + 1


def _append_changelog(ld: Path, entry: ChangelogEntry) -> None:
    cl = _changelog_path(ld)
    line = entry.model_dump_json() + "\n"
    with open(cl, "a") as f:
        f.write(line)


def _load_backend_metadata(yaml_file: Path) -> BackendMetadata:
    data = yaml.safe_load(yaml_file.read_text())
    return BackendMetadata(**data)


# ── Public API ────────────────────────────────────────

def init(root: Path) -> None:
    root = Path(root)
    ld = root / ".ledger"

    if ld.exists():
        # Check for corruption: all three must exist
        registry = ld / "registry"
        plans = ld / "plans"
        changelog = ld / "changelog.jsonl"
        expected = {
            str(registry): registry.is_dir(),
            str(plans): plans.is_dir(),
            str(changelog): changelog.is_file(),
        }
        missing = [p for p, ok in expected.items() if not ok]
        if missing:
            raise LedgerCorruptedError(
                message=f".ledger/ is corrupted, missing: {missing}",
                missing_paths=missing,
            )
        # Already fully initialized — idempotent no-op
        return

    # Fresh creation
    ld.mkdir(parents=True)
    (ld / "registry").mkdir()
    (ld / "plans").mkdir()
    (ld / "changelog.jsonl").touch()


def register_backend(root: Path, metadata: BackendMetadata, actor: str) -> ChangelogEntry:
    ld = _require_initialized(root)
    registry_dir = ld / "registry"
    yaml_file = registry_dir / f"{metadata.backend_id}.yaml"

    # Check duplicate
    if yaml_file.exists():
        existing = _load_backend_metadata(yaml_file)
        if existing.owner_component != metadata.owner_component:
            raise OwnershipConflictError(
                message=f"Backend {metadata.backend_id} already owned by {existing.owner_component}",
                backend_id=metadata.backend_id,
                existing_owner=existing.owner_component,
                attempted_owner=metadata.owner_component,
            )
        raise DuplicateBackendError(
            message=f"Backend {metadata.backend_id} already registered",
            backend_id=metadata.backend_id,
        )

    # Write metadata YAML
    data = {
        "backend_id": metadata.backend_id,
        "backend_type": metadata.backend_type.value,
        "owner_component": metadata.owner_component,
        "registered_at": metadata.registered_at.isoformat(),
    }
    yaml_file.write_text(yaml.dump(data, default_flow_style=False))

    # Changelog entry
    seq = _next_sequence(ld)
    entry = ChangelogEntry(
        timestamp=datetime.now(timezone.utc),
        sequence=seq,
        actor=actor,
        change_type=ChangeType.backend_registered,
        backend_id=metadata.backend_id,
    )
    _append_changelog(ld, entry)
    return entry


def store_schema(
    root: Path,
    backend_id: str,
    table: str,
    raw_yaml: bytes,
    actor: str,
) -> ChangelogEntry:
    ld = _require_initialized(root)
    registry_dir = ld / "registry"

    # Check backend exists
    backend_file = registry_dir / f"{backend_id}.yaml"
    if not backend_file.exists():
        raise BackendNotFoundError(
            message=f"Backend {backend_id} not found",
            backend_id=backend_id,
        )

    # Validate YAML is parseable
    try:
        parsed = yaml.safe_load(raw_yaml)
    except yaml.YAMLError as e:
        raise SchemaParseError(
            message=f"Cannot parse schema YAML for {backend_id}/{table}",
            backend_id=backend_id,
            table=table,
            parse_error=str(e),
        )

    # Ensure parsed is a dict (None from empty doc is fine, treat as empty dict)
    if parsed is None:
        parsed = {}
    if not isinstance(parsed, dict):
        parsed = {"_value": parsed}

    # Create backend subdirectory if needed
    backend_dir = registry_dir / backend_id
    backend_dir.mkdir(exist_ok=True)

    # Write raw bytes verbatim
    schema_file = backend_dir / f"{table}.yaml"
    schema_file.write_bytes(raw_yaml)

    # Changelog entry
    seq = _next_sequence(ld)
    entry = ChangelogEntry(
        timestamp=datetime.now(timezone.utc),
        sequence=seq,
        actor=actor,
        change_type=ChangeType.schema_added,
        backend_id=backend_id,
        table=table,
    )
    _append_changelog(ld, entry)
    return entry


def list_backends(root: Path) -> list[BackendMetadata]:
    ld = _require_initialized(root)
    registry_dir = ld / "registry"
    results = []
    for f in sorted(registry_dir.glob("*.yaml")):
        results.append(_load_backend_metadata(f))
    return sorted(results, key=lambda m: m.backend_id)


def list_schemas(root: Path, backend_id: str) -> list[SchemaRecord]:
    ld = _require_initialized(root)
    registry_dir = ld / "registry"

    # Check backend is registered
    backend_file = registry_dir / f"{backend_id}.yaml"
    if not backend_file.exists():
        raise BackendNotFoundError(
            message=f"Backend {backend_id} not found",
            backend_id=backend_id,
        )

    backend_dir = registry_dir / backend_id
    if not backend_dir.is_dir():
        return []

    results = []
    for f in sorted(backend_dir.glob("*.yaml")):
        raw = f.read_bytes()
        parsed = yaml.safe_load(raw)
        if parsed is None:
            parsed = {}
        if not isinstance(parsed, dict):
            parsed = {"_value": parsed}
        table_name = f.stem
        results.append(SchemaRecord(
            backend_id=backend_id,
            table_name=table_name,
            raw_content=raw,
            parsed_content=parsed,
            stored_at=datetime.fromtimestamp(f.stat().st_mtime, tz=timezone.utc),
        ))
    return sorted(results, key=lambda r: r.table_name)


def get_schema(root: Path, backend_id: str, table: str) -> SchemaRecord | None:
    ld = _require_initialized(root)
    registry_dir = ld / "registry"
    schema_file = registry_dir / backend_id / f"{table}.yaml"
    if not schema_file.exists():
        return None

    raw = schema_file.read_bytes()
    parsed = yaml.safe_load(raw)
    if parsed is None:
        parsed = {}
    if not isinstance(parsed, dict):
        parsed = {"_value": parsed}

    return SchemaRecord(
        backend_id=backend_id,
        table_name=table,
        raw_content=raw,
        parsed_content=parsed,
        stored_at=datetime.fromtimestamp(schema_file.stat().st_mtime, tz=timezone.utc),
    )


def validate_all(root: Path) -> ValidationResult:
    ld = _require_initialized(root)
    violations: list[Violation] = []

    # Load all backends
    backends = list_backends(root)

    # Check ownership exclusivity: no two components own the same backend
    # (Already enforced on write, but validate_all re-checks from disk)
    seen_owners: dict[str, str] = {}
    for bm in backends:
        if bm.backend_id in seen_owners:
            violations.append(Violation(
                severity=ViolationSeverity.error,
                rule="ownership_exclusive",
                backend_id=bm.backend_id,
                message=f"Backend {bm.backend_id} has duplicate registration",
            ))
        seen_owners[bm.backend_id] = bm.owner_component

    # Check schemas for annotation conflicts and REQUIRES satisfaction
    for bm in backends:
        try:
            schemas = list_schemas(root, bm.backend_id)
        except BackendNotFoundError:
            continue
        for schema in schemas:
            _check_schema_violations(bm.backend_id, schema, violations)

    has_errors = any(v.severity == ViolationSeverity.error for v in violations)
    return ValidationResult(violations=violations, valid=not has_errors)


def _check_schema_violations(
    backend_id: str, schema: SchemaRecord, violations: list[Violation]
) -> None:
    """Check a single schema for annotation conflict pairs and REQUIRES satisfaction."""
    content = schema.parsed_content
    if not isinstance(content, dict):
        return

    # Look for fields with annotations
    columns = content.get("columns") or content.get("fields") or {}
    if not isinstance(columns, dict):
        return

    # Annotation conflict pairs
    conflict_pairs = [
        ("pii", "public"),
        ("encrypted_at_rest", "public"),
        ("immutable", "mutable"),
    ]

    for field_name, field_def in columns.items():
        if not isinstance(field_def, dict):
            continue
        annotations = field_def.get("annotations", [])
        if not isinstance(annotations, list):
            continue
        ann_set = set(annotations)

        # Check conflict pairs
        for a, b in conflict_pairs:
            if a in ann_set and b in ann_set:
                violations.append(Violation(
                    severity=ViolationSeverity.error,
                    rule="annotation_conflict",
                    backend_id=backend_id,
                    table=schema.table_name,
                    field=field_name,
                    message=f"Annotations '{a}' and '{b}' are mutually exclusive",
                ))

        # Check REQUIRES satisfaction
        requires_map = {
            "pii": {"requires": ["classification"], "severity": "warning"},
            "encrypted_at_rest": {"requires": ["classification"], "severity": "warning"},
            "audit_field": {"requires": ["retention_days"], "severity": "warning"},
        }
        for ann in annotations:
            if ann in requires_map:
                req = requires_map[ann]
                for required_ann in req["requires"]:
                    if required_ann not in ann_set:
                        sev = (ViolationSeverity.warning
                               if req["severity"] == "warning"
                               else ViolationSeverity.error)
                        violations.append(Violation(
                            severity=sev,
                            rule="requires_unsatisfied",
                            backend_id=backend_id,
                            table=schema.table_name,
                            field=field_name,
                            message=f"Annotation '{ann}' requires '{required_ann}'",
                        ))


def read_changelog(
    root: Path,
    backend_id: str | None = None,
    limit: int = 0,
) -> list[ChangelogEntry]:
    ld = _require_initialized(root)
    cl = _changelog_path(ld)

    entries: list[ChangelogEntry] = []
    if not cl.exists() or cl.stat().st_size == 0:
        return entries

    with open(cl, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            data = json.loads(line)
            entry = ChangelogEntry(**data)
            # Filter by backend_id if provided (non-empty string)
            if backend_id and entry.backend_id != backend_id:
                continue
            entries.append(entry)

    # Sort by sequence ascending
    entries.sort(key=lambda e: e.sequence)

    # Apply limit (most recent first when limited, but return ascending)
    if limit > 0 and len(entries) > limit:
        entries = entries[-limit:]

    return entries
