"""Migration Parser & Planner — parses SQL migrations, computes diffs, evaluates gates, manages plans."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import tempfile
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, field_validator


# ── Enums ──────────────────────────────────────────────


class OperationType(str, Enum):
    ADD_COLUMN = "ADD_COLUMN"
    DROP_COLUMN = "DROP_COLUMN"
    ALTER_COLUMN = "ALTER_COLUMN"


class GateDecision(str, Enum):
    AUTO_PROCEED = "AUTO_PROCEED"
    HUMAN_GATE = "HUMAN_GATE"
    BLOCKED = "BLOCKED"


class PlanStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class ViolationSeverity(str, Enum):
    INFO = "INFO"
    WARN = "WARN"
    BLOCK = "BLOCK"


# Severity ordering for GateDecision
_GATE_SEVERITY: dict[GateDecision, int] = {
    GateDecision.AUTO_PROCEED: 0,
    GateDecision.HUMAN_GATE: 1,
    GateDecision.BLOCKED: 2,
}


# ── Data Models ────────────────────────────────────────


class ColumnConstraint(BaseModel):
    model_config = ConfigDict(frozen=False)
    constraint_type: str
    value: Optional[str] = None


class ColumnOperation(BaseModel):
    model_config = ConfigDict(frozen=False)
    op_type: OperationType
    table_name: str
    column_name: str
    new_type: Optional[str] = None
    old_type: Optional[str] = None
    constraints: list[ColumnConstraint] = []


class ParseWarning(BaseModel):
    model_config = ConfigDict(frozen=False)
    line_number: int
    message: str
    raw_statement: Optional[str] = None


class ParsedMigration(BaseModel):
    model_config = ConfigDict(frozen=False)
    operations: list[ColumnOperation]
    source_path: str
    source_hash: str
    statement_count: int
    warnings: list[ParseWarning] = []


class FieldAnnotation(BaseModel):
    model_config = ConfigDict(frozen=False)
    classification_tier: str
    is_audit_field: bool
    is_immutable: bool
    is_encrypted: bool


class DiffEntry(BaseModel):
    model_config = ConfigDict(frozen=False)
    operation: ColumnOperation
    annotation: Optional[FieldAnnotation] = None
    is_new_field: bool
    is_field_removal: bool


class SchemaDiff(BaseModel):
    model_config = ConfigDict(frozen=False)
    entries: list[DiffEntry]
    affected_tables: list[str]
    source_path: str
    source_hash: str


class GateViolation(BaseModel):
    model_config = ConfigDict(frozen=False)
    rule_id: str
    severity: GateDecision
    table_name: str
    column_name: str
    message: str
    context: dict = {}


class GateRuleEntry(BaseModel):
    model_config = ConfigDict(frozen=False)
    condition_type: str
    decision: GateDecision
    description: str


class ComponentContext(BaseModel):
    model_config = ConfigDict(frozen=False)
    component_id: str
    declared_data_access_tiers: list[str]


class MigrationPlan(BaseModel):
    model_config = ConfigDict(frozen=False)
    plan_id: str
    schema_version: int
    diff: SchemaDiff
    violations: list[GateViolation]
    overall_gate: GateDecision
    blast_radius: list[str]
    status: PlanStatus
    created_at: str
    updated_at: str
    source_path: str
    source_hash: str


class ApprovalRecord(BaseModel):
    model_config = ConfigDict(frozen=False)
    plan_id: str
    reviewer: str
    review_reference: str
    rationale: str
    timestamp: str
    new_status: PlanStatus


# ── Error Types ────────────────────────────────────────


class MigrationParseError(Exception):
    def __init__(self, source_path: str, message: str, line_number: int | None = None,
                 raw_content: str | None = None):
        self.source_path = source_path
        self.message = message
        self.line_number = line_number
        self.raw_content = raw_content
        super().__init__(message)


class PlanNotFoundError(Exception):
    def __init__(self, plan_id: str, search_path: str):
        self.plan_id = plan_id
        self.search_path = search_path
        super().__init__(f"Plan {plan_id} not found in {search_path}")


class InvalidPlanTransitionError(Exception):
    def __init__(self, plan_id: str, current_status: PlanStatus,
                 requested_status: PlanStatus, message: str):
        self.plan_id = plan_id
        self.current_status = current_status
        self.requested_status = requested_status
        self.message = message
        super().__init__(message)


class PlanPersistenceError(Exception):
    def __init__(self, plan_id: str, target_path: str, message: str):
        self.plan_id = plan_id
        self.target_path = target_path
        self.message = message
        super().__init__(message)


# ── Gate Rule Table ────────────────────────────────────

GATE_RULES: list[GateRuleEntry] = [
    GateRuleEntry(
        condition_type="audit_field_drop",
        decision=GateDecision.BLOCKED,
        description="Dropping an audit field is blocked",
    ),
    GateRuleEntry(
        condition_type="immutable_modify",
        decision=GateDecision.BLOCKED,
        description="Modifying an immutable field is blocked",
    ),
    GateRuleEntry(
        condition_type="encryption_removal",
        decision=GateDecision.HUMAN_GATE,
        description="Removing encryption from a field requires human review",
    ),
    GateRuleEntry(
        condition_type="tier_mismatch",
        decision=GateDecision.HUMAN_GATE,
        description="Classification tier not in component declared data access tiers",
    ),
    GateRuleEntry(
        condition_type="public_only_change",
        decision=GateDecision.AUTO_PROCEED,
        description="PUBLIC-only change to declared-PUBLIC component",
    ),
]

_RULE_MAP: dict[str, GateRuleEntry] = {r.condition_type: r for r in GATE_RULES}


# ── SQL Parsing ────────────────────────────────────────

_RE_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_RE_LINE_COMMENT = re.compile(r"--[^\n]*")

# ALTER TABLE <table> ADD COLUMN <col> <type> [constraints...];
_RE_ADD_COL = re.compile(
    r"ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(\S+)\s+ADD\s+(?:COLUMN\s+)?(\S+)\s+(.+)",
    re.IGNORECASE,
)
# ALTER TABLE <table> DROP COLUMN <col>
_RE_DROP_COL = re.compile(
    r"ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(\S+)\s+DROP\s+(?:COLUMN\s+)?(\S+)",
    re.IGNORECASE,
)
# ALTER TABLE <table> ALTER COLUMN <col> [SET DATA] TYPE <type>
_RE_ALTER_COL = re.compile(
    r"ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(\S+)\s+ALTER\s+(?:COLUMN\s+)?(\S+)\s+(?:SET\s+DATA\s+)?TYPE\s+(.+)",
    re.IGNORECASE,
)

# Constraint patterns
_RE_NOT_NULL = re.compile(r"\bNOT\s+NULL\b", re.IGNORECASE)
_RE_DEFAULT = re.compile(r"\bDEFAULT\s+(.+?)(?:\s+(?:NOT\s+NULL|UNIQUE|PRIMARY\s+KEY|REFERENCES|CHECK)\b|$)", re.IGNORECASE)
_RE_UNIQUE = re.compile(r"\bUNIQUE\b", re.IGNORECASE)
_RE_PRIMARY_KEY = re.compile(r"\bPRIMARY\s+KEY\b", re.IGNORECASE)
_RE_REFERENCES = re.compile(r"\bREFERENCES\s+(\S+)", re.IGNORECASE)
_RE_CHECK = re.compile(r"\bCHECK\s*\(([^)]+)\)", re.IGNORECASE)


def _strip_comments(sql: str) -> str:
    sql = _RE_BLOCK_COMMENT.sub("", sql)
    sql = _RE_LINE_COMMENT.sub("", sql)
    return sql


def _extract_constraints(remainder: str) -> list[ColumnConstraint]:
    constraints: list[ColumnConstraint] = []
    if _RE_NOT_NULL.search(remainder):
        constraints.append(ColumnConstraint(constraint_type="NOT_NULL"))
    m = _RE_DEFAULT.search(remainder)
    if m:
        constraints.append(ColumnConstraint(constraint_type="DEFAULT", value=m.group(1).strip().rstrip(",")))
    if _RE_UNIQUE.search(remainder):
        constraints.append(ColumnConstraint(constraint_type="UNIQUE"))
    if _RE_PRIMARY_KEY.search(remainder):
        constraints.append(ColumnConstraint(constraint_type="PRIMARY_KEY"))
    m = _RE_REFERENCES.search(remainder)
    if m:
        constraints.append(ColumnConstraint(constraint_type="REFERENCES", value=m.group(1)))
    m = _RE_CHECK.search(remainder)
    if m:
        constraints.append(ColumnConstraint(constraint_type="CHECK", value=m.group(1)))
    return constraints


def _extract_type_and_constraints(raw: str) -> tuple[str, list[ColumnConstraint]]:
    """Split a type+constraints string like 'VARCHAR(255) NOT NULL DEFAULT ...' into type and constraints."""
    raw = raw.strip().rstrip(";").strip()

    # Find where the type ends and constraints begin
    # Type can include parenthesized parts like VARCHAR(255) or NUMERIC(10,2)
    # Constraints start with known keywords
    constraint_keywords = re.compile(
        r"\b(NOT\s+NULL|DEFAULT|UNIQUE|PRIMARY\s+KEY|REFERENCES|CHECK)\b",
        re.IGNORECASE,
    )
    m = constraint_keywords.search(raw)
    if m:
        type_part = raw[:m.start()].strip()
        constraint_part = raw[m.start():]
    else:
        type_part = raw
        constraint_part = ""

    constraints = _extract_constraints(constraint_part) if constraint_part else []
    return type_part, constraints


def _split_sql_clauses(sql: str, delimiter: str) -> list[str]:
    """Split only outside quoted literals/identifiers and parenthesized types."""
    parts = []
    start = 0
    depth = 0
    quote = None
    index = 0
    while index < len(sql):
        char = sql[index]
        if quote:
            if char == quote:
                if index + 1 < len(sql) and sql[index + 1] == quote:
                    index += 1
                else:
                    quote = None
        elif char in ("'", '"', "`"):
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth = max(0, depth - 1)
        elif char == delimiter and depth == 0:
            parts.append(sql[start:index].strip())
            start = index + 1
        index += 1
    parts.append(sql[start:].strip())
    return [part for part in parts if part]


def parse_migration(sql: str, source_path: str) -> ParsedMigration:
    """Parse SQL migration file using regex extraction."""
    if not sql or not sql.strip():
        raise MigrationParseError(source_path=source_path, message="SQL content is empty or contains only comments")

    # Check for replacement characters indicating encoding issues
    if "\ufffd" in sql:
        raise MigrationParseError(source_path=source_path, message="SQL content contains invalid characters")

    source_hash = hashlib.sha256(sql.encode()).hexdigest()

    stripped = _strip_comments(sql)

    if not stripped.strip():
        raise MigrationParseError(source_path=source_path, message="SQL content is empty or contains only comments")

    # Split on semicolons to get statements
    raw_statements = _split_sql_clauses(stripped, ";")
    statement_count = len(raw_statements)

    operations: list[ColumnOperation] = []
    warnings: list[ParseWarning] = []

    # Expand comma-separated ALTER actions while preserving statement count.
    statements = []
    for statement in raw_statements:
        match = re.match(r"(ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?\S+)\s+(.+)",
                         statement, re.IGNORECASE | re.DOTALL)
        if match:
            statements.extend(f"{match.group(1)} {clause}"
                              for clause in _split_sql_clauses(match.group(2), ","))
        else:
            statements.append(statement)

    # Track line numbers for statements
    for stmt in statements:
        # Try ADD COLUMN
        m = _RE_ADD_COL.match(stmt)
        if m:
            table_name = m.group(1)
            column_name = m.group(2)
            remainder = m.group(3)
            new_type, constraints = _extract_type_and_constraints(remainder)
            operations.append(ColumnOperation(
                op_type=OperationType.ADD_COLUMN,
                table_name=table_name,
                column_name=column_name,
                new_type=new_type,
                constraints=constraints,
            ))
            continue

        # Try DROP COLUMN
        m = _RE_DROP_COL.match(stmt)
        if m:
            table_name = m.group(1)
            column_name = m.group(2).rstrip(";").strip()
            operations.append(ColumnOperation(
                op_type=OperationType.DROP_COLUMN,
                table_name=table_name,
                column_name=column_name,
            ))
            continue

        # Try ALTER COLUMN TYPE
        m = _RE_ALTER_COL.match(stmt)
        if m:
            table_name = m.group(1)
            column_name = m.group(2)
            new_type = m.group(3).strip().rstrip(";").strip()
            operations.append(ColumnOperation(
                op_type=OperationType.ALTER_COLUMN,
                table_name=table_name,
                column_name=column_name,
                new_type=new_type,
            ))
            continue

        # Non-ALTER statement — count it but no operation
        # Could generate a warning for unrecognized ALTER TABLE statements
        if re.match(r"ALTER\s+TABLE", stmt, re.IGNORECASE):
            # ALTER TABLE but not recognized pattern
            line_num = _find_line_number(sql, stmt)
            warnings.append(ParseWarning(
                line_number=line_num,
                message=f"Unrecognized ALTER TABLE statement",
                raw_statement=stmt,
            ))

    return ParsedMigration(
        operations=operations,
        source_path=source_path,
        source_hash=source_hash,
        statement_count=statement_count,
        warnings=warnings,
    )


def _find_line_number(full_sql: str, fragment: str) -> int:
    idx = full_sql.find(fragment[:30]) if len(fragment) >= 30 else full_sql.find(fragment)
    if idx < 0:
        return 1
    return full_sql[:idx].count("\n") + 1


# ── Diff Computation ───────────────────────────────────


def compute_diff(parsed: ParsedMigration, registry: Any) -> SchemaDiff:
    """Compute schema diff between parsed migration and registry state."""
    if not parsed.operations:
        raise ValueError("Cannot compute diff from a migration with zero operations")

    entries: list[DiffEntry] = []

    for op in parsed.operations:
        try:
            annotation = registry.get_field_annotation(op.table_name, op.column_name)
        except Exception as e:
            raise MigrationParseError(
                source_path=parsed.source_path,
                message=f"Failed to retrieve registry data for table {op.table_name}",
            ) from e

        is_new_field = (op.op_type == OperationType.ADD_COLUMN and annotation is None)
        is_field_removal = (op.op_type == OperationType.DROP_COLUMN and annotation is not None)

        entries.append(DiffEntry(
            operation=op,
            annotation=annotation,
            is_new_field=is_new_field,
            is_field_removal=is_field_removal,
        ))

    # Deduplicated affected tables preserving order
    seen: set[str] = set()
    affected_tables: list[str] = []
    for op in parsed.operations:
        if op.table_name not in seen:
            seen.add(op.table_name)
            affected_tables.append(op.table_name)

    return SchemaDiff(
        entries=entries,
        affected_tables=affected_tables,
        source_path=parsed.source_path,
        source_hash=parsed.source_hash,
    )


# ── Gate Evaluation ────────────────────────────────────


def evaluate_gates(diff: SchemaDiff, component_context: ComponentContext) -> list[GateViolation]:
    """Evaluate gate rules against all diff entries. Returns ALL violations, never short-circuits."""
    if not diff.entries:
        raise ValueError("Cannot evaluate gates on an empty diff")

    violations: list[GateViolation] = []
    declared_tiers = set(component_context.declared_data_access_tiers)

    for entry in diff.entries:
        op = entry.operation
        ann = entry.annotation

        if ann is None:
            continue

        # audit_field_drop: dropping an audit field
        if ann.is_audit_field and op.op_type == OperationType.DROP_COLUMN:
            rule = _RULE_MAP["audit_field_drop"]
            violations.append(GateViolation(
                rule_id=rule.condition_type,
                severity=rule.decision,
                table_name=op.table_name,
                column_name=op.column_name,
                message=f"Cannot drop audit field {op.column_name} on {op.table_name}",
                context={"is_audit_field": True},
            ))

        # immutable_modify: modifying an immutable field
        if ann.is_immutable and op.op_type == OperationType.ALTER_COLUMN:
            rule = _RULE_MAP["immutable_modify"]
            violations.append(GateViolation(
                rule_id=rule.condition_type,
                severity=rule.decision,
                table_name=op.table_name,
                column_name=op.column_name,
                message=f"Cannot modify immutable field {op.column_name} on {op.table_name}",
                context={"is_immutable": True},
            ))

        # encryption_removal: altering an encrypted field
        if ann.is_encrypted and op.op_type == OperationType.ALTER_COLUMN:
            rule = _RULE_MAP["encryption_removal"]
            violations.append(GateViolation(
                rule_id=rule.condition_type,
                severity=rule.decision,
                table_name=op.table_name,
                column_name=op.column_name,
                message=f"Removing encryption from field {op.column_name} on {op.table_name} requires review",
                context={"is_encrypted": True},
            ))

        # tier_mismatch: classification tier not in component's declared tiers
        if ann.classification_tier not in declared_tiers:
            rule = _RULE_MAP["tier_mismatch"]
            violations.append(GateViolation(
                rule_id=rule.condition_type,
                severity=rule.decision,
                table_name=op.table_name,
                column_name=op.column_name,
                message=f"Classification tier {ann.classification_tier} not in declared access tiers {sorted(declared_tiers)}",
                context={"classification_tier": ann.classification_tier, "declared_tiers": sorted(declared_tiers)},
            ))

    # Sort by severity descending
    violations.sort(key=lambda v: _GATE_SEVERITY.get(v.severity, 0), reverse=True)
    return violations


# ── Plan Creation ──────────────────────────────────────


def _max_gate(violations: list[GateViolation]) -> GateDecision:
    if not violations:
        return GateDecision.AUTO_PROCEED
    return max(violations, key=lambda v: _GATE_SEVERITY[v.severity]).severity


def _atomic_write_json(path: str, data: dict, plan_id: str) -> None:
    """Write JSON atomically: write to temp file then rename."""
    dir_path = os.path.dirname(path)
    try:
        fd, tmp_path = tempfile.mkstemp(dir=dir_path, suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(data, f, indent=2)
            os.replace(tmp_path, path)
        except Exception:
            # Clean up temp file on failure
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
    except Exception as e:
        raise PlanPersistenceError(
            plan_id=plan_id,
            target_path=path,
            message=f"Atomic write of plan file failed: {e}",
        ) from e


def create_plan(
    diff: SchemaDiff,
    violations: list[GateViolation],
    registry: Any,
    plans_dir: str,
) -> MigrationPlan:
    """Create a migration plan, compute blast radius, persist to disk."""
    # Validate plans_dir exists and is writable
    if not os.path.isdir(plans_dir):
        raise PlanPersistenceError(
            plan_id="<new>",
            target_path=plans_dir,
            message="Cannot write to plans directory",
        )

    # Compute blast radius: affected tables + single-hop FK
    blast_radius_set: set[str] = set(diff.affected_tables)
    for table in diff.affected_tables:
        try:
            fk_tables = registry.get_foreign_keys(table)
            blast_radius_set.update(fk_tables)
        except Exception as e:
            raise MigrationParseError(
                source_path=diff.source_path,
                message=f"Failed to retrieve FK annotations for blast radius computation: {e}",
            ) from e

    plan_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    overall_gate = _max_gate(violations)

    plan = MigrationPlan(
        plan_id=plan_id,
        schema_version=1,
        diff=diff,
        violations=violations,
        overall_gate=overall_gate,
        blast_radius=sorted(blast_radius_set),
        status=PlanStatus.PENDING,
        created_at=now,
        updated_at=now,
        source_path=diff.source_path,
        source_hash=diff.source_hash,
    )

    plan_path = os.path.join(plans_dir, f"{plan_id}.json")
    _atomic_write_json(plan_path, plan.model_dump(mode="json"), plan_id)

    return plan


# ── Plan Loading ───────────────────────────────────────


def load_plan(plan_id: str, plans_dir: str) -> MigrationPlan:
    """Load a persisted migration plan from disk."""
    plan_path = os.path.join(plans_dir, f"{plan_id}.json")

    if not os.path.exists(plan_path):
        raise PlanNotFoundError(plan_id=plan_id, search_path=plans_dir)

    try:
        with open(plan_path, "r") as f:
            raw = f.read()
    except PermissionError as e:
        raise PlanPersistenceError(
            plan_id=plan_id,
            target_path=plan_path,
            message=f"Cannot read plan file: {e}",
        ) from e
    except Exception as e:
        raise PlanPersistenceError(
            plan_id=plan_id,
            target_path=plan_path,
            message=f"Cannot read plan file: {e}",
        ) from e

    if not raw.strip():
        raise MigrationParseError(
            source_path=plan_path,
            message="Plan file is corrupted or has incompatible schema version",
        )

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise MigrationParseError(
            source_path=plan_path,
            message=f"Plan file is corrupted or has incompatible schema version: {e}",
        ) from e

    try:
        return MigrationPlan.model_validate(data)
    except Exception as e:
        raise MigrationParseError(
            source_path=plan_path,
            message=f"Plan file is corrupted or has incompatible schema version: {e}",
        ) from e


# ── Plan Approval ──────────────────────────────────────


def approve_plan(
    plan_id: str,
    reviewer: str,
    review_ref: str,
    rationale: str,
    plans_dir: str,
) -> MigrationPlan:
    """Serialize approval and its audit record across processes."""
    if not os.path.isdir(plans_dir):
        raise PlanNotFoundError(plan_id=plan_id, search_path=plans_dir)
    lock_path = os.path.join(plans_dir, ".approval.lock")
    try:
        with open(lock_path, "a") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            return _approve_plan_locked(plan_id, reviewer, review_ref, rationale, plans_dir)
    except OSError as exc:
        raise PlanPersistenceError(plan_id=plan_id, target_path=plans_dir,
                                   message=f"Cannot persist approval: {exc}") from exc


def _approve_plan_locked(
    plan_id: str,
    reviewer: str,
    review_ref: str,
    rationale: str,
    plans_dir: str,
) -> MigrationPlan:
    """Approve a HUMAN_GATE PENDING plan."""
    plan = load_plan(plan_id, plans_dir)

    # Check status transitions
    if plan.status == PlanStatus.APPROVED:
        raise InvalidPlanTransitionError(
            plan_id=plan_id,
            current_status=PlanStatus.APPROVED,
            requested_status=PlanStatus.APPROVED,
            message="Plan is already approved",
        )

    if plan.status == PlanStatus.REJECTED:
        raise InvalidPlanTransitionError(
            plan_id=plan_id,
            current_status=PlanStatus.REJECTED,
            requested_status=PlanStatus.APPROVED,
            message="Cannot approve a rejected plan",
        )

    # Check gate constraints
    if plan.overall_gate == GateDecision.BLOCKED:
        raise InvalidPlanTransitionError(
            plan_id=plan_id,
            current_status=PlanStatus.PENDING,
            requested_status=PlanStatus.APPROVED,
            message="Cannot approve a BLOCKED plan — migration must be modified to remove blocking violations",
        )

    if plan.overall_gate == GateDecision.AUTO_PROCEED:
        raise InvalidPlanTransitionError(
            plan_id=plan_id,
            current_status=PlanStatus.PENDING,
            requested_status=PlanStatus.APPROVED,
            message="AUTO_PROCEED plans do not require manual approval",
        )

    # Transition to APPROVED
    now = datetime.now(timezone.utc).isoformat()
    plan.status = PlanStatus.APPROVED
    plan.updated_at = now

    # Persist updated plan
    plan_path = os.path.join(plans_dir, f"{plan_id}.json")
    record = ApprovalRecord(
        plan_id=plan_id, reviewer=reviewer, review_reference=review_ref,
        rationale=rationale, timestamp=now, new_status=PlanStatus.APPROVED,
    )
    changelog_path = os.path.join(plans_dir, "changelog.jsonl")
    with open(changelog_path, "a+") as changelog:
        changelog.seek(0, os.SEEK_END)
        original_size = changelog.tell()
        try:
            changelog.write(record.model_dump_json() + "\n")
            changelog.flush()
            os.fsync(changelog.fileno())
            _atomic_write_json(plan_path, plan.model_dump(mode="json"), plan_id)
        except Exception:
            changelog.truncate(original_size)
            changelog.flush()
            os.fsync(changelog.fileno())
            raise

    return plan
