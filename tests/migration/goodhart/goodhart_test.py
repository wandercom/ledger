
"""
Adversarial hidden acceptance tests for Migration Parser & Planner component.
These tests target gaps in visible test coverage to detect implementations that
hardcode returns or take shortcuts matching only visible test inputs.
"""
import hashlib
import json
import os
import tempfile
import uuid
from datetime import datetime
from unittest.mock import MagicMock, PropertyMock, patch

import pytest

from src.migration import (
    ApprovalRecord,
    ColumnConstraint,
    ColumnOperation,
    ComponentContext,
    DiffEntry,
    FieldAnnotation,
    GateDecision,
    GateViolation,
    InvalidPlanTransitionError,
    MigrationParseError,
    MigrationPlan,
    OperationType,
    ParsedMigration,
    PlanNotFoundError,
    PlanPersistenceError,
    PlanStatus,
    SchemaDiff,
    approve_plan,
    compute_diff,
    create_plan,
    evaluate_gates,
    load_plan,
    parse_migration,
)


# ============================================================
# PARSE_MIGRATION TESTS
# ============================================================


class TestGoodhartParseMigration:
    """Adversarial tests for parse_migration function."""

    def test_goodhart_parse_case_insensitive_keywords(self):
        """SQL keywords like ALTER TABLE, ADD COLUMN should be recognized regardless of case."""
        sql = "alter table users add column name varchar(100);"
        result = parse_migration(sql, "/migrations/V001.sql")
        assert len(result.operations) == 1
        op = result.operations[0]
        assert op.op_type == OperationType.ADD_COLUMN
        assert op.table_name.lower() == "users"
        assert op.column_name.lower() == "name"

    def test_goodhart_parse_case_insensitive_mixed(self):
        """Mixed case SQL keywords should be recognized (e.g., Alter Table, Drop Column)."""
        sql = "Alter Table orders Drop Column legacy_flag;"
        result = parse_migration(sql, "/migrations/V002.sql")
        assert len(result.operations) == 1
        assert result.operations[0].op_type == OperationType.DROP_COLUMN

    def test_goodhart_parse_multiple_columns_same_alter(self):
        """A single ALTER TABLE with multiple ADD COLUMN clauses must produce multiple operations."""
        sql = "ALTER TABLE users ADD COLUMN first_name VARCHAR(50), ADD COLUMN last_name VARCHAR(50);"
        result = parse_migration(sql, "/migrations/V003.sql")
        assert len(result.operations) >= 2
        for op in result.operations:
            assert op.op_type == OperationType.ADD_COLUMN
            assert op.table_name.lower() == "users"

    def test_goodhart_parse_schema_qualified_table(self):
        """Schema-qualified table names should be handled in ALTER TABLE statements."""
        sql = "ALTER TABLE public.users ADD COLUMN email VARCHAR(255);"
        result = parse_migration(sql, "/migrations/V004.sql")
        assert len(result.operations) == 1
        op = result.operations[0]
        assert op.op_type == OperationType.ADD_COLUMN
        # table_name should contain the schema-qualified name or at least 'users'
        assert "users" in op.table_name.lower()

    def test_goodhart_parse_statement_count_mixed_types(self):
        """Statement count must reflect ALL semicolon-delimited statements, not just ALTER TABLE."""
        sql = (
            "CREATE TABLE tmp (id INT);\n"
            "INSERT INTO tmp VALUES (1);\n"
            "ALTER TABLE users ADD COLUMN age INT;\n"
            "UPDATE tmp SET id = 2;\n"
            "ALTER TABLE users DROP COLUMN old_field;\n"
        )
        result = parse_migration(sql, "/migrations/V005.sql")
        assert result.statement_count == 5
        assert len(result.operations) == 2
        op_types = {op.op_type for op in result.operations}
        assert OperationType.ADD_COLUMN in op_types
        assert OperationType.DROP_COLUMN in op_types

    def test_goodhart_parse_source_path_passthrough_unusual(self):
        """source_path must be returned exactly as provided, even with unusual characters."""
        unusual_path = "/opt/migrations/2024 Q1/deep/nested/V001__add_cols.sql"
        sql = "ALTER TABLE t ADD COLUMN c INT;"
        result = parse_migration(sql, unusual_path)
        assert result.source_path == unusual_path

    def test_goodhart_parse_hash_deterministic_different_sql(self):
        """Different SQL inputs must produce different SHA-256 hashes."""
        sql1 = "ALTER TABLE a ADD COLUMN x INT;"
        sql2 = "ALTER TABLE b ADD COLUMN y TEXT;"
        result1 = parse_migration(sql1, "/m/v1.sql")
        result2 = parse_migration(sql2, "/m/v2.sql")
        assert result1.source_hash != result2.source_hash
        assert len(result1.source_hash) == 64
        assert len(result2.source_hash) == 64
        assert result1.source_hash == hashlib.sha256(sql1.encode()).hexdigest()
        assert result2.source_hash == hashlib.sha256(sql2.encode()).hexdigest()

    def test_goodhart_parse_hash_includes_comments(self):
        """source_hash is computed on the raw input sql string including comments."""
        sql_with_comments = "-- this is a comment\nALTER TABLE t ADD COLUMN c INT;"
        sql_without_comments = "ALTER TABLE t ADD COLUMN c INT;"
        result_with = parse_migration(sql_with_comments, "/m/v1.sql")
        result_without = parse_migration(sql_without_comments, "/m/v2.sql")
        # Hash should be of raw input
        assert result_with.source_hash == hashlib.sha256(sql_with_comments.encode()).hexdigest()
        assert result_without.source_hash == hashlib.sha256(sql_without_comments.encode()).hexdigest()
        # They should differ since the inputs differ
        assert result_with.source_hash != result_without.source_hash

    def test_goodhart_parse_nested_block_comments(self):
        """Block comments mid-statement should be stripped and parsing should continue."""
        sql = "ALTER TABLE users /* adding email column */ ADD COLUMN email VARCHAR(255);"
        result = parse_migration(sql, "/m/v1.sql")
        assert len(result.operations) == 1
        assert result.operations[0].column_name.lower() == "email"

    def test_goodhart_parse_drop_column_extracts_name(self):
        """DROP COLUMN must correctly extract the column name being dropped."""
        sql = "ALTER TABLE orders DROP COLUMN legacy_status;"
        result = parse_migration(sql, "/m/v1.sql")
        assert len(result.operations) == 1
        op = result.operations[0]
        assert op.op_type == OperationType.DROP_COLUMN
        assert op.column_name.lower() == "legacy_status"
        assert op.table_name.lower() == "orders"

    def test_goodhart_parse_alter_column_type_change(self):
        """ALTER COLUMN TYPE operations should extract column name and new type."""
        sql = "ALTER TABLE products ALTER COLUMN price TYPE NUMERIC(10,2);"
        result = parse_migration(sql, "/m/v1.sql")
        assert len(result.operations) == 1
        op = result.operations[0]
        assert op.op_type == OperationType.ALTER_COLUMN
        assert op.column_name.lower() == "price"
        assert "numeric" in op.new_type.lower() or "NUMERIC" in op.new_type

    def test_goodhart_parse_empty_after_comment_stripping(self):
        """SQL containing only comments (no actual statements) should raise empty_sql error."""
        sql = "/* this is all comments */\n-- and this too\n/* another block */"
        with pytest.raises(MigrationParseError):
            parse_migration(sql, "/m/v1.sql")

    def test_goodhart_parse_constraints_unique(self):
        """UNIQUE constraint should be extracted from ADD COLUMN."""
        sql = "ALTER TABLE users ADD COLUMN username VARCHAR(50) UNIQUE NOT NULL;"
        result = parse_migration(sql, "/m/v1.sql")
        assert len(result.operations) == 1
        constraint_types = [c.constraint_type.upper() for c in result.operations[0].constraints]
        assert "UNIQUE" in constraint_types or "unique" in [c.constraint_type.lower() for c in result.operations[0].constraints]
        assert "NOT NULL" in constraint_types or "not null" in [c.constraint_type.lower() for c in result.operations[0].constraints] or "NOT_NULL" in constraint_types

    def test_goodhart_parse_whitespace_between_keywords(self):
        """Extra whitespace, tabs, and newlines between SQL keywords should not prevent extraction."""
        sql = "ALTER   TABLE\n  users\n  ADD   COLUMN\n  email   VARCHAR(255);"
        result = parse_migration(sql, "/m/v1.sql")
        assert len(result.operations) == 1
        assert result.operations[0].op_type == OperationType.ADD_COLUMN

    def test_goodhart_parse_default_with_value(self):
        """DEFAULT constraint with a specific value should be extracted with the value."""
        sql = "ALTER TABLE users ADD COLUMN status VARCHAR(20) NOT NULL DEFAULT 'active';"
        result = parse_migration(sql, "/m/v1.sql")
        assert len(result.operations) == 1
        constraints = result.operations[0].constraints
        has_default = any("default" in c.constraint_type.lower() for c in constraints)
        has_not_null = any("not" in c.constraint_type.lower() and "null" in c.constraint_type.lower() for c in constraints) or any("not_null" == c.constraint_type.lower() for c in constraints)
        assert has_default, f"DEFAULT constraint not found in {constraints}"
        assert has_not_null, f"NOT NULL constraint not found in {constraints}"

    def test_goodhart_parse_no_operations_but_valid_statements(self):
        """SQL with valid non-ALTER statements should return empty operations and correct statement count."""
        sql = "CREATE TABLE t (id INT);\nINSERT INTO t VALUES (1);\nSELECT 1;"
        result = parse_migration(sql, "/m/v1.sql")
        assert len(result.operations) == 0
        assert result.statement_count == 3

    def test_goodhart_parse_references_constraint(self):
        """REFERENCES constraint (FK) should be extracted from ADD COLUMN."""
        sql = "ALTER TABLE orders ADD COLUMN user_id INTEGER REFERENCES users(id);"
        result = parse_migration(sql, "/m/v1.sql")
        assert len(result.operations) == 1
        constraints = result.operations[0].constraints
        has_references = any("reference" in c.constraint_type.lower() for c in constraints)
        assert has_references, f"REFERENCES constraint not found in {[c.constraint_type for c in constraints]}"

    def test_goodhart_parse_quoted_identifiers(self):
        """Quoted identifiers should be handled for table and column names."""
        sql = 'ALTER TABLE "User" ADD COLUMN "Order" INTEGER;'
        result = parse_migration(sql, "/m/v1.sql")
        assert len(result.operations) >= 1
        op = result.operations[0]
        assert op.op_type == OperationType.ADD_COLUMN

    def test_goodhart_parse_if_exists_clause(self):
        """IF EXISTS / IF NOT EXISTS clauses should not prevent operation extraction."""
        sql = "ALTER TABLE IF EXISTS users ADD COLUMN IF NOT EXISTS email VARCHAR(255);"
        result = parse_migration(sql, "/m/v1.sql")
        # Should extract at least the operation (may or may not strip IF NOT EXISTS)
        assert len(result.operations) >= 1
        op = result.operations[0]
        assert op.op_type == OperationType.ADD_COLUMN
        assert "users" in op.table_name.lower()


# ============================================================
# COMPUTE_DIFF TESTS
# ============================================================


class TestGoodhartComputeDiff:

    def _make_parsed(self, operations, source_path="/m/v1.sql", source_hash="abc123"):
        return ParsedMigration(
            operations=operations,
            source_path=source_path,
            source_hash=source_hash,
            statement_count=len(operations),
            warnings=[],
        )

    def _make_registry(self, field_map=None, raise_on_lookup=False):
        """Create a mock registry.
        field_map: dict of (table, column) -> FieldAnnotation or None
        """
        registry = MagicMock()
        if raise_on_lookup:
            registry.get_field_annotation = MagicMock(side_effect=Exception("registry failure"))
            registry.lookup_field = MagicMock(side_effect=Exception("registry failure"))
        elif field_map is not None:
            def lookup(table, column):
                return field_map.get((table.lower(), column.lower()))
            registry.get_field_annotation = MagicMock(side_effect=lookup)
            registry.lookup_field = MagicMock(side_effect=lookup)
            registry.field_exists = MagicMock(side_effect=lambda t, c: (t.lower(), c.lower()) in field_map and field_map[(t.lower(), c.lower())] is not None)
            registry.has_field = MagicMock(side_effect=lambda t, c: (t.lower(), c.lower()) in field_map and field_map[(t.lower(), c.lower())] is not None)
        return registry

    def test_goodhart_diff_add_column_existing_field_not_new(self):
        """ADD_COLUMN for a field already in registry should have is_new_field=False and annotation populated."""
        annotation = FieldAnnotation(
            classification_tier="INTERNAL",
            is_audit_field=False,
            is_immutable=False,
            is_encrypted=False,
        )
        op = ColumnOperation(
            op_type=OperationType.ADD_COLUMN,
            table_name="users",
            column_name="email",
            new_type="VARCHAR(255)",
            old_type="",
            constraints=[],
        )
        parsed = self._make_parsed([op])
        registry = self._make_registry({("users", "email"): annotation})
        diff = compute_diff(parsed, registry)
        assert len(diff.entries) == 1
        entry = diff.entries[0]
        assert entry.is_new_field is False
        assert entry.annotation is not None

    def test_goodhart_diff_drop_nonexistent_field(self):
        """DROP_COLUMN for a field NOT in registry should have is_field_removal=False."""
        op = ColumnOperation(
            op_type=OperationType.DROP_COLUMN,
            table_name="users",
            column_name="nonexistent",
            new_type="",
            old_type="",
            constraints=[],
        )
        parsed = self._make_parsed([op])
        registry = self._make_registry({})  # empty registry
        diff = compute_diff(parsed, registry)
        assert len(diff.entries) == 1
        entry = diff.entries[0]
        assert entry.is_field_removal is False
        assert entry.annotation is None

    def test_goodhart_diff_alter_column_not_new_not_removal(self):
        """ALTER_COLUMN should never set is_new_field or is_field_removal to True."""
        annotation = FieldAnnotation(
            classification_tier="PUBLIC",
            is_audit_field=False,
            is_immutable=False,
            is_encrypted=False,
        )
        op = ColumnOperation(
            op_type=OperationType.ALTER_COLUMN,
            table_name="users",
            column_name="status",
            new_type="TEXT",
            old_type="VARCHAR(20)",
            constraints=[],
        )
        parsed = self._make_parsed([op])
        registry = self._make_registry({("users", "status"): annotation})
        diff = compute_diff(parsed, registry)
        assert len(diff.entries) == 1
        entry = diff.entries[0]
        assert entry.is_new_field is False
        assert entry.is_field_removal is False

    def test_goodhart_diff_preserves_operation_order(self):
        """DiffEntry ordering must match the exact order of operations, not reordered."""
        ops = [
            ColumnOperation(op_type=OperationType.ADD_COLUMN, table_name="beta", column_name="c1", new_type="INT", old_type="", constraints=[]),
            ColumnOperation(op_type=OperationType.ADD_COLUMN, table_name="alpha", column_name="c2", new_type="INT", old_type="", constraints=[]),
            ColumnOperation(op_type=OperationType.ADD_COLUMN, table_name="gamma", column_name="c3", new_type="INT", old_type="", constraints=[]),
        ]
        parsed = self._make_parsed(ops)
        registry = self._make_registry({})
        diff = compute_diff(parsed, registry)
        assert len(diff.entries) == 3
        assert diff.entries[0].operation.table_name == "beta"
        assert diff.entries[1].operation.table_name == "alpha"
        assert diff.entries[2].operation.table_name == "gamma"

    def test_goodhart_diff_multiple_ops_same_table(self):
        """Multiple operations on same table produce multiple entries but table appears once in affected_tables."""
        ops = [
            ColumnOperation(op_type=OperationType.ADD_COLUMN, table_name="users", column_name="a", new_type="INT", old_type="", constraints=[]),
            ColumnOperation(op_type=OperationType.DROP_COLUMN, table_name="users", column_name="b", new_type="", old_type="", constraints=[]),
            ColumnOperation(op_type=OperationType.ALTER_COLUMN, table_name="users", column_name="c", new_type="TEXT", old_type="INT", constraints=[]),
        ]
        parsed = self._make_parsed(ops)
        registry = self._make_registry({})
        diff = compute_diff(parsed, registry)
        assert len(diff.entries) == 3
        assert len(diff.affected_tables) == 1
        assert "users" in [t.lower() for t in diff.affected_tables]


# ============================================================
# EVALUATE_GATES TESTS
# ============================================================


class TestGoodhartEvaluateGates:

    def _make_diff_entry(self, op_type, table, column, annotation, is_new=False, is_removal=False):
        op = ColumnOperation(
            op_type=op_type,
            table_name=table,
            column_name=column,
            new_type="TEXT" if op_type != OperationType.DROP_COLUMN else "",
            old_type="" if op_type == OperationType.ADD_COLUMN else "VARCHAR(50)",
            constraints=[],
        )
        return DiffEntry(
            operation=op,
            annotation=annotation,
            is_new_field=is_new,
            is_field_removal=is_removal,
        )

    def _make_diff(self, entries, tables=None):
        if tables is None:
            tables = list({e.operation.table_name for e in entries})
        return SchemaDiff(
            entries=entries,
            affected_tables=tables,
            source_path="/m/v1.sql",
            source_hash="abc123def456",
        )

    def test_goodhart_gates_audit_field_add_not_blocked(self):
        """Adding an audit field should NOT trigger audit_field_drop BLOCKED rule."""
        annotation = FieldAnnotation(
            classification_tier="PUBLIC",
            is_audit_field=True,
            is_immutable=False,
            is_encrypted=False,
        )
        entry = self._make_diff_entry(
            OperationType.ADD_COLUMN, "audit_log", "created_by", annotation, is_new=True
        )
        diff = self._make_diff([entry])
        ctx = ComponentContext(component_id="svc-test", declared_data_access_tiers=["PUBLIC"])
        violations = evaluate_gates(diff, ctx)
        # Should NOT have a BLOCKED violation for audit field drop
        blocked_audit = [v for v in violations if v.severity == GateDecision.BLOCKED and "audit" in v.rule_id.lower()]
        assert len(blocked_audit) == 0

    def test_goodhart_gates_immutable_drop_not_modify_blocked(self):
        """Dropping an immutable (non-audit) field should NOT trigger immutable_field_modify BLOCKED rule."""
        annotation = FieldAnnotation(
            classification_tier="PUBLIC",
            is_audit_field=False,
            is_immutable=True,
            is_encrypted=False,
        )
        entry = self._make_diff_entry(
            OperationType.DROP_COLUMN, "users", "created_at", annotation, is_removal=True
        )
        diff = self._make_diff([entry])
        ctx = ComponentContext(component_id="svc-test", declared_data_access_tiers=["PUBLIC"])
        violations = evaluate_gates(diff, ctx)
        # The immutable_modify rule should NOT fire for a DROP
        immutable_modify = [v for v in violations if v.severity == GateDecision.BLOCKED and "immutable" in v.rule_id.lower() and "modif" in v.rule_id.lower()]
        assert len(immutable_modify) == 0

    def test_goodhart_gates_multiple_tiers_component(self):
        """Component declaring multiple tiers should not get violations for declared tiers."""
        annotation = FieldAnnotation(
            classification_tier="INTERNAL",
            is_audit_field=False,
            is_immutable=False,
            is_encrypted=False,
        )
        entry = self._make_diff_entry(
            OperationType.ADD_COLUMN, "orders", "details", annotation, is_new=True
        )
        diff = self._make_diff([entry])
        ctx = ComponentContext(
            component_id="svc-test",
            declared_data_access_tiers=["PUBLIC", "INTERNAL"],
        )
        violations = evaluate_gates(diff, ctx)
        tier_violations = [v for v in violations if "tier" in v.rule_id.lower() or "tier" in v.message.lower()]
        assert len(tier_violations) == 0

    def test_goodhart_gates_combined_audit_and_immutable_drop(self):
        """Dropping a field that is both audit AND immutable should produce at least a BLOCKED violation (audit drop)."""
        annotation = FieldAnnotation(
            classification_tier="PUBLIC",
            is_audit_field=True,
            is_immutable=True,
            is_encrypted=False,
        )
        entry = self._make_diff_entry(
            OperationType.DROP_COLUMN, "audit_log", "created_at", annotation, is_removal=True
        )
        diff = self._make_diff([entry])
        ctx = ComponentContext(component_id="svc-test", declared_data_access_tiers=["PUBLIC"])
        violations = evaluate_gates(diff, ctx)
        blocked = [v for v in violations if v.severity == GateDecision.BLOCKED]
        assert len(blocked) >= 1

    def test_goodhart_gates_violation_references_correct_table_column(self):
        """Each GateViolation must reference the correct table_name and column_name from its triggering entry."""
        annotation1 = FieldAnnotation(
            classification_tier="CONFIDENTIAL",
            is_audit_field=True,
            is_immutable=False,
            is_encrypted=False,
        )
        annotation2 = FieldAnnotation(
            classification_tier="RESTRICTED",
            is_audit_field=False,
            is_immutable=True,
            is_encrypted=False,
        )
        entry1 = self._make_diff_entry(
            OperationType.DROP_COLUMN, "table_alpha", "col_one", annotation1, is_removal=True
        )
        entry2 = self._make_diff_entry(
            OperationType.ALTER_COLUMN, "table_beta", "col_two", annotation2
        )
        diff = self._make_diff([entry1, entry2])
        ctx = ComponentContext(component_id="svc-test", declared_data_access_tiers=["PUBLIC"])
        violations = evaluate_gates(diff, ctx)
        # All violations should reference one of the entry tables/columns
        valid_pairs = {
            ("table_alpha", "col_one"),
            ("table_beta", "col_two"),
        }
        for v in violations:
            assert (v.table_name, v.column_name) in valid_pairs

    def test_goodhart_gates_three_entries_all_different_violations(self):
        """Three entries triggering different rules should all produce violations, ordered by severity."""
        audit_ann = FieldAnnotation(classification_tier="PUBLIC", is_audit_field=True, is_immutable=False, is_encrypted=False)
        immutable_ann = FieldAnnotation(classification_tier="PUBLIC", is_audit_field=False, is_immutable=True, is_encrypted=False)
        tier_ann = FieldAnnotation(classification_tier="RESTRICTED", is_audit_field=False, is_immutable=False, is_encrypted=False)

        entry_audit = self._make_diff_entry(OperationType.DROP_COLUMN, "t1", "c1", audit_ann, is_removal=True)
        entry_immutable = self._make_diff_entry(OperationType.ALTER_COLUMN, "t2", "c2", immutable_ann)
        entry_tier = self._make_diff_entry(OperationType.ADD_COLUMN, "t3", "c3", tier_ann, is_new=True)

        diff = self._make_diff([entry_audit, entry_immutable, entry_tier])
        ctx = ComponentContext(component_id="svc-test", declared_data_access_tiers=["PUBLIC"])
        violations = evaluate_gates(diff, ctx)

        assert len(violations) >= 3
        # Verify ordering: BLOCKED first, then HUMAN_GATE
        severity_order = [v.severity for v in violations]
        for i in range(len(severity_order) - 1):
            if severity_order[i] == GateDecision.HUMAN_GATE:
                assert severity_order[i + 1] != GateDecision.BLOCKED, "BLOCKED should come before HUMAN_GATE"


# ============================================================
# CREATE_PLAN TESTS
# ============================================================


class TestGoodhartCreatePlan:

    def _make_diff(self, tables=None):
        if tables is None:
            tables = ["orders"]
        op = ColumnOperation(
            op_type=OperationType.ADD_COLUMN,
            table_name=tables[0],
            column_name="new_col",
            new_type="INT",
            old_type="",
            constraints=[],
        )
        entries = [
            DiffEntry(
                operation=op,
                annotation=None,
                is_new_field=True,
                is_field_removal=False,
            )
        ]
        return SchemaDiff(
            entries=entries,
            affected_tables=tables,
            source_path="/m/test.sql",
            source_hash="deadbeef" * 8,
        )

    def _make_registry(self, fk_map=None):
        """Mock registry for FK lookups.
        fk_map: dict of table -> list of FK-referenced tables
        """
        registry = MagicMock()
        if fk_map is None:
            fk_map = {}

        def get_fk(table):
            return fk_map.get(table, [])

        registry.get_foreign_keys = MagicMock(side_effect=get_fk)
        registry.get_fk_references = MagicMock(side_effect=get_fk)
        registry.lookup_fk = MagicMock(side_effect=get_fk)
        return registry

    def test_goodhart_create_plan_multiple_plans_unique_ids(self):
        """Creating multiple plans must produce unique UUID v4 plan_ids."""
        with tempfile.TemporaryDirectory() as tmpdir:
            diff = self._make_diff()
            reg = self._make_registry()
            plan1 = create_plan(diff, [], reg, tmpdir)
            plan2 = create_plan(diff, [], reg, tmpdir)
            assert plan1.plan_id != plan2.plan_id
            # Both should be valid UUID v4
            uuid.UUID(plan1.plan_id, version=4)
            uuid.UUID(plan2.plan_id, version=4)

    def test_goodhart_create_plan_blast_radius_no_fk(self):
        """When no FK references exist, blast_radius should equal affected_tables exactly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            diff = self._make_diff(["orders", "users"])
            # Add a second entry for users
            op2 = ColumnOperation(op_type=OperationType.ADD_COLUMN, table_name="users", column_name="c2", new_type="INT", old_type="", constraints=[])
            diff.entries.append(DiffEntry(operation=op2, annotation=None, is_new_field=True, is_field_removal=False))
            reg = self._make_registry({})
            plan = create_plan(diff, [], reg, tmpdir)
            blast = set(t.lower() for t in plan.blast_radius)
            assert blast == {"orders", "users"}

    def test_goodhart_create_plan_blast_radius_deduplication(self):
        """FK-referenced tables should appear only once in blast_radius even if referenced from multiple affected tables."""
        with tempfile.TemporaryDirectory() as tmpdir:
            diff = self._make_diff(["orders", "invoices"])
            op2 = ColumnOperation(op_type=OperationType.ADD_COLUMN, table_name="invoices", column_name="c2", new_type="INT", old_type="", constraints=[])
            diff.entries.append(DiffEntry(operation=op2, annotation=None, is_new_field=True, is_field_removal=False))
            reg = self._make_registry({"orders": ["customers"], "invoices": ["customers"]})
            plan = create_plan(diff, [], reg, tmpdir)
            blast_lower = [t.lower() for t in plan.blast_radius]
            assert blast_lower.count("customers") == 1
            assert "orders" in blast_lower
            assert "invoices" in blast_lower

    def test_goodhart_create_plan_overall_gate_human_gate_only(self):
        """When all violations are HUMAN_GATE, overall_gate should be HUMAN_GATE."""
        with tempfile.TemporaryDirectory() as tmpdir:
            diff = self._make_diff()
            violations = [
                GateViolation(rule_id="r1", severity=GateDecision.HUMAN_GATE, table_name="t", column_name="c", message="v1", context={}),
                GateViolation(rule_id="r2", severity=GateDecision.HUMAN_GATE, table_name="t", column_name="c", message="v2", context={}),
            ]
            reg = self._make_registry()
            plan = create_plan(diff, violations, reg, tmpdir)
            assert plan.overall_gate == GateDecision.HUMAN_GATE

    def test_goodhart_create_plan_overall_gate_mixed_blocked_wins(self):
        """When violations include HUMAN_GATE and BLOCKED, overall_gate must be BLOCKED."""
        with tempfile.TemporaryDirectory() as tmpdir:
            diff = self._make_diff()
            violations = [
                GateViolation(rule_id="r1", severity=GateDecision.HUMAN_GATE, table_name="t", column_name="c", message="v1", context={}),
                GateViolation(rule_id="r2", severity=GateDecision.BLOCKED, table_name="t", column_name="c", message="v2", context={}),
            ]
            reg = self._make_registry()
            plan = create_plan(diff, violations, reg, tmpdir)
            assert plan.overall_gate == GateDecision.BLOCKED

    def test_goodhart_create_plan_source_propagated(self):
        """Plan source_path and source_hash must come from the diff, not be hardcoded."""
        with tempfile.TemporaryDirectory() as tmpdir:
            diff = self._make_diff()
            diff.source_path = "/custom/path/migration_xyz.sql"
            diff.source_hash = "a1b2c3d4" * 8
            reg = self._make_registry()
            plan = create_plan(diff, [], reg, tmpdir)
            assert plan.source_path == "/custom/path/migration_xyz.sql"
            assert plan.source_hash == "a1b2c3d4" * 8

    def test_goodhart_create_plan_timestamps_iso8601(self):
        """Timestamps must be valid ISO 8601 format."""
        with tempfile.TemporaryDirectory() as tmpdir:
            diff = self._make_diff()
            reg = self._make_registry()
            plan = create_plan(diff, [], reg, tmpdir)
            # Should be parseable as ISO 8601
            dt_created = datetime.fromisoformat(plan.created_at.replace("Z", "+00:00"))
            dt_updated = datetime.fromisoformat(plan.updated_at.replace("Z", "+00:00"))
            assert dt_created is not None
            assert dt_updated is not None
            assert plan.created_at == plan.updated_at

    def test_goodhart_create_plan_persisted_file_deserializable(self):
        """The persisted JSON file must be valid and deserializable back into the plan."""
        with tempfile.TemporaryDirectory() as tmpdir:
            diff = self._make_diff()
            reg = self._make_registry()
            plan = create_plan(diff, [], reg, tmpdir)
            plan_file = os.path.join(tmpdir, f"{plan.plan_id}.json")
            assert os.path.exists(plan_file)
            with open(plan_file, "r") as f:
                data = json.load(f)
            assert data is not None
            # Verify key fields match
            assert data.get("plan_id") == plan.plan_id or data.get("plan_id", "") == plan.plan_id

    def test_goodhart_create_plan_blast_radius_fk_table_not_in_affected(self):
        """FK-referenced tables not in affected_tables should still appear in blast_radius."""
        with tempfile.TemporaryDirectory() as tmpdir:
            diff = self._make_diff(["orders"])
            reg = self._make_registry({"orders": ["products", "warehouses"]})
            plan = create_plan(diff, [], reg, tmpdir)
            blast_lower = [t.lower() for t in plan.blast_radius]
            assert "products" in blast_lower
            assert "warehouses" in blast_lower
            assert "orders" in blast_lower


# ============================================================
# APPROVE_PLAN TESTS
# ============================================================


class TestGoodhartApprovePlan:

    def _create_human_gate_plan(self, tmpdir):
        """Helper to create a PENDING HUMAN_GATE plan for approval tests."""
        op = ColumnOperation(
            op_type=OperationType.ALTER_COLUMN,
            table_name="users",
            column_name="email",
            new_type="TEXT",
            old_type="VARCHAR",
            constraints=[],
        )
        entry = DiffEntry(
            operation=op,
            annotation=FieldAnnotation(
                classification_tier="INTERNAL",
                is_audit_field=False,
                is_immutable=False,
                is_encrypted=True,
            ),
            is_new_field=False,
            is_field_removal=False,
        )
        diff = SchemaDiff(
            entries=[entry],
            affected_tables=["users"],
            source_path="/m/v1.sql",
            source_hash="abc" * 20 + "ab",
        )
        violations = [
            GateViolation(
                rule_id="encryption_removal",
                severity=GateDecision.HUMAN_GATE,
                table_name="users",
                column_name="email",
                message="Encryption removal detected",
                context={},
            )
        ]
        registry = MagicMock()
        registry.get_foreign_key_references = MagicMock(return_value=[])
        registry.get_fk_references = MagicMock(return_value=[])
        registry.lookup_fk = MagicMock(return_value=[])
        plan = create_plan(diff, violations, registry, tmpdir)
        return plan

    def test_goodhart_approve_changelog_appended(self):
        """Approval must append an ApprovalRecord to changelog.jsonl."""
        with tempfile.TemporaryDirectory() as tmpdir:
            plan = self._create_human_gate_plan(tmpdir)
            approved = approve_plan(
                plan.plan_id,
                "reviewer@example.com",
                "JIRA-999",
                "Reviewed and approved",
                tmpdir,
            )
            changelog_path = os.path.join(tmpdir, "changelog.jsonl")
            assert os.path.exists(changelog_path), "changelog.jsonl should be created after approval"
            with open(changelog_path, "r") as f:
                content = f.read().strip()
            assert len(content) > 0
            # Should contain the plan_id
            assert plan.plan_id in content

    def test_goodhart_approve_reviewer_and_rationale_preserved(self):
        """Approval record must preserve exact reviewer, review_ref, and rationale."""
        with tempfile.TemporaryDirectory() as tmpdir:
            plan = self._create_human_gate_plan(tmpdir)
            approved = approve_plan(
                plan.plan_id,
                "security-team@corp.com",
                "JIRA-12345",
                "Reviewed encryption changes in detail",
                tmpdir,
            )
            changelog_path = os.path.join(tmpdir, "changelog.jsonl")
            with open(changelog_path, "r") as f:
                lines = [l.strip() for l in f.readlines() if l.strip()]
            found = False
            for line in lines:
                record = json.loads(line)
                if record.get("plan_id") == plan.plan_id:
                    assert record.get("reviewer") == "security-team@corp.com" or record.get("reviewer", "") == "security-team@corp.com"
                    found = True
            assert found, "Approval record not found in changelog"

    def test_goodhart_approve_updated_at_after_created_at(self):
        """After approval, updated_at must differ from created_at."""
        with tempfile.TemporaryDirectory() as tmpdir:
            plan = self._create_human_gate_plan(tmpdir)
            import time
            time.sleep(0.01)  # Ensure time passes
            approved = approve_plan(
                plan.plan_id,
                "reviewer@test.com",
                "REF-001",
                "Approved",
                tmpdir,
            )
            assert approved.status == PlanStatus.APPROVED
            # updated_at should reflect the approval time, which should be >= created_at
            created = datetime.fromisoformat(approved.created_at.replace("Z", "+00:00"))
            updated = datetime.fromisoformat(approved.updated_at.replace("Z", "+00:00"))
            assert updated >= created


# ============================================================
# LOAD_PLAN TESTS
# ============================================================


class TestGoodhartLoadPlan:

    def test_goodhart_load_plan_id_matches_input(self):
        """Loaded plan's plan_id must equal the requested plan_id."""
        with tempfile.TemporaryDirectory() as tmpdir:
            op = ColumnOperation(
                op_type=OperationType.ADD_COLUMN,
                table_name="t",
                column_name="c",
                new_type="INT",
                old_type="",
                constraints=[],
            )
            entry = DiffEntry(operation=op, annotation=None, is_new_field=True, is_field_removal=False)
            diff = SchemaDiff(entries=[entry], affected_tables=["t"], source_path="/m/v.sql", source_hash="h" * 64)
            reg = MagicMock()
            reg.get_foreign_key_references = MagicMock(return_value=[])
            reg.get_fk_references = MagicMock(return_value=[])
            reg.lookup_fk = MagicMock(return_value=[])

            plan1 = create_plan(diff, [], reg, tmpdir)
            plan2 = create_plan(diff, [], reg, tmpdir)

            loaded1 = load_plan(plan1.plan_id, tmpdir)
            loaded2 = load_plan(plan2.plan_id, tmpdir)

            assert loaded1.plan_id == plan1.plan_id
            assert loaded2.plan_id == plan2.plan_id
            assert loaded1.plan_id != loaded2.plan_id

    def test_goodhart_load_corrupted_missing_required_fields(self):
        """Valid JSON but missing required MigrationPlan fields should raise corrupted_plan_file error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_id = str(uuid.uuid4())
            plan_file = os.path.join(tmpdir, f"{fake_id}.json")
            with open(plan_file, "w") as f:
                json.dump({"some_field": "value", "another": 42}, f)
            with pytest.raises(Exception):
                load_plan(fake_id, tmpdir)

    def test_goodhart_load_plan_preserves_all_fields_after_round_trip(self):
        """A plan with violations should round-trip correctly through create_plan and load_plan."""
        with tempfile.TemporaryDirectory() as tmpdir:
            op = ColumnOperation(
                op_type=OperationType.ADD_COLUMN,
                table_name="orders",
                column_name="total",
                new_type="NUMERIC(10,2)",
                old_type="",
                constraints=[],
            )
            entry = DiffEntry(operation=op, annotation=None, is_new_field=True, is_field_removal=False)
            diff = SchemaDiff(entries=[entry], affected_tables=["orders"], source_path="/m/v99.sql", source_hash="f" * 64)
            violations = [
                GateViolation(rule_id="tier_mismatch", severity=GateDecision.HUMAN_GATE, table_name="orders", column_name="total", message="tier issue", context={"tier": "RESTRICTED"})
            ]
            reg = MagicMock()
            reg.get_foreign_key_references = MagicMock(return_value=["products"])
            reg.get_fk_references = MagicMock(return_value=["products"])
            reg.lookup_fk = MagicMock(return_value=["products"])

            plan = create_plan(diff, violations, reg, tmpdir)
            loaded = load_plan(plan.plan_id, tmpdir)

            assert loaded.plan_id == plan.plan_id
            assert loaded.status == plan.status
            assert loaded.overall_gate == plan.overall_gate
            assert loaded.source_path == plan.source_path
            assert loaded.source_hash == plan.source_hash
