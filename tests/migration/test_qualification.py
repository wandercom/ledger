"""Regression coverage for SQL action boundaries and approval audit consistency."""
import json
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock, patch

import pytest

from migration import (
    ApprovalRecord, GateDecision, GateViolation, InvalidPlanTransitionError,
    PlanPersistenceError, PlanStatus, SchemaDiff, approve_plan, create_plan,
    load_plan, parse_migration,
)


def make_plan(tmp_path):
    diff = SchemaDiff(entries=[], affected_tables=['users'], source_path='change.sql', source_hash='a' * 64)
    violation = GateViolation(rule_id='review', severity=GateDecision.HUMAN_GATE,
                              table_name='users', column_name='email', message='Review required', context={})
    registry = Mock()
    registry.get_foreign_keys.return_value = []
    return create_plan(diff, [violation], registry, str(tmp_path))


def test_multiple_actions_preserve_literals_and_numeric_type():
    parsed = parse_migration(
        "ALTER TABLE users ADD COLUMN amount DECIMAL(10,2), "
        "ADD COLUMN label TEXT DEFAULT 'a,b; c', DROP COLUMN old;", 'change.sql')
    assert parsed.statement_count == 1
    assert [op.column_name for op in parsed.operations] == ['amount', 'label', 'old']
    assert parsed.operations[0].new_type == 'DECIMAL(10,2)'


def test_concurrent_approval_has_one_audit_record(tmp_path):
    plan = make_plan(tmp_path)
    def approve(reviewer):
        try:
            approve_plan(plan.plan_id, reviewer, 'REVIEW-1', 'Inspected migration', str(tmp_path))
            return True
        except InvalidPlanTransitionError:
            return False
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sum(pool.map(approve, ['alice', 'bob'])) == 1
    records = [ApprovalRecord.model_validate_json(line) for line in (tmp_path / 'changelog.jsonl').read_text().splitlines()]
    assert len(records) == 1
    assert records[0].plan_id == plan.plan_id
    assert records[0].review_reference == 'REVIEW-1'
    assert records[0].rationale == 'Inspected migration'
    assert load_plan(plan.plan_id, str(tmp_path)).status == PlanStatus.APPROVED


def test_failed_plan_write_keeps_pending_plan_and_no_success_record(tmp_path):
    plan = make_plan(tmp_path)
    with patch('migration.migration._atomic_write_json', side_effect=PlanPersistenceError(
            plan_id=plan.plan_id, target_path=str(tmp_path), message='write failed')):
        with pytest.raises(PlanPersistenceError):
            approve_plan(plan.plan_id, 'alice', 'REVIEW-1', 'Inspected migration', str(tmp_path))
    assert load_plan(plan.plan_id, str(tmp_path)).status == PlanStatus.PENDING
    assert (tmp_path / 'changelog.jsonl').read_text() == ''
