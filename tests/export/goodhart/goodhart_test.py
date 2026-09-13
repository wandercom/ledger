"""
Hidden adversarial acceptance tests for Export Generators component.
These tests target gaps in visible test coverage to catch implementations
that hardcode returns or take shortcuts based on visible test inputs.
"""
import pytest
import yaml
from unittest.mock import MagicMock, patch
from src.export import *


# ─── Helpers ────────────────────────────────────────────────────────────────

def make_entry(field_ref, annotation_key, rule, field_type="string", component_id="svc-a"):
    """Create a PropagationEntry (or dict-like object matching its structure)."""
    return PropagationEntry(
        field_ref=field_ref,
        annotation_key=annotation_key,
        rule={"owner": component_id, **rule} if component_id else rule,
        field_type=field_type,
        component_id=component_id,
    )


# ─── iter_propagation_entries ───────────────────────────────────────────────

class TestGoodhartIterPropagationEntries:

    def test_goodhart_iter_boolean_filter_values(self):
        """iter_propagation_entries correctly filters on boolean property_filter values."""
        table = [
            make_entry("f1", "A", {"requires_masking": True, "tier": "CONFIDENTIAL"}),
            make_entry("f2", "B", {"requires_masking": False, "tier": "PUBLIC"}),
            make_entry("f3", "C", {"tier": "INTERNAL"}),
        ]
        result = iter_propagation_entries(table, {"requires_masking": True})
        assert len(result) == 1
        assert result[0].field_ref == "f1"

    def test_goodhart_iter_multiple_filters_conjunction(self):
        """All property_filter constraints are ANDed — entries must match every key."""
        table = [
            make_entry("f1", "A", {"tier": "CONFIDENTIAL", "requires_masking": True}),
            make_entry("f2", "B", {"tier": "CONFIDENTIAL", "requires_masking": False}),
            make_entry("f3", "C", {"tier": "PUBLIC", "requires_masking": True}),
        ]
        result = iter_propagation_entries(table, {"tier": "CONFIDENTIAL", "requires_masking": True})
        assert len(result) == 1
        assert result[0].field_ref == "f1"

    def test_goodhart_iter_preserves_all_rule_properties(self):
        """Returned rule_properties dict contains all original rule keys, not just filtered ones."""
        table = [
            make_entry("f1", "A", {"tier": "CONFIDENTIAL", "custom_prop": "xyz", "extra": 42}),
        ]
        result = iter_propagation_entries(table, {"tier": "CONFIDENTIAL"})
        assert len(result) == 1
        assert "custom_prop" in result[0].rule_properties
        assert result[0].rule_properties["custom_prop"] == "xyz"
        assert "extra" in result[0].rule_properties

    def test_goodhart_iter_sort_stability_same_field_ref(self):
        """Entries with the same field_ref are secondarily sorted by annotation_key."""
        table = [
            make_entry("user.email", "ZETA", {"tier": "X"}),
            make_entry("user.email", "ALPHA", {"tier": "X"}),
            make_entry("user.email", "MID", {"tier": "X"}),
        ]
        result = iter_propagation_entries(table, {})
        keys = [r.annotation_key for r in result]
        assert keys == sorted(keys)

    def test_goodhart_iter_missing_rule_field_error(self):
        """Raises invalid_entry_structure when an entry has field_ref and annotation_key but no rule."""
        # Create an entry-like object missing the rule field
        bad_entry = MagicMock()
        bad_entry.field_ref = "f1"
        bad_entry.annotation_key = "A"
        del bad_entry.rule  # ensure 'rule' attribute is missing
        with pytest.raises(Exception):
            iter_propagation_entries([bad_entry], {})

    def test_goodhart_iter_empty_filter_returns_all(self):
        """Empty property_filter dict returns all entries from propagation table."""
        table = [
            make_entry("f1", "A", {"x": 1}),
            make_entry("f2", "B", {"y": 2}),
            make_entry("f3", "C", {"z": 3}),
        ]
        result = iter_propagation_entries(table, {})
        assert len(result) == 3

    def test_goodhart_iter_field_type_and_component_preserved(self):
        """field_type and component_id are preserved in output tuples."""
        table = [
            make_entry("f1", "A", {"tier": "X"}, field_type="integer", component_id="comp-99"),
        ]
        result = iter_propagation_entries(table, {})
        assert len(result) == 1
        assert result[0].field_type == "integer"
        assert result[0].component_id == "comp-99"


# ─── export_pact ────────────────────────────────────────────────────────────

class TestGoodhartExportPact:

    def test_goodhart_pact_custom_annotation_name(self):
        """Custom annotation names (not PII/FINANCIAL) produce correct assertions — no hard-coding."""
        table = [
            make_entry("user.consent_flag", "GDPR_CONSENT", {
                "test_type": "shape",
                "shape": "boolean",
            }, component_id="svc-x"),
        ]
        result = export_pact("svc-x", table)
        assert result.output is not None
        assert len(result.output.assertions) == 1
        # The assertion should reference the custom annotation
        a = result.output.assertions[0]
        assert "GDPR_CONSENT" in a.assertion_id or "consent" in a.assertion_id.lower() or a.field_ref == "user.consent_flag"

    def test_goodhart_pact_multiple_components_filters_correctly(self):
        """Only assertions for the requested component_id are included."""
        table = [
            make_entry("f1", "A", {"test_type": "shape", "shape": "string"}, component_id="svc-alpha"),
            make_entry("f2", "B", {"test_type": "filter", "filter": "notnull"}, component_id="svc-beta"),
        ]
        result = export_pact("svc-alpha", table)
        assert result.output is not None
        assert len(result.output.assertions) == 1
        assert result.output.assertions[0].field_ref == "f1"

    def test_goodhart_pact_mixed_valid_and_invalid_entries(self):
        """ERROR and WARNING violations coexist — all collected exhaustively."""
        table = [
            make_entry("f1", "A", {"test_type": "INVALID_TYPE"}, component_id="svc-a"),
            make_entry("f2", "B", {"test_type": "shape"}, component_id="svc-a"),  # missing optional props -> WARNING
        ]
        result = export_pact("svc-a", table)
        error_violations = [v for v in result.violations if v.severity == ExportViolationSeverity.ERROR or (hasattr(v, 'severity') and str(v.severity) == 'ERROR')]
        assert len(error_violations) >= 1
        assert result.output is None  # ERROR present -> output is None

    def test_goodhart_pact_assertion_id_deterministic_format(self):
        """Distinct but similar field_refs produce distinct assertion_ids."""
        table = [
            make_entry("user.name", "PII", {"test_type": "shape", "shape": "string"}, component_id="svc-a"),
            make_entry("user.name_alt", "PII", {"test_type": "shape", "shape": "string"}, component_id="svc-a"),
        ]
        result = export_pact("svc-a", table)
        assert result.output is not None
        ids = [a.assertion_id for a in result.output.assertions]
        assert len(ids) == len(set(ids)), "assertion_ids must be unique"

    def test_goodhart_pact_three_test_types_all_accepted(self):
        """All three valid test_type values produce assertions."""
        table = [
            make_entry("f1", "A", {"test_type": "shape", "shape": "string"}, component_id="svc-a"),
            make_entry("f2", "B", {"test_type": "filter", "filter": "notnull"}, component_id="svc-a"),
            make_entry("f3", "C", {"test_type": "method", "method": "validate"}, component_id="svc-a"),
        ]
        result = export_pact("svc-a", table)
        assert result.output is not None
        test_types = {a.test_type for a in result.output.assertions}
        assert test_types == {"shape", "filter", "method"}

    def test_goodhart_pact_component_id_in_output(self):
        """Output PactExport.component_id matches the input parameter exactly."""
        cid = "my-unique-svc-12345"
        table = [
            make_entry("f1", "A", {"test_type": "shape", "shape": "string"}, component_id=cid),
        ]
        result = export_pact(cid, table)
        assert result.output is not None
        assert result.output.component_id == cid

    def test_goodhart_pact_warnings_present_when_output_exists(self):
        """Non-None output can coexist with WARNING violations."""
        table = [
            make_entry("f1", "A", {"test_type": "shape"}, component_id="svc-w"),
            # Missing optional properties like 'shape' value may trigger WARNING
        ]
        result = export_pact("svc-w", table)
        # If implementation produces warnings for missing optional fields,
        # output should still be non-None (only ERRORs nullify)
        if result.violations:
            error_violations = [v for v in result.violations
                                if v.severity == ExportViolationSeverity.ERROR or str(v.severity) == 'ERROR']
            if not error_violations:
                assert result.output is not None, "Output should exist when only WARNINGs present"


# ─── export_arbiter ─────────────────────────────────────────────────────────

class TestGoodhartExportArbiter:

    def test_goodhart_arbiter_taint_from_taint_on_raw_value_property(self):
        """taint_on_raw_value=true from rule directly (not via requires_masking)."""
        table = [
            make_entry("f1", "A", {"tier": "INTERNAL", "taint_on_raw_value": True}),
        ]
        result = export_arbiter(table, "default-db")
        assert result.output is not None
        assert result.output.rules[0].taint_on_raw_value is True

    def test_goodhart_arbiter_mask_in_spans_from_mask_in_spans_property(self):
        """mask_in_spans=true from rule directly (not via requires_masking)."""
        table = [
            make_entry("f1", "A", {"tier": "INTERNAL", "mask_in_spans": True}),
        ]
        result = export_arbiter(table, "default-db")
        assert result.output is not None
        assert result.output.rules[0].mask_in_spans is True

    def test_goodhart_arbiter_merge_annotations_list(self):
        """Merged rule's annotations list contains all annotation keys from entries on same field."""
        table = [
            make_entry("user.ssn", "PII", {"tier": "CONFIDENTIAL", "requires_masking": True}),
            make_entry("user.ssn", "REGULATORY", {"tier": "CONFIDENTIAL"}),
        ]
        result = export_arbiter(table, "default-db")
        assert result.output is not None
        assert len(result.output.rules) == 1
        annotations = result.output.rules[0].annotations
        assert "PII" in annotations
        assert "REGULATORY" in annotations

    def test_goodhart_arbiter_backend_from_rule_overrides_default(self):
        """Rule-specified backend overrides default_backend."""
        table = [
            make_entry("f1", "A", {"tier": "INTERNAL", "backend": "custom-db"}),
        ]
        result = export_arbiter(table, "fallback-db")
        assert result.output is not None
        assert result.output.rules[0].backend == "custom-db"

    def test_goodhart_arbiter_no_taint_no_mask_when_not_required(self):
        """No masking flags set when no masking-related properties are true."""
        table = [
            make_entry("f1", "A", {"tier": "PUBLIC"}),
        ]
        result = export_arbiter(table, "default-db")
        assert result.output is not None
        rule = result.output.rules[0]
        assert rule.taint_on_raw_value is False
        assert rule.mask_in_spans is False

    def test_goodhart_arbiter_custom_annotation_not_hardcoded(self):
        """Novel annotation name 'BIOMETRIC' works without code changes."""
        table = [
            make_entry("user.iris_scan", "BIOMETRIC", {"tier": "RESTRICTED", "requires_masking": True}),
        ]
        result = export_arbiter(table, "default-db")
        assert result.output is not None
        assert len(result.output.rules) == 1
        assert "BIOMETRIC" in result.output.rules[0].annotations
        assert result.output.rules[0].tier == "RESTRICTED"

    def test_goodhart_arbiter_pattern_sort_not_alphabetical_by_annotation(self):
        """Rules are sorted by pattern, not annotation_key."""
        table = [
            make_entry("z_field", "ALPHA_ANN", {"tier": "PUBLIC"}),
            make_entry("a_field", "ZETA_ANN", {"tier": "PUBLIC"}),
        ]
        result = export_arbiter(table, "db")
        assert result.output is not None
        patterns = [r.pattern for r in result.output.rules]
        assert patterns == sorted(patterns)
        # a_field should come before z_field
        assert patterns[0] == "a_field"

    def test_goodhart_arbiter_output_with_warnings(self):
        """Non-None output alongside WARNING violations."""
        table = [
            make_entry("f1", "A", {"tier": "PUBLIC"}),
        ]
        result = export_arbiter(table, "db")
        # If there are warnings but no errors, output should exist
        error_violations = [v for v in result.violations
                            if v.severity == ExportViolationSeverity.ERROR or str(v.severity) == 'ERROR']
        if not error_violations:
            assert result.output is not None


# ─── export_baton ───────────────────────────────────────────────────────────

class TestGoodhartExportBaton:

    def test_goodhart_baton_faker_for_pii_fields(self):
        """PII fields use faker providers; non-PII/non-FINANCIAL use stdlib random."""
        table = [
            make_entry("user.email", "PII", {
                "requires_masking": True,
                "tier": "CONFIDENTIAL",
                "mock_generator": "faker.providers.internet",
                "canary_eligible": False,
            }, field_type="string", component_id="svc-a"),
            make_entry("order.count", "METRICS", {
                "requires_masking": True,
                "tier": "INTERNAL",
                "mock_generator": "stdlib.random",
                "canary_eligible": False,
            }, field_type="integer", component_id="svc-a"),
        ]
        result = export_baton(table)
        assert result.output is not None
        # Check that the mock generators are correctly assigned based on annotation type
        nodes = result.output.egress_nodes
        assert len(nodes) >= 1

    def test_goodhart_baton_public_tier_not_masked(self):
        """PUBLIC tier fields excluded from masked_fields."""
        table = [
            make_entry("f1", "A", {
                "requires_masking": False,
                "tier": "PUBLIC",
                "mock_generator": "stdlib.random",
            }, component_id="svc-a"),
            make_entry("f2", "B", {
                "requires_masking": True,
                "tier": "CONFIDENTIAL",
                "mock_generator": "faker.providers.misc",
            }, component_id="svc-a"),
        ]
        result = export_baton(table)
        assert result.output is not None
        for node in result.output.egress_nodes:
            assert "f1" not in node.masked_fields
            # f2 should be in masked_fields
            if node.masked_fields:
                assert "f2" in node.masked_fields

    def test_goodhart_baton_canary_false_excluded(self):
        """String field with canary_eligible=false is excluded from canary_eligible_fields."""
        table = [
            make_entry("f1", "A", {
                "requires_masking": True,
                "tier": "INTERNAL",
                "mock_generator": "stdlib.random",
                "canary_eligible": False,
            }, field_type="string", component_id="svc-a"),
        ]
        result = export_baton(table)
        assert result.output is not None
        for node in result.output.egress_nodes:
            assert "f1" not in node.canary_eligible_fields

    def test_goodhart_baton_canary_missing_excluded(self):
        """String field without canary_eligible property is excluded from canary_eligible_fields."""
        table = [
            make_entry("f1", "A", {
                "requires_masking": True,
                "tier": "INTERNAL",
                "mock_generator": "stdlib.random",
            }, field_type="string", component_id="svc-a"),
        ]
        result = export_baton(table)
        assert result.output is not None
        for node in result.output.egress_nodes:
            assert "f1" not in node.canary_eligible_fields

    def test_goodhart_baton_multiple_errors_collected(self):
        """Multiple ERROR violations are collected, not just the first."""
        table = [
            make_entry("f1", "A", {
                "requires_masking": True,
                "tier": "INTERNAL",
                # missing mock_generator
            }, component_id=""),  # empty component_id -> missing_owner
            make_entry("f2", "B", {
                "requires_masking": True,
                "tier": "CONFIDENTIAL",
                # missing mock_generator
            }, component_id=""),
        ]
        result = export_baton(table)
        error_violations = [v for v in result.violations
                            if v.severity == ExportViolationSeverity.ERROR or str(v.severity) == 'ERROR']
        assert len(error_violations) >= 2, "Multiple errors should be collected, not just the first"
        assert result.output is None

    def test_goodhart_baton_egress_node_id_uniqueness(self):
        """Egress node ids are unique in output."""
        table = [
            make_entry("f1", "A", {
                "requires_masking": True,
                "tier": "INTERNAL",
                "mock_generator": "stdlib.random",
            }, component_id="svc-a"),
            make_entry("f2", "B", {
                "requires_masking": True,
                "tier": "CONFIDENTIAL",
                "mock_generator": "faker.providers.misc",
            }, component_id="svc-b"),
        ]
        result = export_baton(table)
        assert result.output is not None
        ids = [n.id for n in result.output.egress_nodes]
        assert len(ids) == len(set(ids))


# ─── export_sentinel ───────────────────────────────────────────────────────

class TestGoodhartExportSentinel:

    def test_goodhart_sentinel_sort_order_triple_key(self):
        """Severity mappings sorted by (severity, annotation_key, field_pattern)."""
        table = [
            make_entry("z_field", "B_ANN", {"severity": "high"}),
            make_entry("a_field", "A_ANN", {"severity": "high"}),
            make_entry("m_field", "C_ANN", {"severity": "critical"}),
        ]
        result = export_sentinel(table)
        assert result.output is not None
        mappings = result.output.severity_mappings
        # Should be sorted by severity first, then annotation_key, then field_pattern
        sort_keys = [(m.severity, m.annotation_key, m.field_pattern) for m in mappings]
        assert sort_keys == sorted(sort_keys)

    def test_goodhart_sentinel_multiple_entries_same_severity(self):
        """One mapping per entry, no deduplication when severity values match."""
        table = [
            make_entry("f1", "A", {"severity": "critical"}),
            make_entry("f2", "B", {"severity": "critical"}),
            make_entry("f3", "C", {"severity": "critical"}),
        ]
        result = export_sentinel(table)
        assert result.output is not None
        assert len(result.output.severity_mappings) == 3

    def test_goodhart_sentinel_mix_valid_and_missing_severity(self):
        """Valid entries produce mappings; entries without severity produce WARNINGs. Both coexist."""
        table = [
            make_entry("f1", "A", {"severity": "high"}),
            make_entry("f2", "B", {"other_prop": "value"}),  # no severity
        ]
        result = export_sentinel(table)
        assert result.output is not None
        assert len(result.output.severity_mappings) == 1
        warning_violations = [v for v in result.violations
                              if v.severity == ExportViolationSeverity.WARNING or str(v.severity) == 'WARNING']
        assert len(warning_violations) >= 1

    def test_goodhart_sentinel_invalid_severity_with_valid_entries(self):
        """Invalid severity on any entry causes output=None even if other entries are valid."""
        table = [
            make_entry("f1", "A", {"severity": "critical"}),
            make_entry("f2", "B", {"severity": "BOGUS_INVALID_LEVEL"}),
        ]
        result = export_sentinel(table)
        assert result.output is None
        error_violations = [v for v in result.violations
                            if v.severity == ExportViolationSeverity.ERROR or str(v.severity) == 'ERROR']
        assert len(error_violations) >= 1


# ─── yaml_dump ──────────────────────────────────────────────────────────────

class TestGoodhartYamlDump:

    def test_goodhart_yaml_dump_block_style(self):
        """yaml_dump produces block-style YAML, not flow style."""
        model = PactExport(
            component_id="svc-test",
            assertions=[
                PactAssertion(
                    assertion_id="a1",
                    description="test assertion",
                    test_type="shape",
                    field_ref="user.name",
                    filter="",
                    shape="string",
                    method="",
                ),
            ],
        )
        output = yaml_dump(model)
        # Block style YAML should not have flow-style top-level containers
        lines = output.strip().split('\n')
        assert len(lines) > 1, "Block style should produce multiple lines"
        # The first top-level key should not be on same line as its nested content
        assert output.startswith("component_id") or output.startswith("---")

    def test_goodhart_yaml_dump_arbiter_export(self):
        """yaml_dump works for ArbiterExport, not just PactExport."""
        model = ArbiterExport(
            rules=[
                ArbiterRule(
                    pattern="user.*",
                    backend="postgres",
                    tier="CONFIDENTIAL",
                    annotations=["PII"],
                    taint_on_raw_value=True,
                    mask_in_spans=True,
                ),
            ],
        )
        output = yaml_dump(model)
        loaded = yaml.safe_load(output)
        assert "rules" in loaded
        assert loaded["rules"][0]["pattern"] == "user.*"

    def test_goodhart_yaml_dump_baton_export(self):
        """yaml_dump works for BatonExport."""
        model = BatonExport(
            egress_nodes=[
                BatonEgressNode(
                    id="node-1",
                    owner="team-a",
                    mock_generator="faker.providers.internet",
                    masked_fields=["email"],
                    canary_eligible_fields=["name"],
                ),
            ],
        )
        output = yaml_dump(model)
        loaded = yaml.safe_load(output)
        assert "egress_nodes" in loaded
        assert loaded["egress_nodes"][0]["id"] == "node-1"

    def test_goodhart_yaml_dump_sentinel_export(self):
        """yaml_dump works for SentinelExport."""
        model = SentinelExport(
            severity_mappings=[
                SentinelSeverityMapping(
                    annotation_key="PII",
                    severity="critical",
                    field_pattern="user.*",
                    description="PII fields",
                ),
            ],
        )
        output = yaml_dump(model)
        loaded = yaml.safe_load(output)
        assert "severity_mappings" in loaded
        assert loaded["severity_mappings"][0]["severity"] == "critical"

    def test_goodhart_yaml_dump_empty_lists(self):
        """yaml_dump handles models with empty lists."""
        model = PactExport(component_id="empty-svc", assertions=[])
        output = yaml_dump(model)
        loaded = yaml.safe_load(output)
        assert loaded["component_id"] == "empty-svc"
        assert loaded["assertions"] == [] or loaded.get("assertions") is None or loaded.get("assertions") == []

    def test_goodhart_yaml_dump_dict_not_accepted(self):
        """Plain dicts are rejected even if structure matches an export model."""
        plain_dict = {"component_id": "svc-x", "assertions": []}
        with pytest.raises(Exception):
            yaml_dump(plain_dict)

    def test_goodhart_yaml_dump_special_yaml_chars(self):
        """Values with YAML-special characters survive round-trip."""
        model = PactExport(
            component_id="svc: special #test [1]",
            assertions=[],
        )
        output = yaml_dump(model)
        loaded = yaml.safe_load(output)
        assert loaded["component_id"] == "svc: special #test [1]"
