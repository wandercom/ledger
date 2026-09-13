"""
Adversarial hidden acceptance tests for Mock Data Generator.
These tests target gaps in visible test coverage and catch implementations
that may be hardcoded or shortcut-based.
"""
import hashlib
import random
import re
import uuid
from unittest.mock import MagicMock, patch, AsyncMock

import pytest

from src.mock import (
    generate_mock_records,
    compute_field_seeds,
    generate_field_value,
    generate_canary_fingerprint,
    shape_canary_to_type,
    generate_token_value,
    register_canary_with_arbiter,
    resolve_seed,
    parse_varchar_length,
    get_type_generator,
    get_classification_generator,
    validate_request,
    FieldSpec,
    FieldClassification,
    MockPurpose,
    MockGenerationRequest,
    MockViolation,
    ViolationSeverity,
    CanaryValue,
)


# ---------------------------------------------------------------------------
# generate_canary_fingerprint – novel inputs
# ---------------------------------------------------------------------------

class TestGoodhartCanaryFingerprint:

    def test_goodhart_canary_fingerprint_different_inputs(self):
        """Canary fingerprint hex8 is correctly derived from SHA-256 of concatenated
        inputs for arbitrary backend/table/field combinations, not hardcoded."""
        cases = [
            ("backend-xyz", "orders", "amount", 0, "staging"),
            ("prod-001", "users", "ssn", 5, "gold"),
            ("dev", "payments", "card_number", 99, "silver"),
        ]
        for backend_id, table_name, field_name, row_index, tier in cases:
            result = generate_canary_fingerprint(backend_id, table_name, field_name, row_index, tier)
            expected_hex8 = hashlib.sha256(
                (backend_id + table_name + field_name + str(row_index)).encode()
            ).hexdigest()[:8]
            assert result == f"ledger-canary-{tier}-{expected_hex8}", (
                f"Fingerprint mismatch for {backend_id}/{table_name}/{field_name}/{row_index}"
            )
            assert re.fullmatch(rf"ledger-canary-{re.escape(tier)}-[0-9a-f]{{8}}", result)

    def test_goodhart_canary_fingerprint_special_chars(self):
        """Canary fingerprint correctly handles input strings containing special
        characters in the SHA-256 computation."""
        backend_id = "back-end.v2"
        table_name = "user_data"
        field_name = "first-name"
        row_index = 3
        tier = "tier-1"
        result = generate_canary_fingerprint(backend_id, table_name, field_name, row_index, tier)
        expected_hex8 = hashlib.sha256(
            (backend_id + table_name + field_name + str(row_index)).encode()
        ).hexdigest()[:8]
        assert result == f"ledger-canary-{tier}-{expected_hex8}"

    def test_goodhart_canary_fingerprint_row_index_large(self):
        """Canary fingerprint correctly converts large row indices to string for hashing."""
        results = set()
        for idx in [0, 1, 999999, 100000]:
            fp = generate_canary_fingerprint("b", "t", "f", idx, "tier")
            expected_hex8 = hashlib.sha256(
                ("b" + "t" + "f" + str(idx)).encode()
            ).hexdigest()[:8]
            assert fp.endswith(expected_hex8)
            results.add(fp)
        assert len(results) == 4, "Each row_index should produce a unique fingerprint"

    def test_goodhart_canary_fingerprint_tier_embedded(self):
        """The tier value is embedded literally in the canary fingerprint, not hashed."""
        tier = "production-alpha"
        result = generate_canary_fingerprint("b", "t", "f", 0, tier)
        assert f"ledger-canary-{tier}-" in result
        hex_part = result.split("-")[-1]
        assert re.fullmatch(r"[0-9a-f]{8}", hex_part)


# ---------------------------------------------------------------------------
# generate_token_value – exhaustive format checks
# ---------------------------------------------------------------------------

class TestGoodhartTokenValue:

    def test_goodhart_token_value_length_exact(self):
        """Token values must be exactly 28 characters for any seed value."""
        for seed_val in [0, 1, 42, 99999, 2**31 - 1]:
            rng = random.Random(seed_val)
            token = generate_token_value(rng)
            assert len(token) == 28, f"Token length {len(token)} != 28 for seed {seed_val}"
            assert token.startswith("tok_")
            assert re.fullmatch(r"tok_[A-Za-z0-9_\-]{24}", token), f"Bad token format: {token}"

    def test_goodhart_token_value_different_seeds_different_output(self):
        """Different seeds produce different token payloads, proving actual RNG usage."""
        tokens = set()
        for seed_val in range(10):
            rng = random.Random(seed_val)
            tokens.add(generate_token_value(rng))
        assert len(tokens) >= 9, "Tokens should be unique across different seeds"


# ---------------------------------------------------------------------------
# compute_field_seeds – novel field names and edge cases
# ---------------------------------------------------------------------------

class TestGoodhartComputeFieldSeeds:

    def test_goodhart_compute_seeds_large_base_seed(self):
        """Per-field seed computation works with large base_seed values."""
        base = 2**31 - 1
        result = compute_field_seeds(["x", "a", "m"], base)
        assert len(result) == 3
        sorted_names = sorted(["x", "a", "m"])
        for i, info in enumerate(result):
            assert info.field_name == sorted_names[i]
            assert info.field_index_offset == i
            assert info.field_seed == base + i

    def test_goodhart_compute_seeds_single_field(self):
        """Single field case assigns offset 0 and field_seed == base_seed."""
        result = compute_field_seeds(["alpha"], 100)
        assert len(result) == 1
        assert result[0].field_index_offset == 0
        assert result[0].field_seed == 100
        assert result[0].field_name == "alpha"

    def test_goodhart_compute_seeds_lexicographic_order_numbers(self):
        """Lexicographic sorting follows string rules, not natural number ordering."""
        result = compute_field_seeds(["field_10", "field_2", "field_1"], 0)
        expected_order = ["field_1", "field_10", "field_2"]
        actual_order = [info.field_name for info in result]
        assert actual_order == expected_order
        for i, info in enumerate(result):
            assert info.field_index_offset == i

    def test_goodhart_compute_seeds_five_fields_correct_offsets(self):
        """Field index offsets assigned correctly for 5 diverse field names."""
        fields = ["zebra", "apple", "mango", "banana", "cherry"]
        result = compute_field_seeds(fields, 500)
        expected = ["apple", "banana", "cherry", "mango", "zebra"]
        for i, info in enumerate(result):
            assert info.field_name == expected[i]
            assert info.field_index_offset == i
            assert info.field_seed == 500 + i


# ---------------------------------------------------------------------------
# resolve_seed – edge cases around falsy values
# ---------------------------------------------------------------------------

class TestGoodhartResolveSeed:

    def test_goodhart_resolve_seed_zero(self):
        """resolve_seed treats 0 as a valid explicit seed, not as falsy/None."""
        assert resolve_seed(0, 42) == 0

    def test_goodhart_resolve_seed_negative(self):
        """resolve_seed accepts negative seed values as valid."""
        assert resolve_seed(-1, None) == -1


# ---------------------------------------------------------------------------
# parse_varchar_length – boundary and format variations
# ---------------------------------------------------------------------------

class TestGoodhartParseVarchar:

    def test_goodhart_parse_varchar_zero_length(self):
        """parse_varchar_length rejects varchar(0) since min is 1."""
        with pytest.raises(Exception):
            parse_varchar_length("varchar(0)")

    def test_goodhart_parse_varchar_large_length(self):
        """parse_varchar_length correctly parses large length values."""
        assert parse_varchar_length("varchar(65535)") == 65535

    def test_goodhart_parse_varchar_length_one(self):
        """parse_varchar_length accepts varchar(1) as the minimum valid length."""
        assert parse_varchar_length("varchar(1)") == 1


# ---------------------------------------------------------------------------
# generate_field_value – precedence chain and edge cases
# ---------------------------------------------------------------------------

class TestGoodhartGenerateFieldValue:

    def _make_field_spec(self, **kwargs):
        defaults = {
            "field_name": "test_field",
            "sql_type": "varchar(255)",
            "max_length": 255,
            "classification": None,
            "encrypted_at_rest": False,
            "tokenized": False,
            "nullable": False,
        }
        defaults.update(kwargs)
        return FieldSpec(**defaults)

    def test_goodhart_encrypted_pii_precedence(self):
        """encrypted_at_rest takes precedence over PII classification in test mode."""
        spec = self._make_field_spec(encrypted_at_rest=True, classification=FieldClassification.PII)
        result = generate_field_value(spec, 42, 0, MockPurpose.test, None, "b", "t", 0.0)
        assert re.fullmatch(r"tok_[A-Za-z0-9_\-]{24}", result), f"Expected tok_ pattern, got: {result}"

    def test_goodhart_tokenized_financial_precedence(self):
        """tokenized takes precedence over FINANCIAL classification in test mode."""
        spec = self._make_field_spec(tokenized=True, classification=FieldClassification.FINANCIAL)
        result = generate_field_value(spec, 42, 0, MockPurpose.test, None, "b", "t", 0.0)
        assert re.fullmatch(r"tok_[A-Za-z0-9_\-]{24}", result)

    def test_goodhart_nullable_zero_probability_never_none(self):
        """Nullable fields with null_probability=0.0 never produce None."""
        spec = self._make_field_spec(nullable=True)
        for row_idx in range(100):
            result = generate_field_value(spec, 42, row_idx, MockPurpose.test, None, "b", "t", 0.0)
            assert result is not None, f"Got None at row_index={row_idx} with null_probability=0.0"

    def test_goodhart_different_row_indices_different_values(self):
        """Same field with different row_index values produces different values."""
        spec = self._make_field_spec()
        values = set()
        for row_idx in range(10):
            val = generate_field_value(spec, 42, row_idx, MockPurpose.test, None, "b", "t", 0.0)
            values.add(str(val))
        assert len(values) >= 8, "Expected mostly unique values across row indices"

    def test_goodhart_classification_override_unsupported_type(self):
        """A field with unsupported SQL type but PII classification uses classification
        generator, not fallback."""
        spec = self._make_field_spec(sql_type="nonsense_type", max_length=None,
                                      classification=FieldClassification.PII)
        result = generate_field_value(spec, 42, 0, MockPurpose.test, None, "b", "t", 0.0)
        # Should not be a simple fallback random string; PII generator should kick in
        assert result is not None

    def test_goodhart_bigint_produces_integer(self):
        """generate_field_value produces an integer for bigint SQL type."""
        spec = self._make_field_spec(sql_type="bigint", max_length=None)
        result = generate_field_value(spec, 42, 0, MockPurpose.test, None, "b", "t", 0.0)
        assert isinstance(result, int), f"Expected int for bigint, got {type(result)}: {result}"


# ---------------------------------------------------------------------------
# shape_canary_to_type – additional shaping scenarios
# ---------------------------------------------------------------------------

class TestGoodhartShapeCanary:

    def _make_field_spec(self, **kwargs):
        defaults = {
            "field_name": "test_field",
            "sql_type": "varchar(255)",
            "max_length": 255,
            "classification": None,
            "encrypted_at_rest": False,
            "tokenized": False,
            "nullable": False,
        }
        defaults.update(kwargs)
        return FieldSpec(**defaults)

    def test_goodhart_shape_canary_varchar_no_max_length(self):
        """varchar without max_length returns full fingerprint without truncation."""
        fp = "ledger-canary-staging-abcdef01"
        spec = self._make_field_spec(sql_type="varchar", max_length=None)
        result = shape_canary_to_type(fp, spec)
        assert fp in str(result), "Full fingerprint should be preserved when no max_length"

    def test_goodhart_shape_canary_varchar_tight_max_length(self):
        """varchar with small max_length truncates the shaped value appropriately."""
        fp = "ledger-canary-staging-abcdef01"
        spec = self._make_field_spec(sql_type="varchar(30)", max_length=30)
        result = shape_canary_to_type(fp, spec)
        assert len(str(result)) <= 30

    def test_goodhart_shape_canary_tokenized_and_email(self):
        """When field is both tokenized and PII email, tokenized shaping wins with tok_ prefix."""
        fp = "ledger-canary-tier1-abcdef01"
        spec = self._make_field_spec(
            field_name="email", sql_type="varchar(255)",
            classification=FieldClassification.PII, tokenized=True
        )
        result = shape_canary_to_type(fp, spec)
        assert str(result).startswith("tok_"), f"Expected tok_ prefix, got: {result}"

    def test_goodhart_shape_canary_uuid_valid_format(self):
        """UUID-shaped canary values are parseable as valid UUIDs."""
        fp = "ledger-canary-prod-12345678"
        spec = self._make_field_spec(sql_type="uuid", max_length=None)
        result = shape_canary_to_type(fp, spec)
        # Should be parseable as UUID
        parsed = uuid.UUID(str(result))
        assert parsed is not None


# ---------------------------------------------------------------------------
# validate_request – boundary row_count and tier edge cases
# ---------------------------------------------------------------------------

class TestGoodhartValidateRequest:

    def _base_request(self, **overrides):
        req = {
            "backend_id": "test-backend",
            "table_name": "test_table",
            "fields": [
                {
                    "field_name": "id",
                    "sql_type": "bigint",
                    "max_length": None,
                    "classification": None,
                    "encrypted_at_rest": False,
                    "tokenized": False,
                    "nullable": False,
                }
            ],
            "row_count": 10,
            "seed": 42,
            "purpose": "test",
            "tier": None,
            "arbiter_api": None,
            "null_probability": 0.1,
        }
        req.update(overrides)
        return req

    def test_goodhart_validate_row_count_zero(self):
        """Validation rejects row_count of 0 since minimum is 1."""
        violations = validate_request(self._base_request(row_count=0))
        assert len(violations) > 0
        assert any("row_count" in str(v.message).lower() or "row_count" in str(v.field_name).lower()
                    for v in violations)

    def test_goodhart_validate_row_count_negative(self):
        """Validation rejects negative row_count values."""
        violations = validate_request(self._base_request(row_count=-5))
        assert len(violations) > 0

    def test_goodhart_validate_row_count_exceeds_max(self):
        """Validation rejects row_count exceeding 1,000,000."""
        violations = validate_request(self._base_request(row_count=1_000_001))
        assert len(violations) > 0

    def test_goodhart_validate_canary_empty_tier_string(self):
        """Validation rejects empty string tier when purpose is canary."""
        violations = validate_request(self._base_request(purpose="canary", tier=""))
        assert len(violations) > 0

    def test_goodhart_validate_row_count_boundary_valid(self):
        """Validation accepts row_count=1 and row_count=1_000_000 as boundary valid values."""
        violations_min = validate_request(self._base_request(row_count=1))
        # row_count=1 should be valid
        row_count_violations = [v for v in violations_min
                                 if "row_count" in str(v.message).lower() or "row_count" in str(v.field_name).lower()]
        assert len(row_count_violations) == 0

        violations_max = validate_request(self._base_request(row_count=1_000_000))
        row_count_violations = [v for v in violations_max
                                 if "row_count" in str(v.message).lower() or "row_count" in str(v.field_name).lower()]
        assert len(row_count_violations) == 0


# ---------------------------------------------------------------------------
# register_canary_with_arbiter – endpoint and response handling
# ---------------------------------------------------------------------------

class TestGoodhartArbiter:

    def _make_canary_values(self):
        return [
            CanaryValue(
                field_name="test_field",
                row_index=0,
                raw_fingerprint="ledger-canary-tier1-abcdef01",
                shaped_value="ledger-canary-tier1-abcdef01",
            )
        ]

    def test_goodhart_arbiter_http_4xx(self):
        """Arbiter returning 403 is handled gracefully with success=False."""
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.text = "Forbidden"
        mock_response.json.side_effect = Exception("not json")

        with patch("httpx.Client.post", return_value=mock_response) as mock_post:
            result = register_canary_with_arbiter(
                "https://arbiter.example.com",
                self._make_canary_values(),
                "tier1", "backend", "table"
            )
        assert result.success is False
        assert result.arbiter_response_code == 403
        assert result.error_message is not None and len(result.error_message) > 0

    def test_goodhart_arbiter_success_has_registration_id(self):
        """On success, registration_id identifies the run sent to Arbiter."""
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {"status": "ok", "registered": 1}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.Client.post", return_value=mock_response):
            result = register_canary_with_arbiter(
                "https://arbiter.example.com",
                self._make_canary_values(),
                "tier1", "backend", "table"
            )
        assert result.success is True
        assert result.registration_id.startswith("ledger-backend-table-")
        assert result.arbiter_response_code == 201

    def test_goodhart_arbiter_200_missing_registration_id(self):
        """200 with valid JSON but no registration acknowledgement is treated as error."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.Client.post", return_value=mock_response):
            result = register_canary_with_arbiter(
                "https://arbiter.example.com",
                self._make_canary_values(),
                "tier1", "backend", "table"
            )
        assert result.success is False
        assert result.error_message is not None

    def test_goodhart_arbiter_posts_to_correct_endpoint(self):
        """Arbiter registration POSTs to {arbiter_api}/canary/register-fingerprint."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "ok", "registered": 1}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.Client.post", return_value=mock_response) as mock_post:
            register_canary_with_arbiter(
                "https://arbiter.example.com",
                self._make_canary_values(),
                "tier1", "backend", "table"
            )
        called_url = mock_post.call_args[0][0] if mock_post.call_args[0] else mock_post.call_args[1].get("url", "")
        assert called_url == "https://arbiter.example.com/canary/register-fingerprint"


# ---------------------------------------------------------------------------
# generate_mock_records – end-to-end adversarial tests
# ---------------------------------------------------------------------------

class TestGoodhartE2E:

    def _make_request(self, **kwargs):
        defaults = {
            "backend_id": "test-backend",
            "table_name": "test_table",
            "fields": [
                FieldSpec(
                    field_name="name",
                    sql_type="varchar(100)",
                    max_length=100,
                    classification=None,
                    encrypted_at_rest=False,
                    tokenized=False,
                    nullable=False,
                ),
            ],
            "row_count": 5,
            "seed": 42,
            "purpose": MockPurpose.test,
            "tier": None,
            "arbiter_api": None,
            "null_probability": 0.0,
        }
        defaults.update(kwargs)
        return MockGenerationRequest(**defaults)

    def test_goodhart_e2e_field_order_independence(self):
        """Records contain identical values regardless of field declaration order."""
        fields_order_1 = [
            FieldSpec(field_name="beta", sql_type="varchar(50)", max_length=50,
                      classification=None, encrypted_at_rest=False, tokenized=False, nullable=False),
            FieldSpec(field_name="alpha", sql_type="bigint", max_length=None,
                      classification=None, encrypted_at_rest=False, tokenized=False, nullable=False),
        ]
        fields_order_2 = [
            FieldSpec(field_name="alpha", sql_type="bigint", max_length=None,
                      classification=None, encrypted_at_rest=False, tokenized=False, nullable=False),
            FieldSpec(field_name="beta", sql_type="varchar(50)", max_length=50,
                      classification=None, encrypted_at_rest=False, tokenized=False, nullable=False),
        ]
        req1 = self._make_request(fields=fields_order_1, seed=777, row_count=3)
        req2 = self._make_request(fields=fields_order_2, seed=777, row_count=3)
        result1 = generate_mock_records(req1)
        result2 = generate_mock_records(req2)
        for i in range(3):
            assert result1.records[i]["alpha"] == result2.records[i]["alpha"]
            assert result1.records[i]["beta"] == result2.records[i]["beta"]

    def test_goodhart_e2e_canary_registered_true_on_success(self):
        """canary_registered is exactly True when arbiter returns 2xx."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "ok", "registered": 2}
        mock_response.raise_for_status = MagicMock()

        fields = [
            FieldSpec(field_name="data", sql_type="varchar(100)", max_length=100,
                      classification=None, encrypted_at_rest=False, tokenized=False, nullable=False),
        ]
        req = self._make_request(
            fields=fields, purpose=MockPurpose.canary, tier="staging",
            arbiter_api="https://arbiter.test", row_count=2
        )
        with patch("httpx.Client.post", return_value=mock_response):
            result = generate_mock_records(req)
        assert result.canary_registered is True

    def test_goodhart_e2e_canary_registered_false_on_failure(self):
        """canary_registered is exactly False when arbiter returns error."""
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        mock_response.json.side_effect = Exception("not json")

        fields = [
            FieldSpec(field_name="data", sql_type="varchar(100)", max_length=100,
                      classification=None, encrypted_at_rest=False, tokenized=False, nullable=False),
        ]
        req = self._make_request(
            fields=fields, purpose=MockPurpose.canary, tier="staging",
            arbiter_api="https://arbiter.test", row_count=2
        )
        with patch("httpx.Client.post", return_value=mock_response):
            result = generate_mock_records(req)
        assert result.canary_registered is False

    def test_goodhart_e2e_test_purpose_canary_registered_none_with_arbiter(self):
        """When purpose='test', canary_registered is None even if arbiter_api is set."""
        req = self._make_request(
            purpose=MockPurpose.test,
            arbiter_api="https://arbiter.test",
        )
        result = generate_mock_records(req)
        assert result.canary_registered is None

    def test_goodhart_e2e_multiple_unsupported_types(self):
        """Multiple unsupported type fields each produce their own warning violation."""
        fields = [
            FieldSpec(field_name="geo", sql_type="geometry", max_length=None,
                      classification=None, encrypted_at_rest=False, tokenized=False, nullable=False),
            FieldSpec(field_name="store", sql_type="hstore", max_length=None,
                      classification=None, encrypted_at_rest=False, tokenized=False, nullable=False),
            FieldSpec(field_name="doc", sql_type="xml", max_length=None,
                      classification=None, encrypted_at_rest=False, tokenized=False, nullable=False),
        ]
        req = self._make_request(fields=fields, row_count=2)
        result = generate_mock_records(req)
        warning_fields = {e.field_name for e in result.errors if e.severity == ViolationSeverity.warning}
        assert "geo" in warning_fields
        assert "store" in warning_fields
        assert "doc" in warning_fields
        # Records should still be generated with fallback values
        assert len(result.records) == 2
        for record in result.records:
            assert "geo" in record and "store" in record and "doc" in record

    def test_goodhart_e2e_canary_all_rows_unique_fingerprints(self):
        """In canary mode, each row produces a unique fingerprint per field."""
        fields = [
            FieldSpec(field_name="data", sql_type="varchar(255)", max_length=255,
                      classification=None, encrypted_at_rest=False, tokenized=False, nullable=False),
        ]
        req = self._make_request(
            fields=fields, purpose=MockPurpose.canary, tier="test-tier",
            row_count=5
        )
        with patch("httpx.Client.post", side_effect=Exception("no arbiter")):
            result = generate_mock_records(req)
        values = [str(record["data"]) for record in result.records]
        assert len(set(values)) == 5, f"Expected 5 unique canary values, got {len(set(values))}"

    def test_goodhart_e2e_mixed_encrypted_and_normal(self):
        """Only encrypted fields produce tok_ values; normal fields produce type-appropriate values."""
        fields = [
            FieldSpec(field_name="secret", sql_type="varchar(100)", max_length=100,
                      classification=None, encrypted_at_rest=True, tokenized=False, nullable=False),
            FieldSpec(field_name="count", sql_type="bigint", max_length=None,
                      classification=None, encrypted_at_rest=False, tokenized=False, nullable=False),
        ]
        req = self._make_request(fields=fields, row_count=5)
        result = generate_mock_records(req)
        for record in result.records:
            assert re.fullmatch(r"tok_[A-Za-z0-9_\-]{24}", record["secret"]), \
                f"Encrypted field not tok_ pattern: {record['secret']}"
            assert isinstance(record["count"], int), \
                f"Normal bigint field should be int, got {type(record['count'])}: {record['count']}"

    def test_goodhart_e2e_seed_used_reflects_explicit(self):
        """seed_used in result reflects the explicit seed from the request."""
        req = self._make_request(seed=98765)
        result = generate_mock_records(req)
        assert result.seed_used == 98765

    def test_goodhart_e2e_different_seeds_different_records(self):
        """Different seeds produce different record values."""
        req1 = self._make_request(seed=1, row_count=3)
        req2 = self._make_request(seed=2, row_count=3)
        result1 = generate_mock_records(req1)
        result2 = generate_mock_records(req2)
        # At least one record should differ
        any_different = False
        for i in range(3):
            for key in result1.records[i]:
                if result1.records[i][key] != result2.records[i][key]:
                    any_different = True
                    break
        assert any_different, "Different seeds should produce different records"

    def test_goodhart_e2e_row_count_one(self):
        """Generating exactly 1 row produces a result with exactly 1 record."""
        req = self._make_request(row_count=1)
        result = generate_mock_records(req)
        assert len(result.records) == 1
        assert result.row_count == 1

    def test_goodhart_e2e_canary_every_field_has_fingerprint(self):
        """In canary mode, every field in every row contains the canary substring."""
        fields = [
            FieldSpec(field_name="a", sql_type="varchar(255)", max_length=255,
                      classification=None, encrypted_at_rest=False, tokenized=False, nullable=False),
            FieldSpec(field_name="b", sql_type="varchar(255)", max_length=255,
                      classification=None, encrypted_at_rest=False, tokenized=False, nullable=False),
            FieldSpec(field_name="c", sql_type="varchar(255)", max_length=255,
                      classification=None, encrypted_at_rest=False, tokenized=False, nullable=False),
        ]
        req = self._make_request(
            fields=fields, purpose=MockPurpose.canary, tier="alpha",
            row_count=3
        )
        with patch("httpx.Client.post", side_effect=Exception("no arbiter")):
            result = generate_mock_records(req)
        for record in result.records:
            for field_name in ["a", "b", "c"]:
                assert "ledger-canary-alpha" in str(record[field_name]), \
                    f"Field {field_name} missing canary substring: {record[field_name]}"

    def test_goodhart_e2e_encrypted_across_all_rows(self):
        """Encrypted field produces tok_ pattern for every row, not just the first."""
        fields = [
            FieldSpec(field_name="token", sql_type="varchar(100)", max_length=100,
                      classification=None, encrypted_at_rest=True, tokenized=False, nullable=False),
        ]
        req = self._make_request(fields=fields, row_count=10)
        result = generate_mock_records(req)
        for i, record in enumerate(result.records):
            assert re.fullmatch(r"tok_[A-Za-z0-9_\-]{24}", record["token"]), \
                f"Row {i} encrypted field not tok_ pattern: {record['token']}"

    def test_goodhart_e2e_no_exception_on_generation_errors(self):
        """generate_mock_records never raises; errors are captured in result."""
        fields = [
            FieldSpec(field_name="valid", sql_type="bigint", max_length=None,
                      classification=None, encrypted_at_rest=False, tokenized=False, nullable=False),
            FieldSpec(field_name="invalid1", sql_type="totally_fake_type", max_length=None,
                      classification=None, encrypted_at_rest=False, tokenized=False, nullable=False),
        ]
        req = self._make_request(fields=fields, row_count=3)
        # Should not raise
        result = generate_mock_records(req)
        assert len(result.records) == 3
        assert len(result.errors) > 0
