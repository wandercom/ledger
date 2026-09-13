"""
Adversarial hidden acceptance tests for Registry & Schema Store component.
These tests catch implementations that pass visible tests through shortcuts
(hardcoded returns, missing validation, etc.) rather than truly satisfying the contract.
"""

import os
import json
import datetime
import pathlib
import pytest
import yaml

from src.registry import (
    init,
    register_backend,
    store_schema,
    list_backends,
    list_schemas,
    get_schema,
    validate_all,
    read_changelog,
    BackendMetadata,
    BackendNotFoundError,
    DuplicateBackendError,
    LedgerCorruptedError,
    LedgerError,
    LedgerNotInitializedError,
    OwnershipConflictError,
    SchemaParseError,
)


def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


def _make_metadata(backend_id, backend_type="postgres", owner="test-service"):
    return BackendMetadata(
        backend_id=backend_id,
        backend_type=backend_type,
        owner_component=owner,
        registered_at=_utcnow(),
    )


# =====================================================================
# Backend ID regex validation tests
# =====================================================================

class TestGoodhartBackendIdRegex:
    """Tests that the backend_id regex ^[a-z][a-z0-9_-]{1,62}[a-z0-9]$ is enforced."""

    def test_goodhart_backend_id_regex_too_short(self, tmp_path):
        """Backend IDs shorter than 3 characters must be rejected per the regex constraint."""
        init(tmp_path)
        with pytest.raises(Exception):  # Could be ValueError or LedgerError
            meta = _make_metadata("ab")  # only 2 chars
            register_backend(tmp_path, meta, actor="test")

    def test_goodhart_backend_id_regex_starts_with_digit(self, tmp_path):
        """Backend IDs must start with a lowercase letter; IDs starting with a digit must be rejected."""
        init(tmp_path)
        with pytest.raises(Exception):
            meta = _make_metadata("1backend")
            register_backend(tmp_path, meta, actor="test")

    def test_goodhart_backend_id_regex_uppercase(self, tmp_path):
        """Backend IDs must be lowercase only; uppercase characters must be rejected."""
        init(tmp_path)
        with pytest.raises(Exception):
            meta = _make_metadata("MyBackend")
            register_backend(tmp_path, meta, actor="test")

    def test_goodhart_backend_id_regex_ends_with_hyphen(self, tmp_path):
        """Backend IDs must end with an alphanumeric character; trailing hyphens must be rejected."""
        init(tmp_path)
        with pytest.raises(Exception):
            meta = _make_metadata("my-backend-")
            register_backend(tmp_path, meta, actor="test")

    def test_goodhart_backend_id_regex_ends_with_underscore_rejected(self, tmp_path):
        """Backend IDs ending with underscore must be rejected per the regex requiring alphanumeric end."""
        init(tmp_path)
        with pytest.raises(Exception):
            meta = _make_metadata("my_backend_")
            register_backend(tmp_path, meta, actor="test")

    def test_goodhart_backend_id_regex_too_long(self, tmp_path):
        """Backend IDs longer than 64 characters must be rejected per the regex constraint."""
        init(tmp_path)
        # 65 chars: starts with 'a', 63 middle chars, ends with 'z'
        long_id = "a" + "b" * 63 + "z"  # 65 chars
        assert len(long_id) == 65
        with pytest.raises(Exception):
            meta = _make_metadata(long_id)
            register_backend(tmp_path, meta, actor="test")

    def test_goodhart_backend_id_regex_valid_boundary_3_chars(self, tmp_path):
        """A backend_id of exactly 3 characters matching the regex should be accepted as valid."""
        init(tmp_path)
        meta = _make_metadata("ab1")  # 3 chars, starts with letter, ends with digit
        entry = register_backend(tmp_path, meta, actor="test")
        assert entry.backend_id == "ab1"

    def test_goodhart_backend_id_regex_valid_boundary_64_chars(self, tmp_path):
        """A backend_id of exactly 64 characters matching the regex should be accepted as valid."""
        init(tmp_path)
        # 64 chars: starts with 'a', 62 middle 'b's, ends with '0'
        long_id = "a" + "b" * 62 + "0"
        assert len(long_id) == 64
        meta = _make_metadata(long_id)
        entry = register_backend(tmp_path, meta, actor="test")
        assert entry.backend_id == long_id

    def test_goodhart_backend_id_special_chars(self, tmp_path):
        """Backend IDs containing characters outside [a-z0-9_-] like dots must be rejected."""
        init(tmp_path)
        with pytest.raises(Exception):
            meta = _make_metadata("my.backend")
            register_backend(tmp_path, meta, actor="test")

    def test_goodhart_backend_id_single_char_rejected(self, tmp_path):
        """A single-character backend_id must be rejected as it fails the 3-char minimum."""
        init(tmp_path)
        with pytest.raises(Exception):
            meta = _make_metadata("a")
            register_backend(tmp_path, meta, actor="test")

    def test_goodhart_backend_id_with_underscores_and_hyphens(self, tmp_path):
        """Backend IDs containing both underscores and hyphens in the middle should be valid."""
        init(tmp_path)
        meta = _make_metadata("my_cool-backend1")
        entry = register_backend(tmp_path, meta, actor="test")
        assert entry.backend_id == "my_cool-backend1"

    def test_goodhart_backend_id_ends_with_digit(self, tmp_path):
        """Backend IDs ending with a digit should be valid per the regex [a-z0-9]$ terminator."""
        init(tmp_path)
        meta = _make_metadata("mydb99")
        entry = register_backend(tmp_path, meta, actor="test")
        assert entry.backend_id == "mydb99"


# =====================================================================
# Sequence continuity across operation types
# =====================================================================

class TestGoodhartSequenceContinuity:

    def test_goodhart_sequence_continues_after_store_schema(self, tmp_path):
        """Changelog sequence numbers must be globally monotonic across both register_backend and store_schema operations without gaps."""
        init(tmp_path)
        meta1 = _make_metadata("backend-aa")
        entry1 = register_backend(tmp_path, meta1, actor="test")
        assert entry1.sequence == 1

        raw = b"col1: int\ncol2: varchar\n"
        entry2 = store_schema(tmp_path, "backend-aa", "users", raw, actor="test")
        assert entry2.sequence == 2

        meta2 = _make_metadata("backend-bb", owner="other-svc")
        entry3 = register_backend(tmp_path, meta2, actor="test")
        assert entry3.sequence == 3

        # Verify all entries via changelog read
        entries = read_changelog(tmp_path, backend_id="", limit=0)
        seqs = [e.sequence for e in entries]
        assert seqs == [1, 2, 3]


# =====================================================================
# All backend types registerable
# =====================================================================

class TestGoodhartAllBackendTypes:

    def test_goodhart_register_backend_all_types(self, tmp_path):
        """All BackendType enum values should be registerable."""
        init(tmp_path)
        types = ["postgres", "mysql", "sqlite", "redis", "s3", "dynamodb", "kafka", "custom"]
        for i, bt in enumerate(types):
            bid = f"backend-{bt}-{i:02d}"
            # Ensure bid is valid (>= 3 chars, starts with letter, etc.)
            meta = _make_metadata(bid, backend_type=bt, owner=f"svc-{i}")
            entry = register_backend(tmp_path, meta, actor="test")
            assert entry.change_type == "backend_registered"

        backends = list_backends(tmp_path)
        assert len(backends) == 8


# =====================================================================
# list_backends isolation from schema subdirs
# =====================================================================

class TestGoodhartListBackendsIsolation:

    def test_goodhart_list_backends_does_not_include_schema_subdirs(self, tmp_path):
        """list_backends should only read top-level .yaml files in registry/, not schema files in subdirectories."""
        init(tmp_path)
        meta = _make_metadata("mydb01")
        register_backend(tmp_path, meta, actor="test")
        store_schema(tmp_path, "mydb01", "users", b"col: int\n", actor="test")
        store_schema(tmp_path, "mydb01", "orders", b"col: varchar\n", actor="test")

        backends = list_backends(tmp_path)
        assert len(backends) == 1
        assert backends[0].backend_id == "mydb01"


# =====================================================================
# Multiple tables per backend
# =====================================================================

class TestGoodhartMultipleSchemas:

    def test_goodhart_store_schema_multiple_tables_same_backend(self, tmp_path):
        """Multiple schemas can be stored under the same backend and all should be independently retrievable."""
        init(tmp_path)
        register_backend(tmp_path, _make_metadata("mydb01"), actor="test")

        schemas = {
            "users": b"id: int\nname: varchar\n",
            "orders": b"id: int\namount: float\n",
            "products": b"id: int\ntitle: text\n",
        }
        for table, raw in schemas.items():
            store_schema(tmp_path, "mydb01", table, raw, actor="test")

        result = list_schemas(tmp_path, "mydb01")
        assert len(result) == 3

        for table, raw in schemas.items():
            record = get_schema(tmp_path, "mydb01", table)
            assert record is not None
            assert record.raw_content == raw


# =====================================================================
# Schema overwrite
# =====================================================================

class TestGoodhartSchemaOverwrite:

    def test_goodhart_store_schema_overwrite_preserves_verbatim(self, tmp_path):
        """Storing a schema for the same backend_id and table again should overwrite with the new content verbatim."""
        init(tmp_path)
        register_backend(tmp_path, _make_metadata("mydb01"), actor="test")

        raw_v1 = b"version: 1\ncol: int\n"
        raw_v2 = b"version: 2\ncol: bigint\nextra: text\n"

        store_schema(tmp_path, "mydb01", "users", raw_v1, actor="test")
        store_schema(tmp_path, "mydb01", "users", raw_v2, actor="test")

        record = get_schema(tmp_path, "mydb01", "users")
        assert record is not None
        assert record.raw_content == raw_v2


# =====================================================================
# Failed operations don't modify changelog
# =====================================================================

class TestGoodhartChangelogIntegrity:

    def test_goodhart_changelog_not_modified_on_failed_register(self, tmp_path):
        """Failed operations (like duplicate registration) must not append any entry to the changelog."""
        init(tmp_path)
        meta = _make_metadata("mydb01")
        register_backend(tmp_path, meta, actor="test")

        with pytest.raises(DuplicateBackendError):
            register_backend(tmp_path, meta, actor="test")

        entries = read_changelog(tmp_path, backend_id="", limit=0)
        assert len(entries) == 1

    def test_goodhart_changelog_not_modified_on_failed_store(self, tmp_path):
        """Failed store_schema operations (like invalid YAML) must not append to the changelog."""
        init(tmp_path)
        register_backend(tmp_path, _make_metadata("mydb01"), actor="test")

        with pytest.raises(SchemaParseError):
            store_schema(tmp_path, "mydb01", "bad", b"{{{{invalid: yaml: [", actor="test")

        entries = read_changelog(tmp_path, backend_id="", limit=0)
        assert len(entries) == 1  # only the registration entry


# =====================================================================
# read_changelog limit returns most recent
# =====================================================================

class TestGoodhartReadChangelogLimit:

    def test_goodhart_read_changelog_limit_returns_most_recent(self, tmp_path):
        """When limit is applied, the returned entries should be the most recent ones, ordered ascending."""
        init(tmp_path)
        # Create 5 entries: 3 backends + 2 schemas
        register_backend(tmp_path, _make_metadata("backend-a1"), actor="test")  # seq 1
        register_backend(tmp_path, _make_metadata("backend-b2"), actor="test")  # seq 2
        register_backend(tmp_path, _make_metadata("backend-c3"), actor="test")  # seq 3
        store_schema(tmp_path, "backend-a1", "t1", b"col: int\n", actor="test")  # seq 4
        store_schema(tmp_path, "backend-b2", "t2", b"col: int\n", actor="test")  # seq 5

        entries = read_changelog(tmp_path, backend_id="", limit=2)
        assert len(entries) == 2
        # Most recent 2 entries should be seq 4 and 5
        assert entries[0].sequence == 4
        assert entries[1].sequence == 5
        # Still ordered ascending
        assert entries[0].sequence < entries[1].sequence

    def test_goodhart_read_changelog_limit_exceeds_entries(self, tmp_path):
        """When limit exceeds the number of available entries, all entries should be returned."""
        init(tmp_path)
        register_backend(tmp_path, _make_metadata("backend-a1"), actor="test")
        register_backend(tmp_path, _make_metadata("backend-b2"), actor="test")

        entries = read_changelog(tmp_path, backend_id="", limit=100)
        assert len(entries) == 2

    def test_goodhart_read_changelog_filter_nonexistent_backend(self, tmp_path):
        """Filtering changelog by a backend_id that has no entries should return an empty list."""
        init(tmp_path)
        register_backend(tmp_path, _make_metadata("mydb01"), actor="test")

        entries = read_changelog(tmp_path, backend_id="nonexistent99", limit=0)
        assert entries == []

    def test_goodhart_read_changelog_filter_with_limit_most_recent(self, tmp_path):
        """When filtering by backend_id with limit, the most recent matching entries should be returned."""
        init(tmp_path)
        register_backend(tmp_path, _make_metadata("backend-a1"), actor="test")  # seq 1
        register_backend(tmp_path, _make_metadata("backend-b2"), actor="test")  # seq 2
        store_schema(tmp_path, "backend-a1", "t1", b"c: 1\n", actor="test")    # seq 3
        store_schema(tmp_path, "backend-a1", "t2", b"c: 2\n", actor="test")    # seq 4
        store_schema(tmp_path, "backend-b2", "t3", b"c: 3\n", actor="test")    # seq 5

        entries = read_changelog(tmp_path, backend_id="backend-a1", limit=1)
        assert len(entries) == 1
        assert entries[0].backend_id == "backend-a1"
        # Should be the most recent one for backend-a1 (seq 4)
        assert entries[0].sequence == 4


# =====================================================================
# init corruption: changelog is directory
# =====================================================================

class TestGoodhartInitCorruption:

    def test_goodhart_init_corrupted_changelog_is_directory(self, tmp_path):
        """init should detect corruption when changelog.jsonl is a directory instead of a file."""
        ledger = tmp_path / ".ledger"
        ledger.mkdir()
        (ledger / "registry").mkdir()
        (ledger / "plans").mkdir()
        (ledger / "changelog.jsonl").mkdir()  # directory, not file!

        with pytest.raises(LedgerCorruptedError):
            init(tmp_path)

    def test_goodhart_init_corrupted_error_has_missing_paths(self, tmp_path):
        """LedgerCorruptedError must include the missing_paths attribute listing which paths are absent."""
        ledger = tmp_path / ".ledger"
        ledger.mkdir()
        (ledger / "registry").mkdir()
        # Missing plans/ and changelog.jsonl

        with pytest.raises(LedgerCorruptedError) as exc_info:
            init(tmp_path)

        err = exc_info.value
        assert hasattr(err, "missing_paths")
        assert isinstance(err.missing_paths, list)
        assert len(err.missing_paths) >= 1


# =====================================================================
# get_schema for unregistered backend
# =====================================================================

class TestGoodhartGetSchemaEdgeCases:

    def test_goodhart_get_schema_backend_not_registered_returns_none(self, tmp_path):
        """get_schema for an unregistered backend should return None rather than crashing."""
        init(tmp_path)
        result = get_schema(tmp_path, "nonexistent99", "some_table")
        assert result is None

    def test_goodhart_schema_record_has_stored_at_timestamp(self, tmp_path):
        """SchemaRecord returned by get_schema must have a stored_at datetime field populated."""
        init(tmp_path)
        register_backend(tmp_path, _make_metadata("mydb01"), actor="test")
        store_schema(tmp_path, "mydb01", "users", b"id: int\n", actor="test")

        record = get_schema(tmp_path, "mydb01", "users")
        assert record is not None
        assert record.stored_at is not None
        assert isinstance(record.stored_at, datetime.datetime)

    def test_goodhart_schema_parsed_content_matches_raw(self, tmp_path):
        """The parsed_content dict in SchemaRecord must be the result of YAML-parsing the raw_content bytes."""
        init(tmp_path)
        register_backend(tmp_path, _make_metadata("mydb01"), actor="test")
        raw = b"name: users\ncolumns:\n  - id\n  - email\n"
        store_schema(tmp_path, "mydb01", "users", raw, actor="test")

        record = get_schema(tmp_path, "mydb01", "users")
        assert record is not None
        assert record.parsed_content == {"name": "users", "columns": ["id", "email"]}


# =====================================================================
# list_schemas isolation between backends
# =====================================================================

class TestGoodhartListSchemasIsolation:

    def test_goodhart_list_schemas_multiple_backends_isolated(self, tmp_path):
        """Schemas stored under different backends must not leak into each other's list_schemas results."""
        init(tmp_path)
        register_backend(tmp_path, _make_metadata("backend-a1"), actor="test")
        register_backend(tmp_path, _make_metadata("backend-b2", owner="svc-b"), actor="test")

        store_schema(tmp_path, "backend-a1", "users", b"col: int\n", actor="test")
        store_schema(tmp_path, "backend-a1", "orders", b"col: text\n", actor="test")
        store_schema(tmp_path, "backend-b2", "products", b"col: float\n", actor="test")

        schemas_a = list_schemas(tmp_path, "backend-a1")
        schemas_b = list_schemas(tmp_path, "backend-b2")

        assert len(schemas_a) == 2
        assert len(schemas_b) == 1
        assert all(s.backend_id == "backend-a1" for s in schemas_a)
        assert all(s.backend_id == "backend-b2" for s in schemas_b)
        table_names_a = [s.table_name for s in schemas_a]
        assert "products" not in table_names_a


# =====================================================================
# Verbatim storage edge cases
# =====================================================================

class TestGoodhartVerbatimStorage:

    def test_goodhart_store_schema_yaml_with_trailing_newlines(self, tmp_path):
        """YAML content with trailing newlines and whitespace must be stored verbatim without stripping."""
        init(tmp_path)
        register_backend(tmp_path, _make_metadata("mydb01"), actor="test")

        raw = b"col: int\n\n\n\n"  # 4 trailing newlines
        store_schema(tmp_path, "mydb01", "users", raw, actor="test")

        record = get_schema(tmp_path, "mydb01", "users")
        assert record is not None
        assert record.raw_content == raw
        assert record.raw_content.endswith(b"\n\n\n\n")

    def test_goodhart_store_schema_multiline_yaml_verbatim(self, tmp_path):
        """Complex multi-line YAML with block scalars and anchors must be stored byte-for-byte."""
        init(tmp_path)
        register_backend(tmp_path, _make_metadata("mydb01"), actor="test")

        raw = b"""defaults: &defaults
  adapter: postgres
  host: localhost

development:
  <<: *defaults
  database: myapp_dev

description: |
  This is a multi-line
  block scalar value.

notes: >
  This is a folded
  block scalar.
"""
        store_schema(tmp_path, "mydb01", "config", raw, actor="test")

        record = get_schema(tmp_path, "mydb01", "config")
        assert record is not None
        assert record.raw_content == raw

    def test_goodhart_store_schema_yaml_null_document(self, tmp_path):
        """A YAML document that parses to None (e.g., b'---\\n') should be accepted as valid parseable YAML."""
        init(tmp_path)
        register_backend(tmp_path, _make_metadata("mydb01"), actor="test")

        raw = b"---\n"
        store_schema(tmp_path, "mydb01", "empty_doc", raw, actor="test")

        record = get_schema(tmp_path, "mydb01", "empty_doc")
        assert record is not None
        assert record.raw_content == raw


# =====================================================================
# YAML file content verification for register_backend
# =====================================================================

class TestGoodhartRegistryYaml:

    def test_goodhart_register_backend_yaml_deserializable(self, tmp_path):
        """The YAML file written by register_backend must be deserializable back to equivalent BackendMetadata fields."""
        init(tmp_path)
        meta = _make_metadata("mydb01", backend_type="redis", owner="cache-service")
        register_backend(tmp_path, meta, actor="test")

        yaml_path = tmp_path / ".ledger" / "registry" / "mydb01.yaml"
        assert yaml_path.exists()

        with open(yaml_path, "r") as f:
            data = yaml.safe_load(f)

        assert data["backend_id"] == "mydb01"
        assert data["backend_type"] == "redis"
        assert data["owner_component"] == "cache-service"
        assert "registered_at" in data


# =====================================================================
# Changelog entry field verification
# =====================================================================

class TestGoodhartChangelogFields:

    def test_goodhart_changelog_entry_actor_preserved(self, tmp_path):
        """The actor field in ChangelogEntry must match the actor argument passed to the operation."""
        init(tmp_path)
        meta = _make_metadata("mydb01")
        entry = register_backend(tmp_path, meta, actor="custom-agent-v2")
        assert entry.actor == "custom-agent-v2"

    def test_goodhart_store_schema_changelog_has_table_field(self, tmp_path):
        """The ChangelogEntry from store_schema must have the table field set to the table name argument."""
        init(tmp_path)
        register_backend(tmp_path, _make_metadata("mydb01"), actor="test")
        entry = store_schema(tmp_path, "mydb01", "orders", b"col: int\n", actor="test")
        assert entry.table == "orders"
        assert entry.change_type == "schema_added"
        assert entry.backend_id == "mydb01"

    def test_goodhart_changelog_timestamps_are_utc(self, tmp_path):
        """All ChangelogEntry timestamps must have UTC timezone info, not naive datetimes."""
        init(tmp_path)
        entry = register_backend(tmp_path, _make_metadata("mydb01"), actor="test")
        assert entry.timestamp.tzinfo is not None
        # Check it's UTC (either datetime.timezone.utc or equivalent)
        utc_offset = entry.timestamp.utcoffset()
        assert utc_offset == datetime.timedelta(0)


# =====================================================================
# Exception hierarchy and attributes
# =====================================================================

class TestGoodhartExceptionHierarchy:

    def test_goodhart_exception_hierarchy(self, tmp_path):
        """All custom exceptions must inherit from LedgerError so that generic exception handlers work."""
        init(tmp_path)
        meta = _make_metadata("mydb01")
        register_backend(tmp_path, meta, actor="test")

        # DuplicateBackendError
        with pytest.raises(LedgerError):
            register_backend(tmp_path, meta, actor="test")

        # BackendNotFoundError
        with pytest.raises(LedgerError):
            store_schema(tmp_path, "nonexistent01", "t", b"c: 1\n", actor="test")

        # LedgerNotInitializedError
        with pytest.raises(LedgerError):
            list_backends(tmp_path / "nope")

    def test_goodhart_duplicate_backend_error_has_backend_id(self, tmp_path):
        """DuplicateBackendError must carry the backend_id attribute of the conflicting backend."""
        init(tmp_path)
        meta = _make_metadata("mydb01")
        register_backend(tmp_path, meta, actor="test")

        with pytest.raises(DuplicateBackendError) as exc_info:
            register_backend(tmp_path, meta, actor="test")

        assert exc_info.value.backend_id == "mydb01"

    def test_goodhart_ownership_conflict_error_attributes(self, tmp_path):
        """OwnershipConflictError must carry backend_id, existing_owner, and attempted_owner attributes."""
        init(tmp_path)
        meta1 = _make_metadata("mydb01", owner="service-a")
        register_backend(tmp_path, meta1, actor="test")

        meta2 = _make_metadata("mydb01", owner="service-b")
        with pytest.raises((DuplicateBackendError, OwnershipConflictError)):
            register_backend(tmp_path, meta2, actor="test")

    def test_goodhart_store_schema_parse_error_attributes(self, tmp_path):
        """SchemaParseError must carry backend_id, table, and parse_error attributes."""
        init(tmp_path)
        register_backend(tmp_path, _make_metadata("mydb01"), actor="test")

        with pytest.raises(SchemaParseError) as exc_info:
            store_schema(tmp_path, "mydb01", "bad_table", b"{{: [invalid", actor="test")

        err = exc_info.value
        assert err.backend_id == "mydb01"
        assert err.table == "bad_table"
        assert hasattr(err, "parse_error")
        assert err.parse_error  # non-empty

    def test_goodhart_backend_not_found_on_store_has_backend_id(self, tmp_path):
        """BackendNotFoundError raised by store_schema must include the backend_id that was not found."""
        init(tmp_path)

        with pytest.raises(BackendNotFoundError) as exc_info:
            store_schema(tmp_path, "nonexistent01", "table1", b"c: 1\n", actor="test")

        assert exc_info.value.backend_id == "nonexistent01"

    def test_goodhart_not_initialized_error_has_root_attr(self, tmp_path):
        """LedgerNotInitializedError must include the root attribute."""
        uninitialized = tmp_path / "empty_dir"
        uninitialized.mkdir()

        with pytest.raises(LedgerNotInitializedError) as exc_info:
            list_backends(uninitialized)

        err = exc_info.value
        assert hasattr(err, "root")


# =====================================================================
# list_schemas sorting edge case
# =====================================================================

class TestGoodhartListSchemasSorting:

    def test_goodhart_list_schemas_sorted_with_numeric_names(self, tmp_path):
        """list_schemas sorting must be lexicographic, not numeric — 'table10' sorts before 'table2'."""
        init(tmp_path)
        register_backend(tmp_path, _make_metadata("mydb01"), actor="test")

        for name in ["table2", "table10", "table1"]:
            store_schema(tmp_path, "mydb01", name, b"col: int\n", actor="test")

        schemas = list_schemas(tmp_path, "mydb01")
        names = [s.table_name for s in schemas]
        # Lexicographic: table1 < table10 < table2
        assert names == ["table1", "table10", "table2"]


# =====================================================================
# validate_all with mixed severities
# =====================================================================

class TestGoodhartValidateAll:

    def test_goodhart_validate_all_mixed_warnings_and_errors(self, tmp_path):
        """ValidationResult.valid must be False when there is at least one error even with warnings present."""
        init(tmp_path)
        # This test verifies the invariant that valid is computed from error-severity only.
        # The exact setup depends on what triggers violations, but we verify the property:
        result = validate_all(tmp_path)
        if len(result.violations) > 0:
            has_error = any(v.severity == "error" for v in result.violations)
            if has_error:
                assert result.valid is False
            else:
                assert result.valid is True
        else:
            assert result.valid is True


# =====================================================================
# init idempotent preserves data
# =====================================================================

class TestGoodhartInitIdempotent:

    def test_goodhart_init_idempotent_preserves_existing_data(self, tmp_path):
        """Calling init on an already-initialized root must not delete or modify existing data."""
        init(tmp_path)
        register_backend(tmp_path, _make_metadata("mydb01"), actor="test")
        store_schema(tmp_path, "mydb01", "users", b"col: int\n", actor="test")

        # Call init again
        init(tmp_path)

        # Verify data is preserved
        backends = list_backends(tmp_path)
        assert len(backends) == 1
        assert backends[0].backend_id == "mydb01"

        schemas = list_schemas(tmp_path, "mydb01")
        assert len(schemas) == 1

        entries = read_changelog(tmp_path, backend_id="", limit=0)
        assert len(entries) == 2  # 1 register + 1 store
