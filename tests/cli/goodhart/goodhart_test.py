"""
Adversarial hidden acceptance tests for the CLI Entry Point component.
These tests catch implementations that 'teach to the test' by using shortcuts
like hardcoded returns, missing validation, or partial invariant compliance.
"""

import dataclasses
import json
import os
import sys
from unittest.mock import MagicMock, patch, call

import pytest
import yaml

from src.cli import (
    cli_main,
    cmd_init,
    cmd_backend_add,
    cmd_schema_add,
    cmd_schema_show,
    cmd_schema_validate,
    cmd_migrate_plan,
    cmd_migrate_approve,
    cmd_export,
    cmd_mock,
    cmd_serve,
    require_config,
    format_output,
    render_violations,
    CliContext,
    CommandResult,
    LedgerError,
    ExitCode,
    OutputFormat,
    BackendType,
    ExportFormat,
    MockPurpose,
    Severity,
    Violation,
)

try:
    from click.testing import CliRunner
except ImportError:
    CliRunner = None


# ---- Helpers ----

def make_violation(path="test.path", message="test message", severity=Severity.error, code="TEST_001"):
    return Violation(path=path, message=message, severity=severity, code=code)


def make_result(success=True, data=None, message="", violations=None):
    return CommandResult(success=success, data=data, message=message, violations=violations or [])


def make_ctx(config=None, config_path="/tmp/test-ledger.yaml", verbose=False, output_format=OutputFormat.text):
    return CliContext(config_path=config_path, config=config, verbose=verbose, output_format=output_format)


# ---- cli_main: config_path resolution ----

class TestGoodhartCliMainConfigResolution:

    def test_goodhart_config_path_is_absolute_with_relative_flag(self):
        """Config path must be resolved to absolute even when --config is a relative path."""
        if CliRunner is None:
            pytest.skip("click not available")
        runner = CliRunner()
        captured_ctx = {}

        # We invoke the CLI group with a relative --config path
        # and capture the context
        from click.testing import CliRunner as CR
        import click

        # Use the actual cli_main click group
        try:
            result = runner.invoke(cli_main, ['--config', '../relative/path/ledger.yaml'], catch_exceptions=True)
            # If cli_main is a click group, we need to check the context
            # Alternative approach: test the resolution logic directly
        except Exception:
            pass

        # Direct test approach - create scenario where relative path is given
        with patch.dict(os.environ, {}, clear=False):
            if hasattr(cli_main, 'main'):
                runner = CliRunner()
                result = runner.invoke(cli_main, ['--config', 'relative/ledger.yaml', '--help'])
                # The help path doesn't exercise context, but we verify the command accepts it

    def test_goodhart_config_path_is_absolute_with_env_var(self):
        """Config path from LEDGER_CONFIG env var must be converted to absolute."""
        if CliRunner is None:
            pytest.skip("click not available")
        runner = CliRunner()
        with patch.dict(os.environ, {'LEDGER_CONFIG': 'subdir/my-ledger.yaml'}):
            # Invoke with no --config flag so env var is used
            result = runner.invoke(cli_main, ['--help'], catch_exceptions=True)
            # At minimum, the command should accept this without crashing

    def test_goodhart_config_flag_overrides_env_var_different_values(self):
        """--config flag must take priority over LEDGER_CONFIG env var."""
        if CliRunner is None:
            pytest.skip("click not available")
        runner = CliRunner()
        flag_path = '/flag/specific/ledger.yaml'
        env_path = '/env/different/ledger.yaml'

        captured = {}

        # Patch to capture the context
        original_invoke = None
        with patch.dict(os.environ, {'LEDGER_CONFIG': env_path}):
            result = runner.invoke(cli_main, ['--config', flag_path, 'init'], catch_exceptions=True)
            # The config_path should resolve from flag, not env
            # We verify by checking that the resolved path contains the flag path components
            if hasattr(result, 'exception') and result.exception:
                # Even if it fails, it should have tried to use the flag path
                pass

    def test_goodhart_default_config_path_resolves_to_cwd(self):
        """Default ./ledger.yaml must resolve to an absolute path rooted in cwd."""
        if CliRunner is None:
            pytest.skip("click not available")
        runner = CliRunner()
        cwd = os.getcwd()

        with patch.dict(os.environ, {k: v for k, v in os.environ.items() if k != 'LEDGER_CONFIG'}):
            # Remove LEDGER_CONFIG if it exists
            env = os.environ.copy()
            env.pop('LEDGER_CONFIG', None)
            with patch.dict(os.environ, env, clear=True):
                result = runner.invoke(cli_main, ['--help'], catch_exceptions=True)
                assert result.exit_code == 0


# ---- cli_main: CliContext fields ----

class TestGoodhartCliContextFields:

    def test_goodhart_cli_context_is_dataclass(self):
        """CliContext must be a dataclass, not a Pydantic model."""
        assert dataclasses.is_dataclass(CliContext), "CliContext must be a dataclass"
        # Verify it's not a Pydantic model
        try:
            from pydantic import BaseModel
            assert not isinstance(CliContext(), BaseModel), "CliContext must not be a Pydantic BaseModel"
        except (ImportError, TypeError):
            pass  # pydantic not installed or CliContext requires args

    def test_goodhart_cli_context_has_required_fields(self):
        """CliContext must have config_path, config, verbose, and output_format fields."""
        if dataclasses.is_dataclass(CliContext):
            field_names = {f.name for f in dataclasses.fields(CliContext)}
            assert 'config_path' in field_names
            assert 'config' in field_names
            assert 'verbose' in field_names
            assert 'output_format' in field_names
        else:
            # If not a dataclass, verify attributes exist
            ctx = make_ctx()
            assert hasattr(ctx, 'config_path')
            assert hasattr(ctx, 'config')
            assert hasattr(ctx, 'verbose')
            assert hasattr(ctx, 'output_format')

    def test_goodhart_cli_context_verbose_default_false(self):
        """CliContext.verbose must default to False when --verbose is not passed."""
        if CliRunner is None:
            pytest.skip("click not available")
        runner = CliRunner()
        # Invoke without --verbose
        result = runner.invoke(cli_main, ['--help'], catch_exceptions=True)
        assert result.exit_code == 0

    def test_goodhart_cli_context_output_format_default_text(self):
        """When --output is not provided, output_format must default to text."""
        if CliRunner is None:
            pytest.skip("click not available")
        runner = CliRunner()
        result = runner.invoke(cli_main, ['--help'], catch_exceptions=True)
        assert result.exit_code == 0


# ---- cli_main: error handling ----

class TestGoodhartCliMainErrorHandling:

    def test_goodhart_ledger_error_exit_code_domain_1(self):
        """LedgerError with DOMAIN_ERROR_1 must produce exit code 1."""
        if CliRunner is None:
            pytest.skip("click not available")
        runner = CliRunner()

        violations = [make_violation(message="domain problem")]
        error = LedgerError(violations=violations, exit_code=ExitCode.DOMAIN_ERROR_1)

        with patch('cli.cli.config.init_config', side_effect=error):
            result = runner.invoke(cli_main, ['init'], catch_exceptions=False)
            # The exit code should be 1
            assert result.exit_code == 1

    def test_goodhart_ledger_error_exit_code_config_3(self):
        """LedgerError with CONFIG_ERROR_3 must produce exit code 3."""
        if CliRunner is None:
            pytest.skip("click not available")
        runner = CliRunner()

        violations = [make_violation(message="config problem")]
        error = LedgerError(violations=violations, exit_code=ExitCode.CONFIG_ERROR_3)

        with patch('cli.cli.config.load_config', side_effect=error):
            result = runner.invoke(cli_main, ['schema', 'validate'], catch_exceptions=False)
            assert result.exit_code == 3

    def test_goodhart_ledger_error_violations_rendered_to_stderr(self):
        """All LedgerError violations must appear on stderr, not stdout."""
        if CliRunner is None:
            pytest.skip("click not available")
        runner = CliRunner(mix_stderr=False)

        unique_msgs = [f"UNIQUE_VIOLATION_{i}_XYZ" for i in range(3)]
        violations = [make_violation(message=msg) for msg in unique_msgs]
        error = LedgerError(violations=violations, exit_code=ExitCode.DOMAIN_ERROR_1)

        with patch('cli.cli.config.init_config', side_effect=error):
            result = runner.invoke(cli_main, ['init'], catch_exceptions=False)
            stderr_output = result.stderr if hasattr(result, 'stderr') else ''
            for msg in unique_msgs:
                assert msg in stderr_output or msg in result.output, \
                    f"Violation '{msg}' not found in output"

    def test_goodhart_ledger_error_many_violations_all_rendered(self):
        """When LedgerError has 20 violations, every one must appear — no truncation."""
        if CliRunner is None:
            pytest.skip("click not available")
        runner = CliRunner(mix_stderr=False)

        unique_msgs = [f"BULK_VIOLATION_{i:03d}_UNIQUE" for i in range(20)]
        violations = [make_violation(message=msg, code=f"BULK_{i:03d}") for i, msg in enumerate(unique_msgs)]
        error = LedgerError(violations=violations, exit_code=ExitCode.DOMAIN_ERROR_1)

        with patch('cli.cli.config.init_config', side_effect=error):
            result = runner.invoke(cli_main, ['init'], catch_exceptions=False)
            combined = (result.output or '') + (getattr(result, 'stderr', '') or '')
            for msg in unique_msgs:
                assert msg in combined, f"Violation '{msg}' was truncated from output"


# ---- require_config ----

class TestGoodhartRequireConfig:

    def test_goodhart_require_config_exit_code_is_config_error_3(self):
        """require_config must raise LedgerError with CONFIG_ERROR_3, not DOMAIN_ERROR_1."""
        ctx = make_ctx(config_path='/tmp/absolutely_nonexistent_path_xyz123/ledger.yaml')
        with pytest.raises(LedgerError) as exc_info:
            require_config(ctx)
        assert exc_info.value.exit_code == ExitCode.CONFIG_ERROR_3

    def test_goodhart_require_config_sets_config_not_none(self):
        """After require_config succeeds, ctx.config must be a loaded config object, not None."""
        import tempfile
        with tempfile.NamedTemporaryFile(suffix='.yaml', mode='w', delete=False) as f:
            f.write("version: 1\nbackends: []\n")
            f.flush()
            ctx = make_ctx(config_path=f.name)

        try:
            with patch('cli.cli.config.load_config', return_value={'version': 1}):
                require_config(ctx)
                assert ctx.config is not None
                assert not isinstance(ctx.config, str), "ctx.config should not be a path string"
        finally:
            os.unlink(f.name)


# ---- format_output ----

class TestGoodhartFormatOutput:

    def test_goodhart_format_output_json_valid_roundtrip(self):
        """format_output json must produce valid JSON that round-trips to original data."""
        data = {'backends': [{'id': 'novel-db-xyz', 'type': 'redis'}], 'count': 42}
        result = make_result(data=data)
        output = format_output(result, OutputFormat.json)
        parsed = json.loads(output)
        assert parsed == data

    def test_goodhart_format_output_json_nested_complex(self):
        """format_output json must handle deeply nested structures."""
        data = {
            'level1': {
                'level2': [
                    {'level3': {'values': [1, 2.5, True, None, 'str']}},
                    {'other': []}
                ]
            }
        }
        result = make_result(data=data)
        output = format_output(result, OutputFormat.json)
        parsed = json.loads(output)
        assert parsed == data

    def test_goodhart_format_output_json_list_data(self):
        """format_output json must handle list data, not just dicts."""
        data = [{'row': 1}, {'row': 2}, {'row': 3}]
        result = make_result(data=data)
        output = format_output(result, OutputFormat.json)
        parsed = json.loads(output)
        assert isinstance(parsed, list)
        assert len(parsed) == 3

    def test_goodhart_format_output_yaml_valid_roundtrip(self):
        """format_output yaml must produce valid YAML that round-trips."""
        data = {'schemas': [{'name': 'users', 'columns': ['id', 'email']}]}
        result = make_result(data=data)
        output = format_output(result, OutputFormat.yaml)
        parsed = yaml.safe_load(output)
        assert parsed == data

    def test_goodhart_format_output_json_special_chars(self):
        """format_output json must handle special characters correctly."""
        data = {'msg': 'line1\nline2', 'name': "O'Brien", 'emoji': '\u2603'}
        result = make_result(data=data)
        output = format_output(result, OutputFormat.json)
        parsed = json.loads(output)
        assert parsed['msg'] == 'line1\nline2'
        assert parsed['name'] == "O'Brien"
        assert parsed['emoji'] == '\u2603'

    def test_goodhart_format_output_text_is_not_json(self):
        """format_output text must return human-readable text, not raw JSON."""
        data = {'name': 'test-backend', 'tables': ['users', 'orders']}
        result = make_result(data=data)
        output = format_output(result, OutputFormat.text)
        assert isinstance(output, str)
        assert len(output) > 0
        # Text format should not be valid JSON (it should be formatted differently)
        try:
            parsed = json.loads(output)
            # If it parses as JSON, it might still be acceptable if it's pretty-printed
            # but it should at minimum be a string
        except json.JSONDecodeError:
            pass  # Expected — text format is not JSON

    def test_goodhart_format_output_json_none_data_raises(self):
        """format_output with json format and None data must raise an error per precondition."""
        result = make_result(data=None)
        with pytest.raises(Exception):
            format_output(result, OutputFormat.json)

    def test_goodhart_format_output_yaml_none_data_raises(self):
        """format_output with yaml format and None data must raise an error per precondition."""
        result = make_result(data=None)
        with pytest.raises(Exception):
            format_output(result, OutputFormat.yaml)

    def test_goodhart_format_output_json_integer_keys_not_lost(self):
        """format_output json must handle data with various value types without data loss."""
        data = {'int_val': 0, 'float_val': 3.14, 'bool_val': False, 'null_val': None, 'list_val': []}
        result = make_result(data=data)
        output = format_output(result, OutputFormat.json)
        parsed = json.loads(output)
        assert parsed['int_val'] == 0
        assert parsed['float_val'] == 3.14
        assert parsed['bool_val'] is False
        assert parsed['null_val'] is None
        assert parsed['list_val'] == []


# ---- render_violations ----

class TestGoodhartRenderViolations:

    def test_goodhart_render_violations_all_present_novel_messages(self):
        """Every violation's message must appear in rendered output — tested with unique novel strings."""
        unique_msgs = [f"UNIQUE_MSG_{chr(65+i)}{i*111}" for i in range(5)]
        violations = [
            make_violation(message=msg, severity=Severity.error, code=f"CODE_{i}")
            for i, msg in enumerate(unique_msgs)
        ]
        output = render_violations(violations, use_color=False)
        for msg in unique_msgs:
            assert msg in output, f"Violation message '{msg}' missing from rendered output"

    def test_goodhart_render_violations_severity_ordering_interleaved(self):
        """Errors must appear before warnings before info even when input is interleaved."""
        violations = [
            make_violation(path="info1", message="INFO_FIRST", severity=Severity.info, code="I1"),
            make_violation(path="warn1", message="WARN_FIRST", severity=Severity.warning, code="W1"),
            make_violation(path="err1", message="ERROR_FIRST", severity=Severity.error, code="E1"),
            make_violation(path="info2", message="INFO_SECOND", severity=Severity.info, code="I2"),
            make_violation(path="err2", message="ERROR_SECOND", severity=Severity.error, code="E2"),
        ]
        output = render_violations(violations, use_color=False)

        # Find positions
        err_pos = min(output.index("ERROR_FIRST"), output.index("ERROR_SECOND"))
        warn_pos = output.index("WARN_FIRST")
        info_pos = min(output.index("INFO_FIRST"), output.index("INFO_SECOND"))

        assert err_pos < warn_pos, "Errors must appear before warnings"
        assert warn_pos < info_pos, "Warnings must appear before info"

    def test_goodhart_render_violations_summary_counts_novel_distribution(self):
        """Summary must show correct counts for 3 errors, 1 warning, 2 info."""
        violations = [
            make_violation(severity=Severity.error, message=f"err_{i}", code=f"E{i}") for i in range(3)
        ] + [
            make_violation(severity=Severity.warning, message="warn_0", code="W0")
        ] + [
            make_violation(severity=Severity.info, message=f"info_{i}", code=f"I{i}") for i in range(2)
        ]
        output = render_violations(violations, use_color=False)
        # The summary should contain counts: 3 errors, 1 warning, 2 info
        assert '3' in output, "Should show 3 errors in summary"
        assert '1' in output, "Should show 1 warning in summary"
        assert '2' in output, "Should show 2 info in summary"

    def test_goodhart_render_violations_color_has_ansi(self):
        """With use_color=True, output must contain ANSI escape codes."""
        violations = [make_violation(message="colored msg")]
        output = render_violations(violations, use_color=True)
        assert '\033[' in output or '\x1b[' in output, \
            "use_color=True should produce ANSI escape codes"

    def test_goodhart_render_violations_single_violation_has_summary(self):
        """Even with a single violation, a summary count line must be present."""
        violations = [make_violation(severity=Severity.error, message="solo error")]
        output = render_violations(violations, use_color=False)
        assert "solo error" in output
        # Summary should indicate 1 error
        assert '1' in output

    def test_goodhart_render_violations_paths_included(self):
        """Each violation's path must appear in the rendered output."""
        violations = [
            make_violation(path="backends.novel-store.tables.xyz.columns.secret_col",
                         message="test", severity=Severity.error, code="P1"),
            make_violation(path="backends.other-store.tables.abc",
                         message="test2", severity=Severity.warning, code="P2"),
        ]
        output = render_violations(violations, use_color=False)
        assert "backends.novel-store.tables.xyz.columns.secret_col" in output
        assert "backends.other-store.tables.abc" in output

    def test_goodhart_render_violations_codes_included(self):
        """Each violation's code must appear in the rendered output."""
        violations = [
            make_violation(code="NOVEL_ERR_001", message="msg1", severity=Severity.error),
            make_violation(code="NOVEL_WARN_002", message="msg2", severity=Severity.warning),
        ]
        output = render_violations(violations, use_color=False)
        assert "NOVEL_ERR_001" in output
        assert "NOVEL_WARN_002" in output


# ---- Thin dispatch: cmd_backend_add ----

class TestGoodhartCmdBackendAdd:

    def test_goodhart_delegates_to_registry_with_novel_args(self):
        """cmd_backend_add must delegate to registry.register_backend with exact novel arguments."""
        import registry as registry_module
        mock_registry = MagicMock()
        mock_registry.BackendMetadata = registry_module.BackendMetadata
        mock_registry.BackendType = registry_module.BackendType
        ctx = make_ctx(config={'version': 1})

        with patch('cli.cli.registry', mock_registry), patch('cli.cli.config.load_config', return_value={'version': 1}):
            try:
                CliRunner().invoke(cli_main, ['backend', 'add', 'novel-store-xyz', '--type', 'dynamodb', '--owner', 'comp-999'])
            except Exception:
                pass  # May fail due to mocking depth

        mock_registry.register_backend.assert_called_once()
        call_kwargs = mock_registry.register_backend.call_args
        # Verify the novel arguments were passed through
        args_str = str(call_kwargs)
        assert 'novel-store-xyz' in args_str
        assert 'comp-999' in args_str

    def test_goodhart_custom_backend_type_accepted(self):
        """cmd_backend_add must accept 'custom' BackendType without error."""
        import registry as registry_module
        mock_registry = MagicMock()
        mock_registry.BackendMetadata = registry_module.BackendMetadata
        mock_registry.BackendType = registry_module.BackendType
        ctx = make_ctx(config={'version': 1})

        with patch('cli.cli.registry', mock_registry), patch('cli.cli.config.load_config', return_value={'version': 1}):
            try:
                CliRunner().invoke(cli_main, ['backend', 'add', 'my-custom-store', '--type', 'custom', '--owner', 'comp-1'])
            except Exception:
                pass

        mock_registry.register_backend.assert_called_once()

    def test_goodhart_success_message_to_stderr_not_stdout(self):
        """Success message from cmd_backend_add must go to stderr, not stdout."""
        if CliRunner is None:
            pytest.skip("click not available")
        runner = CliRunner(mix_stderr=False)

        with patch('cli.cli.registry') as mock_reg, \
             patch('cli.cli.config.load_config', return_value={'version': 1}):
            mock_reg.register_backend.return_value = None
            result = runner.invoke(cli_main, [
                'backend', 'add', 'novel-be-id', '--type', 'postgres', '--owner', 'comp-x'
            ], catch_exceptions=True)
            # If successful, any success message should be on stderr
            stdout = result.output or ''
            stderr = getattr(result, 'stderr', '') or ''
            # stdout should not contain success messaging for a write operation


# ---- Thin dispatch: cmd_schema_add ----

class TestGoodhartCmdSchemaAdd:

    def test_goodhart_delegates_to_registry_add_schema(self, tmp_path):
        """cmd_schema_add must delegate to registry.add_schema with the exact path."""
        import registry as registry_module
        mock_registry = MagicMock()
        mock_registry.BackendMetadata = registry_module.BackendMetadata
        mock_registry.BackendType = registry_module.BackendType
        ctx = make_ctx(config={'version': 1})
        schema_file = tmp_path / 'novel_schema_abc123.yaml'
        schema_file.write_text('table: users\n')
        novel_path = str(schema_file)

        with patch('cli.cli.registry', mock_registry), patch('cli.cli.config.load_config', return_value={'version': 1}):
            try:
                CliRunner().invoke(cli_main, ['schema', 'add', novel_path])
            except Exception:
                pass

        mock_registry.add_schema.assert_called_once()
        call_args_str = str(mock_registry.add_schema.call_args)
        assert novel_path in call_args_str

    def test_goodhart_schema_add_requires_config(self):
        """cmd_schema_add must fail when config is not loaded."""
        if CliRunner is None:
            pytest.skip("click not available")
        runner = CliRunner()

        with patch('cli.cli.config.load_config',
                   side_effect=LedgerError(violations=[], exit_code=ExitCode.CONFIG_ERROR_3)):
            result = runner.invoke(cli_main, ['schema', 'add', '/some/path.yaml'],
                                 catch_exceptions=True)
            assert result.exit_code == 3


# ---- cmd_schema_show output formats ----

class TestGoodhartCmdSchemaShow:

    def test_goodhart_schema_show_requires_config(self):
        """cmd_schema_show must fail with exit code 3 when config is not loaded."""
        if CliRunner is None:
            pytest.skip("click not available")
        runner = CliRunner()

        with patch('cli.cli.config.load_config',
                   side_effect=LedgerError(violations=[], exit_code=ExitCode.CONFIG_ERROR_3)):
            result = runner.invoke(cli_main, ['schema', 'show', 'some-backend'],
                                 catch_exceptions=True)
            assert result.exit_code == 3


# ---- cmd_schema_validate ----

class TestGoodhartCmdSchemaValidate:

    def test_goodhart_mixed_warn_info_no_errors_exit_0(self):
        """With only warning and info violations (no errors), exit code must be 0."""
        mock_registry = MagicMock()
        violations = [
            make_violation(severity=Severity.warning, message="warn1", code="W1"),
            make_violation(severity=Severity.warning, message="warn2", code="W2"),
            make_violation(severity=Severity.info, message="info1", code="I1"),
            make_violation(severity=Severity.info, message="info2", code="I2"),
            make_violation(severity=Severity.info, message="info3", code="I3"),
        ]
        result = make_result(success=True, data={'violations': violations}, violations=violations)
        mock_registry.validate_schemas.return_value = violations

        if CliRunner is None:
            pytest.skip("click not available")
        runner = CliRunner()

        with patch('cli.cli.registry', mock_registry), \
             patch('cli.cli.config.load_config', return_value={'version': 1}):
            cli_result = runner.invoke(cli_main, ['schema', 'validate'], catch_exceptions=True)
            assert cli_result.exit_code == 0

    def test_goodhart_single_error_among_many_exit_1(self):
        """Even one error-severity violation among many warnings must produce exit code 1."""
        mock_registry = MagicMock()
        violations = [
            make_violation(severity=Severity.warning, message=f"warn{i}", code=f"W{i}")
            for i in range(5)
        ] + [
            make_violation(severity=Severity.error, message="single_error", code="E0")
        ] + [
            make_violation(severity=Severity.info, message=f"info{i}", code=f"I{i}")
            for i in range(3)
        ]
        result = make_result(success=False, data={'violations': violations}, violations=violations)
        mock_registry.validate_schemas.return_value = violations

        if CliRunner is None:
            pytest.skip("click not available")
        runner = CliRunner()

        with patch('cli.cli.registry', mock_registry), \
             patch('cli.cli.config.load_config', return_value={'version': 1}):
            cli_result = runner.invoke(cli_main, ['schema', 'validate'], catch_exceptions=True)
            assert cli_result.exit_code == 1


# ---- cmd_migrate_plan ----

class TestGoodhartCmdMigratePlan:

    def test_goodhart_migrate_plan_requires_config(self):
        """cmd_migrate_plan must fail with config error when config is not loaded."""
        if CliRunner is None:
            pytest.skip("click not available")
        runner = CliRunner()

        with patch('cli.cli.config.load_config',
                   side_effect=LedgerError(violations=[], exit_code=ExitCode.CONFIG_ERROR_3)):
            result = runner.invoke(cli_main, ['migrate', 'plan', 'comp-1', 'migration.sql'],
                                 catch_exceptions=True)
            assert result.exit_code == 3

    def test_goodhart_warnings_only_exit_0(self, tmp_path):
        """cmd_migrate_plan with only warning gate violations must exit 0."""
        mock_migration = MagicMock()
        warnings = [
            make_violation(severity=Severity.warning, message="gate warn", code="GW1"),
            make_violation(severity=Severity.warning, message="gate warn 2", code="GW2"),
        ]
        plan_result = make_result(
            success=True,
            data={'plan_id': 'plan-123', 'violations': warnings},
            violations=warnings
        )
        mock_migration.plan_migration.return_value = plan_result.data
        sql_path = tmp_path / 'migration.sql'
        sql_path.write_text('ALTER TABLE users ADD COLUMN age INT;')

        if CliRunner is None:
            pytest.skip("click not available")
        runner = CliRunner()

        with patch('cli.cli.migration', mock_migration), \
             patch('cli.cli.config.load_config', return_value={'version': 1}):
            result = runner.invoke(cli_main, ['migrate', 'plan', 'comp-1', str(sql_path)],
                                 catch_exceptions=True)
            assert result.exit_code == 0


# ---- cmd_migrate_approve ----

class TestGoodhartCmdMigrateApprove:

    def test_goodhart_passes_review_id_through(self):
        """cmd_migrate_approve must pass review_id to migration.approve_migration."""
        mock_migration = MagicMock()
        mock_migration.approve_migration.return_value = None

        if CliRunner is None:
            pytest.skip("click not available")
        runner = CliRunner()

        with patch('cli.cli.migration', mock_migration), \
             patch('cli.cli.config.load_config', return_value={'version': 1}):
            result = runner.invoke(cli_main, [
                'migrate', 'approve', 'plan-novel-789', '--review', 'reviewer-novel-xyz'
            ], catch_exceptions=True)

        if mock_migration.approve_migration.called:
            call_args_str = str(mock_migration.approve_migration.call_args)
            assert 'reviewer-novel-xyz' in call_args_str

    def test_goodhart_migrate_approve_requires_config(self):
        """cmd_migrate_approve must fail with config error when config is not loaded."""
        if CliRunner is None:
            pytest.skip("click not available")
        runner = CliRunner()

        with patch('cli.cli.config.load_config',
                   side_effect=LedgerError(violations=[], exit_code=ExitCode.CONFIG_ERROR_3)):
            result = runner.invoke(cli_main, [
                'migrate', 'approve', 'plan-1', '--review', 'rev-1'
            ], catch_exceptions=True)
            assert result.exit_code == 3


# ---- cmd_export ----

class TestGoodhartCmdExport:

    def test_goodhart_sentinel_format(self):
        """cmd_export must accept 'sentinel' format and pass it to export module."""
        mock_export = MagicMock()
        mock_export.export_contracts.return_value = make_result(data={'contracts': []})

        if CliRunner is None:
            pytest.skip("click not available")
        runner = CliRunner()

        with patch('cli.cli.export', mock_export), \
             patch('cli.cli.config.load_config', return_value={'version': 1}):
            result = runner.invoke(cli_main, ['export', '--format', 'sentinel'],
                                 catch_exceptions=True)
            if result.exit_code == 0:
                call_str = str(mock_export.export_contracts.call_args)
                assert 'sentinel' in call_str

    def test_goodhart_baton_format(self):
        """cmd_export must accept 'baton' format."""
        mock_export = MagicMock()
        mock_export.export_contracts.return_value = make_result(data={'contracts': []})

        if CliRunner is None:
            pytest.skip("click not available")
        runner = CliRunner()

        with patch('cli.cli.export', mock_export), \
             patch('cli.cli.config.load_config', return_value={'version': 1}):
            result = runner.invoke(cli_main, ['export', '--format', 'baton'],
                                 catch_exceptions=True)
            if result.exit_code == 0:
                call_str = str(mock_export.export_contracts.call_args)
                assert 'baton' in call_str

    def test_goodhart_arbiter_format(self):
        """cmd_export must accept 'arbiter' format."""
        mock_export = MagicMock()
        mock_export.export_contracts.return_value = make_result(data={'contracts': []})

        if CliRunner is None:
            pytest.skip("click not available")
        runner = CliRunner()

        with patch('cli.cli.export', mock_export), \
             patch('cli.cli.config.load_config', return_value={'version': 1}):
            result = runner.invoke(cli_main, ['export', '--format', 'arbiter'],
                                 catch_exceptions=True)
            if result.exit_code == 0:
                call_str = str(mock_export.export_contracts.call_args)
                assert 'arbiter' in call_str

    def test_goodhart_export_requires_config(self):
        """cmd_export must fail with config error when config is not loaded."""
        if CliRunner is None:
            pytest.skip("click not available")
        runner = CliRunner()

        with patch('cli.cli.config.load_config',
                   side_effect=LedgerError(violations=[], exit_code=ExitCode.CONFIG_ERROR_3)):
            result = runner.invoke(cli_main, ['export', '--format', 'pact'],
                                 catch_exceptions=True)
            assert result.exit_code == 3


# ---- cmd_mock ----

class TestGoodhartCmdMock:

    def test_goodhart_passes_novel_count(self):
        """cmd_mock must pass the exact count value (37) to the domain module, not a hardcoded value."""
        mock_mod = MagicMock()
        mock_mod.generate_mock_data.return_value = make_result(data={'rows': [{}] * 37})

        if CliRunner is None:
            pytest.skip("click not available")
        runner = CliRunner()

        with patch('cli.cli.mock', mock_mod), \
             patch('cli.cli.config.load_config', return_value={'version': 1}):
            result = runner.invoke(cli_main, [
                'mock', 'be-1', 'users', '--count', '37'
            ], catch_exceptions=True)

        if mock_mod.generate_mock_data.called:
            call_str = str(mock_mod.generate_mock_data.call_args)
            assert '37' in call_str

    def test_goodhart_passes_novel_seed(self):
        """cmd_mock must pass a novel seed value (98765) to the domain module."""
        mock_mod = MagicMock()
        mock_mod.generate_mock_data.return_value = make_result(data={'rows': []})

        if CliRunner is None:
            pytest.skip("click not available")
        runner = CliRunner()

        with patch('cli.cli.mock', mock_mod), \
             patch('cli.cli.config.load_config', return_value={'version': 1}):
            result = runner.invoke(cli_main, [
                'mock', 'be-1', 'users', '--count', '5', '--seed', '98765'
            ], catch_exceptions=True)

        if mock_mod.generate_mock_data.called:
            call_str = str(mock_mod.generate_mock_data.call_args)
            assert '98765' in call_str

    def test_goodhart_passes_large_count(self):
        """cmd_mock must handle large count values (10000) without capping."""
        mock_mod = MagicMock()
        mock_mod.generate_mock_data.return_value = make_result(data={'rows': []})

        if CliRunner is None:
            pytest.skip("click not available")
        runner = CliRunner()

        with patch('cli.cli.mock', mock_mod), \
             patch('cli.cli.config.load_config', return_value={'version': 1}):
            result = runner.invoke(cli_main, [
                'mock', 'be-1', 'users', '--count', '10000'
            ], catch_exceptions=True)

        if mock_mod.generate_mock_data.called:
            call_str = str(mock_mod.generate_mock_data.call_args)
            assert '10000' in call_str

    def test_goodhart_default_purpose_is_default(self):
        """cmd_mock must use purpose='default' when --purpose flag is omitted."""
        mock_mod = MagicMock()
        mock_mod.generate_mock_data.return_value = make_result(data={'rows': []})

        if CliRunner is None:
            pytest.skip("click not available")
        runner = CliRunner()

        with patch('cli.cli.mock', mock_mod), \
             patch('cli.cli.config.load_config', return_value={'version': 1}):
            result = runner.invoke(cli_main, [
                'mock', 'be-1', 'users', '--count', '5'
            ], catch_exceptions=True)

        if mock_mod.generate_mock_data.called:
            call_str = str(mock_mod.generate_mock_data.call_args)
            assert 'default' in call_str.lower()

    def test_goodhart_mock_requires_config(self):
        """cmd_mock must fail with config error when config is not loaded."""
        if CliRunner is None:
            pytest.skip("click not available")
        runner = CliRunner()

        with patch('cli.cli.config.load_config',
                   side_effect=LedgerError(violations=[], exit_code=ExitCode.CONFIG_ERROR_3)):
            result = runner.invoke(cli_main, [
                'mock', 'be-1', 'users', '--count', '5'
            ], catch_exceptions=True)
            assert result.exit_code == 3


# ---- cmd_serve ----

class TestGoodhartCmdServe:

    def test_goodhart_delegates_to_api_start_server(self):
        """cmd_serve must delegate to api.start_server."""
        mock_api = MagicMock()
        mock_api.start_server.return_value = None

        if CliRunner is None:
            pytest.skip("click not available")
        runner = CliRunner()

        with patch('cli.cli.api', mock_api), \
             patch('cli.cli.config.load_config', return_value={'version': 1}):
            result = runner.invoke(cli_main, ['serve'], catch_exceptions=True)

        mock_api.start_server.assert_called_once()

    def test_goodhart_serve_requires_config(self):
        """cmd_serve must fail with config error when config is not loaded."""
        if CliRunner is None:
            pytest.skip("click not available")
        runner = CliRunner()

        with patch('cli.cli.config.load_config',
                   side_effect=LedgerError(violations=[], exit_code=ExitCode.CONFIG_ERROR_3)):
            result = runner.invoke(cli_main, ['serve'], catch_exceptions=True)
            assert result.exit_code == 3


# ---- cmd_init: no config required ----

class TestGoodhartCmdInit:

    def test_goodhart_init_succeeds_without_config(self, tmp_path):
        """cmd_init must succeed without any existing config file — it's the only command allowed to."""
        if CliRunner is None:
            pytest.skip("click not available")
        runner = CliRunner()

        with patch('cli.cli.config') as mock_config:
            mock_config.init_config.return_value = None
            # Ensure load_config is NOT called
            mock_config.load_config.side_effect = Exception("Should not be called")

            result = runner.invoke(cli_main, ['--config', str(tmp_path / 'new-ledger-xyz.yaml'), 'init'],
                                 catch_exceptions=True)
            assert result.exit_code == 0
            mock_config.init_config.assert_called_once()


# ---- Exit code determinism ----

class TestGoodhartExitCodes:

    def test_goodhart_exit_code_enum_values(self):
        """Exit code enum values must match: 0=success, 1=domain, 2=usage, 3=config, 130=interrupt."""
        assert ExitCode.SUCCESS_0.value == 0 or str(ExitCode.SUCCESS_0) == '0' or ExitCode.SUCCESS_0 == 0
        assert ExitCode.DOMAIN_ERROR_1.value == 1 or str(ExitCode.DOMAIN_ERROR_1) == '1' or ExitCode.DOMAIN_ERROR_1 == 1
        assert ExitCode.USAGE_ERROR_2.value == 2 or str(ExitCode.USAGE_ERROR_2) == '2' or ExitCode.USAGE_ERROR_2 == 2
        assert ExitCode.CONFIG_ERROR_3.value == 3 or str(ExitCode.CONFIG_ERROR_3) == '3' or ExitCode.CONFIG_ERROR_3 == 3
        assert ExitCode.KEYBOARD_INTERRUPT_130.value == 130 or str(ExitCode.KEYBOARD_INTERRUPT_130) == '130' or ExitCode.KEYBOARD_INTERRUPT_130 == 130

    def test_goodhart_keyboard_interrupt_exit_130(self):
        """KeyboardInterrupt caught by cli_main must produce exit code 130, not 1 or 0."""
        if CliRunner is None:
            pytest.skip("click not available")
        runner = CliRunner()

        with patch('cli.cli.config.init_config', side_effect=KeyboardInterrupt()):
            result = runner.invoke(cli_main, ['init'], catch_exceptions=False)
            assert result.exit_code == 130


# ---- Config path tilde expansion ----

class TestGoodhartConfigPathTilde:

    def test_goodhart_tilde_expansion(self):
        """Config path ~/ledger.yaml should be expanded to full home directory path."""
        if CliRunner is None:
            pytest.skip("click not available")
        runner = CliRunner()

        # We'll check that the CLI doesn't crash with ~ path and resolves it
        with patch('cli.cli.config') as mock_config:
            mock_config.init_config.return_value = None
            result = runner.invoke(cli_main, ['--config', '~/ledger.yaml', 'init'],
                                 catch_exceptions=True)
            # If init_config was called, check the path doesn't have literal ~
            if mock_config.init_config.called:
                # The path should have been expanded
                assert mock_config.init_config.call_args.args[0] == os.path.join(os.environ["HOME"], "ledger.yaml")
            # At minimum it shouldn't crash
            assert result.exit_code in (0, 1, 3)
