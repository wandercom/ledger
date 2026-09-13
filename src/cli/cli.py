"""CLI Entry Point — Click-based CLI for all Ledger subcommands."""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field as dataclass_field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional

import click
import yaml

# Import the core domain modules so tests can patch cli.config, cli.registry, etc.
import config
import registry
import migration
import export
import mock
import api
import inference


# ── Enums ──────────────────────────────────────────────


class ExitCode(int, Enum):
    SUCCESS_0 = 0
    DOMAIN_ERROR_1 = 1
    USAGE_ERROR_2 = 2
    CONFIG_ERROR_3 = 3
    KEYBOARD_INTERRUPT_130 = 130


class OutputFormat(str, Enum):
    text = "text"
    json = "json"
    yaml = "yaml"


class BackendType(str, Enum):
    postgres = "postgres"
    mysql = "mysql"
    sqlite = "sqlite"
    redis = "redis"
    dynamodb = "dynamodb"
    s3 = "s3"
    custom = "custom"


class ExportFormat(str, Enum):
    pact = "pact"
    arbiter = "arbiter"
    baton = "baton"
    sentinel = "sentinel"
    retention = "retention"


class MockPurpose(str, Enum):
    default = "default"
    canary = "canary"


class Severity(str, Enum):
    error = "error"
    warning = "warning"
    info = "info"


# ── Data Models ────────────────────────────────────────


@dataclass
class Violation:
    path: str
    message: str
    severity: Severity
    code: str


@dataclass
class CliContext:
    config_path: str
    config: Any
    verbose: bool
    output_format: OutputFormat


@dataclass
class CommandResult:
    success: bool
    data: Any
    message: str
    violations: list


# ── Exceptions ────────────────────────────────────────


class LedgerError(Exception):
    def __init__(self, violations=None, exit_code=None):
        self.violations = violations or []
        self.exit_code = exit_code or ExitCode.DOMAIN_ERROR_1
        messages = "; ".join(
            getattr(v, "message", str(v)) for v in self.violations
        )
        super().__init__(messages)


# ── Helpers ────────────────────────────────────────────


def require_config(ctx: CliContext) -> None:
    """Load config into ctx.config. Raises LedgerError on failure."""
    if ctx.config is not None:
        return
    config_path = ctx.config_path
    try:
        ctx.config = config.load_config(config_path)
    except KeyboardInterrupt:
        raise
    except LedgerError:
        raise
    except FileNotFoundError:
        raise LedgerError(
            violations=[Violation(
                path=config_path,
                message=f"Config file not found: {config_path}",
                severity=Severity.error,
                code="E_CONFIG_MISSING",
            )],
            exit_code=ExitCode.CONFIG_ERROR_3,
        )
    except Exception as e:
        raise LedgerError(
            violations=[Violation(
                path=config_path,
                message=str(e),
                severity=Severity.error,
                code="E_CONFIG_LOAD",
            )],
            exit_code=ExitCode.CONFIG_ERROR_3,
        ) from e


def format_output(result: CommandResult, fmt: OutputFormat) -> str:
    """Serialize CommandResult.data to the requested format string."""
    data = result.data
    if data is None and fmt in (OutputFormat.json, OutputFormat.yaml):
        raise LedgerError(violations=[Violation(
            path="output", message="Structured output requires a data payload",
            severity=Severity.error, code="SERIALIZATION_ERROR",
        )])
    if fmt == OutputFormat.json:
        return json.dumps(data)
    elif fmt == OutputFormat.yaml:
        return yaml.dump(data, sort_keys=False, allow_unicode=True, default_flow_style=False)
    else:
        # text format
        if data is None:
            return ""
        return str(data)


def render_violations(violations: list, use_color: bool = False) -> str:
    """Render violations as a human-readable string, grouped by severity."""
    if not violations:
        return ""
    # Sort: errors first, then warnings, then info
    severity_order = {"error": 0, "warning": 1, "info": 2}
    sorted_viols = sorted(
        violations,
        key=lambda v: severity_order.get(
            getattr(v, "severity", Severity.info).value
            if hasattr(getattr(v, "severity", None), "value")
            else str(getattr(v, "severity", "info")),
            3,
        ),
    )

    lines = []
    for v in sorted_viols:
        sev = getattr(v, "severity", Severity.info)
        sev_str = sev.value if hasattr(sev, "value") else str(sev)
        code = getattr(v, "code", "")
        path = getattr(v, "path", "")
        message = getattr(v, "message", str(v))

        if use_color:
            color_map = {"error": "\x1b[31m", "warning": "\x1b[33m", "info": "\x1b[36m"}
            reset = "\x1b[0m"
            color = color_map.get(sev_str, "")
            lines.append(f"{color}[{sev_str.upper()}]{reset} {code} {path}: {message}")
        else:
            lines.append(f"[{sev_str.upper()}] {code} {path}: {message}")

    # Summary counts
    counts = {}
    for v in violations:
        sev = getattr(v, "severity", Severity.info)
        sev_str = sev.value if hasattr(sev, "value") else str(sev)
        counts[sev_str] = counts.get(sev_str, 0) + 1

    summary_parts = []
    for sev_name in ["error", "warning", "info"]:
        if sev_name in counts:
            summary_parts.append(f"{counts[sev_name]} {sev_name}(s)")
    lines.append(f"Summary: {', '.join(summary_parts)}")

    return "\n".join(lines)


# ── Click CLI ──────────────────────────────────────────


@click.group()
@click.option("--config", "config_path",
              envvar="LEDGER_CONFIG",
              default="./ledger.yaml",
              help="Path to ledger.yaml config file")
@click.option("--verbose", is_flag=True, default=False, help="Enable verbose output")
@click.option("--format", "output_format", type=click.Choice(["text", "json", "yaml"]),
              default="text", help="Output format")
@click.pass_context
def cli_main(ctx, config_path, verbose, output_format):
    """Ledger CLI — schema governance and migration tooling."""
    ctx.ensure_object(dict)
    ctx.obj["cli_ctx"] = CliContext(
        config_path=os.path.abspath(os.path.expanduser(config_path)),
        config=None,
        verbose=verbose,
        output_format=OutputFormat(output_format),
    )


def _handle_command(ctx, func, *args, **kwargs):
    """Standard wrapper: run func, handle LedgerError and KeyboardInterrupt."""
    try:
        return func(ctx, *args, **kwargs)
    except LedgerError as e:
        cli_ctx = ctx.obj["cli_ctx"]
        rendered = render_violations(e.violations, use_color=True)
        click.echo(rendered, err=False)
        ctx.exit(e.exit_code.value if isinstance(e.exit_code, ExitCode) else int(e.exit_code))
    except KeyboardInterrupt:
        ctx.exit(ExitCode.KEYBOARD_INTERRUPT_130.value)


# ── init ──────────────────────────────────────────────


@cli_main.command("init")
@click.pass_context
def cmd_init(ctx):
    """Initialize a new ledger.yaml scaffold."""
    cli_ctx = ctx.obj["cli_ctx"]
    try:
        config.init_config(cli_ctx.config_path)
        registry.init(Path(cli_ctx.config_path).parent)
        if cli_ctx.verbose:
            click.echo("Config initialized.", err=True)
    except LedgerError as e:
        rendered = render_violations(e.violations, use_color=True)
        click.echo(rendered)
        ctx.exit(e.exit_code.value if isinstance(e.exit_code, ExitCode) else int(e.exit_code))
    except KeyboardInterrupt:
        ctx.exit(ExitCode.KEYBOARD_INTERRUPT_130.value)


# ── backend ───────────────────────────────────────────


@cli_main.group("backend")
@click.pass_context
def backend_group(ctx):
    """Backend management commands."""
    pass


@backend_group.command("add")
@click.argument("backend_id")
@click.option("--type", "backend_type", required=True, help="Backend type")
@click.option("--owner", required=True, help="Owner component ID")
@click.pass_context
def cmd_backend_add(ctx, backend_id, backend_type, owner):
    """Register a new backend."""
    cli_ctx = ctx.obj["cli_ctx"]
    try:
        require_config(cli_ctx)
        metadata = registry.BackendMetadata(
            backend_id=backend_id,
            backend_type=registry.BackendType(backend_type),
            owner_component=owner,
            registered_at=datetime.now(timezone.utc),
        )
        root = Path(cli_ctx.config_path).parent
        registry.register_backend(root, metadata, owner)
        if cli_ctx.verbose:
            click.echo(f"Backend '{backend_id}' registered.", err=True)
    except registry.DuplicateBackendError:
        if cli_ctx.verbose:
            click.echo(f"Backend '{backend_id}' already registered (skipping).", err=True)
    except LedgerError as e:
        rendered = render_violations(e.violations, use_color=True)
        click.echo(rendered)
        ctx.exit(e.exit_code.value if isinstance(e.exit_code, ExitCode) else int(e.exit_code))
    except KeyboardInterrupt:
        ctx.exit(ExitCode.KEYBOARD_INTERRUPT_130.value)


# ── schema ────────────────────────────────────────────


@cli_main.group("schema")
@click.pass_context
def schema_group(ctx):
    """Schema management commands."""
    pass


@schema_group.command("add")
@click.argument("schema_path")
@click.pass_context
def cmd_schema_add(ctx, schema_path):
    """Ingest a schema YAML file."""
    cli_ctx = ctx.obj["cli_ctx"]
    try:
        require_config(cli_ctx)
        if not os.path.isfile(schema_path):
            raise LedgerError(
                violations=[Violation(
                    path=schema_path,
                    message=f"Schema file not found: {schema_path}",
                    severity=Severity.error,
                    code="E_FILE_404",
                )],
                exit_code=ExitCode.DOMAIN_ERROR_1,
            )
        with open(schema_path, "r") as f:
            content = f.read()
        registry.add_schema(cli_ctx.config, schema_path, content)
        if cli_ctx.verbose:
            click.echo(f"Schema '{schema_path}' added.", err=True)
    except LedgerError as e:
        rendered = render_violations(e.violations, use_color=True)
        click.echo(rendered)
        ctx.exit(e.exit_code.value if isinstance(e.exit_code, ExitCode) else int(e.exit_code))
    except KeyboardInterrupt:
        ctx.exit(ExitCode.KEYBOARD_INTERRUPT_130.value)


@schema_group.command("show")
@click.argument("backend_id")
@click.argument("table", required=False, default=None)
@click.pass_context
def cmd_schema_show(ctx, backend_id, table):
    """Display schema for a backend (optionally filtered to a table)."""
    cli_ctx = ctx.obj["cli_ctx"]
    try:
        require_config(cli_ctx)
        if table:
            data = registry.show_schema(cli_ctx.config, backend_id, table)
        else:
            data = registry.show_schema(cli_ctx.config, backend_id)
        result = CommandResult(success=True, data=data, message="OK", violations=[])
        output = format_output(result, cli_ctx.output_format)
        click.echo(output)
    except LedgerError as e:
        rendered = render_violations(e.violations, use_color=True)
        click.echo(rendered)
        ctx.exit(e.exit_code.value if isinstance(e.exit_code, ExitCode) else int(e.exit_code))
    except KeyboardInterrupt:
        ctx.exit(ExitCode.KEYBOARD_INTERRUPT_130.value)


@schema_group.command("validate")
@click.pass_context
def cmd_schema_validate(ctx):
    """Validate all registered schemas."""
    cli_ctx = ctx.obj["cli_ctx"]
    try:
        require_config(cli_ctx)
        violations = registry.validate_schemas(cli_ctx.config)
        if violations:
            # Check if there are error-severity violations
            has_errors = any(
                getattr(v, "severity", None) == Severity.error
                for v in violations
            )
            rendered = render_violations(violations, use_color=True)
            click.echo(rendered)
            if has_errors:
                ctx.exit(ExitCode.DOMAIN_ERROR_1.value)
        else:
            if cli_ctx.verbose:
                click.echo("All schemas valid.", err=True)
    except LedgerError as e:
        rendered = render_violations(e.violations, use_color=True)
        click.echo(rendered)
        ctx.exit(e.exit_code.value if isinstance(e.exit_code, ExitCode) else int(e.exit_code))
    except KeyboardInterrupt:
        ctx.exit(ExitCode.KEYBOARD_INTERRUPT_130.value)


@schema_group.command("infer")
@click.argument("backend_id")
@click.option("--output", "output_path", default=None,
              help="Write draft schema to file (default: stdout)")
@click.option("--confidence", is_flag=True, default=False,
              help="Show confidence levels on inferred fields")
@click.pass_context
def cmd_schema_infer(ctx, backend_id, output_path, confidence):
    """Infer schema from a registered backend via live introspection."""
    cli_ctx = ctx.obj["cli_ctx"]
    try:
        require_config(cli_ctx)

        # Look up the backend config
        backend_config = None
        if hasattr(cli_ctx.config, 'backends'):
            for b in cli_ctx.config.backends:
                bname = getattr(b, 'name', getattr(b, 'backend_id', None))
                if bname == backend_id:
                    backend_config = b
                    break

        if backend_config is None:
            raise LedgerError(
                violations=[Violation(
                    path=backend_id,
                    message=f"Backend '{backend_id}' not found in config",
                    severity=Severity.error,
                    code="E_BACKEND_NOT_FOUND",
                )],
                exit_code=ExitCode.DOMAIN_ERROR_1,
            )

        # Extract backend type and connection config
        backend_type = getattr(backend_config, 'backend_type',
                               getattr(backend_config, 'type', 'unknown'))
        if hasattr(backend_type, 'value'):
            backend_type = backend_type.value

        connection_config = {}
        if hasattr(backend_config, 'base_url') and backend_config.base_url:
            connection_config["connection_string"] = backend_config.base_url

        schema = inference.infer_schema(
            backend_id=backend_id,
            backend_type=backend_type,
            connection_config=connection_config,
            show_confidence=confidence,
        )

        output_yaml = inference.schema_to_yaml(schema, show_confidence=confidence)

        if output_path:
            with open(output_path, "w") as f:
                f.write(output_yaml)
            if cli_ctx.verbose:
                click.echo(f"Draft schema written to {output_path}", err=True)
        else:
            click.echo(output_yaml)

    except LedgerError as e:
        rendered = render_violations(e.violations, use_color=True)
        click.echo(rendered)
        ctx.exit(e.exit_code.value if isinstance(e.exit_code, ExitCode) else int(e.exit_code))
    except inference.MissingDependencyError as e:
        click.echo(e.message, err=True)
        ctx.exit(ExitCode.DOMAIN_ERROR_1.value)
    except inference.InferenceError as e:
        click.echo(f"Inference error: {e.message}", err=True)
        ctx.exit(ExitCode.DOMAIN_ERROR_1.value)
    except KeyboardInterrupt:
        ctx.exit(ExitCode.KEYBOARD_INTERRUPT_130.value)


# ── migrate ───────────────────────────────────────────


@cli_main.group("migrate")
@click.pass_context
def migrate_group(ctx):
    """Migration management commands."""
    pass


@migrate_group.command("plan")
@click.argument("component_id")
@click.argument("sql_path")
@click.pass_context
def cmd_migrate_plan(ctx, component_id, sql_path):
    """Create a migration plan from SQL file."""
    cli_ctx = ctx.obj["cli_ctx"]
    try:
        require_config(cli_ctx)
        if not os.path.isfile(sql_path):
            raise LedgerError(
                violations=[Violation(
                    path=sql_path,
                    message=f"Migration file not found: {sql_path}",
                    severity=Severity.error,
                    code="E_FILE_404",
                )],
                exit_code=ExitCode.DOMAIN_ERROR_1,
            )
        with open(sql_path, "r") as f:
            sql_content = f.read()
        result = migration.plan_migration(cli_ctx.config, component_id, sql_content)
        violations = result.get("violations", [])
        if violations:
            has_errors = any(
                getattr(v, "severity", None) == Severity.error
                for v in violations
            )
            rendered = render_violations(violations, use_color=True)
            click.echo(rendered)
            if has_errors:
                ctx.exit(ExitCode.DOMAIN_ERROR_1.value)
        else:
            output = format_output(
                CommandResult(success=True, data=result, message="OK", violations=[]),
                cli_ctx.output_format,
            )
            click.echo(output)
    except LedgerError as e:
        rendered = render_violations(e.violations, use_color=True)
        click.echo(rendered)
        ctx.exit(e.exit_code.value if isinstance(e.exit_code, ExitCode) else int(e.exit_code))
    except KeyboardInterrupt:
        ctx.exit(ExitCode.KEYBOARD_INTERRUPT_130.value)


@migrate_group.command("approve")
@click.argument("plan_id")
@click.option("--review", required=True, help="Review reference ID")
@click.pass_context
def cmd_migrate_approve(ctx, plan_id, review):
    """Approve a pending migration plan."""
    cli_ctx = ctx.obj["cli_ctx"]
    try:
        require_config(cli_ctx)
        migration.approve_migration(cli_ctx.config, plan_id, review)
        if cli_ctx.verbose:
            click.echo(f"Plan '{plan_id}' approved.", err=True)
    except LedgerError as e:
        rendered = render_violations(e.violations, use_color=True)
        click.echo(rendered)
        ctx.exit(e.exit_code.value if isinstance(e.exit_code, ExitCode) else int(e.exit_code))
    except KeyboardInterrupt:
        ctx.exit(ExitCode.KEYBOARD_INTERRUPT_130.value)


# ── export ────────────────────────────────────────────


@cli_main.command("export")
@click.option("--format", "export_format", required=True,
              type=click.Choice(["pact", "arbiter", "baton", "sentinel", "retention"]),
              help="Export format")
@click.option("--component", default=None, help="Filter by component ID")
@click.pass_context
def cmd_export(ctx, export_format, component):
    """Export contracts to external tools."""
    cli_ctx = ctx.obj["cli_ctx"]
    try:
        require_config(cli_ctx)

        if export_format == "retention":
            # Build schemas list from config for retention export
            data = export.export_retention_from_config(cli_ctx.config, component)
        else:
            data = export.export_contracts(cli_ctx.config, export_format, component)

        result = CommandResult(success=True, data=data, message="OK", violations=[])
        output = format_output(result, cli_ctx.output_format)
        click.echo(output)
    except LedgerError as e:
        rendered = render_violations(e.violations, use_color=True)
        click.echo(rendered)
        ctx.exit(e.exit_code.value if isinstance(e.exit_code, ExitCode) else int(e.exit_code))
    except KeyboardInterrupt:
        ctx.exit(ExitCode.KEYBOARD_INTERRUPT_130.value)


# ── builtins ─────────────────────────────────────────


@cli_main.group("builtins")
@click.pass_context
def builtins_group(ctx):
    """Built-in annotation definitions and propagation rules."""
    pass


@builtins_group.command("list")
@click.pass_context
def cmd_builtins_list(ctx):
    """Show all built-in annotation definitions with their propagation rules."""
    cli_ctx = ctx.obj["cli_ctx"]
    try:
        table = config.get_builtin_propagation_table()
        if cli_ctx.output_format == OutputFormat.json:
            data = {}
            for name, rule in sorted(table.items()):
                data[name] = {
                    "pact_assertion_type": rule.pact_assertion_type,
                    "arbiter_tier_behavior": rule.arbiter_tier_behavior,
                    "baton_masking_rule": rule.baton_masking_rule,
                    "sentinel_severity": rule.sentinel_severity,
                }
            click.echo(json.dumps(data))
        elif cli_ctx.output_format == OutputFormat.yaml:
            data = {}
            for name, rule in sorted(table.items()):
                data[name] = {
                    "pact_assertion_type": rule.pact_assertion_type,
                    "arbiter_tier_behavior": rule.arbiter_tier_behavior,
                    "baton_masking_rule": rule.baton_masking_rule,
                    "sentinel_severity": rule.sentinel_severity,
                }
            click.echo(yaml.dump(data, sort_keys=False, default_flow_style=False))
        else:
            lines = []
            for name, rule in sorted(table.items()):
                lines.append(
                    f"{name}: pact={rule.pact_assertion_type} "
                    f"arbiter={rule.arbiter_tier_behavior} "
                    f"baton={rule.baton_masking_rule} "
                    f"sentinel={rule.sentinel_severity}"
                )
            click.echo("\n".join(lines))
    except KeyboardInterrupt:
        ctx.exit(ExitCode.KEYBOARD_INTERRUPT_130.value)


@builtins_group.command("show")
@click.argument("name")
@click.pass_context
def cmd_builtins_show(ctx, name):
    """Show detail for a specific built-in annotation."""
    cli_ctx = ctx.obj["cli_ctx"]
    try:
        table = config.get_builtin_propagation_table()
        if name not in table:
            click.echo(f"Unknown annotation: '{name}'", err=True)
            click.echo(f"Available: {', '.join(sorted(table.keys()))}", err=True)
            ctx.exit(ExitCode.DOMAIN_ERROR_1.value)
            return

        rule = table[name]
        data = {
            "annotation_name": rule.annotation_name,
            "pact_assertion_type": rule.pact_assertion_type,
            "arbiter_tier_behavior": rule.arbiter_tier_behavior,
            "baton_masking_rule": rule.baton_masking_rule,
            "sentinel_severity": rule.sentinel_severity,
        }

        if cli_ctx.output_format == OutputFormat.json:
            click.echo(json.dumps(data))
        elif cli_ctx.output_format == OutputFormat.yaml:
            click.echo(yaml.dump(data, sort_keys=False, default_flow_style=False))
        else:
            for k, v in data.items():
                click.echo(f"  {k}: {v}")
    except KeyboardInterrupt:
        ctx.exit(ExitCode.KEYBOARD_INTERRUPT_130.value)


@builtins_group.command("stripe")
@click.pass_context
def cmd_builtins_stripe(ctx):
    """Show Stripe-specific built-in annotation definitions."""
    cli_ctx = ctx.obj["cli_ctx"]
    try:
        stripe_builtins = config.get_stripe_builtins()

        if cli_ctx.output_format == OutputFormat.json:
            click.echo(json.dumps(stripe_builtins))
        elif cli_ctx.output_format == OutputFormat.yaml:
            click.echo(yaml.dump(stripe_builtins, sort_keys=False, default_flow_style=False))
        else:
            for name, defn in sorted(stripe_builtins.items()):
                click.echo(f"{name}:")
                click.echo(f"  description: {defn['description']}")
                click.echo(f"  field_pattern: {defn['field_pattern']}")
                click.echo(f"  classification: {defn['classification']}")
                click.echo(f"  annotations: {', '.join(defn['annotations'])}")
                prop = defn['propagation']
                click.echo(f"  propagation:")
                for pk, pv in prop.items():
                    click.echo(f"    {pk}: {pv}")
                click.echo()
    except KeyboardInterrupt:
        ctx.exit(ExitCode.KEYBOARD_INTERRUPT_130.value)


# ── mock ──────────────────────────────────────────────


@cli_main.command("mock")
@click.argument("backend_id")
@click.argument("table")
@click.option("--count", type=int, default=10, help="Number of rows to generate")
@click.option("--seed", type=int, default=None, help="Random seed for determinism")
@click.option("--purpose", type=click.Choice(["default", "canary"]),
              default="default", help="Mock generation purpose")
@click.pass_context
def cmd_mock(ctx, backend_id, table, count, seed, purpose):
    """Generate mock data for a backend table."""
    cli_ctx = ctx.obj["cli_ctx"]
    try:
        require_config(cli_ctx)
        data = mock.generate_mock_data(
            cli_ctx.config, backend_id, table, count, seed, purpose
        )
        result = CommandResult(success=True, data=data, message="OK", violations=[])
        output = format_output(result, cli_ctx.output_format)
        click.echo(output)
    except LedgerError as e:
        rendered = render_violations(e.violations, use_color=True)
        click.echo(rendered)
        ctx.exit(e.exit_code.value if isinstance(e.exit_code, ExitCode) else int(e.exit_code))
    except KeyboardInterrupt:
        ctx.exit(ExitCode.KEYBOARD_INTERRUPT_130.value)


# ── serve ─────────────────────────────────────────────


@cli_main.command("serve")
@click.pass_context
def cmd_serve(ctx):
    """Start the Ledger API server."""
    cli_ctx = ctx.obj["cli_ctx"]
    try:
        require_config(cli_ctx)
        api.start_server(cli_ctx.config)
    except LedgerError as e:
        rendered = render_violations(e.violations, use_color=True)
        click.echo(rendered)
        ctx.exit(e.exit_code.value if isinstance(e.exit_code, ExitCode) else int(e.exit_code))
    except KeyboardInterrupt:
        ctx.exit(ExitCode.KEYBOARD_INTERRUPT_130.value)
