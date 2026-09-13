# Ledger

Schema registry and data obligation manager. Ledger is the authoritative answer to
"what does the data look like and what are its rules?" for distributed systems built
with [Pact](https://github.com/wandercom/pact),
[Arbiter](https://github.com/wandercom/arbiter),
[Baton](https://github.com/wandercom/baton), and
[Sentinel](https://github.com/wandercom/sentinel).

Ledger tracks every storage backend and external data surface in your system through
a unified abstraction. Engineers annotate fields with classification tiers and
obligations. Those annotations automatically propagate into contract assertions,
access control rules, egress masking, severity mappings, and infrastructure retention
requirements — without touching any downstream tool directly.

## What Ledger Does

**Registers schemas** across 12 backend types — relational databases, document stores,
key-value caches, message streams, object storage, and external APIs — using a single
`unit`/`unit_type` abstraction.

**Validates obligations** by catching contradictory annotations at schema time
(immutable + erasable, audit + deletable) before they reach production.

**Gates migrations** by parsing schema changes and returning BLOCKED, HUMAN_GATE, or
AUTO_PROCEED based on what annotations are affected. Dropping an audit column is
unconditionally blocked. Removing encryption requires human approval with rationale.

**Exports rules** to peer tools:
- **Pact**: contract test assertions derived from field annotations
- **Arbiter**: classification rules with taint detection flags
- **Baton**: egress node configs with field masking
- **Sentinel**: severity mappings for annotated fields
- **Retention**: infrastructure config hints (Kafka retention, S3 lifecycle rules)

**Generates mock data** that respects classification tiers — encrypted fields get
token-shaped values, PII fields get realistic fakes, canary fields get fingerprinted
values that Arbiter can track through the system.

## Supported Backends

| Type | Storage Unit | Migration Support |
|---|---|---|
| PostgreSQL / MySQL / SQLite | table | SQL, Alembic, Flyway, Liquibase |
| MongoDB | collection | JSON patch, custom scripts |
| Redis | key pattern | Manual schema update |
| Cassandra | table | CQL migrations |
| Kafka | topic | Schema Registry evolution |
| RabbitMQ / SQS | queue | Config changes |
| S3 / Cloudflare R2 | object pattern | Bucket policy/lifecycle |
| Stripe | API resource | N/A (external, read-only) |
| Generic HTTP | API endpoint | N/A (external, read-only) |

## Quick Start

```bash
pip install ledger

# Initialize registry
ledger init

# Register a storage backend
ledger backend add users_db --type postgres --owner user_service

# Add a schema
ledger schema add schemas/users.yaml

# Validate annotations
ledger schema validate

# Infer schema from a live backend (draft mode)
ledger schema infer users_db
ledger schema infer users_db --output draft.yaml --confidence

# Analyze a migration
ledger migrate plan user_service migrations/002_add_email.sql

# Export rules to peer tools
ledger export --format pact --component user_service
ledger export --format arbiter
ledger export --format baton
ledger export --format sentinel
ledger export --format retention

# Inspect built-in annotations
ledger builtins list
ledger builtins show immutable
ledger builtins stripe

# Generate mock data
ledger mock users_db users --count 10

# Start the API server
ledger serve
```

## Schema Format

```yaml
name: users
version: 1

fields:
  - name: id
    field_type: uuid
    classification: PUBLIC
    nullable: false
    annotations:
      - name: primary_key
      - name: immutable

  - name: email
    field_type: varchar(255)
    classification: PII
    nullable: false
    annotations:
      - name: indexed
      - name: unique
      - name: gdpr_erasable

  - name: payment_token
    field_type: varchar(512)
    classification: FINANCIAL
    nullable: true
    annotations:
      - name: encrypted_at_rest
      - name: tokenized

  - name: created_at
    field_type: timestamptz
    classification: PUBLIC
    nullable: false
    annotations:
      - name: audit_field
      - name: immutable

  - name: deleted_at
    field_type: timestamptz
    classification: PUBLIC
    nullable: true
    annotations:
      - name: soft_delete_marker
```

> The top-level keys `name` and `version` are required. Use `field_type` (not `type`). Annotations must be a list of mappings with a `name` key — bare strings are not accepted by the validator.

## Classification Tiers

| Tier | Severity | Examples |
|---|---|---|
| PUBLIC | Lowest | Timestamps, IDs, URLs |
| PII | Medium | Email, name, phone, address |
| FINANCIAL | High | Payment tokens, amounts, account numbers |
| AUTH | Higher | Password hashes, API keys, session tokens |
| COMPLIANCE | Highest | Audit trails, regulatory records |

## Annotations

| Annotation | Meaning | Propagation |
|---|---|---|
| `primary_key` | Row identifier | Operational only |
| `immutable` | Cannot change after creation | Pact: no update path. Migration: BLOCKED on modify |
| `gdpr_erasable` | Must be erasable on request | Pact: erasure handler required. Requires soft_delete_marker |
| `audit_field` | Compliance evidence trail | Migration: BLOCKED on drop. Never deleted |
| `encrypted_at_rest` | Raw value never stored plaintext | Baton: masked in spans. Mock: token-shaped only |
| `tokenized` | Stored value is a reference token | Arbiter: raw value = taint escape |
| `soft_delete_marker` | Logical deletion indicator | Pact: queries must filter on this field |
| `foreign_key:<ref>` | References another field | Migration: blast radius includes referenced table |
| `indexed` | Has a database index | Operational only |
| `unique` | Uniqueness constraint | Operational only |

Custom annotations can be defined in `ledger.yaml` with propagation rules.

## Migration Gating

```
BLOCKED        — Redesign required. Cannot proceed under any circumstances.
                 (e.g., dropping an audit_field column)

HUMAN_GATE     — Requires explicit human approval with documented rationale.
                 (e.g., removing encryption from a field)

AUTO_PROCEED   — Safe to deploy automatically.
                 (e.g., adding a PUBLIC field to a declared component)
```

## Configuration

```yaml
# ledger.yaml
version: "2.0"

registry:
  path: ".ledger/registry/"
  append_only: true

api:
  port: 7701

integrations:
  arbiter_api: null          # http://localhost:7700 when configured
  pact_project_dir: null
  stigmergy_endpoint: null

mock:
  seed: 42
  canary_prefix: "ledger-canary"

custom_annotations:
  - name: hipaa_phi
    propagation:
      arbiter_tier_override: COMPLIANCE
      sentinel_severity: HIGH
      pact_contract_assertion: "phi_handling_verified"
```

## CLI Reference

| Command | Description |
|---|---|
| `ledger init` | Initialize a new `ledger.yaml` scaffold |
| `ledger backend add <id> --type <type> --owner <owner>` | Register a storage backend |
| `ledger schema add <path>` | Ingest a schema YAML file |
| `ledger schema show <backend_id> [table]` | Display schema for a backend |
| `ledger schema validate` | Validate all registered schemas |
| `ledger schema infer <backend_id> [--output path] [--confidence]` | Infer schema from live backend introspection |
| `ledger migrate plan <component_id> <sql_path>` | Create a migration plan from SQL |
| `ledger migrate approve <plan_id> --review <ref>` | Approve a pending migration plan |
| `ledger export --format <fmt> [--component <id>]` | Export contracts (pact, arbiter, baton, sentinel, retention) |
| `ledger builtins list` | Show all built-in annotations with propagation rules |
| `ledger builtins show <name>` | Show detail for a specific annotation |
| `ledger builtins stripe` | Show Stripe-specific built-in annotations |
| `ledger mock <backend_id> <table> [--count N] [--seed N]` | Generate mock data |
| `ledger serve` | Start the Ledger API server |

### Schema Inference

`ledger schema infer` connects to a registered backend and generates draft schema YAML
with classification guesses and annotation suggestions. Each inferred field is marked
with `_confidence: draft` to indicate human review is needed.

Currently supported for live introspection:
- **PostgreSQL** (requires `psycopg2-binary`): queries `information_schema.columns`

Other backend types will report which optional dependency package is needed.

### Retention Export

`ledger export --format retention` generates infrastructure config hints for data
retention policies based on field annotations:
- `gdpr_erasable` fields: 90-day retention + hard delete or anonymize
- `audit_field` fields: 7-year retention + archive then purge
- `soft_delete_marker` fields: 30-day soft delete window

### Stripe Built-in Annotations

`ledger builtins stripe` shows pre-configured annotation sets for Stripe API fields:
- **Card fields** (`card.number`, `card.cvc`, `card.exp_*`): FINANCIAL classification,
  `encrypted_at_rest` + `tokenized`, full masking
- **Customer fields** (`customer.email`, `customer.name`, `customer.phone`,
  `customer.address.*`): PII classification, `pii_field` + `gdpr_erasable`, partial masking

## Architecture

Ledger is part of a distributed system stack:

```
Constrain ──> defines boundaries
Pact ──────> contract-first build system
Arbiter ───> trust enforcement ("who can access what?")
Ledger ────> schema registry ("what does data look like?")
Baton ─────> circuit orchestration
Sentinel ──> production attribution
```

Ledger and Arbiter are peers — Ledger tells Arbiter what the data looks like,
Arbiter tells Ledger what components are authorized to access it.

## Development

```bash
# Install dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/

# Run specific component tests
pytest tests/registry/
pytest tests/migration/
```

## License

[MIT](LICENSE)

### Qualification

The executable suite passes 984 tests. Another 142 root scaffold cases skip because
the draft `ledger` facade is not implemented; they are not evidence of working features.
Migration approval records are retained in the plans directory `changelog.jsonl`.
Canary registration uses Arbiter's `/canary/register-fingerprint` endpoint and requires
an acknowledgement for every submitted fingerprint before reporting success.
