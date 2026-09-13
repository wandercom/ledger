# Ledger

Schema registry and data obligation manager. Owns field-level classifications and annotations that propagate into Pact, Arbiter, Baton, and Sentinel. Unified backend model covers 12 storage types.

## Quick Reference

```bash
# CLI
ledger init                        # create ledger.yaml
ledger register <schema.yaml>      # register a schema
ledger annotate <field> <annotation> # add annotation
ledger migrate check <migration>   # blast radius analysis
ledger export pact|arbiter|baton|sentinel  # export for consumer
ledger serve                       # HTTP API (port 7701)
python3 -m pytest tests/ -v       # run executable tests (984; 142 root scaffold cases skip)
```

## Architecture

Core insight: **field classification drives everything**. When a field is tagged `pii_field`, that annotation propagates to Pact (test requirements), Arbiter (trust rules), Baton (field masking), and Sentinel (severity overrides).

### Data Flow
```
Schema YAML → Registry (store verbatim) → Annotations (field-level)
  → Propagation Table (data-driven rules)
  → Export adapters (Pact, Arbiter, Baton, Sentinel, retention)
  → Migration gating (BLOCKED / HUMAN_GATE / AUTO_PROCEED)
```

### Unified Backend Model
12 backend types via `unit`/`unit_type` abstraction:
postgres, mysql, sqlite, mongodb, redis, cassandra, kafka, rabbitmq, sqs, s3/r2, stripe, generic_http

### Classification Tiers
PUBLIC, PII, FINANCIAL, AUTH, COMPLIANCE — each with distinct propagation rules.

### Built-in Annotations
| Annotation | Conflict | Requires |
|-----------|----------|----------|
| immutable | gdpr_erasable, soft_delete_marker | — |
| gdpr_erasable | immutable, audit_field | — |
| audit_field | gdpr_erasable | — |
| encrypted_at_rest | — | not_null |
| pii_field | — | — |
| primary_key | — | — |
| soft_delete_marker | immutable | — |
| not_null | — | — |

## Structure

```
src/
  config/          # ledger.yaml loader, classification tiers, propagation table
  registry/        # Schema store, annotation index, backend registry
  migration/       # Migration parser, diff engine, blast radius calculator
  export/          # Export adapters: Pact, Arbiter, Baton, Sentinel, retention
  mock/            # Schema-aware mock data generator, canary fingerprinting
  cli/             # Click CLI entry point
  api/             # FastAPI HTTP server (port 7701)
```

## Exports

| Consumer | Endpoint | What |
|----------|----------|------|
| Pact | /export/pact | Component contracts with field annotations |
| Arbiter | /export/arbiter | Classification rules, canary fingerprints |
| Baton | /export/baton | Egress node config, field masks |
| Sentinel | /export/sentinel | Severity mappings per field |

## Conventions

- Python 3.12+, Pydantic v2, FastAPI, Click, hatchling, pytest
- Frozen Pydantic models for schemas and annotations
- File locking (fcntl) for concurrent changelog and plan writes
- Schemas stored verbatim (no normalization)
- Return ALL validation violations, not just first
- Graceful degradation when Arbiter unavailable (skip canary registration)
- Tests: 984 passing (contract, Goodhart, regression); 142 root scaffold cases skip because the ledger facade is not implemented. No external services required
- 38 constraints (C001-C038) in constraints.yaml

## Kindex

Ledger captures discoveries, decisions, and classification rationale in [Kindex](~/WanderRepos/repos/kindex). Search before adding. Link related concepts.
