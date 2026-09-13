"""Mock data generation component for Ledger."""

from __future__ import annotations

import hashlib
import random
import re
import string
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Optional
from uuid import UUID, uuid4

import httpx
from faker import Faker
from pydantic import BaseModel, field_validator, model_validator, ConfigDict


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class FieldClassification(str, Enum):
    PII = "PII"
    FINANCIAL = "FINANCIAL"
    INTERNAL = "INTERNAL"
    PUBLIC = "PUBLIC"


class MockPurpose(str, Enum):
    test = "test"
    canary = "canary"


class ViolationSeverity(str, Enum):
    error = "error"
    warning = "warning"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class MockGenerationError(Exception):
    pass


class ValidationError(Exception):
    pass


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class FieldSpec(BaseModel):
    model_config = ConfigDict(use_enum_values=False)

    field_name: str
    sql_type: str
    max_length: Optional[int] = None
    classification: Optional[FieldClassification] = None
    encrypted_at_rest: bool = False
    tokenized: bool = False
    nullable: bool = False

    @field_validator("max_length")
    @classmethod
    def validate_max_length(cls, v: Optional[int]) -> Optional[int]:
        if v is not None and (v < 1 or v > 65535):
            raise ValueError("max_length must be between 1 and 65535")
        return v


class MockGenerationRequest(BaseModel):
    model_config = ConfigDict(use_enum_values=False)

    backend_id: str
    table_name: str
    fields: list[FieldSpec]
    row_count: int
    seed: Optional[int] = None
    purpose: MockPurpose = MockPurpose.test
    tier: Optional[str] = None
    arbiter_api: Optional[str] = None
    null_probability: float = 0.1

    @field_validator("backend_id")
    @classmethod
    def validate_backend_id(cls, v: str) -> str:
        if not v or len(v) > 128:
            raise ValueError("backend_id must be between 1 and 128 characters")
        return v

    @field_validator("table_name")
    @classmethod
    def validate_table_name(cls, v: str) -> str:
        if not v or len(v) > 256:
            raise ValueError("table_name must be between 1 and 256 characters")
        return v

    @field_validator("row_count")
    @classmethod
    def validate_row_count(cls, v: int) -> int:
        if v < 1 or v > 1_000_000:
            raise ValueError("row_count must be between 1 and 1,000,000")
        return v

    @field_validator("fields")
    @classmethod
    def validate_fields_nonempty(cls, v: list[FieldSpec]) -> list[FieldSpec]:
        if len(v) < 1:
            raise ValueError("fields must contain at least one field")
        return v

    @field_validator("null_probability")
    @classmethod
    def validate_null_probability(cls, v: float) -> float:
        if v < 0.0 or v > 1.0:
            raise ValueError("null_probability must be between 0.0 and 1.0")
        return v

    @field_validator("arbiter_api")
    @classmethod
    def validate_arbiter_api(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not re.match(r"^https?://.+", v):
            raise ValueError("arbiter_api must be a valid HTTP(S) URL")
        return v

    @model_validator(mode="after")
    def check_canary_tier(self) -> "MockGenerationRequest":
        if self.purpose == MockPurpose.canary and (self.tier is None or self.tier == ""):
            raise ValueError("tier is required when purpose is 'canary'")
        return self


class MockViolation(BaseModel):
    field_name: str
    error_type: str
    message: str
    severity: ViolationSeverity


class MockGenerationResult(BaseModel):
    records: list[dict[str, Any]]
    seed_used: int
    canary_registered: Optional[bool] = None
    warnings: list[str]
    errors: list[MockViolation]
    row_count: int


class CanaryRegistrationResult(BaseModel):
    success: bool
    arbiter_response_code: Optional[int] = None
    registration_id: Optional[str] = None
    error_message: Optional[str] = None


class CanaryValue(BaseModel):
    field_name: str
    row_index: int
    raw_fingerprint: str
    shaped_value: Any


class TypeGeneratorEntry(BaseModel):
    sql_type_pattern: str
    generator_fn_name: str
    description: Optional[str] = None


class ClassificationGeneratorEntry(BaseModel):
    classification: FieldClassification
    generator_fn_name: str
    description: Optional[str] = None


class SeedInfo(BaseModel):
    base_seed: int
    field_index_offset: int
    field_seed: int
    field_name: str


# ---------------------------------------------------------------------------
# Type generators: (Random, FieldSpec, int) -> Any
# ---------------------------------------------------------------------------

_BASE64URL_CHARS = string.ascii_letters + string.digits + "_-"


def _gen_uuid(rng: random.Random, spec: FieldSpec, row_index: int) -> str:
    bytes_ = bytes(rng.randint(0, 255) for _ in range(16))
    return str(UUID(bytes=bytes_, version=4))


def _gen_varchar(rng: random.Random, spec: FieldSpec, row_index: int) -> str:
    length = min(spec.max_length or 12, 255)
    length = max(1, length)
    actual_len = rng.randint(1, length)
    return "".join(rng.choices(string.ascii_lowercase + string.digits, k=actual_len))


def _gen_text(rng: random.Random, spec: FieldSpec, row_index: int) -> str:
    length = rng.randint(10, 100)
    return "".join(rng.choices(string.ascii_lowercase + " ", k=length))


def _gen_bigint(rng: random.Random, spec: FieldSpec, row_index: int) -> int:
    return rng.randint(-(2**31), 2**31 - 1)


def _gen_integer(rng: random.Random, spec: FieldSpec, row_index: int) -> int:
    return rng.randint(-(2**15), 2**15 - 1)


def _gen_boolean(rng: random.Random, spec: FieldSpec, row_index: int) -> bool:
    return rng.choice([True, False])


def _gen_timestamptz(rng: random.Random, spec: FieldSpec, row_index: int) -> str:
    ts = rng.randint(0, 2_000_000_000)
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _gen_timestamp(rng: random.Random, spec: FieldSpec, row_index: int) -> str:
    return _gen_timestamptz(rng, spec, row_index)


def _gen_decimal(rng: random.Random, spec: FieldSpec, row_index: int) -> str:
    whole = rng.randint(0, 999999)
    frac = rng.randint(0, 99)
    return f"{whole}.{frac:02d}"


TYPE_GENERATORS: dict[str, Callable] = {
    "uuid": _gen_uuid,
    "varchar": _gen_varchar,
    "character varying": _gen_varchar,
    "text": _gen_text,
    "bigint": _gen_bigint,
    "integer": _gen_integer,
    "int": _gen_integer,
    "boolean": _gen_boolean,
    "bool": _gen_boolean,
    "timestamptz": _gen_timestamptz,
    "timestamp": _gen_timestamp,
    "decimal": _gen_decimal,
    "numeric": _gen_decimal,
}


# ---------------------------------------------------------------------------
# Classification generators: (Faker, FieldSpec, int) -> Any
# ---------------------------------------------------------------------------

def _gen_pii(fake: Faker, spec: FieldSpec, row_index: int) -> str:
    name_lower = spec.field_name.lower()
    if "email" in name_lower:
        return fake.email()
    if "phone" in name_lower:
        return fake.phone_number()
    if "address" in name_lower:
        return fake.address().replace("\n", ", ")
    if "name" in name_lower:
        return fake.name()
    if "ssn" in name_lower:
        return fake.ssn()
    return fake.name()


def _gen_financial(fake: Faker, spec: FieldSpec, row_index: int) -> str:
    name_lower = spec.field_name.lower()
    if "account" in name_lower:
        return fake.bban()
    if "routing" in name_lower:
        return fake.aba()
    if "amount" in name_lower or "price" in name_lower or "balance" in name_lower:
        return f"{fake.random_int(1, 999999)}.{fake.random_int(0, 99):02d}"
    if "card" in name_lower or "credit" in name_lower:
        return fake.credit_card_number()
    return f"{fake.random_int(1, 999999)}.{fake.random_int(0, 99):02d}"


CLASSIFICATION_GENERATORS: dict[Optional[FieldClassification], Callable] = {
    FieldClassification.PII: _gen_pii,
    FieldClassification.FINANCIAL: _gen_financial,
}


# ---------------------------------------------------------------------------
# Public functions
# ---------------------------------------------------------------------------

def resolve_seed(explicit_seed: Optional[int], config_seed: Optional[int]) -> int:
    if explicit_seed is not None:
        return explicit_seed
    if config_seed is not None:
        return config_seed
    raise MockGenerationError(
        "No seed available: provide --seed flag or set mock.seed in ledger.yaml."
    )


def compute_field_seeds(field_names: list[str], base_seed: int) -> list[SeedInfo]:
    if not field_names:
        raise ValueError("field_names must contain at least one field name.")
    if len(field_names) != len(set(field_names)):
        raise ValueError("field_names must be unique.")
    sorted_names = sorted(field_names)
    return [
        SeedInfo(
            base_seed=base_seed,
            field_index_offset=i,
            field_seed=base_seed + i,
            field_name=name,
        )
        for i, name in enumerate(sorted_names)
    ]


def parse_varchar_length(sql_type: str) -> Optional[int]:
    m = re.match(r"^(?:varchar|character varying)\((.+)\)$", sql_type.strip(), re.IGNORECASE)
    if m:
        raw = m.group(1).strip()
        try:
            val = int(raw)
        except ValueError:
            raise ValueError(f"Invalid varchar length specification: '{sql_type}'")
        if val < 1:
            raise ValueError(f"Invalid varchar length specification: '{sql_type}'")
        return val
    # Check if it's a varchar variant without length
    if re.match(r"^(?:varchar|character varying)$", sql_type.strip(), re.IGNORECASE):
        return None
    # Not a varchar type at all
    return None


def get_type_generator(sql_type: str) -> Optional[Callable]:
    return TYPE_GENERATORS.get(sql_type.lower().strip())


def get_classification_generator(classification: Optional[FieldClassification]) -> Optional[Callable]:
    if classification is None:
        return None
    return CLASSIFICATION_GENERATORS.get(classification)


def generate_token_value(rng: random.Random) -> str:
    payload = "".join(rng.choices(_BASE64URL_CHARS, k=24))
    return f"tok_{payload}"


def generate_canary_fingerprint(
    backend_id: str,
    table_name: str,
    field_name: str,
    row_index: int,
    tier: str,
) -> str:
    if not tier:
        raise ValueError("tier must not be empty.")
    data = (backend_id + table_name + field_name + str(row_index)).encode()
    hex8 = hashlib.sha256(data).hexdigest()[:8]
    return f"ledger-canary-{tier}-{hex8}"


def shape_canary_to_type(raw_fingerprint: str, field_spec: FieldSpec) -> Any:
    sql_base = re.split(r"\(", field_spec.sql_type.lower())[0].strip()

    # Tokenized fields get tok_ prefix
    if field_spec.tokenized:
        result = f"tok_{raw_fingerprint}"
        if field_spec.max_length and len(result) > field_spec.max_length:
            result = result[: field_spec.max_length]
        return result

    # UUID fields
    if sql_base == "uuid":
        # Embed fingerprint hex into a valid UUID structure
        hex8 = raw_fingerprint.split("-")[-1]
        padded = (hex8 * 4)[:32]
        formatted = f"{padded[:8]}-{padded[8:12]}-4{padded[13:16]}-a{padded[17:20]}-{padded[20:32]}"
        return formatted

    # PII email fields
    if (
        field_spec.classification == FieldClassification.PII
        and "email" in field_spec.field_name.lower()
    ):
        result = f"{raw_fingerprint}@canary.invalid"
        if field_spec.max_length and len(result) > field_spec.max_length:
            # Truncate the fingerprint part to fit
            avail = field_spec.max_length - len("@canary.invalid")
            if avail > 0:
                result = f"{raw_fingerprint[:avail]}@canary.invalid"
            else:
                result = result[: field_spec.max_length]
        return result

    # Default: varchar or other string types
    result = raw_fingerprint
    if field_spec.max_length and len(result) > field_spec.max_length:
        result = result[: field_spec.max_length]
    return result


def generate_field_value(
    field_spec: FieldSpec,
    field_seed: int,
    row_index: int,
    purpose: MockPurpose,
    tier: Optional[str],
    backend_id: str,
    table_name: str,
    null_probability: float = 0.1,
) -> Any:
    row_seed = field_seed + row_index
    rng = random.Random(row_seed)

    # Nullable check first (but not for canary - canary always produces fingerprints)
    if field_spec.nullable and purpose != MockPurpose.canary:
        if rng.random() < null_probability:
            return None

    # Precedence: canary > tokenized/encrypted > classification > type > fallback
    # 1. Canary
    if purpose == MockPurpose.canary:
        if tier is None:
            raise ValueError("tier must be provided for canary generation.")
        fp = generate_canary_fingerprint(
            backend_id, table_name, field_spec.field_name, row_index, tier
        )
        return shape_canary_to_type(fp, field_spec)

    # 2. Tokenized / encrypted_at_rest
    if field_spec.tokenized or field_spec.encrypted_at_rest:
        return generate_token_value(rng)

    # 3. Classification
    cls_gen = get_classification_generator(field_spec.classification)
    if cls_gen is not None:
        fake = Faker()
        Faker.seed(row_seed)
        fake.seed_instance(row_seed)
        return cls_gen(fake, field_spec, row_index)

    # 4. Type generator
    sql_base = re.split(r"\(", field_spec.sql_type.lower())[0].strip()
    type_gen = get_type_generator(sql_base)
    if type_gen is not None:
        return type_gen(rng, field_spec, row_index)

    # 5. Fallback: random string
    return "".join(rng.choices(string.ascii_lowercase + string.digits, k=12))


def register_canary_with_arbiter(
    arbiter_api: str,
    canary_values: list[CanaryValue],
    tier: str,
    backend_id: str,
    table_name: str,
) -> CanaryRegistrationResult:
    try:
        run_id = f"ledger-{backend_id}-{table_name}-{uuid4().hex}"
        payload = {
            "run_id": run_id,
            "fingerprints": [
                {"fingerprint": cv.raw_fingerprint, "category": tier, "tier": tier}
                for cv in canary_values
            ],
        }
        with httpx.Client() as client:
            resp = client.post(f"{arbiter_api.rstrip('/')}/canary/register-fingerprint",
                               json=payload, timeout=10.0)

        if resp.status_code >= 200 and resp.status_code < 300:
            try:
                body = resp.json()
                registered = body.get("registered")
                if (body.get("status") != "ok" or type(registered) is not int
                        or registered != len(canary_values)):
                    return CanaryRegistrationResult(
                        success=False,
                        arbiter_response_code=resp.status_code,
                        error_message="Invalid response body from Arbiter.",
                    )
                return CanaryRegistrationResult(
                    success=True,
                    arbiter_response_code=resp.status_code,
                    registration_id=run_id,
                )
            except (ValueError, KeyError):
                return CanaryRegistrationResult(
                    success=False,
                    arbiter_response_code=resp.status_code,
                    error_message="Invalid response body from Arbiter.",
                )
        else:
            return CanaryRegistrationResult(
                success=False,
                arbiter_response_code=resp.status_code,
                error_message=f"Arbiter returned HTTP {resp.status_code}.",
            )
    except httpx.TimeoutException:
        return CanaryRegistrationResult(
            success=False,
            error_message="Connection to Arbiter timed out.",
        )
    except httpx.ConnectError as e:
        return CanaryRegistrationResult(
            success=False,
            error_message=f"DNS resolution failed for Arbiter: {e}",
        )
    except Exception as e:
        return CanaryRegistrationResult(
            success=False,
            error_message=f"Arbiter registration failed: {e}",
        )


def validate_request(raw_input: dict[str, Any]) -> list[MockViolation]:
    violations: list[MockViolation] = []

    if not isinstance(raw_input, dict):
        violations.append(
            MockViolation(
                field_name="",
                error_type="validation_error",
                message="Input must be a dict.",
                severity=ViolationSeverity.error,
            )
        )
        return violations

    try:
        req = MockGenerationRequest(**raw_input)
    except Exception as e:
        # Aggregate all Pydantic validation errors
        from pydantic import ValidationError as PydanticValidationError

        if isinstance(e, PydanticValidationError):
            for err in e.errors():
                loc = ".".join(str(x) for x in err.get("loc", []))
                violations.append(
                    MockViolation(
                        field_name=loc,
                        error_type="validation_error",
                        message=err.get("msg", str(err)),
                        severity=ViolationSeverity.error,
                    )
                )
        else:
            violations.append(
                MockViolation(
                    field_name="",
                    error_type="validation_error",
                    message=str(e),
                    severity=ViolationSeverity.error,
                )
            )
        return violations

    # Check for duplicate field names
    field_names = [f.field_name for f in req.fields]
    seen = set()
    dupes = set()
    for fn in field_names:
        if fn in seen:
            dupes.add(fn)
        seen.add(fn)
    if dupes:
        violations.append(
            MockViolation(
                field_name="",
                error_type="duplicate_field_names",
                message=f"Duplicate field names detected: {sorted(dupes)}",
                severity=ViolationSeverity.error,
            )
        )

    return violations


def generate_mock_records(request: MockGenerationRequest) -> MockGenerationResult:
    warnings: list[str] = []
    errors: list[MockViolation] = []

    # Check for duplicate fields
    field_names = [f.field_name for f in request.fields]
    seen = set()
    dupes = set()
    for fn in field_names:
        if fn in seen:
            dupes.add(fn)
        seen.add(fn)
    if dupes:
        errors.append(
            MockViolation(
                field_name="",
                error_type="duplicate_field_names",
                message=f"Duplicate field names detected: {sorted(dupes)}",
                severity=ViolationSeverity.error,
            )
        )
        return MockGenerationResult(
            records=[],
            seed_used=request.seed or 0,
            canary_registered=None,
            warnings=warnings,
            errors=errors,
            row_count=0,
        )

    # Resolve seed
    base_seed = resolve_seed(request.seed, None)

    # Compute field seeds
    seed_infos = compute_field_seeds(field_names, base_seed)
    seed_map = {si.field_name: si.field_seed for si in seed_infos}

    # Build field spec map
    spec_map = {f.field_name: f for f in request.fields}

    # Track unsupported types to warn only once per field
    unsupported_warned: set[str] = set()

    records: list[dict[str, Any]] = []
    for row_idx in range(request.row_count):
        record: dict[str, Any] = {}
        for f in request.fields:
            fs = seed_map[f.field_name]
            try:
                val = generate_field_value(
                    f,
                    fs,
                    row_idx,
                    request.purpose,
                    request.tier,
                    request.backend_id,
                    request.table_name,
                    request.null_probability,
                )
                record[f.field_name] = val

                # Check if this was a fallback for unsupported type
                if f.field_name not in unsupported_warned:
                    sql_base = re.split(r"\(", f.sql_type.lower())[0].strip()
                    if (
                        get_type_generator(sql_base) is None
                        and get_classification_generator(f.classification) is None
                        and not f.tokenized
                        and not f.encrypted_at_rest
                        and request.purpose != MockPurpose.canary
                    ):
                        unsupported_warned.add(f.field_name)
                        w = MockViolation(
                            field_name=f.field_name,
                            error_type="unsupported_type",
                            message=f"Unsupported SQL type '{f.sql_type}' for field '{f.field_name}'; falling back to random string.",
                            severity=ViolationSeverity.warning,
                        )
                        errors.append(w)
                        warnings.append(w.message)
            except Exception as e:
                record[f.field_name] = None
                errors.append(
                    MockViolation(
                        field_name=f.field_name,
                        error_type="generation_error",
                        message=str(e),
                        severity=ViolationSeverity.error,
                    )
                )
        records.append(record)

    # Canary registration
    canary_registered: Optional[bool] = None
    if request.purpose == MockPurpose.canary:
        if request.arbiter_api is None:
            warnings.append("Arbiter API not configured; canary registration skipped.")
            canary_registered = None
        else:
            # Collect canary values for registration
            canary_values: list[CanaryValue] = []
            for row_idx, record in enumerate(records):
                for f in request.fields:
                    fp = generate_canary_fingerprint(
                        request.backend_id,
                        request.table_name,
                        f.field_name,
                        row_idx,
                        request.tier,
                    )
                    canary_values.append(
                        CanaryValue(
                            field_name=f.field_name,
                            row_index=row_idx,
                            raw_fingerprint=fp,
                            shaped_value=record[f.field_name],
                        )
                    )
            reg_result = register_canary_with_arbiter(
                request.arbiter_api,
                canary_values,
                request.tier,
                request.backend_id,
                request.table_name,
            )
            canary_registered = reg_result.success
            if not reg_result.success:
                warnings.append(
                    f"Arbiter registration failed: {reg_result.error_message}. "
                    "Canary values generated but not registered."
                )

    return MockGenerationResult(
        records=records,
        seed_used=base_seed,
        canary_registered=canary_registered,
        warnings=warnings,
        errors=errors,
        row_count=len(records),
    )
