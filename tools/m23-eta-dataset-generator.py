#!/usr/bin/env python3
"""Generate a private, non-activating M23 pragmatic calibration candidate."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import re
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, ROUND_HALF_UP, localcontext
from fractions import Fraction
from pathlib import Path
from typing import Any


GENERATOR_VERSION = "m23-eta-dataset-generator-1"
RESOURCE_FORMAT = "cryptobenchmark-runtime-calibration"
MODEL_SCHEMA_VERSION = "m23-pragmatic-1"
CALIBRATION_PROTOCOL_ID = "memory-v2-calibration-v1"
MEASURED_SAMPLING_INTERVAL_MS = 5
MAX_WORKLOAD_BYTES = 268_435_456
MAX_U64 = (1 << 64) - 1
MAX_I64 = (1 << 63) - 1

NIGHT_RESULT = "M23_NIGHT_result.json"
SUPPLEMENTAL_RESULT = "M23_HIANYZO_5ms_239_result.json"
SPLIT_MANIFEST = "CryptoBenchmark_EJSZAKAI_563_M10_BECSESI_MANIFESZT.json"
OFFLINE_CANDIDATE = "M23_ETA_175_OFFLINE_MODELLJELÖLT_2026-11-01.json"
OFFLINE_HOLDOUT_CSV = "M23_ETA_291_FUGGETLEN_MERET_HOLDOUT_2026-11-01.csv"
CAMPAIGN_PLAN = "CryptoBenchmark_EJSZAKAI_SZELSESSZAV_FELMERES_563_M10_MAX1MiB(1).json"

EXPECTED_SOURCE_SHA256 = {
    NIGHT_RESULT: "9d4c3f61fbda8df095e758f2b0a7462aa3ed8f84959c380f6d0b5b021dbb3f52",
    SUPPLEMENTAL_RESULT: "e887fdf3ce4338fbdef2f26a9fef0fe936482a727b8d28c838d16d85007280d2",
    SPLIT_MANIFEST: "c35e832ffec5af33fc489a2b93a6d8198a80590001c7c41a35530c297b3d4748",
    OFFLINE_CANDIDATE: "da8b7756a3f40125c745a49d0e8068a5025c7b220f69b8f3db00435e1a1d3a49",
    OFFLINE_HOLDOUT_CSV: "4c58f8bbc81688d7a66a79ac162514111a8d7d9be59993af6d8a1909615407b6",
    CAMPAIGN_PLAN: "ff68c6fb3a121aaa9f4e969df8b524b625ce1362d3b1689a1aae7f4c9902e9b4",
}

EXPECTED_INVENTORY_SHA256 = (
    "1fcc10b1d78b45556cf3989125228799952b0bc11aae2c0953401e3b9b090cf1"
)

SUPPLEMENTAL_PREFIX_COUNTS = {
    "m23256m": 97,
    "m2316m": 97,
    "nmhold": 17,
    "probe16m": 14,
    "p256canary": 1,
    "p256pilot": 13,
}

ALLOWED_NULL_PROVENANCE_REASONS = {
    "referenceWorkerSha256": "notRecordedInCampaignEvidence",
    "referenceAppSha256": "notRecordedInCampaignEvidence",
    "qtVersion": "notRecordedInCampaignEvidence",
    "compilerId": "notRecordedInCampaignEvidence",
    "referenceCpu": "notRecordedInCampaignEvidence",
    "referenceRamBytes": "notRecordedInCampaignEvidence",
    "powerPlan": "notRecordedInCampaignEvidence",
}


class DatasetError(ValueError):
    """Raised when source evidence or an output safety invariant is invalid."""


@dataclass(frozen=True)
class GenerationRequest:
    evidence_directory: Path
    inventory_plan_writer: Path
    output_directory: Path
    generated_at_utc: str
    dataset_id: str
    dataset_version: str


@dataclass(frozen=True)
class Observation:
    source_file: str
    entry_id: str
    canonical_case_id: str
    case_code: str
    input_kind: str
    profile_id: str
    operation: str
    input_bytes: int | None
    iterations_per_run: int
    runs: int
    median_nanoseconds: Decimal
    evidence_role: str


@dataclass(frozen=True)
class VerifiedInputs:
    evidence_directory: Path
    contents: dict[str, Any]
    source_hashes: dict[str, str]
    inventory_sha256: str
    inventory_cases: dict[str, tuple[str, str, str]]
    case_code_map: dict[str, dict[str, Any]]
    references_by_case: dict[str, list[Observation]]
    holdouts_by_case: dict[str, list[Observation]]
    excluded_supplemental_counts: dict[str, int]
    prior_candidate_summary: dict[str, Any]
    prior_candidate_counts: dict[str, int]
    prior_csv_rows: list[dict[str, str]]


def _reject_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DatasetError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise DatasetError(f"non-standard JSON constant is not accepted: {value}")


def parse_json_bytes(data: bytes, source: str) -> Any:
    try:
        text = data.decode("utf-8-sig", errors="strict")
        return json.loads(
            text,
            parse_float=Decimal,
            parse_constant=_reject_json_constant,
            object_pairs_hook=_reject_duplicate_members,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DatasetError(f"invalid UTF-8/JSON in {source}: {error}") from error


def read_json(path: Path) -> Any:
    try:
        return parse_json_bytes(path.read_bytes(), str(path))
    except OSError as error:
        raise DatasetError(f"cannot read {path}: {error}") from error


def canonical_json_bytes(value: Any) -> bytes:
    try:
        text = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise DatasetError(f"cannot serialize deterministic JSON: {error}") from error
    return (text + "\n").encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            while True:
                block = stream.read(1024 * 1024)
                if not block:
                    break
                digest.update(block)
    except OSError as error:
        raise DatasetError(f"cannot hash {path}: {error}") from error
    return digest.hexdigest()


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise DatasetError(message)


def _integer(value: Any, label: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise DatasetError(f"{label} must be an integer >= {minimum}")
    return value


def _measurement_value(value: Any, label: str) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (int, Decimal)):
        raise DatasetError(f"{label} must be a JSON number")
    result = Decimal(value)
    if not result.is_finite() or result <= 0:
        raise DatasetError(f"{label} must be finite and positive")
    return result


def _decimal_text(value: Decimal) -> str:
    if not value.is_finite():
        raise DatasetError("non-finite decimal cannot be serialized")
    if value == 0:
        return "0"
    text = format(value, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text


def _fraction_round_half_up(value: Fraction) -> int:
    if value < 0:
        raise DatasetError("negative coefficient cannot be quantized")
    quotient, remainder = divmod(value.numerator, value.denominator)
    return quotient + (1 if remainder * 2 >= value.denominator else 0)


def round_operation_picoseconds_to_ns_after_n(
    picoseconds_per_operation: int,
    iterations_per_run: int,
) -> int:
    if not 0 <= picoseconds_per_operation <= MAX_U64:
        raise DatasetError("per-operation picoseconds are outside uint64")
    if not 1 <= iterations_per_run <= 1_000_000_000:
        raise DatasetError("iterationsPerRun is outside the canonical range")
    total_picoseconds = picoseconds_per_operation * iterations_per_run
    quotient, remainder = divmod(total_picoseconds, 1000)
    rounded = quotient + (1 if remainder >= 500 else 0)
    if rounded > MAX_I64:
        raise DatasetError("nearest-nanosecond N-scaled result exceeds int64")
    return rounded


def _fraction_description(value: Fraction) -> dict[str, str]:
    with localcontext() as context:
        context.prec = 60
        decimal_value = Decimal(value.numerator) / Decimal(value.denominator)
        display_value = decimal_value.quantize(
            Decimal("0.000000000001"), rounding=ROUND_HALF_UP
        )
    return {
        "numerator": str(value.numerator),
        "denominator": str(value.denominator),
        "decimal12": format(display_value, "f"),
    }


def _fraction_median(values: list[Fraction]) -> Fraction:
    ordered = sorted(values)
    if not ordered:
        raise DatasetError("cannot compute a statistic over an empty set")
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) / 2


def _nearest_rank(values: list[Fraction], percentile: int) -> Fraction:
    if not values:
        raise DatasetError("cannot compute a percentile over an empty set")
    rank = (percentile * len(values) + 99) // 100
    return sorted(values)[rank - 1]


def factor_error(predicted_ns: Fraction, observed_ns: Fraction) -> Fraction:
    if predicted_ns <= 0 or observed_ns <= 0:
        raise DatasetError("holdout predictions and observations must be positive")
    return max(predicted_ns / observed_ns, observed_ns / predicted_ns)


def _factor_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    if not rows:
        return {"count": 0}
    factors = [row["_factor"] for row in rows]
    worst = max(rows, key=lambda row: (row["_factor"], row["entryId"]))
    return {
        "count": len(rows),
        "medianFactor": _fraction_description(_fraction_median(factors)),
        "p90FactorNearestRank": _fraction_description(_nearest_rank(factors, 90)),
        "p95FactorNearestRank": _fraction_description(_nearest_rank(factors, 95)),
        "maximumFactor": _fraction_description(max(factors)),
        "worstEntryId": worst["entryId"],
        "above1_1x": sum(value > Fraction(11, 10) for value in factors),
        "above1_25x": sum(value > Fraction(5, 4) for value in factors),
        "above1_5x": sum(value > Fraction(3, 2) for value in factors),
    }


def _utc_timestamp(value: str) -> str:
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", value):
        raise DatasetError("generatedAtUtc must be explicit ISO-8601 UTC with milliseconds")
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise DatasetError(f"generatedAtUtc is invalid: {error}") from error
    return value


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def validate_private_output_directory(output_directory: Path) -> Path:
    repo_root = Path(__file__).resolve().parents[1]
    resolved = output_directory.expanduser().resolve()
    private_root = (repo_root / ".dev-private" / "review-bundles").resolve()
    if _is_relative_to(resolved, repo_root) and not _is_relative_to(resolved, private_root):
        raise DatasetError(
            "candidate output inside the repository must remain under "
            ".dev-private/review-bundles"
        )
    runtime_source = (repo_root / "calibration" / "runtime-calibration-v1.json").resolve()
    if resolved == runtime_source or _is_relative_to(resolved, runtime_source.parent):
        raise DatasetError("runtime calibration source/staging path is forbidden in DATA1")
    if "bin" in [part.lower() for part in resolved.parts]:
        raise DatasetError("candidate output beneath an executable bin directory is forbidden")
    return resolved


def _safe_input_path(directory: Path, name: str) -> Path:
    path = (directory / name).resolve()
    if not path.is_file():
        raise DatasetError(f"required evidence file is missing: {path}")
    if not _is_relative_to(path, directory.resolve()):
        raise DatasetError(f"evidence path escapes its declared directory: {name}")
    return path


def _verify_source_hashes(evidence_directory: Path) -> tuple[dict[str, Path], dict[str, str]]:
    paths: dict[str, Path] = {}
    hashes: dict[str, str] = {}
    for name, expected in EXPECTED_SOURCE_SHA256.items():
        path = _safe_input_path(evidence_directory, name)
        actual = sha256_file(path)
        if actual != expected:
            raise DatasetError(
                f"immutable source SHA-256 mismatch for {name}: "
                f"expected {expected}, got {actual}"
            )
        paths[name] = path
        hashes[name] = actual
    return paths, hashes


def load_live_inventory_plan(inventory_plan_writer: Path) -> dict[str, Any]:
    executable = inventory_plan_writer.expanduser().resolve()
    if not executable.is_file() or executable.name.lower() != "cryptobenchmarkm23calibrationtests.exe":
        raise DatasetError(
            "inventory plan writer must be the existing "
            "CryptoBenchmarkM23CalibrationTests.exe"
        )
    try:
        with tempfile.TemporaryDirectory(prefix="m23-live-inventory-") as directory:
            output_path = Path(directory).resolve() / "candidate-plan.json"
            completed = subprocess.run(
                [str(executable), "--write-candidate-plan", str(output_path)],
                capture_output=True,
                text=True,
                encoding="utf-8",
                check=False,
                timeout=60,
            )
            if completed.returncode != 0:
                raise DatasetError(
                    "C++ live inventory plan writer failed: "
                    + (completed.stderr.strip() or completed.stdout.strip())
                )
            plan = read_json(output_path)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise DatasetError(f"cannot invoke the live C++ inventory writer: {error}") from error
    validate_inventory_plan(plan)
    return plan


def validate_inventory_plan(plan: dict[str, Any]) -> dict[str, tuple[str, str, str]]:
    if not isinstance(plan, dict) \
            or plan.get("format") != "cryptobenchmark-m23-candidate-plan" \
            or plan.get("schemaVersion") != 1 \
            or plan.get("measurementAuthorized") is not False:
        raise DatasetError("C++ inventory plan format/version/authorization is invalid")
    inventory_sha = plan.get("inventorySha256")
    if not isinstance(inventory_sha, str) \
            or not re.fullmatch(r"[0-9a-f]{64}", inventory_sha):
        raise DatasetError("C++ live registry inventory SHA-256 is malformed")
    if inventory_sha != EXPECTED_INVENTORY_SHA256:
        raise DatasetError(
            "live C++ registry inventory differs from the reviewed 175-case snapshot"
        )
    entries = plan.get("entries")
    if not isinstance(entries, list) or len(entries) != 2505:
        raise DatasetError("C++ inventory plan must contain the reviewed 2,505 planning rows")

    cases: dict[str, tuple[str, str, str]] = {}
    for row in entries:
        if not isinstance(row, dict):
            raise DatasetError("C++ inventory row is not an object")
        try:
            profile_id = row["profileId"]
            operation = row["operation"]
            input_kind = row["inputKind"]
            case_id = row["caseId"]
        except KeyError as error:
            raise DatasetError(f"C++ inventory row lacks {error.args[0]}") from error
        if not all(isinstance(value, str) and value for value in (
            profile_id, operation, input_kind, case_id
        )):
            raise DatasetError("C++ inventory row contains an empty/non-string identity")
        key = (profile_id, operation, input_kind)
        stable_case_id = "/".join(key)
        if case_id != stable_case_id:
            raise DatasetError("C++ inventory caseId is not its canonical typed tuple")
        existing = cases.setdefault(case_id, key)
        if existing != key:
            raise DatasetError("C++ inventory caseId maps to multiple typed tuples")
    if len(cases) != 175:
        raise DatasetError(f"live C++ inventory has {len(cases)} cases, expected 175")
    fixed = sum(kind not in ("message", "aead", "hashXof") for _, _, kind in cases.values())
    variable = len(cases) - fixed
    if (fixed, variable) != (78, 97):
        raise DatasetError(f"live inventory split is {(fixed, variable)}, expected (78, 97)")
    return cases


def _size_from_config(config: dict[str, Any]) -> int | None:
    parameters = config.get("parameters")
    if not isinstance(parameters, dict):
        raise DatasetError("result config parameters are missing or not an object")
    size_fields = [
        key for key in ("messageSizeBytes", "plaintextSizeBytes", "inputSizeBytes")
        if key in parameters
    ]
    if len(size_fields) > 1:
        raise DatasetError("result config has multiple workload-size fields")
    if not size_fields:
        return None
    return _integer(parameters[size_fields[0]], f"config.parameters.{size_fields[0]}")


def _case_key_for_config(
    config: dict[str, Any],
    cases: dict[str, tuple[str, str, str]],
) -> tuple[str, str, str]:
    try:
        profile_id = config["profileId"]
        operation = config["operation"]
        parameters = config["parameters"]
    except KeyError as error:
        raise DatasetError(f"result config lacks {error.args[0]}") from error
    if not isinstance(profile_id, str) or not isinstance(operation, str):
        raise DatasetError("result profileId/operation must be stable strings")
    if not isinstance(parameters, dict):
        raise DatasetError("result config parameters are not an object")
    choices = {key[2] for key in cases.values() if key[:2] == (profile_id, operation)}
    if not choices:
        raise DatasetError(f"result config is absent from live C++ inventory: {profile_id}/{operation}")

    input_mode = parameters.get("inputMode")
    if input_mode is not None:
        if input_mode not in ("message", "prehashed"):
            raise DatasetError(f"unsupported explicit signature input mode: {input_mode!r}")
        input_kind = input_mode
    elif "messageSizeBytes" in parameters:
        input_kind = "message"
    elif "plaintextSizeBytes" in parameters:
        input_kind = "aead"
    elif "inputSizeBytes" in parameters:
        input_kind = "hashXof"
    else:
        if len(choices) != 1:
            raise DatasetError(
                f"result config does not disambiguate a canonical typed mode: "
                f"{profile_id}/{operation}"
            )
        input_kind = next(iter(choices))

    key = (profile_id, operation, input_kind)
    if key not in cases.values():
        raise DatasetError(f"result typed config is not in live C++ inventory: {key}")
    variable = input_kind in ("message", "aead", "hashXof")
    size = _size_from_config(config)
    if variable != (size is not None):
        raise DatasetError(f"result size field conflicts with typed input mode: {key}")
    minimum = 0 if input_kind == "hashXof" else 1
    if variable and not minimum <= size <= MAX_WORKLOAD_BYTES:
        raise DatasetError(f"result input size outside legal domain: {key}, {size}")
    return key


def _validate_environment(entry: dict[str, Any], label: str) -> dict[str, str]:
    environment = entry.get("environment")
    if not isinstance(environment, dict):
        raise DatasetError(f"{label} environment is missing")
    expected = {
        "applicationVersion": "0.1.0",
        "architecture": "x86_64",
        "buildType": "Release",
        "gitCommit": "21a21ad2cf51c3c93fdc290a32b0f6cb6e6e7a2f",
        "opensslVersion": "3.6.5",
        "operatingSystem": "Windows 11 Version 25H2",
    }
    for field, value in expected.items():
        if environment.get(field) != value:
            raise DatasetError(
                f"{label} environment {field} mismatch: expected {value!r}, "
                f"got {environment.get(field)!r}"
            )
    measured_at = environment.get("measuredAt")
    if not isinstance(measured_at, str) or not measured_at.endswith("Z"):
        raise DatasetError(f"{label} measuredAt is not recorded as UTC")
    try:
        datetime.fromisoformat(measured_at[:-1] + "+00:00")
    except ValueError as error:
        raise DatasetError(f"{label} measuredAt is invalid: {error}") from error
    return {key: expected[key] for key in expected}


def _validate_result_envelope(
    document: Any,
    file_name: str,
    expected_count: int,
) -> dict[str, dict[str, Any]]:
    if not isinstance(document, dict):
        raise DatasetError(f"{file_name} root is not an object")
    expected_measurement = {
        "memoryModel": "memoryV2",
        "memorySamplingIntervalMilliseconds": 5,
        "workerLifecycle": "freshWorkerPerLogicalRun",
    }
    if document.get("format") != "cryptobenchmark-result" \
            or document.get("schemaVersion") != 2 \
            or document.get("mode") != "batch" \
            or document.get("status") != "completed" \
            or document.get("measurement") != expected_measurement:
        raise DatasetError(f"{file_name} result envelope/measurement context is invalid")
    entries = document.get("entries")
    if not isinstance(entries, list) or len(entries) != expected_count:
        raise DatasetError(f"{file_name} has an unexpected entry count")
    result: dict[str, dict[str, Any]] = {}
    environment_reference: dict[str, str] | None = None
    for index, entry in enumerate(entries):
        label = f"{file_name} entry {index}"
        if not isinstance(entry, dict) or entry.get("status") != "completed":
            raise DatasetError(f"{label} is failed, incomplete, or malformed")
        entry_id = entry.get("id")
        if not isinstance(entry_id, str) or not entry_id or entry_id in result:
            raise DatasetError(f"{label} has an invalid or duplicate ID")
        config = entry.get("config")
        if not isinstance(config, dict):
            raise DatasetError(f"{label} config is missing")
        iterations = _integer(config.get("iterationsPerRun"), f"{label} N", minimum=1)
        runs = _integer(config.get("runs"), f"{label} M", minimum=1)
        if config["runs"] <= 0 or config["iterationsPerRun"] <= 0:
            raise DatasetError(f"{label} has invalid N/M")
        if file_name == NIGHT_RESULT and runs != 10:
            raise DatasetError(f"{label} does not contain the original ten-run measurement")
        if iterations * runs > 1_000_000_000:
            raise DatasetError(f"{label} exceeds the ConfigValidator N*M bound")
        _size_from_config(config)
        environment = _validate_environment(entry, label)
        if environment_reference is None:
            environment_reference = environment
        elif environment != environment_reference:
            raise DatasetError(f"{file_name} has inconsistent source environments")
        statistics = entry.get("statistics")
        if not isinstance(statistics, dict):
            raise DatasetError(f"{label} statistics are missing")
        wall = statistics.get("wallClockNanosecondsPerOperation")
        if not isinstance(wall, dict) or "median" not in wall:
            raise DatasetError(f"{label} per-operation wall-clock median is missing")
        median = _measurement_value(wall["median"], f"{label} wall-clock median")
        result[entry_id] = entry
        entry["_verifiedMedianNs"] = median
    return result


def _candidate_crosscheck_map(candidate: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if not isinstance(candidate, dict) \
            or candidate.get("format") \
                != "cryptobenchmark-eta-offline-candidate-NOT-production-dataset" \
            or candidate.get("canonicalCaseCount") != 175 \
            or candidate.get("constantCaseCount") != 78 \
            or candidate.get("sizeDependentCaseCount") != 97 \
            or candidate.get("independentSizeHoldoutCount") != 291:
        raise DatasetError("offline model candidate cross-check metadata is inconsistent")
    records = candidate.get("records")
    if not isinstance(records, list) or len(records) != 175:
        raise DatasetError("offline cross-check must contain 175 case records")
    expected_sources = {
        NIGHT_RESULT: EXPECTED_SOURCE_SHA256[NIGHT_RESULT],
        SUPPLEMENTAL_RESULT: EXPECTED_SOURCE_SHA256[SUPPLEMENTAL_RESULT],
        SPLIT_MANIFEST: EXPECTED_SOURCE_SHA256[SPLIT_MANIFEST],
    }
    recorded_sources = candidate.get("sources")
    if not isinstance(recorded_sources, list):
        raise DatasetError("offline candidate is missing its source hash cross-check")
    if {
        item.get("file"): item.get("sha256")
        for item in recorded_sources
        if isinstance(item, dict)
    } != expected_sources:
        raise DatasetError("offline candidate source-hash cross-check differs from pinned inputs")
    if candidate.get("sampleSettings") != {
        "memoryModel": "memoryV2",
        "memorySamplingIntervalMilliseconds": 5,
        "workerLifecycle": "freshWorkerPerLogicalRun",
    }:
        raise DatasetError("offline candidate measurement context cross-check differs")
    source_build = candidate.get("sourceBuild")
    if not isinstance(source_build, dict) or any(
        source_build.get(field) != value
        for field, value in {
            "applicationVersion": "0.1.0",
            "architecture": "x86_64",
            "buildType": "Release",
            "gitCommit": "21a21ad2cf51c3c93fdc290a32b0f6cb6e6e7a2f",
            "opensslVersion": "3.6.5",
            "operatingSystem": "Windows 11 Version 25H2",
        }.items()
    ):
        raise DatasetError("offline candidate source-build cross-check differs")
    by_code: dict[str, dict[str, Any]] = {}
    for record in records:
        code = record.get("caseId")
        if not isinstance(code, str) or not code or code in by_code:
            raise DatasetError("offline cross-check has duplicate/invalid case codes")
        by_code[code] = record
    return by_code


def _crosscheck_candidate_case(
    case_code: str,
    case_key: tuple[str, str, str],
    candidate_by_code: dict[str, dict[str, Any]],
) -> None:
    record = candidate_by_code.get(case_code)
    if record is None:
        raise DatasetError(f"offline cross-check lacks case code {case_code}")
    if (record.get("profileId"), record.get("operation")) != case_key[:2]:
        raise DatasetError(f"offline cross-check canonical profile/operation mismatch: {case_code}")
    candidate_mode = record.get("inputMode")
    if candidate_mode not in (None, ""):
        if candidate_mode != case_key[2]:
            raise DatasetError(f"offline cross-check explicit input mode mismatch: {case_code}")
    elif case_key[2] in ("message", "prehashed"):
        raise DatasetError(f"offline cross-check omitted signature input mode: {case_code}")


def _read_holdout_csv(path: Path) -> list[dict[str, str]]:
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as stream:
            rows = list(csv.DictReader(stream))
    except (OSError, csv.Error) as error:
        raise DatasetError(f"cannot read holdout cross-check CSV: {error}") from error
    if len(rows) != 291:
        raise DatasetError(f"holdout cross-check has {len(rows)} rows, expected 291")
    required = {
        "id", "canonicalCaseId", "profileId", "operation", "inputMode",
        "inputBytes", "measuredMedianNs", "affineFactorError",
        "referenceOrHoldout", "N", "M",
    }
    if not rows or not required.issubset(rows[0]):
        raise DatasetError("holdout cross-check CSV is missing required columns")
    for row in rows:
        try:
            factor = Decimal(row["affineFactorError"])
        except (KeyError, ArithmeticError, ValueError) as error:
            raise DatasetError("holdout cross-check factor is malformed") from error
        if not factor.is_finite() or factor < 1:
            raise DatasetError("holdout cross-check factor is invalid")
    return rows


def load_verified_inputs(evidence_directory: Path, inventory_plan_writer: Path) -> VerifiedInputs:
    evidence_directory = evidence_directory.expanduser().resolve()
    paths, hashes = _verify_source_hashes(evidence_directory)
    documents = {
        name: read_json(path)
        for name, path in paths.items()
        if name != OFFLINE_HOLDOUT_CSV
    }
    night = _validate_result_envelope(documents[NIGHT_RESULT], NIGHT_RESULT, 563)
    supplemental = _validate_result_envelope(
        documents[SUPPLEMENTAL_RESULT], SUPPLEMENTAL_RESULT, 239)
    split = documents[SPLIT_MANIFEST]
    campaign_plan = documents[CAMPAIGN_PLAN]
    candidate = documents[OFFLINE_CANDIDATE]
    if not isinstance(split, dict) \
            or split.get("referenceCount") != 369 \
            or split.get("holdoutCount") != 194 \
            or len(split.get("entries", [])) != 563:
        raise DatasetError("563-entry split manifest metadata is invalid")
    if not isinstance(campaign_plan, dict) \
            or campaign_plan.get("format") != "cryptobenchmark-batch-input" \
            or campaign_plan.get("schemaVersion") != 1 \
            or len(campaign_plan.get("entries", [])) != 563:
        raise DatasetError("authenticated original 563-entry campaign plan is invalid")
    if split.get("sourceDataEnvironment") is None:
        raise DatasetError("split manifest omits its source environment")

    live_plan = load_live_inventory_plan(inventory_plan_writer)
    cases = validate_inventory_plan(live_plan)
    candidate_by_code = _candidate_crosscheck_map(candidate)
    try:
        prior_candidate_summary = candidate["holdoutValidation"]["all"]["anchoredAffine"]
        prior_candidate_count = prior_candidate_summary["count"]
        prior_candidate_metrics = {
            key: prior_candidate_summary[key]
            for key in ("median", "p90", "p95", "maximum")
        }
    except (KeyError, TypeError) as error:
        raise DatasetError("offline candidate is missing its all-size affine metrics") from error
    if prior_candidate_count != 291 or any(
        not isinstance(value, Decimal) or not value.is_finite() or value < 1
        for value in prior_candidate_metrics.values()
    ):
        raise DatasetError("offline candidate holdout metrics are malformed")
    split_by_id: dict[str, dict[str, Any]] = {}
    for entry in split["entries"]:
        entry_id = entry.get("id")
        if not isinstance(entry_id, str) or not entry_id or entry_id in split_by_id:
            raise DatasetError("split manifest has duplicate/invalid IDs")
        split_by_id[entry_id] = entry
    campaign_by_id = {entry.get("id"): entry for entry in campaign_plan["entries"]}
    if len(campaign_by_id) != 563 or set(campaign_by_id) != set(night):
        raise DatasetError("campaign plan IDs differ from original result IDs")
    if set(split_by_id) != set(night):
        raise DatasetError("split manifest IDs differ from original result IDs")

    environment = next(iter(night.values()))["environment"]
    manifest_environment = split["sourceDataEnvironment"]
    for field in (
        "applicationVersion", "architecture", "buildType", "gitCommit",
        "opensslVersion", "operatingSystem",
    ):
        if manifest_environment.get(field) != environment.get(field):
            raise DatasetError(f"split manifest environment differs for {field}")
    if split.get("runsPerEntry") != 10 or split.get("maxInputBytes") != 1_048_576:
        raise DatasetError("split manifest run count/input cap differs from its source contract")

    references_by_case: dict[str, list[Observation]] = defaultdict(list)
    holdouts_by_case: dict[str, list[Observation]] = defaultdict(list)
    for entry_id, entry in night.items():
        config = entry["config"]
        case_key = _case_key_for_config(config, cases)
        case_id = "/".join(case_key)
        manifest_entry = split_by_id[entry_id]
        plan_entry = campaign_by_id[entry_id]
        if manifest_entry.get("split") not in ("reference", "holdout"):
            raise DatasetError(f"unknown split label for {entry_id}")
        if manifest_entry.get("canonicalCaseId") not in candidate_by_code:
            raise DatasetError(f"cross-check lacks split case code for {entry_id}")
        _crosscheck_candidate_case(
            manifest_entry["canonicalCaseId"], case_key, candidate_by_code)
        if ("fit" in entry_id or "exact" in entry_id) \
                != (manifest_entry["split"] == "reference"):
            raise DatasetError(f"entry ID role conflicts with split manifest: {entry_id}")
        if manifest_entry["split"] == "holdout" and "hold" not in entry_id:
            raise DatasetError(f"holdout ID lacks its holdout marker: {entry_id}")

        parameters = config["parameters"]
        size = _size_from_config(config)
        if plan_entry.get("profileId") != config["profileId"] \
                or plan_entry.get("operation") != config["operation"] \
                or plan_entry.get("iterationsPerRun") != config["iterationsPerRun"] \
                or plan_entry.get("runs") != config["runs"] \
                or plan_entry.get("parameters") != parameters:
            raise DatasetError(f"original campaign input differs from measured config: {entry_id}")
        manifest_size = manifest_entry.get("byteSize")
        if (None if manifest_size is None else int(manifest_size)) != size \
                or _integer(manifest_entry.get("N"), "split manifest N", 1) \
                    != config["iterationsPerRun"] \
                or _integer(manifest_entry.get("M"), "split manifest M", 1) \
                    != config["runs"]:
            raise DatasetError(f"split manifest N/M/size differs from measured config: {entry_id}")
        observation = Observation(
            NIGHT_RESULT,
            entry_id,
            case_id,
            manifest_entry["canonicalCaseId"],
            case_key[2],
            case_key[0],
            case_key[1],
            size,
            config["iterationsPerRun"],
            config["runs"],
            entry["_verifiedMedianNs"],
            manifest_entry["split"],
        )
        bucket = references_by_case if observation.evidence_role == "reference" \
            else holdouts_by_case
        bucket[case_id].append(observation)

    supplemental_entries = documents[SUPPLEMENTAL_RESULT]["entries"]
    prefix_counts = Counter(entry["id"].split("-", 1)[0] for entry in supplemental_entries)
    if dict(prefix_counts) != SUPPLEMENTAL_PREFIX_COUNTS:
        raise DatasetError(f"supplemental category counts changed: {dict(prefix_counts)}")
    supplemental_refs: list[Observation] = []
    supplemental_holds: list[Observation] = []
    for entry in supplemental_entries:
        entry_id = entry["id"]
        if entry_id.startswith("m23256m-"):
            role = "reference"
            expected_size = MAX_WORKLOAD_BYTES
        elif entry_id.startswith("m2316m-"):
            role = "holdout"
            expected_size = 16_777_216
        else:
            continue
        config = entry["config"]
        if config["runs"] != 5:
            raise DatasetError(f"supplemental size entry does not use five runs: {entry_id}")
        size = _size_from_config(config)
        if size != expected_size:
            raise DatasetError(f"supplemental entry size conflicts with its role: {entry_id}")
        case_key = _case_key_for_config(config, cases)
        case_id = "/".join(case_key)
        suffix_code = entry_id.rsplit("-", 1)[-1]
        _crosscheck_candidate_case(suffix_code, case_key, candidate_by_code)
        observation = Observation(
            SUPPLEMENTAL_RESULT,
            entry_id,
            case_id,
            suffix_code,
            case_key[2],
            case_key[0],
            case_key[1],
            size,
            config["iterationsPerRun"],
            config["runs"],
            _measurement_value(
                entry["statistics"]["wallClockNanosecondsPerOperation"]["median"],
                f"supplemental {entry_id} wall-clock median"),
            role,
        )
        if role == "reference":
            supplemental_refs.append(observation)
            references_by_case[case_id].append(observation)
        else:
            supplemental_holds.append(observation)
            holdouts_by_case[case_id].append(observation)

    if len(supplemental_refs) != 97 or len(supplemental_holds) != 97:
        raise DatasetError("supplemental references/holdouts are not exactly 97 each")
    if sum(map(len, references_by_case.values())) != 466 \
            or sum(map(len, holdouts_by_case.values())) != 291 \
            or set(references_by_case) != set(cases) \
            or set(holdouts_by_case) != {
                case_id for case_id, (_, _, kind) in cases.items()
                if kind in ("message", "aead", "hashXof")
            }:
        raise DatasetError("training/holdout split has missing or extra canonical cases")

    for case_id, key in cases.items():
        references = references_by_case[case_id]
        holds = holdouts_by_case.get(case_id, [])
        if key[2] in ("message", "aead", "hashXof"):
            minimum = 0 if key[2] == "hashXof" else 1
            ref_sizes = sorted(row.input_bytes for row in references)
            expected_holds = [1, 65_536, 16_777_216] if key[2] == "hashXof" \
                else [64, 65_536, 16_777_216]
            hold_sizes = sorted(row.input_bytes for row in holds)
            if ref_sizes != [minimum, 4096, 1_048_576, MAX_WORKLOAD_BYTES]:
                raise DatasetError(f"reference sizes differ from the approved grid: {case_id}")
            if hold_sizes != expected_holds:
                raise DatasetError(f"holdout sizes differ from the independent grid: {case_id}")
        elif len(references) != 1 or holds:
            raise DatasetError(f"fixed case has unexpected size/reference holdouts: {case_id}")

    holdout_csv_rows = _read_holdout_csv(paths[OFFLINE_HOLDOUT_CSV])
    expected_hold_ids = {
        observation.entry_id
        for rows in holdouts_by_case.values()
        for observation in rows
    }
    if {row["id"] for row in holdout_csv_rows} != expected_hold_ids:
        raise DatasetError("offline holdout CSV IDs differ from raw independent holdouts")
    raw_by_id = {
        observation.entry_id: observation
        for rows in holdouts_by_case.values()
        for observation in rows
    }
    for row in holdout_csv_rows:
        observation = raw_by_id[row["id"]]
        try:
            csv_median = Decimal(row["measuredMedianNs"])
            csv_factor = Decimal(row["affineFactorError"])
        except (ArithmeticError, ValueError) as error:
            raise DatasetError(
                f"offline holdout CSV measurement is malformed: {row.get('id')}"
            ) from error
        if row.get("referenceOrHoldout") != "holdout" \
                or row.get("canonicalCaseId") != observation.case_code \
                or row.get("profileId") != observation.profile_id \
                or row.get("operation") != observation.operation \
                or row.get("inputMode") != (
                    candidate_by_code[observation.case_code].get("inputMode") or ""
                ) \
                or int(row.get("inputBytes", "-1")) != observation.input_bytes \
                or int(row.get("N", "-1")) != observation.iterations_per_run \
                or int(row.get("M", "-1")) != observation.runs \
                or not csv_median.is_finite() \
                or not csv_factor.is_finite() \
                or csv_factor < 1 \
                or abs(csv_median - observation.median_nanoseconds) > max(
                    abs(observation.median_nanoseconds) * Decimal("1e-12"),
                    Decimal("1e-12"),
                ):
            raise DatasetError(f"offline holdout CSV cross-check mismatch: {row.get('id')}")

    excluded_supplemental_counts = {
        prefix: prefix_counts[prefix]
        for prefix in ("nmhold", "probe16m", "p256canary", "p256pilot")
    }

    return VerifiedInputs(
        evidence_directory,
        {
            NIGHT_RESULT: night,
            SUPPLEMENTAL_RESULT: supplemental,
            SPLIT_MANIFEST: split,
            CAMPAIGN_PLAN: campaign_plan,
            OFFLINE_CANDIDATE: candidate,
        },
        hashes,
        live_plan["inventorySha256"],
        cases,
        candidate_by_code,
        dict(references_by_case),
        dict(holdouts_by_case),
        excluded_supplemental_counts,
        {
            "count": prior_candidate_count,
            **prior_candidate_metrics,
            "coefficientsUsedForTraining": False,
        },
        {
            "canonicalCaseCount": candidate["canonicalCaseCount"],
            "constantCaseCount": candidate["constantCaseCount"],
            "sizeDependentCaseCount": candidate["sizeDependentCaseCount"],
            "independentSizeHoldoutCount": candidate["independentSizeHoldoutCount"],
        },
        holdout_csv_rows,
    )


def _membership_sha256(observations: list[Observation]) -> str:
    membership = [
        {"sourceFile": row.source_file, "entryId": row.entry_id}
        for row in sorted(
            observations,
            key=lambda row: (row.source_file, row.entry_id),
        )
    ]
    return sha256_bytes(canonical_json_bytes(membership))


def _prediction_ps(model: dict[str, Any], size: int) -> int:
    if model["kind"] == "constantPerOperation":
        return int(model["picosecondsPerOperation"])
    delta = size - int(model["anchorInputBytes"])
    if delta < 0:
        raise DatasetError("prediction requested below the anchored model minimum")
    prediction = (
        int(model["anchorPicosecondsPerOperation"])
        + int(model["slopePicosecondsPerBytePerOperation"]) * delta
    )
    if prediction <= 0 or prediction > MAX_U64:
        raise DatasetError("quantized prediction is nonpositive or exceeds uint64 ps")
    return prediction


def _size_factor(
    predicted_picoseconds: int,
    observed_nanoseconds: Decimal,
) -> Fraction:
    predicted_ns = Fraction(predicted_picoseconds, 1000)
    observed_ns = Fraction(observed_nanoseconds)
    return factor_error(predicted_ns, observed_ns)


def _build_models(
    inputs: VerifiedInputs,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    records: list[dict[str, Any]] = []
    diagnostics: list[dict[str, Any]] = []
    holdout_rows: list[dict[str, Any]] = []
    for case_id in sorted(inputs.inventory_cases):
        profile_id, operation, input_kind = inputs.inventory_cases[case_id]
        references = sorted(
            inputs.references_by_case[case_id],
            key=lambda row: (row.input_bytes if row.input_bytes is not None else -1,
                             row.source_file, row.entry_id),
        )
        holdouts = sorted(
            inputs.holdouts_by_case.get(case_id, []),
            key=lambda row: (row.input_bytes, row.source_file, row.entry_id),
        )
        variable = input_kind in ("message", "aead", "hashXof")
        training_ids = [row.entry_id for row in references]
        evidence_hash = _membership_sha256(references)
        holdout_hash = _membership_sha256(holdouts)

        if not variable:
            if len(references) != 1 or holdouts:
                raise DatasetError(f"fixed-input model membership changed: {case_id}")
            median = references[0].median_nanoseconds
            picoseconds_per_operation = _fraction_round_half_up(
                Fraction(median) * 1000
            )
            if picoseconds_per_operation <= 0:
                raise DatasetError(f"fixed per-operation coefficient quantized to zero: {case_id}")
            model = {
                "kind": "constantPerOperation",
                "picosecondsPerOperation": str(picoseconds_per_operation),
            }
            record_status = "perOperationReferenceFitOnly"
            model_info = {
                "caseId": case_id,
                "profileId": profile_id,
                "operation": operation,
                "inputKind": input_kind,
                "modelKind": "constantPerOperation",
                "picosecondsPerOperation": str(picoseconds_per_operation),
                "trainingReferenceIds": training_ids,
                "coefficientReferenceIds": training_ids,
                "secondaryReferenceDiagnostics": [],
                "independentHoldoutIds": [],
            }
        else:
            minimum = 0 if input_kind == "hashXof" else 1
            max_ref = MAX_WORKLOAD_BYTES
            by_size = {row.input_bytes: row for row in references}
            if set(by_size) != {minimum, 4096, 1_048_576, max_ref}:
                raise DatasetError(f"reference grid changed before model fit: {case_id}")
            min_ref = by_size[minimum]
            max_ref_row = by_size[max_ref]
            anchor_ps = _fraction_round_half_up(
                Fraction(min_ref.median_nanoseconds) * 1000
            )
            slope_ns = Fraction(
                max_ref_row.median_nanoseconds - min_ref.median_nanoseconds
            ) / (max_ref - minimum)
            slope_ps = _fraction_round_half_up(max(slope_ns * 1000, Fraction(0)))
            if anchor_ps <= 0:
                raise DatasetError(f"anchored per-operation coefficient quantized to zero: {case_id}")
            model = {
                "kind": "anchoredAffinePerOperation",
                "anchorInputBytes": str(minimum),
                "anchorPicosecondsPerOperation": str(anchor_ps),
                "slopePicosecondsPerBytePerOperation": str(slope_ps),
            }
            maximum_prediction = anchor_ps + slope_ps * (max_ref - minimum)
            if maximum_prediction > MAX_U64:
                raise DatasetError(f"quantized model overflows at 256 MiB: {case_id}")
            record_status = "perOperationReferenceFitSizeHoldoutOnly"
            secondary = []
            for size in (4096, 1_048_576, max_ref):
                observation = by_size[size]
                predicted = _prediction_ps(model, size)
                secondary.append({
                    "inputBytes": size,
                    "entryId": observation.entry_id,
                    "observedMedianNanoseconds": _decimal_text(
                        observation.median_nanoseconds),
                    "predictedPicoseconds": str(predicted),
                    "predictedNanosecondsExact": _fraction_description(
                        Fraction(predicted, 1000)),
                    "factorError": _fraction_description(_size_factor(
                        predicted, observation.median_nanoseconds)),
                    "pointRole": "256MiBReferenceEndpoint" if size == max_ref
                        else "TrainingSanityReference",
                })
            model_info = {
                "caseId": case_id,
                "profileId": profile_id,
                "operation": operation,
                "inputKind": input_kind,
                "modelKind": "anchoredAffinePerOperation",
                "anchorInputBytes": str(minimum),
                "anchorPicosecondsPerOperation": str(anchor_ps),
                "slopePicosecondsPerBytePerOperation": str(slope_ps),
                "trainingReferenceIds": training_ids,
                "coefficientReferenceIds": [
                    min_ref.entry_id,
                    max_ref_row.entry_id,
                ],
                "secondaryReferenceDiagnostics": secondary,
                "independentHoldoutIds": [
                    row.entry_id for row in holdouts
                ],
            }
            for holdout in holdouts:
                if holdout.input_bytes is None:
                    raise DatasetError(f"size holdout lacks inputBytes: {holdout.entry_id}")
                prediction = _prediction_ps(model, holdout.input_bytes)
                factor = _size_factor(prediction, holdout.median_nanoseconds)
                holdout_rows.append({
                    "entryId": holdout.entry_id,
                    "sourceFile": holdout.source_file,
                    "caseId": case_id,
                    "profileId": profile_id,
                    "operation": operation,
                    "inputKind": input_kind,
                    "inputBytes": holdout.input_bytes,
                    "N": holdout.iterations_per_run,
                    "M": holdout.runs,
                    "observedMedianNanoseconds": _decimal_text(
                        holdout.median_nanoseconds),
                    "predictedPicoseconds": str(prediction),
                    "predictedNanosecondsExact": _fraction_description(
                        Fraction(prediction, 1000)),
                    "factorError": _fraction_description(factor),
                    "_factor": factor,
                })

        variable_bounds: dict[str, str] = {}
        if variable:
            variable_bounds = {
                "validInputBytesMin": "0" if input_kind == "hashXof" else "1",
                "validInputBytesMax": str(MAX_WORKLOAD_BYTES),
            }
        record = {
            "profileId": profile_id,
            "operation": operation,
            "inputKind": input_kind,
            "samplingIntervalMilliseconds": MEASURED_SAMPLING_INTERVAL_MS,
            "measuredModel": model,
            **variable_bounds,
            "evidenceSubsetSha256": evidence_hash,
            "holdoutSubsetSha256": holdout_hash,
            "modelQualificationStatus": record_status,
        }
        records.append(record)
        diagnostics.append(model_info)

    if len(records) != 175 or len(holdout_rows) != 291:
        raise DatasetError(
            f"generated case/holdout counts are {len(records)}/{len(holdout_rows)}, "
            "expected 175/291"
        )
    return records, diagnostics, holdout_rows


def _clean_report_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{key: value for key, value in row.items() if not key.startswith("_")}
            for row in rows]


def _build_holdout_report(
    inputs: VerifiedInputs,
    request: GenerationRequest,
    model_diagnostics: list[dict[str, Any]],
    holdout_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    factors = [row["_factor"] for row in holdout_rows]
    size_buckets: dict[str, list[dict[str, Any]]] = {}
    for bucket, predicate in (
        ("1Byte", lambda size: size == 1),
        ("64Byte", lambda size: size == 64),
        ("upTo64Bytes", lambda size: size <= 64),
        ("64KiB", lambda size: size == 65_536),
        ("16MiB", lambda size: size == 16_777_216),
    ):
        size_buckets[bucket] = [
            row for row in holdout_rows if predicate(row["inputBytes"])
        ]
    old_csv_factors = [
        Decimal(row["affineFactorError"])
        for row in inputs.prior_csv_rows
    ]
    if any(not value.is_finite() or value < 1 for value in old_csv_factors):
        raise DatasetError("offline CSV factor-error cross-check is invalid")
    old_csv_sorted = sorted(old_csv_factors)
    old_csv_p90_rank = (90 * len(old_csv_sorted) + 99) // 100
    old_csv_p95_rank = (95 * len(old_csv_sorted) + 99) // 100
    middle = len(old_csv_sorted) // 2
    old_csv_median = (
        old_csv_sorted[middle]
        if len(old_csv_sorted) % 2
        else (old_csv_sorted[middle - 1] + old_csv_sorted[middle]) / 2
    )
    zero_byte_records = [
        {
            "caseId": model["caseId"],
            "profileId": model["profileId"],
            "operation": model["operation"],
            "anchorPicosecondsPerOperation": model["anchorPicosecondsPerOperation"],
        }
        for model in model_diagnostics
        if model["inputKind"] == "hashXof"
        and model.get("anchorInputBytes") == "0"
    ]
    return {
        "format": "cryptobenchmark-m23-pragmatic-holdout-validation",
        "schemaVersion": 1,
        "generatorVersion": GENERATOR_VERSION,
        "datasetId": request.dataset_id,
        "datasetVersion": request.dataset_version,
        "generatedAtUtc": request.generated_at_utc,
        "fitMethod": (
            "constant median per operation for fixed cases; anchored affine from "
            "minimum and 256 MiB references only; 4 KiB/1 MiB are diagnostics"
        ),
        "quantization": {
            "unit": "integer picoseconds per operation; integer picoseconds per byte per operation",
            "tieRule": "nearest integer, ties round half up using exact rational arithmetic",
            "nanosecondReporting": (
                "exact predictedPicoseconds/1000 for per-operation errors; "
                "M22 nearest-nanosecond rounding is tested after N scaling"
            ),
        },
        "assumptions": {
            "warmupOperationsPerLogicalRun": 1,
            "fixedEntryOverhead": "0 assumedUnmeasured",
            "batchOverhead": "0 assumedUnmeasured",
            "samplingIntervals1to4Ms": "assumedFrom5ms; not measured",
            "endToEndQualification": "not performed; waived gates are not claimed passed",
        },
        "sources": {
            "sha256": inputs.source_hashes,
            "inventorySha256": inputs.inventory_sha256,
            "campaignPlanSha256": inputs.source_hashes[CAMPAIGN_PLAN],
            "rawEvidenceManifestSha256": inputs.source_hashes[SPLIT_MANIFEST],
        },
        "counts": {
            "canonicalCases": len(inputs.inventory_cases),
            "fixedCases": sum(
                key[2] not in ("message", "aead", "hashXof")
                for key in inputs.inventory_cases.values()
            ),
            "variableCases": sum(
                key[2] in ("message", "aead", "hashXof")
                for key in inputs.inventory_cases.values()
            ),
            "trainingReferences": sum(
                len(values) for values in inputs.references_by_case.values()
            ),
            "independentSizeHoldouts": len(holdout_rows),
            "excludedSupplementalControls": sum(inputs.excluded_supplemental_counts.values()),
            "excludedSupplementalControlCategories": inputs.excluded_supplemental_counts,
        },
        "offlineCandidateCountsCrossCheckOnly": inputs.prior_candidate_counts,
        "quantizedHoldoutStatistics": {
            "all": _factor_summary(holdout_rows),
            "sizeBuckets": {
                name: _factor_summary(rows)
                for name, rows in sorted(size_buckets.items())
            },
            "priorOfflineCandidateJsonCrossCheckOnly": {
                "count": inputs.prior_candidate_summary["count"],
                "medianFactor": _decimal_text(
                    inputs.prior_candidate_summary["median"]),
                "p90Factor": _decimal_text(
                    inputs.prior_candidate_summary["p90"]),
                "p95Factor": _decimal_text(
                    inputs.prior_candidate_summary["p95"]),
                "maximumFactor": _decimal_text(
                    inputs.prior_candidate_summary["maximum"]),
                "coefficientsUsedForTraining": False,
            },
            "priorOfflineCandidateCrossCheckOnly": {
                "rowCount": len(old_csv_sorted),
                "medianFactor": _decimal_text(old_csv_median),
                "p90FactorNearestRank": _decimal_text(old_csv_sorted[old_csv_p90_rank - 1]),
                "p95FactorNearestRank": _decimal_text(old_csv_sorted[old_csv_p95_rank - 1]),
                "maximumFactor": _decimal_text(old_csv_sorted[-1]),
                "coefficientsUsedForTraining": False,
            },
        },
        "zeroByteHashXofAnchors": zero_byte_records,
        "modelDiagnostics": model_diagnostics,
        "holdoutErrors": _clean_report_rows(holdout_rows),
    }


def _build_candidate_resource(
    inputs: VerifiedInputs,
    request: GenerationRequest,
    records: list[dict[str, Any]],
    holdout_report_sha256: str,
) -> dict[str, Any]:
    environment = next(iter(inputs.contents[NIGHT_RESULT].values()))["environment"]
    null_fields = sorted(ALLOWED_NULL_PROVENANCE_REASONS)
    source_hashes = inputs.source_hashes
    return {
        "format": "cryptobenchmark-runtime-calibration",
        "schemaVersion": 1,
        "datasetId": request.dataset_id,
        "datasetVersion": request.dataset_version,
        "generatedAtUtc": request.generated_at_utc,
        "calibrationProtocolId": "memory-v2-calibration-v1",
        "modelSchemaVersion": "m23-pragmatic-1",
        "generatorVersion": GENERATOR_VERSION,
        "sourceGitCommit": environment["gitCommit"],
        "referenceAppVersion": environment["applicationVersion"],
        "referenceBuildType": environment["buildType"],
        "referenceWorkerSha256": None,
        "referenceAppSha256": None,
        "opensslVersion": environment["opensslVersion"],
        "qtVersion": None,
        "compilerId": None,
        "os": environment["operatingSystem"],
        "architecture": environment["architecture"],
        "referenceCpu": None,
        "referenceRamBytes": None,
        "powerPlan": None,
        "registryInventorySha256": inputs.inventory_sha256,
        "campaignPlanSha256": source_hashes[CAMPAIGN_PLAN],
        "rawEvidenceManifestSha256": source_hashes[SPLIT_MANIFEST],
        "holdoutReportSha256": holdout_report_sha256,
        "qualificationStatus": "reducedScopeApproximate",
        "qualificationSummary": (
            "Approximate per-operation models; only independent size holdouts "
            "are validated. No end-to-end Batch qualification, measured overhead, "
            "or 1-4 ms sampling comparison is claimed."
        ),
        "qualifiedRuntimeContexts": [{
            "os": environment["operatingSystem"],
            "architecture": environment["architecture"],
            "buildType": environment["buildType"],
            "opensslVersion": environment["opensslVersion"],
            "calibrationProtocolId": "memory-v2-calibration-v1",
            "samplingIntervalMilliseconds": 5,
        }],
        "sourceEvidenceSha256": {
            "nightResultSha256": source_hashes[NIGHT_RESULT],
            "supplementalResultSha256": source_hashes[SUPPLEMENTAL_RESULT],
            "splitManifestSha256": source_hashes[SPLIT_MANIFEST],
        },
        "provenanceMissingReasons": {
            field: ALLOWED_NULL_PROVENANCE_REASONS[field]
            for field in null_fields
        },
        "approximationPolicy": {
            "warmupOperationsPerLogicalRun": 1,
            "fixedEntryOverhead": {
                "nanoseconds": "0",
                "status": "assumedUnmeasured",
            },
            "batchOverhead": {
                "nanoseconds": "0",
                "status": "assumedUnmeasured",
            },
            "samplingIntervalAssumptions": [
                {
                    "requestedIntervalMilliseconds": interval,
                    "sourceMeasuredIntervalMilliseconds": 5,
                    "status": "assumedFrom5ms",
                }
                for interval in (1, 2, 3, 4)
            ],
        },
        "records": records,
        "batchOverheadModels": [],
    }


def _validate_generation_arguments(request: GenerationRequest) -> None:
    _utc_timestamp(request.generated_at_utc)
    if not request.dataset_id or not request.dataset_version:
        raise DatasetError("datasetId and datasetVersion must be explicit non-empty values")
    if any(character in request.dataset_id + request.dataset_version for character in "\r\n\0"):
        raise DatasetError("datasetId/datasetVersion contains a control character")
    output = validate_private_output_directory(request.output_directory)
    if output.exists():
        raise DatasetError("output directory must be new; refusing to overwrite evidence")


def generate(request: GenerationRequest) -> dict[str, Any]:
    _validate_generation_arguments(request)
    inputs = load_verified_inputs(
        request.evidence_directory, request.inventory_plan_writer)
    records, diagnostics, holdout_rows = _build_models(inputs)
    report = _build_holdout_report(inputs, request, diagnostics, holdout_rows)
    report_bytes = canonical_json_bytes(report)
    holdout_report_sha256 = sha256_bytes(report_bytes)
    resource = _build_candidate_resource(
        inputs, request, records, holdout_report_sha256)
    resource_bytes = canonical_json_bytes(resource)
    if len(resource_bytes) > 16 * 1024 * 1024:
        raise DatasetError("candidate exceeds the strict 16 MiB resource limit")
    output_directory = validate_private_output_directory(request.output_directory)
    report_path = output_directory / "holdout-validation-report.json"
    resource_path = output_directory / "candidate-runtime-calibration-v1.json"
    if report_path.exists() or resource_path.exists():
        raise DatasetError("candidate/report output already exists; refusing overwrite")
    try:
        output_directory.mkdir(parents=True, exist_ok=False)
        report_path.write_bytes(report_bytes)
        resource_path.write_bytes(resource_bytes)
    except OSError as error:
        raise DatasetError(f"cannot write private candidate outputs: {error}") from error
    return {
        "resourcePath": resource_path,
        "holdoutReportPath": report_path,
        "resourceSha256": sha256_bytes(resource_bytes),
        "holdoutReportSha256": holdout_report_sha256,
        "resourceBytes": len(resource_bytes),
        "holdoutReportBytes": len(report_bytes),
        "inventorySha256": inputs.inventory_sha256,
        "sourceHashes": inputs.source_hashes,
        "recordCount": len(records),
        "holdoutCount": len(holdout_rows),
        "holdoutStatistics": report["quantizedHoldoutStatistics"]["all"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--inventory-plan-writer", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--generated-at-utc", required=True)
    parser.add_argument("--dataset-id", required=True)
    parser.add_argument("--dataset-version", required=True)
    args = parser.parse_args(argv)
    request = GenerationRequest(
        args.evidence_dir,
        args.inventory_plan_writer,
        args.output_dir,
        args.generated_at_utc,
        args.dataset_id,
        args.dataset_version,
    )
    try:
        result = generate(request)
    except (DatasetError, OSError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    print("RESULT=PASS - NO OBSERVATIONS")
    print(f"resource={result['resourcePath']}")
    print(f"resourceSha256={result['resourceSha256']}")
    print(f"holdoutReport={result['holdoutReportPath']}")
    print(f"holdoutReportSha256={result['holdoutReportSha256']}")
    print(f"records={result['recordCount']}; independentSizeHoldouts={result['holdoutCount']}")
    print(f"inventorySha256={result['inventorySha256']}")
    print(f"holdoutStatistics={json.dumps(result['holdoutStatistics'], sort_keys=True)}")
    for name, digest in sorted(result["sourceHashes"].items()):
        print(f"sourceSha256[{name}]={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
