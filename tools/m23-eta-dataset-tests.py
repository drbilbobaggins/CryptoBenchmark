#!/usr/bin/env python3
"""Non-observing determinism, source-integrity, and arithmetic tests for DATA1."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


GENERATOR_PATH = Path(__file__).with_name("m23-eta-dataset-generator.py")
SPEC = importlib.util.spec_from_file_location(
    "m23_eta_dataset_generator", GENERATOR_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load the M23 DATA1 generator module")
GENERATOR = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = GENERATOR
SPEC.loader.exec_module(GENERATOR)


class PragmaticDatasetTests(unittest.TestCase):
    evidence_directory: Path
    inventory_writer: Path
    parser_test_executable: Path
    temporary_directory: tempfile.TemporaryDirectory[str]
    root: Path

    @classmethod
    def setUpClass(cls) -> None:
        cls.evidence_directory = cls.options.evidence_dir.resolve()
        cls.inventory_writer = cls.options.inventory_plan_writer.resolve()
        cls.parser_test_executable = cls.options.parser_test_executable.resolve()
        if not cls.parser_test_executable.is_file():
            raise RuntimeError(
                f"candidate parser test executable is missing: {cls.parser_test_executable}")
        cls.temporary_directory = tempfile.TemporaryDirectory(
            prefix="cryptobenchmark-m23-data1-tests-")
        cls.root = Path(cls.temporary_directory.name)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary_directory.cleanup()

    def _request(
        self,
        output_name: str,
        dataset_version: str = "1.0.0-test",
    ) -> Any:
        return GENERATOR.GenerationRequest(
            self.evidence_directory,
            self.inventory_writer,
            self.root / output_name,
            "2026-11-01T14:00:00.000Z",
            "cryptobenchmark-m23-pragmatic-test",
            dataset_version,
        )

    def test_exact_175_case_deterministic_generation(self) -> None:
        first = GENERATOR.generate(self._request("generation-a"))
        second = GENERATOR.generate(self._request("generation-b"))
        first_resource = first["resourcePath"].read_bytes()
        second_resource = second["resourcePath"].read_bytes()
        first_report = first["holdoutReportPath"].read_bytes()
        second_report = second["holdoutReportPath"].read_bytes()
        self.assertEqual(first_resource, second_resource)
        self.assertEqual(first_report, second_report)
        self.assertEqual(first["resourceSha256"], hashlib.sha256(first_resource).hexdigest())
        self.assertEqual(
            first["holdoutReportSha256"], hashlib.sha256(first_report).hexdigest())

        resource = GENERATOR.parse_json_bytes(first_resource, "synthetic deterministic output")
        self.assertEqual(resource["modelSchemaVersion"], "m23-pragmatic-1")
        self.assertEqual(resource["qualificationStatus"], "reducedScopeApproximate")
        self.assertEqual(len(resource["records"]), 175)
        self.assertEqual(len({
            (row["profileId"], row["operation"], row["inputKind"])
            for row in resource["records"]
        }), 175)
        self.assertEqual(
            (first["sourceHashes"][GENERATOR.CAMPAIGN_PLAN],
             resource["campaignPlanSha256"]),
            (GENERATOR.EXPECTED_SOURCE_SHA256[GENERATOR.CAMPAIGN_PLAN],
             GENERATOR.EXPECTED_SOURCE_SHA256[GENERATOR.CAMPAIGN_PLAN]))
        self.assertEqual(
            resource["sourceEvidenceSha256"]["splitManifestSha256"],
            resource["rawEvidenceManifestSha256"])
        self.assertEqual(resource["batchOverheadModels"], [])

    def test_disjoint_training_and_291_quantized_holdouts(self) -> None:
        generated = GENERATOR.generate(self._request("holdout-check"))
        resource = GENERATOR.parse_json_bytes(
            generated["resourcePath"].read_bytes(), "candidate fixture")
        report = GENERATOR.read_json(generated["holdoutReportPath"])
        self.assertEqual(report["counts"]["trainingReferences"], 466)
        self.assertEqual(report["counts"]["independentSizeHoldouts"], 291)
        self.assertEqual(report["counts"]["excludedSupplementalControls"], 45)
        self.assertEqual(
            report["counts"]["excludedSupplementalControlCategories"],
            {
                "nmhold": 17,
                "probe16m": 14,
                "p256canary": 1,
                "p256pilot": 13,
            },
        )
        self.assertEqual(len(report["holdoutErrors"]), 291)
        self.assertEqual(
            len({row["entryId"] for row in report["holdoutErrors"]}), 291)
        for model in report["modelDiagnostics"]:
            self.assertTrue(
                set(model["trainingReferenceIds"]).isdisjoint(
                    model["independentHoldoutIds"]))
        self.assertEqual(
            report["quantizedHoldoutStatistics"]["all"]["count"], 291)
        self.assertFalse(
            report["quantizedHoldoutStatistics"]
            ["priorOfflineCandidateCrossCheckOnly"]["coefficientsUsedForTraining"])

        sizes = {}
        for row in report["holdoutErrors"]:
            sizes[row["inputBytes"]] = sizes.get(row["inputBytes"], 0) + 1
        self.assertEqual(sizes, {1: 19, 64: 78, 65_536: 97, 16_777_216: 97})

        zero_byte_hash = [
            row for row in resource["records"]
            if row["inputKind"] == "hashXof"
            and row["validInputBytesMin"] == "0"
        ]
        self.assertGreater(len(zero_byte_hash), 0)
        self.assertTrue(all(
            row["measuredModel"]["anchorInputBytes"] == "0"
            for row in zero_byte_hash))
        self.assertEqual(resource["approximationPolicy"]["warmupOperationsPerLogicalRun"], 1)
        self.assertEqual(
            [row["requestedIntervalMilliseconds"] for row in
             resource["approximationPolicy"]["samplingIntervalAssumptions"]],
            [1, 2, 3, 4])
        self.assertTrue(all(
            row["samplingIntervalMilliseconds"] == 5
            for row in resource["records"]))

    def test_explicit_metadata_changes_dataset_bytes(self) -> None:
        baseline = GENERATOR.generate(self._request("metadata-a", "1.0.0-test"))
        changed = GENERATOR.generate(self._request("metadata-b", "1.0.1-test"))
        self.assertNotEqual(
            baseline["resourcePath"].read_bytes(),
            changed["resourcePath"].read_bytes())
        self.assertNotEqual(baseline["resourceSha256"], changed["resourceSha256"])

    def test_source_hash_mismatch_fails_before_output(self) -> None:
        altered = self.root / "altered-evidence"
        altered.mkdir()
        for name in GENERATOR.EXPECTED_SOURCE_SHA256:
            shutil.copyfile(self.evidence_directory / name, altered / name)
        campaign_plan = altered / GENERATOR.CAMPAIGN_PLAN
        campaign_plan.write_bytes(campaign_plan.read_bytes() + b"\n")
        output = self.root / "must-not-be-created"
        request = GENERATOR.GenerationRequest(
            altered,
            self.inventory_writer,
            output,
            "2026-11-01T14:00:00.000Z",
            "cryptobenchmark-m23-pragmatic-test",
            "1.0.0-test",
        )
        with self.assertRaises(GENERATOR.DatasetError):
            GENERATOR.generate(request)
        self.assertFalse(output.exists())

    def test_checked_m22_rounding_occurs_after_n_scaling(self) -> None:
        round_after_n = GENERATOR.round_operation_picoseconds_to_ns_after_n
        self.assertEqual(round_after_n(600, 2), 1)
        self.assertEqual(round_after_n(1250, 2), 3)
        self.assertEqual(round_after_n(499, 1), 0)
        with self.assertRaises(GENERATOR.DatasetError):
            round_after_n(GENERATOR.MAX_U64, 1_000_000_000)

    def test_candidate_loads_through_actual_cpp_parser(self) -> None:
        generated = GENERATOR.generate(self._request("parser-candidate"))
        source = GENERATOR.read_json(
            self.evidence_directory / GENERATOR.NIGHT_RESULT)
        environment = source["entries"][0]["environment"]
        completed = subprocess.run(
            [
                str(self.parser_test_executable),
                "--candidate",
                str(generated["resourcePath"]),
                "--sha256",
                generated["resourceSha256"],
                "--os",
                environment["operatingSystem"],
                "--architecture",
                environment["architecture"],
                "--openssl",
                environment["opensslVersion"],
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
            timeout=30,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("Loaded", completed.stdout)
        self.assertIn("Corrupt", completed.stdout)
        self.assertIn("Inapplicable", completed.stdout)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--inventory-plan-writer", required=True, type=Path)
    parser.add_argument("--parser-test-executable", required=True, type=Path)
    options = parser.parse_args(argv)
    PragmaticDatasetTests.options = options
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(PragmaticDatasetTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
