# M23 pragmatic ETA dataset candidate (DATA1)

This note documents the deterministic, real-data-derived `m23-pragmatic-1`
candidate generated for review. It is **not** an installed production resource,
does not activate a provider/GUI ETA, and does not claim end-to-end Batch
qualification. No new benchmark observations were performed.

## Immutable evidence and provenance

The generator pins and rechecks every input SHA-256 before parsing:

| Input | SHA-256 |
|---|---|
| `M23_NIGHT_result.json` | `9d4c3f61fbda8df095e758f2b0a7462aa3ed8f84959c380f6d0b5b021dbb3f52` |
| `M23_HIANYZO_5ms_239_result.json` | `e887fdf3ce4338fbdef2f26a9fef0fe936482a727b8d28c838d16d85007280d2` |
| `CryptoBenchmark_EJSZAKAI_563_M10_BECSESI_MANIFESZT.json` | `c35e832ffec5af33fc489a2b93a6d8198a80590001c7c41a35530c297b3d4748` |
| `M23_ETA_175_OFFLINE_MODELLJELÖLT_2026-11-01.json` (cross-check only) | `da8b7756a3f40125c745a49d0e8068a5025c7b220f69b8f3db00435e1a1d3a49` |
| `M23_ETA_291_FUGGETLEN_MERET_HOLDOUT_2026-11-01.csv` (cross-check only) | `4c58f8bbc81688d7a66a79ac162514111a8d7d9be59993af6d8a1909615407b6` |
| `CryptoBenchmark_EJSZAKAI_SZELSESSZAV_FELMERES_563_M10_MAX1MiB(1).json` (campaign plan) | `ff68c6fb3a121aaa9f4e969df8b524b625ce1362d3b1689a1aae7f4c9902e9b4` |

The live C++ inventory is obtained by invoking the existing
`CryptoBenchmarkM23CalibrationTests.exe --write-candidate-plan` command. The
writer emits 2,505 non-authorizing plan rows; its `inventorySha256` is
`1fcc10b1d78b45556cf3989125228799952b0bc11aae2c0953401e3b9b090cf1`.
The generator validates all 175 unique typed cases and the 78/97 fixed/variable
split against that plan. It does not derive identities from the offline model
candidate.

Both result files contain completed schema-v2 Batch results with Memory v2,
fresh-worker-per-logical-run, 5 ms sampling, Release, Windows 11 Version 25H2,
x86_64, application version `0.1.0`, source Git commit
`21a21ad2cf51c3c93fdc290a32b0f6cb6e6e7a2f`, and OpenSSL 3.6.5. The 563-entry
split is 369 references and 194 size holdouts. The supplemental file contributes
97 256 MiB references and 97 16 MiB holdouts. The remaining 45 supplemental
entries excluded from fitting and validation are 17 `nmhold`, 14 `probe16m`,
1 `p256canary`, and 13 `p256pilot`. `sourcePerOperationNs` and N/M planning
heuristics in the split manifest are not used as observations; the primary
observation is each completed raw result's
`wallClockNanosecondsPerOperation.median`.

The campaign preflight did not record worker/app executable hashes, Qt/compiler
versions, CPU, RAM or power plan. The historical preflight JSON is absent. Those
seven schema fields are therefore `null`, each paired with
`notRecordedInCampaignEvidence`; no current-machine values are substituted.
`calibrationProtocolId` is the documented inference
`memory-v2-calibration-v1` from the reviewed runtime and measurement settings,
not a field copied from the raw result JSON.

## Fit/holdout separation and integer quantization

Training consists only of:

- 369 original manifest entries labeled `reference`;
- 97 supplemental `m23256m-*` 256 MiB references.

This gives 466 source rows: 78 fixed-input identities have one reference each;
97 variable-size identities have minimum legal size, 4 KiB, 1 MiB and 256 MiB
references. Only the minimum-size and 256 MiB medians determine the affine
coefficients. The 4 KiB and 1 MiB points are independent-of-fit sanity
diagnostics, not coefficient inputs.

The independent size holdouts are:

- 194 original manifest entries labeled `holdout`;
- 97 supplemental `m2316m-*` 16 MiB entries.

The 17 N/M rows and other 28 controls/probes from the supplemental result are
not used for fitting or size holdout statistics. The previous 175-case JSON and
291-row CSV are only source/identity/metric cross-checks.

For each fixed-input case the generator uses the reference median per-operation
nanoseconds and quantizes `medianNs * 1000` to a positive integer
picoseconds-per-operation. For each variable-size case it computes the
nonnegative anchored slope from the actual minimum and 256 MiB reference
medians, then independently quantizes the anchor and slope to integer
picoseconds. Quantization uses exact rational arithmetic with nearest-integer,
ties-round-half-up. The size-domain endpoint prediction is checked for uint64
picosecond overflow.

Holdout prediction is calculated from the final quantized coefficients as exact
`predictedPicoseconds / 1000` nanoseconds and compared with the original
per-operation median. Neither prediction nor observation is prematurely
rounded to an integer nanosecond. Factor errors are exact rational values;
displayed decimals are rounded to 12 places, while numerator/denominator are
also preserved. Median, nearest-rank P90/P95, maximum and worst row are reported.
The 1–4 ms context assumption is separate from the single measured 5 ms context.

## DATA1 output and validation

Generation arguments used for this candidate:

```text
datasetId       cryptobenchmark-m23-pragmatic-2026-11-01-data1
datasetVersion  0.1.0-pragmatic.1
generatedAtUtc  2026-11-01T14:42:46.388Z
```

Private output directory:
`.dev-private/review-bundles/M23.3-DATA1/artifacts/`

| Output | SHA-256 |
|---|---|
| `candidate-runtime-calibration-v1.json` | `d3f2cd021afebf742414ea7bf2a42aae99803ced8e9fef2f220c034d86d46129` |
| `holdout-validation-report.json` | `2c6ad3f3553d4a8aaa09db322d7d28347f5219507f084f4c5e7a0bfafe15435c` |

Post-quantization 291-holdout factor results:

| Statistic | Factor |
|---|---:|
| Median | 1.002893694415× |
| P90 (nearest rank) | 1.032926489102× |
| P95 (nearest rank) | 1.047109330605× |
| Maximum | 1.259366478733× |
| Worst row | `on26-c149-hold-64k` |
| Greater than 1.1× / 1.25× / 1.5× | 6 / 1 / 0 |

Input-size diagnostics: 1-byte holdout maximum 1.060889950531× (19 rows);
64-byte maximum 1.056537950891× (78 rows); 64 KiB maximum 1.259366478733×
(97 rows); 16 MiB maximum 1.057710062088× (97 rows). The 19 legal zero-byte
Hash/XOF anchors are listed in the report. Training sanity-point maximum
factors are 1.162449996218× at 4 KiB and 1.246354722810× at 1 MiB; the
quantized 256 MiB endpoint maximum is 1.002846620264×. The complete 291-row
table, all 194 4 KiB/1 MiB sanity diagnostics, and 97 256 MiB endpoint checks
are in the private report.

The prior floating-point candidate's maximum factor (about 1.260802×) is shown
only as a cross-check; its coefficients and predicted values are not used for
training. Neither these size holdouts nor the reduced-scope status qualify
end-to-end Batch ETA. Waived overhead, sampling-comparison and 12-Batch gates
are **not claimed as passed**.

The candidate was parsed by the committed C++ loader from its private path:
correct expected SHA → `Loaded`; wrong SHA → `Corrupt`; incompatible OpenSSL
context → `Inapplicable`. The source
`calibration/runtime-calibration-v1.json` and both executable-relative staged
resource paths remain absent. The candidate must not be copied there until a
separate review authorizes installation.

## Reproduction

Use the unchanged evidence directory, a Release build's existing C++ plan
writer, a fresh private output directory, and the same explicit metadata:

```powershell
$EvidenceDir = Read-Host 'Path to the verified read-only M23 evidence directory'
python -B .\tools\m23-eta-dataset-generator.py `
  --evidence-dir $EvidenceDir `
  --inventory-plan-writer '.\build-m23-release\test-runtime\CryptoBenchmarkM23CalibrationTests.exe' `
  --output-dir '.dev-private\review-bundles\M23.3-DATA1\reproduction-2026-11-01' `
  --generated-at-utc '2026-11-01T14:42:46.388Z' `
  --dataset-id 'cryptobenchmark-m23-pragmatic-2026-11-01-data1' `
  --dataset-version '0.1.0-pragmatic.1'
```

Run deterministic and parser integration tests without benchmarks:

```powershell
$EvidenceDir = Read-Host 'Path to the verified read-only M23 evidence directory'
python -B .\tools\m23-eta-dataset-tests.py `
  --evidence-dir $EvidenceDir `
  --inventory-plan-writer '.\build-m23-release\test-runtime\CryptoBenchmarkM23CalibrationTests.exe' `
  --parser-test-executable '.\build-m23-release\test-runtime\CryptoBenchmarkM23PragmaticDatasetTests.exe'
```

The output directory must be new. The generator permits a private
`.dev-private/review-bundles` output or an external directory, rejects the
tracked `calibration` location and executable `bin` paths, and does not stage
the candidate.
