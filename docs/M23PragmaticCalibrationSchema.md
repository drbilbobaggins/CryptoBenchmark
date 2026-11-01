# M23 pragmatic calibration resource schema

The resource keeps the existing `format` (`cryptobenchmark-runtime-calibration`),
`schemaVersion: 1`, executable-relative path, 16 MiB limit, compiled expected
SHA-256 check, strict UTF-8/JSON preflight, and registry/environment checks.
`modelSchemaVersion` dispatches to one of two independent exact-key dialects:

- `m23.1-provisional-1`: unchanged legacy validation and typed representation.
- `m23-pragmatic-1`: the reduced-scope per-operation representation below.

The parser rejects unknown versions and does not share permissive key sets
between dialects. This schema change does not add a resource file or activate a
provider or ETA.

## Pragmatic root

The pragmatic root contains the existing v1 provenance fields, `records`,
`batchOverheadModels`, and these exact additional fields:

```text
sourceEvidenceSha256
provenanceMissingReasons
approximationPolicy
```

The exact pragmatic root keys are:

```text
format, schemaVersion, datasetId, datasetVersion, generatedAtUtc,
calibrationProtocolId, modelSchemaVersion, generatorVersion, sourceGitCommit,
referenceAppVersion, referenceBuildType, referenceWorkerSha256,
referenceAppSha256, opensslVersion, qtVersion, compilerId, os, architecture,
referenceCpu, referenceRamBytes, powerPlan, registryInventorySha256,
campaignPlanSha256, rawEvidenceManifestSha256, holdoutReportSha256,
qualificationStatus, qualificationSummary, qualifiedRuntimeContexts,
sourceEvidenceSha256, provenanceMissingReasons, approximationPolicy,
records, batchOverheadModels
```

`qualifiedRuntimeContexts` contains one object with exactly
`os`, `architecture`, `buildType`, `opensslVersion`, `calibrationProtocolId`,
and `samplingIntervalMilliseconds`.

`qualificationStatus` is exactly `reducedScopeApproximate`. This means the
user-approved approximate scope only; it does not mean full M23 end-to-end
qualification. `batchOverheadModels` remains an empty array.

`sourceEvidenceSha256` has exactly three lowercase SHA-256 members:

```json
{
  "nightResultSha256": "<hash of M23_NIGHT_result.json>",
  "supplementalResultSha256": "<hash of M23_HIANYZO_5ms_239_result.json>",
  "splitManifestSha256": "<hash of the 563-entry split manifest>"
}
```

The root `rawEvidenceManifestSha256` must equal `splitManifestSha256`.
`campaignPlanSha256`, `holdoutReportSha256`, and `registryInventorySha256`
remain required lowercase SHA-256 strings; the registry digest must match the
live canonical inventory. `calibrationProtocolId` is the fixed
`memory-v2-calibration-v1` value inferred from the reviewed Memory v2 runtime
and measurement settings; the historical result records do not directly record
that identifier. It is not presented as a copied campaign field.

`qualifiedRuntimeContexts` contains exactly one measured context at 5 ms,
matching the source OS, architecture, Release build, OpenSSL version and
calibration protocol. Records also use only 5 ms. The 1–4 ms assumptions are
not measured contexts and must not be added to that array.

## Per-operation records

Both shapes retain the canonical `profileId`, stable `operation`, typed
`inputKind`, 5 ms sampling interval, evidence and holdout subset hashes, and
`modelQualificationStatus`. The parser requires exactly one record for each
live inventory case: 78 fixed-input and 97 variable-size records.

Fixed-input records have exactly these keys:

```text
profileId, operation, inputKind, samplingIntervalMilliseconds, measuredModel,
evidenceSubsetSha256, holdoutSubsetSha256, modelQualificationStatus
```

Variable-size records have exactly these keys:

```text
profileId, operation, inputKind, samplingIntervalMilliseconds, measuredModel,
validInputBytesMin, validInputBytesMax, evidenceSubsetSha256,
holdoutSubsetSha256, modelQualificationStatus
```

Fixed-input records use:

```json
{
  "measuredModel": {
    "kind": "constantPerOperation",
    "picosecondsPerOperation": "1200"
  },
  "modelQualificationStatus": "perOperationReferenceFitOnly"
}
```

The value is a derived per-operation reference statistic, not a measured
`referenceN` or measured N-run block.

Variable-size records use:

```json
{
  "validInputBytesMin": "1",
  "validInputBytesMax": "268435456",
  "measuredModel": {
    "kind": "anchoredAffinePerOperation",
    "anchorInputBytes": "1",
    "anchorPicosecondsPerOperation": "1200",
    "slopePicosecondsPerBytePerOperation": "2"
  },
  "modelQualificationStatus": "perOperationReferenceFitSizeHoldoutOnly"
}
```

The minimum is exactly 1 byte for message/AEAD, or 0 bytes for Hash/XOF; the
maximum is the canonical 256 MiB limit. The anchor must equal the minimum.
Coefficients are canonical unsigned decimal strings. The parser checks the
predicted picosecond value at the maximum input size for unsigned 64-bit
overflow. No holdout value is stored as a coefficient or fitted reference.

`perOperationReferenceFitOnly` and
`perOperationReferenceFitSizeHoldoutOnly` describe per-operation evidence
scope only; neither claims end-to-end ETA qualification.

## Approximation policy

`approximationPolicy` has exactly:

```json
{
  "warmupOperationsPerLogicalRun": 1,
  "fixedEntryOverhead": {
    "nanoseconds": "0",
    "status": "assumedUnmeasured"
  },
  "batchOverhead": {
    "nanoseconds": "0",
    "status": "assumedUnmeasured"
  },
  "samplingIntervalAssumptions": [
    {"requestedIntervalMilliseconds": 1, "sourceMeasuredIntervalMilliseconds": 5, "status": "assumedFrom5ms"},
    {"requestedIntervalMilliseconds": 2, "sourceMeasuredIntervalMilliseconds": 5, "status": "assumedFrom5ms"},
    {"requestedIntervalMilliseconds": 3, "sourceMeasuredIntervalMilliseconds": 5, "status": "assumedFrom5ms"},
    {"requestedIntervalMilliseconds": 4, "sourceMeasuredIntervalMilliseconds": 5, "status": "assumedFrom5ms"}
  ]
}
```

The parser accepts only one warm-up, explicit zero assumptions with the exact
`assumedUnmeasured` tag, and the four ordered 1–4 ms assumptions sourced from
measured 5 ms. The assumption tags never turn these values into observations.
`batchOverheadModels` stays empty and does not encode zero overhead.

The context distinction is explicit in the JSON:

```json
{
  "qualifiedRuntimeContexts": [{
    "os": "Windows 11 Version 25H2",
    "architecture": "x86_64",
    "buildType": "Release",
    "opensslVersion": "3.6.5",
    "calibrationProtocolId": "memory-v2-calibration-v1",
    "samplingIntervalMilliseconds": 5
  }],
  "approximationPolicy": {
    "warmupOperationsPerLogicalRun": 1,
    "fixedEntryOverhead": {"nanoseconds": "0", "status": "assumedUnmeasured"},
    "batchOverhead": {"nanoseconds": "0", "status": "assumedUnmeasured"},
    "samplingIntervalAssumptions": [
      {"requestedIntervalMilliseconds": 1, "sourceMeasuredIntervalMilliseconds": 5, "status": "assumedFrom5ms"},
      {"requestedIntervalMilliseconds": 2, "sourceMeasuredIntervalMilliseconds": 5, "status": "assumedFrom5ms"},
      {"requestedIntervalMilliseconds": 3, "sourceMeasuredIntervalMilliseconds": 5, "status": "assumedFrom5ms"},
      {"requestedIntervalMilliseconds": 4, "sourceMeasuredIntervalMilliseconds": 5, "status": "assumedFrom5ms"}
    ]
  }
}
```

Only the 5 ms object is a measured/qualified context. The sampling assumption
array is inside `approximationPolicy`; it does not add more contexts or records.

## Historical provenance nulls

Only these seven historical fields may be null:

```text
referenceWorkerSha256
referenceAppSha256
qtVersion
compilerId
referenceCpu
referenceRamBytes
powerPlan
```

Every null must have a matching entry in `provenanceMissingReasons`, whose
value is exactly `notRecordedInCampaignEvidence`. That object must contain
exactly the set of null historical fields—no missing reason for a populated
field, no unpaired null, and no unknown key. Recorded hashes and RAM retain
their normal strict format/range checks. Required source Git, app version,
Release, OS/architecture, OpenSSL, protocol, input/manifests, inventory and
report provenance cannot be null.

Synthetic example only (hashes are deliberately not production evidence):

```json
{
  "referenceAppSha256": null,
  "referenceRamBytes": null,
  "provenanceMissingReasons": {
    "referenceAppSha256": "notRecordedInCampaignEvidence",
    "referenceRamBytes": "notRecordedInCampaignEvidence"
  }
}
```

## Arithmetic and lifecycle boundaries

All model coefficients and workload bounds are exact integers. The schema
stores per-operation picoseconds; it does not invent a measured block,
reference N, warm-up timing, or overhead measurement. A future provider must
use checked arithmetic and the M22 nearest-nanosecond rounding rule when
converting/scaling modeled values. Production provider wiring, sampling
assumption resolution, GUI presentation, and ETA activation are later work.

The provisional dialect retains its original model tags, required provenance,
`unqualified` statuses, exact key sets, context handling and rejection
behavior.
