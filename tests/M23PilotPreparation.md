# M23.2-PREP: pilot plan, safe observation path, and offline analysis

For the separately reviewed M23.2-EXEC selection and operator-session safety
package, see [M23PilotExecutionGuide.md](./M23PilotExecutionGuide.md).

## Status and authorization

This is preparation only. The generated plan has
`measurementAuthorized: false`; no human pilot GO is recorded or inferred by
these tools. CTest, the dry-run commands, and the synthetic analyzer do not
start a worker. The legacy M23.1 `--observe-once` route is disabled. No pilot,
full-campaign, or feasibility observation is authorized here.

The candidate plan is separate from the M23.1 2,505-row plan and has its own
format/version and SHA-256. It is generated from the existing typed registry
inventory and stable operation strings; startup fails if any of the twelve
specified profile/operation/input-kind identities is absent or illegal.

## Twelve canonical case types

| # | Stable typed case ID | Purpose |
|---:|---|---|
| 01 | `rsa-3072-keygen/keyGen/noSignature` | Costly fixed KeyGen |
| 02 | `rsa-pss-3072-sha256/sign/prehashed` | Fixed signature input |
| 03 | `rsa-pss-3072-sha256/verify/message` | Verification plus message processing |
| 04 | `ed25519/sign/message` | EdDSA variable message |
| 05 | `ml-dsa-65/sign/message` | PQC variable message |
| 06 | `slh-dsa-sha2-128s/sign/message` | Higher-cost PQC signature |
| 07 | `x25519/derive/keyEstablishment` | XDH fixed workload |
| 08 | `ml-kem-768/decapsulate/keyEstablishment` | KEM fixed workload |
| 09 | `aes-256-gcm/encrypt/aead` | AEAD encryption |
| 10 | `aes-256-gcm/decrypt/aead` | AEAD decryption |
| 11 | `sha256/hash/hashXof` | Streaming hash, including zero bytes |
| 12 | `shake256-64bytes/xof/hashXof` | Fixed-output XOF |

These are validated against `AlgorithmRegistry`, `InputCapability`, the stable
operation formatter, and `ConfigValidator`; they are not display-name keys.

## Candidate reference/holdout and sensitivity matrix

The default workload grid uses 3 repeats at 5 ms, N=1 and M=1:

- Message and AEAD: reference sizes 1 B, 4 KiB, 1 MiB; independent holdouts
  64 B and 64 KiB.
- Hash/XOF: reference sizes 0 B, 4 KiB, 1 MiB; independent holdouts 1 B and
  64 KiB.
- Fixed/no-size: reference N=1 and holdout N=2, with three planned repeats.
  The RSA-3072 KeyGen N=2 row remains deferred until a separate feasibility
  review.

Additional candidate sensitivity rows:

- **N:** RSA-PSS prehashed Sign N=2; X25519 Derive N=10; ML-KEM Decapsulate
  N=2; Ed25519 Sign at 4 KiB N=10; SHA-256 Hash at 4 KiB N=100.
- **M:** X25519 M=3; SHA-256 M=3 and M=10; AES-256-GCM Encrypt M=3.
- **Sampling:** 1–4 ms on SHA-256 Hash and ML-DSA-65 Sign at 4 KiB, compared
  with each case's 5 ms reference.
- **Batch E-shapes:** ordered SHA-256 Hash entries at E=1 and E=3 are initial
  candidates; E=10 and E=20 are explicitly deferred pending checkpoint-growth
  and resource review. The harness executes each shape as one multi-entry
  `BatchController` run, not as unrelated one-entry Batches.

The initial executable workload cap is 1 MiB. Every 16 MiB and 256 MiB point
is deferred; they are not hidden in the initial plan. RSA KeyGen N=2,
SLH-DSA N=10, E=10 and E=20 are also deferred. Deferred rows cannot be selected
by the approved-plan execution path. A later feasibility decision would need a
new reviewed plan revision; this preparation does not silently expand the plan.

The fixed-seed ordering is deterministic. Each row records a stable row ID,
typed case, role, probe kind, exact workload bytes (or no-size), N, M,
sampling interval, repetition, order, risk class, hypothesis, and candidate or
deferred status. The current manifest contains 158 candidate observation rows,
3 deferred rows, and 4 Batch shapes (E=1 and E=3 candidates; E=10 and E=20
deferred). Its SHA-256 is
`f38e4d0cdeee79fbfe0f68876d5a6fb15bbcd92bd5a2e7cb8df9b524657a34fc`.
The plan and dry-run report contain no durations. A candidate row is one
observation opportunity, not an instruction to execute the entire matrix.

## Non-observing plan and analyzer commands

These commands are safe before any human GO:

```powershell
& .\build-m23-debug\test-runtime\CryptoBenchmarkM23CalibrationTests.exe `
  --dry-run-pilot-plan

& .\build-m23-debug\test-runtime\CryptoBenchmarkM23CalibrationTests.exe `
  --write-pilot-plan C:\external\m23-pilot-candidate.json

& .\build-m23-debug\test-runtime\CryptoBenchmarkM23CalibrationTests.exe `
  --analyze-synthetic-pilot
```

`--write-pilot-plan` writes only the separate `CANDIDATE_ONLY_NOT_AUTHORIZED`
plan. The synthetic report is labeled `SYNTHETIC / NOT QUALIFIED`; its test
fixtures exist only in memory. The analyzer can also process a set of approved
pilot evidence files offline and writes a new report:

```powershell
& .\build-m23-release\test-runtime\CryptoBenchmarkM23CalibrationTests.exe `
  --analyze-pilot `
  --evidence C:\external\m23-pilot-evidence-1.json `
  --evidence C:\external\m23-pilot-evidence-2.json `
  --report C:\external\m23-pilot-analysis.json
```

The analyzer validates evidence status, exact candidate-plan rows, typed
context, provenance hashes, fresh worker identities, B/R/entry/Batch timing,
checkpoint ownership, and checksums before computing candidate diagnostics.
It fits `t(s)=a+b*s` from reference-only rows, evaluates independent holdouts
without reusing them in the fit, checks fixed-mode N scaling, reports M and
sampling sensitivity, and computes constant/per-entry/triangular Batch-count
candidate summaries. It always reports model selection as deferred and
`PENDING HUMAN REVIEW`; a pilot report is not a production dataset or ETA.
The conservative factor-5 holdout screen is diagnostic only.

## Approved-plan wrapper and deferred observation command

Only after a distinct, independent human M23.2 pilot GO, create an approved
JSON wrapper around the unchanged candidate plan. It must contain exactly
these fields: `format` = `cryptobenchmark-m23-approved-pilot-plan`,
`schemaVersion` = `1`, `candidatePlanSha256` = the generated candidate-plan
SHA-256, `approvalStatus` = `GO`, `approvalReference` = the human review
reference, `approvedAtUtc` = a UTC timestamp, and `plan` = the complete
candidate-plan JSON object (not a string). The runtime validator rejects any
modified plan row, a synthetic approval, an invalid timestamp, an absent GO,
or a candidate-plan SHA mismatch. A GO for the full/reference campaign does
not authorize the pilot.
These shape/reference checks are safety guards, not cryptographic proof of
human authorization. Evidence validation also rejects the obvious
`SYNTHETIC` approval-reference prefix when evidence claims to be real.

The `--approved-plan-sha256` CLI argument below is a separate SHA-256 of the
exact approved-wrapper file bytes. The operator must select and record no more
than 30 WorkerRunSession observations across the pilot; this is a proposed
aggregate cap, not enforced across separate invocations. The 158 candidate
rows are not all to be run under that cap. Each invocation accepts one exact
candidate row or one E-shape group, and the operator must maintain the
cumulative count and stop before exceeding the cap.

**NOT AUTHORIZED IN M23.2-PREP — DO NOT RUN.** A separate human pilot GO is
required first. This is the exact future multi-entry command shape; the hash
and approval reference below are placeholders, not authorization:

```powershell
& .\build-m23-release\test-runtime\CryptoBenchmarkM23CalibrationTests.exe `
  --observe-pilot-batch `
  --approved-plan C:\external\m23-approved-pilot.json `
  --approved-plan-sha256 0000000000000000000000000000000000000000000000000000000000000000 `
  --batch-id batch-e3-sha256 `
  --output-dir C:\external\m23-pilot-e3-run-001 `
  --i-confirm-m23-2-go
```

The observer accepts only an exact candidate group from the approved plan. It
requires Release, a clean Git worktree whose commit matches the executable's
BuildInfo, valid app/worker identities, at least 512 MiB free disk and available
physical memory, and a new absolute output directory outside the repository.
It executes one approved group per invocation. It does not loop over the plan,
adapt N/M, probe deferred points, or run from CTest/startup/GUI.

### Observation timing ownership

- B remains the worker-reported canonical measured block. No timer or callback
  is added inside it.
- R remains the WorkerRunSession lifecycle from immediately before
  `WorkerRunSession::start()` through its terminal completed signal.
- Each entry starts on the existing `BatchController::progressChanged`
  RunningEntry edge (after the initial checkpoint and before executor start)
  and ends on the persistence-in-progress edge after executor completion,
  before that entry's checkpoint is written.
- Batch time begins immediately before `BatchController::start` and ends in
  terminal `batchFinished` after final persistence.
- The observer derives the disjoint Batch-only complement intervals before,
  between, and after entry intervals. Initial, intermediate, and final
  `SnapshotPersister` write timings are nested diagnostic subdivisions of
  those intervals and are never added a second time.
- Evidence enforces `entryElapsed = sum(R) + entryOutsideRun` and
  `batchElapsed = sum(entryElapsed) + batchOnly`; each checkpoint interval
  must lie wholly inside its expected Batch-only interval. Any timeout,
  cancellation, missing checkpoint, overlap, or conservation failure produces
  incomplete evidence with no success marker.

The observer requests cancellation after 15 minutes for one Batch; candidate
rows and executable E-shapes are bounded to E<=3, N<=100, M<=10, and 1 MiB per
workload, with 512 MiB free disk and available-memory preflight. E=10/20,
16/256 MiB workloads, and other listed high-cost probes are deferred. Cleanup
may outlast the cancellation request; such a run remains incomplete and is
never accepted. These are proposed pilot caps, not final campaign limits.
Proposed aggregate operator cap: 30 WorkerRunSession observations and four
wall-clock hours for the entire pilot, with a pause/review after each case
family; neither aggregate cap can be enforced across separate invocations.

## Evidence archive proposal and remaining decisions

Before any pilot GO, the operator should approve an encrypted, access-controlled
location outside the repository and agree retention. Proposed retention is
through M24 qualification plus 12 months. Preserve original raw observations,
approval wrapper, app/worker/environment hashes, and the analyzer report with a
SHA-256 manifest; do not copy raw evidence into the repository or create the
archive directory during preparation.

The pilot must decide (with measured evidence) whether sampling contexts can
be pooled, whether affine fits are adequate, whether additional holdout repeats
or size feasibility checks are needed, and which Batch-overhead representation
to take forward. No model is selected here. The full campaign GO, 16/256 MiB
feasibility, E=10/20 expansion, archive location/retention approval, and
production schema/provider/ETA remain pending.
