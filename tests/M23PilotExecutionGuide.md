# M23.2-EXEC controlled pilot execution package

## Status: preparation only

**NO MEASUREMENT GO IS GRANTED. NO REAL OBSERVATION IS AUTHORIZED OR PERFORMED BY THIS TASK.**
The proposed selection remains `PROPOSED_NOT_APPROVED` with
`measurementAuthorized: false`. Its approval-reference allowlist is empty, so
the runner rejects every execution attempt until a separately reviewed human
decision updates the selection and its pinned SHA. No approved wrapper,
archive directory, or production calibration resource is created here.

The package is a test-only operator tool. It does not change benchmark timing,
Batch/worker behavior, M22 APIs, result schemas, or production ETA wiring.

## Proposed fixed selection

The runner obtains the committed M23.2 candidate plan through the harness's
read-only `--dry-run-pilot-plan` command and resolves every row by the complete
canonical tuple: typed case ID, role, probe kind, exact byte-size/null,
`iterationsPerRun` (N), `runs` (M), sampling interval, repetition 1, and
candidate status. Every selector must match exactly one plan row and its
resolved row ID must equal the selected ID below. Batch groups resolve by
exact `batchId` and candidate status. No random-plan `order` is used as the
operator sequence; the table ordinal is the proposed sequence.

The frozen candidate plan identity is
`f38e4d0cdeee79fbfe0f68876d5a6fb15bbcd92bd5a2e7cb8df9b524657a34fc`.
The pinned proposed-selection SHA-256 is
`0c62c74be9a33143011a9dbe3cf4924df28e261dc0d1cc1e8167a188ee4160bf`.
The separate M23.1 2,505-row plan is not selected or executed.

| Ordinal | Selected row ID / Batch ID | Case and selector | Logical runs |
|---:|---|---|---:|
| 1 | `pilot-sha256-hash-hashxof-workloadSize-reference-s4096-n1-m1-t5-r1` | SHA-256 Hash, reference, 4096 B, N=1, M=1, 5 ms | 1 |
| 2 | `pilot-x25519-derive-keyestablishment-fixed-n-reference-snone-n1-m1-t5-r1` | X25519 Derive, reference, no size, N=1, M=1, 5 ms | 1 |
| 3 | `pilot-aes-256-gcm-encrypt-aead-workloadSize-reference-s4096-n1-m1-t5-r1` | AES-256-GCM Encrypt, reference, 4096 B, N=1, M=1, 5 ms | 1 |
| 4 | `pilot-aes-256-gcm-decrypt-aead-workloadSize-reference-s4096-n1-m1-t5-r1` | AES-256-GCM Decrypt, reference, 4096 B, N=1, M=1, 5 ms | 1 |
| 5 | `pilot-ed25519-sign-message-workloadSize-reference-s4096-n1-m1-t5-r1` | Ed25519 Sign, reference, 4096 B, N=1, M=1, 5 ms | 1 |
| 6 | `pilot-ml-kem-768-decapsulate-keyestablishment-fixed-n-reference-snone-n1-m1-t5-r1` | ML-KEM-768 Decapsulate, reference, no size, N=1, M=1, 5 ms | 1 |
| 7 | `pilot-rsa-pss-3072-sha256-sign-prehashed-fixed-n-reference-snone-n1-m1-t5-r1` | RSA-PSS-3072/SHA-256 Sign, prehashed, reference, N=1, M=1, 5 ms | 1 |
| 8 | `pilot-rsa-pss-3072-sha256-verify-message-workloadSize-reference-s4096-n1-m1-t5-r1` | RSA-PSS-3072/SHA-256 Verify, message, reference, 4096 B, N=1, M=1, 5 ms | 1 |
| 9 | `pilot-ml-dsa-65-sign-message-workloadSize-reference-s4096-n1-m1-t5-r1` | ML-DSA-65 Sign, reference, 4096 B, N=1, M=1, 5 ms | 1 |
| 10 | `pilot-shake256-64bytes-xof-hashxof-workloadSize-reference-s4096-n1-m1-t5-r1` | SHAKE256-64B XOF, reference, 4096 B, N=1, M=1, 5 ms | 1 |
| 11 | `pilot-rsa-3072-keygen-keygen-nosignature-fixed-n-reference-snone-n1-m1-t5-r1` | RSA-3072 KeyGen, reference, no size, N=1, M=1, 5 ms | 1 |
| 12 | `pilot-slh-dsa-sha2-128s-sign-message-workloadSize-reference-s1-n1-m1-t5-r1` | SLH-DSA-SHA2-128s Sign, reference, 1 B, N=1, M=1, 5 ms | 1 |
| 13 | `pilot-sha256-hash-hashxof-workloadSize-reference-s0-n1-m1-t5-r1` | SHA-256 Hash, reference, 0 B, N=1, M=1, 5 ms | 1 |
| 14 | `pilot-sha256-hash-hashxof-workloadSize-reference-s1048576-n1-m1-t5-r1` | SHA-256 Hash, reference, 1 MiB, N=1, M=1, 5 ms | 1 |
| 15 | `pilot-sha256-hash-hashxof-workloadSize-holdout-s65536-n1-m1-t5-r1` | SHA-256 Hash, holdout, 64 KiB, N=1, M=1, 5 ms | 1 |
| 16 | `pilot-aes-256-gcm-encrypt-aead-workloadSize-reference-s1-n1-m1-t5-r1` | AES-256-GCM Encrypt, reference, 1 B, N=1, M=1, 5 ms | 1 |
| 17 | `pilot-aes-256-gcm-encrypt-aead-workloadSize-reference-s1048576-n1-m1-t5-r1` | AES-256-GCM Encrypt, reference, 1 MiB, N=1, M=1, 5 ms | 1 |
| 18 | `pilot-aes-256-gcm-encrypt-aead-workloadSize-holdout-s65536-n1-m1-t5-r1` | AES-256-GCM Encrypt, holdout, 64 KiB, N=1, M=1, 5 ms | 1 |
| 19 | `pilot-x25519-derive-keyestablishment-runCountSensitivity-sensitivity-snone-n1-m3-t5-r1` | X25519 Derive, sensitivity, no size, N=1, M=3, 5 ms | 3 |
| 20 | `batch-e1-sha256` | SHA-256 Hash, E=1 Batch shape, 4096 B, N=1, M=1 per entry, 5 ms | 1 |
| 21 | `batch-e3-sha256` | SHA-256 Hash, **one E=3 Batch**, 4096 B, N=1, M=1 per entry, 5 ms | 3 |
| 22 | `pilot-sha256-hash-hashxof-samplingSensitivity-sensitivity-s4096-n1-m1-t1-r1` | SHA-256 Hash, sensitivity, 4096 B, N=1, M=1, 1 ms | 1 |
| 23 | `pilot-ed25519-sign-message-iterationScaling-holdout-s4096-n10-m1-t5-r1` | Ed25519 Sign, holdout, 4096 B, N=10, M=1, 5 ms | 1 |

Totals: **23 distinct group invocations, 27 logical WorkerRunSession runs,
12 canonical typed case IDs**. Ordinals 1–12 cover all twelve cases. Ordinal
19 accounts for three X25519 logical runs. Ordinal 21 is one sequential
three-entry Batch, not three separate groups. The selection uses 27 of the
30-run ceiling; the remaining three are contingency only and are never
automatically scheduled. The selection excludes every deferred plan row,
E=10/E=20, and 16 MiB/256 MiB workloads.

This is a proposed limited entry tranche, not qualification of all twelve
cases, size models, holdouts, sampling pooling, Batch models, or a production
ETA.

## Harmless and non-observing commands

Run from the repository root in Windows PowerShell 5.1:

```powershell
& .\tools\m23-pilot-session.ps1
& .\tools\m23-pilot-session.ps1 -DryRun
& .\tools\m23-pilot-session-tests.ps1 -NonObserving
```

The default and explicit dry-run read the current Release harness's dry-run
plan, resolve the exact selected rows, print the plan and selection hashes,
and report `RESULT: PASS - NO OBSERVATIONS`. They do not create an archive,
ledger, output directory, approval wrapper, or worker process. The self-tests
use a temporary dummy PowerShell child tree only; they never invoke
`--observe-pilot-batch`, `--observe-once`, the Release harness observer mode,
or a CryptoBenchmark worker.

Read-only inspection is available only after a future operator-created
external archive root and ledger exist:

```powershell
& .\tools\m23-pilot-session.ps1 -InspectLedger `
  -ArchiveRoot 'D:\RestrictedEvidence\CryptoBenchmark-M23.2'
```

It does not create a root, lock, or ledger and refuses an active exclusive
session lock or an inconsistent ledger.

## Future execution gate — explicitly unapproved

**DO NOT RUN THIS SECTION NOW. No pilot GO has been granted.** Code acceptance,
merge, or an M23 preparation review does not grant measurement permission.
Before any real run, a separate human review must approve the exact 23-group
list, host/environment, resource cap, an operator-chosen restricted archive,
and an exact approval reference. The approval reference must be added to the
selection's reviewed `approvalReferenceAllowlist`; this changes the selection
file SHA and the runner's pinned selection SHA. Both require a separate source
review/commit and a matching `-SelectionSha256`. Do not modify the selection or
run the observer during M23.2-EXEC.

Future steps, after a distinct GO:

1. Commit and audit this code; keep the approved feature branch clean.
2. Select an existing external archive directory on a local fixed-volume
   drive. Mapped network drives, UNC paths, indeterminate drive types, and
   unavailable free-space information are rejected; at least 512 MiB must be
   free. Decide access restrictions and separate encryption/retention controls
   outside this script. The script does **not** encrypt data and does not claim
   encryption.
3. Generate an approved-plan wrapper manually from the frozen candidate plan.
   The wrapper contains exactly `format`,
   `schemaVersion`, `candidatePlanSha256`, `approvalStatus`, `approvalReference`,
   `approvedAtUtc`, and `plan`. `approvalStatus` must be `GO`; `plan` is the
   exact plan object. The script never creates this wrapper.
4. Configure a fresh Release build with the approved clean commit, then check
   `build-m23-release\CMakeCache.txt` says Release and generated `BuildInfo.h`
   commit matches clean Git HEAD. Hash the GUI and worker executables; the
   runner rechecks their hashes and Release provenance.
5. Execute **one ordinal only**, inspect and review its evidence/ledger, then
   explicitly decide whether to issue another command. The only future
   invocation shape is:

   ```powershell
   & .\tools\m23-pilot-session.ps1 -ExecuteNext `
     -Ordinal 1 `
     -ArchiveRoot 'D:\RestrictedEvidence\CryptoBenchmark-M23.2' `
     -ApprovedPlan 'D:\RestrictedEvidence\CryptoBenchmark-M23.2\approved-pilot.json' `
     -ApprovedPlanSha256 '<SHA-256 of exact approved wrapper bytes>' `
     -SelectionSha256 '<SHA-256 printed by DryRun after separately reviewed allowlist update>' `
     -ApprovalReference '<exact allowlisted human review reference>' `
     -IConfirmM232Go
   ```

   `-Ordinal` is the next explicit ordinal (1 through 23); there is no batch
   ID input, arbitrary group choice, automatic loop, retry, or escalation.
   Repeat only as a separate operator command after inspecting the preceding
   evidence and ledger. Do not copy/paste the example before GO; its values
   are placeholders and current selection allowlist is empty.

The C++ harness independently validates the exact approved wrapper, byte SHA,
candidate-plan identity, GO, timestamp, and selected candidate group before it
constructs the production Batch/BenchmarkController execution. The PowerShell
runner performs strict preflight as well and consumes a durable reservation
before launching that child. A rejected/failed launch consumes the reservation
conservatively; there is no retry path.

The following direct commands are **NOT AUTHORIZED and must not be run** in
this task. This includes deliberately invalid hashes/flags and hand-built
files; they still enter the C++ observation handler:

```powershell
& .\build-m23-release\test-runtime\CryptoBenchmarkM23CalibrationTests.exe `
  --observe-pilot-batch `
  --approved-plan '<external approved wrapper>' `
  --approved-plan-sha256 '<exact wrapper SHA-256>' `
  --batch-id '<selected canonical group only>' `
  --output-dir '<new external group directory>' `
  --i-confirm-m23-2-go

& .\build-m23-release\test-runtime\CryptoBenchmarkM23CalibrationTests.exe `
  --observe-once
```

## Caps, locking, recovery and archive contents

- At most **30 reserved logical worker runs** over the session; group M and
  multi-entry E are counted as `sum(M)` for entries, not as one command.
- At most **4 hours cumulative active child-launch time** across invocations.
- At most **900 seconds per child**, further limited to the remaining 4-hour
  budget. The timeout includes a bounded process-tree termination grace.
- Windows Job Object `KILL_ON_JOB_CLOSE` contains the suspended-before-resume
  child process tree. If job assignment or verified termination fails, the
  runner fails closed; it will not launch the next group.
- An exclusive OS file lock is held for the complete invocation. The ledger
  reservation, full group logical-run count, and maximum child-time allowance
  are written atomically and flushed before child launch. A fixed per-user
  archive-root anchor pins the root, ledger sequence, and current ledger SHA
  across invocations; stale/rolled-back ledgers fail closed.
- A `reserved`, `started`, or `interrupted` record blocks retry and advance.
  Interrupted sessions require human reconciliation; reservations are never
  rewound. A completed process with invalid evidence and any nonzero/crashed
  child is retained as quarantined and also blocks all later ordinals. It is
  not accepted as calibration evidence.
- The runner rejects dirty Git, wrong branch, non-Release cache/BuildInfo,
  mismatched build commit, changed application/worker hashes, changed
  selection/plan/wrapper hashes, invalid approval reference, noncanonical
  rows, reparse-point paths, repo-local/network archive paths, mapped network
  or indeterminate archive volumes, unknown free-space information,
  pre-existing per-group output paths, and disk/available-memory preflight
  below 512 MiB. Successful evidence must bind the exact approved-plan hash;
  the harness manifest's completion status, evidence hash, and batch-result
  hash are checked against the actual files before the ledger can complete.

Only future explicitly authorized execution creates archive content. Per
group, preserve the harness's raw `manifest.json`, `pilot-evidence.json`,
`batch-result.json`, success marker only if the harness validates completion,
child console log, human-readable session summary, and an
`archive-manifest.json` with SHA-256 and byte count for every other group file.
The append-only-by-reservation ledger retains all attempts and dispositions.
Failures are preserved; they are never converted into success-shaped evidence.

**Archive proposal pending separate approval:** operator-chosen external,
access-restricted storage, independently encrypted using the operator's
approved storage process, with retention through M24 qualification plus
12 months. This tool performs checksumming, not encryption. It does not create
the archive during this coding task or during DryRun.

The ledger uses a checksummed atomic payload and a fixed per-user archive-root
anchor to prevent accidental root switching. It detects corruption and
ordinary edits, but without an external signing/monotonic authority it cannot
cryptographically prove that an administrator did not restore an older
ledger and recompute its unkeyed SHA-256. Keep a separately controlled copy of
the final ledger/manifest during any future pilot; do not describe the local
ledger as tamper-proof.

## Non-observing test and build policy

`tools/m23-pilot-session-tests.ps1 -NonObserving` checks the 23/27/12
selection, selector uniqueness, the M=3/E=3 accounting, wrong/unknown/deferred
selection, no-GO and hash rejection, dirty/wrong-build gates, archive and
reparse-point rejection, lock collision, interrupted reservation, ledger
checksum/rollback and failure-archive preservation, 30-run and 4-hour
boundaries, dry-run side-effect absence, and a timed-out dummy
PowerShell process tree. It never invokes a CryptoBenchmark worker or the
observation command.

Full Debug and Release CTest remain measurement-free. Do not run any
observation command from CTest, a dry-run, or this safety-test script.

Known platform limitation: if Windows cannot assign the suspended child to a
Job Object (for example, because of an incompatible enclosing job policy), the
runner refuses to resume it. If the OS cannot confirm process-tree termination
within the reserved grace, the ledger becomes interrupted and execution
stops. No exact cap is claimed in a kernel/API hang beyond the supervisor's
verified process-tree boundary.

## Pending decisions and handoff

Pending human decisions: exact final group list/approval reference; separate
pilot GO; operator archive location and access restriction; encryption method;
retention through M24+12 months; environmental host acceptance; any revised
selection or cap. No pilot observation, calibration dataset, production model,
or numeric ETA is authorized by this package.
