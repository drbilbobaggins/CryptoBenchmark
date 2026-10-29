# M23.1 calibration foundation

The M23 test targets only enumerate the live registry, validate synthetic
evidence/resources, and exercise path resolution. Normal CTest does not start
`CryptoBenchmarkWorker.exe` for calibration or create a calibration resource.
The production `NoDataRuntimeCalibrationProvider` remains the active provider.

## Registry inventory and candidate plan

`enumerateRuntimeCalibrationInventory()` derives profile IDs, supported
operations, and typed input modes from `AlgorithmRegistry` and
`InputCapability`. The manifest is sorted by stable profile ID, stable
operation name, and typed input kind. Its SHA-256 is locked by the focused test,
along with the baseline counts of 72 profiles, 139 profile-operation pairs, 175
typed cases, 78 fixed/no-size cases, and 97 variable-size cases. Any registry
coverage change requires a reviewed manifest/test update.

The candidate plan is deterministic and explicitly marked
`candidate-only` / `measurementAuthorized: false`. It uses three repetitions,
5 ms, `M=1`, and candidate `N=1` reference rows (`N=2` fixed-input holdouts).
Variable-size reference and holdout points follow the frozen M23 grid, including
the 256 MiB feasibility-gated candidate. A fixed-seed shuffle assigns stable
observation order. These are planning values, not a pilot decision or execution
authorization.

Generate a plan file without starting a worker:

```powershell
& .\build-m23-baseline-release\test-runtime\CryptoBenchmarkM23CalibrationTests.exe `
  --write-candidate-plan C:\path\new-m23-candidate-plan.json
```

## Explicit real-worker observation

The harness has one opt-in observation path through the production
`BatchController` -> `BenchmarkController` -> fresh `WorkerRunSession` ->
`CryptoBenchmarkWorker` path. It requires a Release build, clean Git worktree,
valid canonical config, new absolute output directory, resolvable app/worker
binaries, environment/provenance capture, and the explicit
`--i-confirm-m23-2-go` acknowledgment. Use it only after the separate M23.2
human GO for a reviewed measurement plan. No observation or calibration
campaign was run for M23.1.

Example command shape (this tuple is candidate-plan row 696; do not run before
that GO):

```powershell
& .\build-m23-baseline-release\test-runtime\CryptoBenchmarkM23CalibrationTests.exe `
  --observe-once `
  --case ed25519/sign/message `
  --input-bytes 64 `
  --iterations 1 `
  --runs 1 `
  --sampling-ms 5 `
  --role holdout `
  --repetition 1 `
  --order 696 `
  --output-dir C:\path\new-m23-observation `
  --i-confirm-m23-2-go
```

`--role` is explicitly `reference` or `holdout`. Each observation records the
typed case, exact workload bytes (or `no-size`), `N`, `M`, sampling interval,
repetition, order, deterministic observation identity, inventory/plan hashes,
UTC timestamp, build/app/worker hashes, Git provenance, OS/architecture,
processor/logical-processor and RAM identity, power plan, Qt/OpenSSL versions,
worker PID/creation-time pairs, and per-run plus enclosing elapsed values.
Evidence is written atomically; failed/incomplete runs do not receive a success
marker and are rejected by the evidence validator. A successful result is one
observation only, not a campaign or a qualified dataset.

## Timing ownership

- **Measured block `B`:** the worker-reported canonical
  `N x executeIteration()` wall-clock value for each completed logical run.
  The harness does not add timers or callbacks inside this block.
- **Run elapsed `R`:** `QElapsedTimer` starts in the test hook immediately
  before `WorkerRunSession::start()` and stops on its terminal `completed`
  signal, after worker termination and session cleanup. Evidence rejects
  `R < B`. The measured run residual is `R - B`.
- **Entry elapsed:** observes the existing `BatchController::progressChanged`
  seam. It starts on the `RunningEntry` progress edge (`currentEntryIndex` is
  set and `persistenceInProgress` is false), after the initial checkpoint and
  immediately before `executor_->start()`. It ends on the first progress edge
  for that entry with `persistenceInProgress` true, after executor completion
  and before the entry/final checkpoint is persisted. The disjoint
  entry-outside-run interval is `entryElapsed - sum(R)`.
- **Batch elapsed:** starts immediately before the explicit
  `BatchController::start(definition, target, settings)` call and ends on the
  terminal `batchFinished` signal callback after final persistence. It excludes
  any GUI confirmation wait because this is a test-only observation, not a GUI
  action.
- **Batch-only intervals:** the monotonic offsets before entry start and after
  entry end are recorded separately. Initial checkpoint persistence must end
  before entry start; final checkpoint persistence must start after entry end.
  The `SnapshotPersister` write intervals are nested diagnostic subdivisions
  of these outside-entry intervals. They are never added again to the
  containing Batch-only overhead. Serialization and other unassigned work
  remains visible in the measured before/after residuals; neither is assumed
  to be zero.

Evidence verifies both identities:
`entryElapsed = sum(R) + entryOutsideRun`,
`batchElapsed = batchBeforeEntry + entryElapsed + batchAfterEntry`, and thus
`sum(B) + sum(R-B) + entryOutsideRun + batchBeforeEntry + batchAfterEntry
= batchElapsed`, subject only to timer resolution and the captured monotonic
boundaries. It also checks that initial/final checkpoint intervals lie wholly
outside the entry interval and that their diagnostic durations fit within
their containing Batch-only intervals. Existing worker timing, fresh-worker
lifecycle, sampler, IPC, result schema, and Batch semantics are unchanged.

## Resource path and provisional parser

The application-relative resource path is
`calibration/runtime-calibration-v1.json`. With the current CMake runtime
output directory, its build-tree location is
`build-*/bin/calibration/runtime-calibration-v1.json`. CMake optionally copies
only a future source file at `calibration/runtime-calibration-v1.json` to that
location and compiles its exact source-byte SHA-256 into `BuildInfo`. No source
resource exists in M23.1, so no file or synthetic fixture is staged beside
`CryptoBenchmark.exe`.

The resource tests resolve the path from the actual
`build-*/bin/CryptoBenchmark.exe`, resolve a separate staged executable, load a
test-only fixture there, and repeat after relocating the staged directory.
The fixture is generated in temporary test directories only.

The loader enforces a 16 MiB byte limit, strict UTF-8, duplicate-key
preflight before Qt DOM parsing, exact schema keys/version, canonical typed
registry identities, legal sampling and workload bounds, canonical decimal
integer strings, required provenance/hash formats, and SHA-256 equality to an
explicit expected digest. Variable-size exact-reference points bind their
single reference byte size to an exact valid interval. It distinguishes missing, corrupt, and
inapplicable resources. This is the `m23.1-provisional-1` parser foundation:
the synthetic fixture is marked unqualified, the batch-overhead model list
must remain empty, and both dataset-level and record-level `qualified` claims
are rejected by this provisional version. Loading it has no connection to the
production provider. The pilot-gated overhead representation and production
schema remain undecided.
