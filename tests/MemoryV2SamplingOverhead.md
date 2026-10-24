# Memory v2 real-worker sampling-overhead Stage B1

This test-only target proves instrumentation on the real OpenSSL worker path.

CLI:

```powershell
build-m19-release\test-runtime\CryptoBenchmarkMemoryV2SamplingOverheadTests.exe
build-m19-release\test-runtime\CryptoBenchmarkMemoryV2SamplingOverheadTests.exe --self-test --output C:\path\stage-a.json
build-m19-release\test-runtime\CryptoBenchmarkMemoryV2SamplingOverheadTests.exe --calibrate sha256 --output C:\path\sha256-calibration.json
build-m19-release\test-runtime\CryptoBenchmarkMemoryV2SamplingOverheadTests.exe --prepare-pilot --seed 42 --repetitions 3 --sha256-n 10000000 --aes256-gcm-n 3000000 --output C:\path\pilot-plan.json
build-m19-release\test-runtime\CryptoBenchmarkMemoryV2SamplingOverheadTests.exe --execute-pilot --plan C:\path\pilot-plan.json --sha256-calibration C:\path\sha256-calibration.json --aes256-gcm-calibration C:\path\aes256-calibration.json --output-dir C:\path\new-pilot-output
```

The normal CTest invocation is bounded and self-contained. It runs five fresh
workers: one SHA-256 qualification-only OFF boundary reference, one AES-256-GCM
qualification-only OFF boundary reference, and SHA-256 periodic 5, 2 and 1 ms
runs. The SHA-256 smoke uses Hash, 8 input bytes, `runs=1`, and fixed
`iterationsPerRun=10000`. This is a smoke, not a pilot and not a quantitative
conclusion. `--output` selects a persistent destination. The writer rejects an
existing destination and uses the existing `AtomicFileWriter`/QSaveFile path
for atomic commit. The output is a versioned batch document retaining all four
observations, with `logicalRunIndex=0` and distinct `executionOrder` values
`0..3`. The self-test also reads the committed JSON back and checks exact
round-trip equality.

`--execute-pilot` is a separately authorized, Release-only mode. It requires a
persisted three-repetition/24-trial plan, successful matching SHA-256 and
AES-256-GCM calibration artifacts, a clean Git worktree, the current worker
hash, and a new nonexistent output directory. Normal CTest and `--self-test`
never execute it.

The executor writes an immutable `manifest.json`, a durable `attempt-XXX.json`
marker before each worker launch, and one atomic `trial-XXX.json` terminal
record before the next launch. A `summary.json` is written only after all 24
records are read back and verified. Worker failure, timeout, interruption or
persistence failure stops execution, preserves prior records, and writes an
explicit incomplete summary when possible. No retries or fabricated worker
measurements are allowed. OFF remains boundary-only with zero periodic samples;
its plan interval `0` is distinct from the internal session placeholder used
to satisfy production MeasurementSettings validation.

The supported workload allowlist is repository-backed and validated by the
normal self-test:

- `sha256`: `AlgorithmProfileId::Sha256`, `Hash`, `HashConfig{8}`;
- `aes256-gcm-encrypt`: `AlgorithmProfileId::Aes256Gcm`, `Encrypt`,
  `AeadConfig{16}`.

The explicit `--calibrate` path uses only the selected workload, OFF reference
runs, a fixed bounded candidate-N list, at most six fresh workers and a
120-second wall budget including the active worker/cleanup allowance. It stops
immediately at the first candidate whose canonical worker measured wall time
reaches the approximately-one-second target. It records status as
`success`, `noSuitableCandidate`, `deadline`, or `failedWorker`, and records
every attempted candidate. Coarse candidate spacing can overshoot the target;
that result is calibration guidance, not a final measurement setting.
Calibration is not sampling-overhead evidence and was not executed as part of
B1 validation.

The explicit `--prepare-pilot` path creates, but does not execute, a
deterministically seeded and shuffled plan. Before shuffling, every
workload/repetition block receives exactly four condition identities: OFF
boundary-only (`intervalMilliseconds=0`), periodic 5 ms, periodic 2 ms and
periodic 1 ms. It contains provisional repetitions, shared per-workload N
across all modes, distinct trial index and actual execution order, and
`notExecuted` status. The validator checks the full per-workload/per-repetition
condition matrix and rejects missing or duplicate conditions. It is rejected if
marked executed. No pilot or confirmatory campaign is run in B1.

Fields include PID and Windows process creation time in 100 ns FILETIME ticks,
worker executable path and SHA-256, Git HEAD and dirty state, build type, OS,
architecture, algorithm/operation/input configuration, M, N, execution order,
interval, terminal status/error, B0/B1/E and phase sample counts. Unavailable
measurements are JSON `null`, never fabricated zero observations.

Measurement windows and units:

- Parent session wall: monotonic nanoseconds from worker process start through
	verified normal process exit.
- Parent CPU: current parent `GetProcessTimes` user+kernel delta over that
	session window, converted from 100 ns ticks to nanoseconds. A zero delta is
	valid at Windows timer resolution; tests require valid nonnegative
	FILETIME-aligned units, not positive CPU consumption.
- Worker wall/CPU: the production worker's canonical measured
	`CPU-before -> wall-start -> N x executeIteration() -> wall-stop -> CPU-after`
	window. Worker CPU is not parent sampler overhead.
- Memory: synchronous OFF B0/B1/E reads or production periodic sampler
	boundaries and phase sample counts. OFF requires zero periodic samples and
	null sampled peaks.

Failed and incomplete artifacts retain `status` (`failed` or `incomplete`) and
a non-empty `error`; their unavailable timing and memory values are explicit
`null`. Malformed JSON, incomplete completed records, and overwrite attempts
are rejected.

Known confounders include OS scheduling, other system activity,
thermal/power-plan changes, timer wakeups, FILETIME rounding, startup and
cleanup costs in the parent session window, and the non-equivalence of process
CPU time and elapsed wall time. Stage A does not select repetitions, thresholds,
workload calibration, or pilot/confirmatory acceptance criteria.
