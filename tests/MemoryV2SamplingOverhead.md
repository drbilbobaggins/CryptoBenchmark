# Memory v2 real-worker sampling-overhead Stage A

This test-only target proves instrumentation on the real OpenSSL worker path.

CLI:

```powershell
build-m19-release\test-runtime\CryptoBenchmarkMemoryV2SamplingOverheadTests.exe
build-m19-release\test-runtime\CryptoBenchmarkMemoryV2SamplingOverheadTests.exe --self-test --output C:\path\stage-a.json
```

The normal CTest invocation is bounded and self-contained. It runs four fresh
workers: one qualification-only OFF boundary reference and periodic 5, 2 and
1 ms runs. It uses SHA-256 Hash, 8 input bytes, `runs=1`, and fixed
`iterationsPerRun=10000`. This is a smoke, not a pilot and not a quantitative
conclusion. `--output` selects a persistent destination. The writer rejects an
existing destination and uses the existing `AtomicFileWriter`/QSaveFile path
for atomic commit. The output is a versioned batch document retaining all four
observations, with `logicalRunIndex=0` and distinct `executionOrder` values
`0..3`. The self-test also reads the committed JSON back and checks exact
round-trip equality.

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
