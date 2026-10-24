# M19.3 confirmatory sampling-overhead preparation

This is a distinct, test-only workflow. The historical M19.3 24-trial pilot and its CLI, schema, plans, calibration files, and evidence remain unchanged.

## Protocol

The frozen confirmatory plan contains two real OpenSSL workloads, SHA-256 Hash with 8-byte input and AES-256-GCM Encrypt with 16-byte input. Each workload has four conditions: qualification-only OFF (`intervalMilliseconds=0`), periodic 5 ms, periodic 2 ms, and periodic 1 ms. One N is shared across all four conditions within a workload. The precommitted default is 12 repetitions per condition, for 96 sequential trials; preparation accepts 10-20 repetitions so a reviewed plan can record a bounded choice. N must come from a fresh, explicitly labeled Release calibration artifact for the current worker hash. The historical pilot N values are not silently reused as confirmatory calibration.

Trials are scheduled as deterministic randomized blocks: each workload/repetition block contains exactly one OFF/5/2/1 ms trial, shuffled only within that four-trial block from the frozen seed. Each trial records `blockIndex`, `blockPosition`, and global `executionOrder`; validation reconstructs the complete order from the seed.

Each trial launches one fresh production worker and records parent-session wall/CPU, canonical worker measured-block wall/CPU, process identity, sampling counts and optional peaks, provenance, and status/error. OFF uses boundary snapshots only; the frozen plan records OFF as `0` ms while the internal valid `MeasurementSettings` placeholder is explicitly recorded as `5` ms; periodic sampling is not enabled. Zero periodic samples require null sampled peaks. Parent-minus-worker wall may be reported descriptively, but is not a canonical overhead metric.

Windows parent process CPU time is quantized at approximately 15.625 ms on the observed host. Balanced repeated blocks can reduce relative quantization impact when aggregating observations, but cannot recover sub-quantum CPU measurements. Analysis therefore reports descriptive distributions, paired/interleaved order effects, uncertainty intervals and quantized observations without claiming significance, equivalence, or zero overhead. No post hoc exclusions or quantitative PASS threshold are defined.

## Preparation and execution

Bounded CTest runs only the frozen-plan and fail-closed synthetic checks. It does not launch workers.

```powershell
build-m19-release\test-runtime\CryptoBenchmarkM19_3ConfirmatorySamplingOverheadTests.exe --prepare-confirmatory --seed 20261024 --repetitions 12 --sha256-calibration C:\path\current-sha256-calibration.json --aes256-gcm-calibration C:\path\current-aes256-gcm-calibration.json --output C:\path\confirmatory-plan.json
build-m19-release\test-runtime\CryptoBenchmarkM19_3ConfirmatorySamplingOverheadTests.exe --execute-confirmatory --plan C:\path\confirmatory-plan.json --output-dir C:\path\new-confirmatory-output
```

Preparation first validates successful SHA-256 and AES-256-GCM calibration artifacts against the current Release worker SHA-256, clean Git HEAD, and Release build identity, then records their immutable hashes, selected N values, complete source JSON objects, and exact original source bytes as Base64 in the frozen plan. The plan is copied into the campaign output; the manifest embeds that plan and records its hash, so an evidence archive containing `plan.json`, `manifest.json`, the source calibration objects and exact bytes embedded in the plan, trial records, summary, and marker remains independently auditable without relying on unverifiable calibration filenames. Execution requires the same clean Release provenance, a new nonexistent output directory, and an unchanged frozen plan. It writes immutable plan/manifest data, per-trial attempt and terminal records, a completion summary, and a final success marker only after read-back/hash validation. Failure preserves partial evidence and writes no success marker. There is no retry, resume or overwrite behavior.

For periodic confirmatory trials whose canonical worker block reaches the approximately one-second target, at least one execution sample and its sampled peak are required; OFF retains zero samples and null peaks.

The real confirmatory campaign is deliberately not executed by this preparation task.
