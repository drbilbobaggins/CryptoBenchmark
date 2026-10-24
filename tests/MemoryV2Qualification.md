# Memory v2 Qualification Smoke

The qualification-only smoke executable writes one raw run artifact to a caller-selected path:

```powershell
build-m19\test-runtime\CryptoBenchmarkMemoryV2QualificationTests.exe `
  --smoke-output build-m19\memory-v2-qualification.json
```

Use the corresponding `build-m19-release` path for Release evidence. The artifact format is `cryptobenchmark-memory-v2-qualification`, schema version `1`. It retains raw B0/B1/Pprep/Pexec/E observations, phase sample counts, derived Memory v2 metrics, synthetic workload metadata, provenance, timing, and worker lifecycle evidence.

The timing fields describe the synthetic workload window and are not canonical cryptographic benchmark performance. Boundary-only output is a noncanonical reference and must not be mixed into public benchmark statistics. This smoke command is a lightweight M19.1 evidence path, not the M19.2 quantitative campaign.

## M19.2 Gate A pilot

The campaign runner reuses the M19.1 `WorkerRunSession` and real sampler path:

```powershell
build-m19-release\test-runtime\CryptoBenchmarkMemoryV2QualificationTests.exe `
  --pilot-output build-m19-release\m19.2-gate-a-pilot
```

This generates a versioned `manifest.json`, one atomic raw artifact per fresh worker under `runs/`, and a separate `summary.json`. Existing output files are never overwritten. A custom validated manifest can be run with:

```powershell
build-m19-release\test-runtime\CryptoBenchmarkMemoryV2QualificationTests.exe `
  --manifest path\to\manifest.json `
  --output-dir build-m19-release\campaign-output
```

The default exploratory pilot is six synthetic cases x four modes (`off`, `5`, `2`, `1`) x three repetitions, with a deterministic seed. `off` is the noncanonical boundary-only reference. The pilot is exploratory evidence only: its capture proportions and intervals do not establish Gate B thresholds or a final M19 qualification decision. Synthetic worker timing is diagnostic workload timing and is not sampler-overhead evidence.
