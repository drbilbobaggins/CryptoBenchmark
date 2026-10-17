# Memory v2 Qualification Smoke

The qualification-only smoke executable writes one raw run artifact to a caller-selected path:

```powershell
build-m19\test-runtime\CryptoBenchmarkMemoryV2QualificationTests.exe `
  --smoke-output build-m19\memory-v2-qualification.json
```

Use the corresponding `build-m19-release` path for Release evidence. The artifact format is `cryptobenchmark-memory-v2-qualification`, schema version `1`. It retains raw B0/B1/Pprep/Pexec/E observations, phase sample counts, derived Memory v2 metrics, synthetic workload metadata, provenance, timing, and worker lifecycle evidence.

The timing fields describe the synthetic workload window and are not canonical cryptographic benchmark performance. Boundary-only output is a noncanonical reference and must not be mixed into public benchmark statistics. This smoke command is a lightweight M19.1 evidence path, not the M19.2 quantitative campaign.
