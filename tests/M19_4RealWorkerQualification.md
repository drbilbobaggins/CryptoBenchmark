# M19.4 real-worker qualification

The test-only target `CryptoBenchmarkM19_4RealWorkerQualificationTests` validates the four-category matrix and evidence failure modes without launching the dedicated campaign.

The explicit future campaign command is:

```powershell
build-m19-release\test-runtime\CryptoBenchmarkM19_4RealWorkerQualificationTests.exe --execute-m19-4 --output-dir C:\path\new-m19-4-output
```

The current bounded CTest self-test validates exact matrix fields and rejects malformed, duplicate, missing, and altered entries. It also proves that complete-looking synthetic evidence without the final success marker is not accepted.

The opt-in campaign uses the production `BenchmarkController` path, a global 2 ms setting, four configurations and `runs=2`: Ed25519 Sign with a 64-byte message and N=2, X25519 Derive with N=2, AES-256-GCM Encrypt with 16-byte plaintext and N=100000, and SHA-256 Hash with 8-byte input and N=100000. It requires a fresh worker per logical run, validates production result-v2 and Memory v2 calculations, persists an immutable manifest, four atomic category artifacts, a hashed completion summary, and an append-only `success.marker`. It refuses existing destinations, dirty Git worktrees, non-Release builds, failed provenance commands, partial evidence, and automatic retries.

Short Ed25519/X25519 workloads may legitimately have zero periodic samples. The validator preserves the Memory v2 null contract: a zero sample count requires a null sampled peak, while a positive sample count requires a sampled peak.

No M19.4 campaign, M19.3 recalibration, pilot, or confirmatory measurement is executed by normal CTest or this implementation task.
