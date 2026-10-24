# M19 — Memory v2 Qualification: results and evidence index

**Project:** CryptoBenchmark  
**Assessment date:** 2026-10-24  
**Scope:** M19.1–M19.4 (including M19.3 pilot and confirmatory campaign)  
**Status at document preparation:** **technical qualification PASS; formal milestone closure pending** feature-branch full regression, reviewed merge, clean post-merge regression/smoke, `origin/main` verification and historical implementation-journal entry.

This is a **qualification report**, not a new normative Memory v2 specification. The normative runtime, sampling, result and KPI contracts remain in `MASTER_01_Benchmark_runtime_architektura_es_Memory_v2.md`; milestone requirements remain in `MASTER_04_Post_M14_scope_es_roadmap.md`.

## 1. M19 exit criteria and disposition

| Requirement | Evidence / finding | Assessment |
|---|---|---|
| M19.1 baseline / qualification infrastructure | Release gate accepted; focused regression gate 9/9, repeated worker-session checks | PASS for qualification infrastructure |
| M19.2 controlled-allocation experiment | 960/960 completed worker runs, 960 unique PID/creation identities; accepted B1/B2 integrity and raw extraction evidence | PASS; historical full raw files are not all in the present offline archive |
| M19.2 transient-peak sensitivity | 48 conditions × 20 repetitions; OFF, 5/2/1 ms and phase-specific allocation patterns | PASS as controlled, descriptive sensitivity study |
| M19.3 original pilot | 24/24 completed workers, four modes across two workloads; evidence integrity verified | PASS as pilot, **not** as a definitive overhead bound |
| M19.3 confirmatory measurement | 96/96 real workers; two workloads × four modes × twelve repetitions; 24 seeded four-trial blocks; complete marker/hash chain | PASS with explicit uncertainty limitations |
| M19.4 real-worker four-category coverage | Ed25519 Sign, X25519 Derive, AES-256-GCM Encrypt, SHA-256 Hash; two runs per category = 8/8 distinct workers | PASS for tested workloads |
| Memory v2 boundary and phase semantics | B0/B1/E and optional preparation/execution sample peaks; short-block null handling; four run-level derived KPIs independently recomputed (8 × 4 = 32 M19.4 checks) | PASS |
| One worker per logical run / no residue | Distinct process identities in M19.2, M19.3 and M19.4 campaigns; recorded no-orphan checks | PASS for audited campaigns |
| Full feature-branch and post-merge integration | Final **full** Debug/Release CTest, main merge, fresh post-merge build, remote SHA check | **PENDING** until performed and reviewed |

**Do not represent this table's technical PASS as proof that `main` has already received M19.**

## 2. Measurement model and interpretation

The **parent** process obtains synchronous `PrivateUsage` boundary observations:

- `B0` (`baselinePrivateUsageBytes`): common runtime ready, immediately before algorithm-specific preparation.
- `B1` (`readyPrivateUsageBytes`): after algorithm-specific preparation/warm-up, before the measured execution block.
- `E` (`finalPrivateUsageBytes`): at the end of measured execution, before the sampler window is closed.
- `Pprep`, `Pexec`: optional peaks of *periodic* samples within the preparation/execution phases. Zero samples imply absent (`null`) sampled peak. The B0/B1/E synchronous observations do **not** increment periodic sample counts.

The four run-level **normative** derived metrics are, where an absent optional peak is simply omitted from the maximum:

```text
ReadyStateDelta      = signed(B1) - signed(B0)
PreparationPeakDelta = max(B0, B1, Pprep if present) - B0
ExecutionPeakDelta   = max(B0, B1, E, Pexec if present) - B0
OperationalPeakDelta = max(B0, B1, E, Pprep if present, Pexec if present) - B0
```

`ReadyStateDelta` may be negative. The other three deltas are nonnegative by construction. **OperationalPeakDelta** is the primary Memory v2 memory KPI; it measures observed peak additional `PrivateUsage` across the post-B0 operational lifecycle, **not** absolute total RAM consumption or a guaranteed unobserved maximum.

Each logical benchmark run uses a new worker process. Parent-session wall and CPU times are separate observations from canonical *worker measured-block* wall/CPU. Parent-minus-worker wall time is a descriptive diagnostic; it must **not** be presented as the canonical CPU or wall overhead of sampling.

## 3. M19.2 controlled-allocation peak sensitivity

The independently analysed synthetic transient was approximately 8 MiB. An event was labelled "captured" for this *analysis* if its phase sampled peak exceeded `max(B0,B1,E)` by at least 4 MiB. **The 4 MiB criterion is an analysis choice, not a production validation threshold or probability guarantee.** Twenty repetitions per cell:

| Transient phase/duration | 5 ms | 2 ms | 1 ms |
|---|---:|---:|---:|
| Preparation, 1 ms | 1/20 | 12/20 | 20/20 |
| Preparation, 2 ms | 0/20 | 19/20 | 19/20 |
| Preparation, 5 ms | 20/20 | 20/20 | 20/20 |
| Preparation, 20 ms | 20/20 | 20/20 | 20/20 |
| Execution, 1 ms | 8/20 | 19/20 | 20/20 |
| Execution, 2 ms | 15/20 | 20/20 | 20/20 |
| Execution, 5 ms | 20/20 | 20/20 | 20/20 |
| Execution, 20 ms | 20/20 | 20/20 | 20/20 |

Qualification-only **OFF** did not periodically capture the transients. Retained and quiet controls have a distinct interpretation; the quiet control did not yield false transient detections under the stated criterion. Short pulses can be missed, especially with longer intervals. These observed fractions concern the controlled schedule and host only, not universal detection probabilities.

## 4. M19.3 sampling-overhead evidence

The historical **24-worker pilot** verified feasibility but each condition had only three repetitions, with 22/24 zero parent-CPU observations. A separate frozen confirmatory protocol therefore used **SHA-256 Hash** (`N=10,000,000`, 8-byte input) and **AES-256-GCM Encrypt** (`N=3,000,000`, 16-byte input). The current Release worker was freshly calibrated to a selected measured block ≥900 ms; calibration files were preserved byte-for-byte inside the frozen plan. The frozen seed is `20261024`; each of 24 four-trial blocks contains OFF, 5, 2 and 1 ms in seeded order; 96/96 runs completed with 96 distinct worker identities and a valid `success.marker`.

The following numbers are **worker measured-block wall** means, with mean *paired* differences from the OFF worker in the same block:

| Workload | OFF mean (ms) | 5 ms Δ (ms) | 2 ms Δ (ms) | 1 ms Δ (ms) |
|---|---:|---:|---:|---:|
| SHA-256 | 1327.14 | +0.21 | +0.14 | +6.96 |
| AES-256-GCM | 1071.49 | +1.10 | +11.83 | +4.16 |

All six descriptive 95% percentile bootstrap intervals (30,000 block-resampling replicates with a frozen analysis seed) **include zero**. This does **not** prove zero overhead, equivalence, a numerical overhead upper bound or an optimal interval. Measurements show variability, incomplete within-block position balance and time-order drift. The parent process CPU values are **0 in 74/96 trials**; the nonzero observations are quantised at approximately **15.625 ms** (21 observations) or 31.25 ms (one). Thus a precise CPU-overhead percentage cannot be inferred from this campaign.

The 72 periodic confirmatory trials all observed execution samples; 24 OFF trials observed no periodic samples. Mean execution samples per worker for SHA-256 at 5/2/1 ms were approximately 256.9 / 636.3 / 878.8; for AES-256-GCM 207.0 / 518.8 / 713.1. The **1 ms setting is a target interval**, not a guarantee: worker duration divided by sample count suggests roughly 1.5 ms per observed sample, **not** directly timestamped inter-sample intervals.

**Disposition:** retain the **5 ms production default** and the allowed user-selectable **1–5 ms target** range. The shorter target may improve transient peak capture, with uncertain incremental CPU/time cost. Qualification-only OFF is not a production selection.

## 5. M19.4 real-worker four-category qualification

The accepted *second* campaign ran two logical runs for each of Ed25519 Sign, X25519 Derive, AES-256-GCM Encrypt and SHA-256 Hash, with **eight unique production worker PID/creation-time identities**, successful B0/B1/E, and 32/32 independent run-level KPI recomputations. Short Ed25519/X25519 execution blocks legitimately recorded zero periodic execution samples (`null` sampled peaks); these were not interpreted as missing boundary observations.

An earlier **first attempt failed** due to an incorrect/empty production worker launch path. The first failure archive is preserved as historical evidence, not erased or relabelled. The corrected test-only launcher explicitly resolves the production worker executable, and the **second attempt passed**. These two attempts must remain distinguishable in the qualification history.

## 6. Evidence ledger and provenance

Evidence ZIPs and raw worker data are stored outside the tracked repository (`.dev-private` or separate evidence archive); only the present report is proposed as tracked documentation. SHA-256 values below identify historical original archives; the archived production worker executables themselves were not subsequently byte-audited in this offline review, only their original run provenance was verified.

| Item | Exact SHA-256 / identifier |
|---|---|
| M19.2 frozen B1 manifest | `460B8B483A4A2349EF3B455388C9676EC0DCFC90AF2A8E7643FF70C33274E707` |
| M19.3 24-trial pilot ZIP | `9528D335F30A5378986B57AD9C6508F5625CBD810D73F3643D010F1ACB6A5E9B` |
| M19.3 96-trial confirmatory ZIP | `E4ED101BC27BF2B3C9F5356B4D4EEA159506AD0CA1304067FD10FBA014AC4589` |
| M19.3 frozen 96-trial plan | `0FEFE5A5C23D0ED5EAE21625CC49F609D3E9CCFE0BDDA3212C83962EB0D471BD` |
| M19.4 corrected 8-run ZIP | `F82A748387A27AE24396C472D76AAF4599E0861DE339797477E4894C2A4A641D` |
| M19.4 first failed attempt ZIP | `8FAC902796604F0E562A33FB1A06198F68046AB21D126342EB58CE1680C03EF5` |

Different experiments legitimately used **different commits/binary builds**. Recorded commit references: M19.2 campaign `e8f106853a420c7554796c90a25eee4350418a2c`; M19.3 pilot `186d7d87e6e1c71d466e7743706a698acd6853bc`; corrected M19.4 `d51ed4f265e531d300895fe08be672c2550aad46`; confirmatory `79255cda1170893fb6b081f297c7db836e638ad3`. Do not retroactively assign one commit or executable hash to all campaigns.

Primary independent analysis references (not normatively authoritative) are `M19_EXIT_PREMERGE_FUGGETLEN_AUDIT_20261024.md`, `M19_3_CONFIRMATORY_FUGGETLEN_AUDIT.md` and the M19.2 transient capture CSV. M19.2 historical B1/B2 audit bundles support the 960-worker result where the complete original worker JSON set is unavailable for this offline audit.

## 7. Remaining integration/closure sequence

Technical qualification **PASS** does not imply completed integration. The workflow requires: documentation diff review → complete feature-branch Debug/Release build and full CTest → relevant GUI/worker smoke → reviewed documentation commit → clean `main` `--no-ff` merge → **fresh independent** post-merge build directory and full CTest → required smoke → push to `origin/main` → verify local/remote/hosted `main` SHA → only then append the M19 chapter to the historical implementation journal. Any reproducible failure blocks the relevant next gate; do not rerun old campaigns merely to make a report appear successful.
