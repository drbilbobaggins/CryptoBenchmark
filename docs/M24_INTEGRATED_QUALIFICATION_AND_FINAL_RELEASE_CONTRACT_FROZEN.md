# CryptoBenchmark — M24 Integrated Qualification & Final Release: FROZEN Contract

**Document:** `M24_INTEGRATED_QUALIFICATION_AND_FINAL_RELEASE_CONTRACT_FROZEN.md`  
**Date:** 2026-11-03  
**Milestone:** M24 — Integrated Qualification & Final Release (P10)  
**Status:** **APPROVED / FROZEN — M24 normative execution and acceptance contract**  
**Approval date:** 2026-11-03 (explicit user approval of the complete approval draft)  
**Planning baseline:** M23-published `main` / `origin/main` / GitHub `main` at `eb5f1edb0d36cc5c33b7c35350c41063396fe05e` (verified at M23 closure, 2026-11-02; must be checked again before M24 starts).  
**Approval history:** On 2026-11-03, the user approved the lean M24 schedule, then separately approved the complete M24 approval draft. This frozen document records that authorization. The stage-by-stage review, evidence, and user-controlled Git gates remain binding.

## 0. Scope of the frozen contract and stage-action boundary

This is the approved M24 execution and acceptance contract, **not** a claim that M24 has begun or passed. Its approval authorizes proceeding to the **M24.1 baseline preflight** under the established human-controlled workflow. It does **not** constitute blanket authorization for branch creation, `CURRENT_TASK.md`, Copilot tasks, Git staging/commit/merge/push/tag, source changes, stress execution, packaging, or release publication. Each must follow its applicable phase and explicit task/user gate. No M24 qualification outcome is presumed PASS by this approval.

**Primary principle:** qualify only risks that M15–M23 did not already qualify. Preserve the previous milestones' specific evidence rather than replaying their entire qualification campaigns. Existing regression tests still execute at the mandated release gates; they do not become separate manual campaigns.

M24 is a **release/integration milestone, not a feature milestone**. Only necessary release-blocking fixes, narrowly reviewed and requalified for their impact, are permitted. No new crypto profiles, APIs, GUI workflows, export formats, measurement semantics, prediction model, or CI/CD product is authorized by M24.

## 1. Authorities, supersession, and unchanged contracts

Read the following together, within their respective scope:

1. `MASTER_04_Post_M14_scope_es_roadmap.md`: active M24/P10 scope and the **2026-11-02 M23 supersession** at the end of the document.
2. `MASTER_05_Build_platform_es_fejlesztoi_kornyezet.md`: Windows 11 x64, CMake, final portable deployment, clean-environment smoke, and release identity.
3. `MASTER_06_Fejlesztesi_egyuttmukodes_es_AI_workflow.md`: one milestone branch, small reviewable tasks, human Git operations, full pre-merge and fresh post-merge CTest requirements, flaky-test handling, and journal timing.
4. `MASTER_01_Benchmark_runtime_architektura_es_Memory_v2.md`: B0/B1/E measurement boundaries, process/memory semantics, fresh-worker-per-logical-run lifecycle, 1–5 ms setting and IPC/result contracts.
5. `MASTER_02_Kriptografiai_domain_profilok_es_OpenSSL.md`: canonical domain inventory and algorithm operations.
6. `MASTER_03_Application_GUI_Batch_es_export.md`: Single/Batch/Creator state, ResultDocument v2, atomic checkpoint, strict input, JSON, Hungarian Excel CSV, and GUI invariants.
7. `IMPLEMENTACIOS_NAPLO_M00-M23_FRISSITETT.md`: historical **implementation evidence**, not a replacement for technical contracts.
8. `CryptoBenchmark_M23_Contract_FROZEN_2026-10-28.md` **only together with** the user-approved 2026-11-01 reduced-scope amendment as documented by the current MASTER_04 and M23 closure; repository `docs/M23PragmaticEta*.md` files provide the implemented pragmatic ETA details.

If a historical embedded roadmap passage demands an M23 full-Batch duration-accuracy campaign, follow the later M23 scope supersession. **WAIVED is not PASS**, and an M23 waiver does not automatically become an M24 task.

### 1.1 Non-negotiable technical invariants

- Windows 11 x64 / Qt 6 Widgets / OpenSSL 3.6.x / C++20; no multi-platform deployment scope.
- Single and Batch share canonical domain validation, measurement settings, real worker and result semantics.
- In a Batch, entries execute in file order and sequentially; each logical run uses a **fresh worker process**; no concurrent benchmark sessions or retry policy.
- Memory v2, B0/B1/E phases, process CPU time, peak PrivateUsage, and sampling setting are not redefined.
- `ResultDocument v2` remains the common canonical source for JSON and CSV. JSON remains lossless/canonical; 77-column Hungarian Excel CSV remains a secondary representation.
- Strict Batch JSON input, 1–1000 entries, 4 MiB input-size limit, existing failure/cancel/atomic persistence and Save As behavior remain unchanged.
- The accepted M23 ETA is **an order-of-magnitude estimate of cryptographic work, not a predicted full Batch wall time**.

## 2. M23 baseline, application version, and immutable calibration identity

At the M23 close, the reported and independently verified GitHub `main` was:

`eb5f1edb0d36cc5c33b7c35350c41063396fe05e`

Historical milestone results: **69/69 Debug CTest PASS, 69/69 Release CTest PASS**, followed by accepted manual GUI checks. These are *prior evidence*, not assertions of new M24 testing.

Production calibration resource:

```text
Path:   calibration/runtime-calibration-v1.json
Bytes:  92881
SHA256: d3f2cd021afebf742414ea7bf2a42aae99803ced8e9fef2f220c034d86d46129
```

Reference context recorded by M23: Windows 11 Version 25H2, x86_64, Release, OpenSSL 3.6.5, `memory-v2-calibration-v1`, plus the canonical registry and other strict resource checks. Inventory: 175 cases = 78 constant + 97 anchored-affine, built from 466 fitting references and validated with 291 independent **size** holdouts. These 291 holdouts are **not** full Batch elapsed-time holdouts.

The M23 pragmatic resource has historical `referenceAppVersion` / dataset identity; the production strict loader does **not** compare that historical reference app version with the running application's `PROJECT_VERSION`. Hence the proposed application-version change `0.1.0` → **`1.0.0`** must not itself force an ETA compatibility rewrite. **Do not rewrite the calibration resource, referenceAppVersion, datasetVersion, or hash merely to match the final application version.** If final builds expose a genuine context mismatch, use the correct nonnumeric `Inapplicable` state, not a compatibility bypass.

Preserve the current approved numeric disclosure verbatim:

> Rough, order-of-magnitude estimate of cryptographic work, actual time may be longer.

Preserve the strict `<1 s` measured-block per-run warning semantics (maximum ten listed indices plus a remaining-count summary) and `No` default / Escape / close rejection with no worker, output file, initial checkpoint, or configuration mutation. These semantics are already covered by prior M22/M23 tests and require **no standalone M24 feature campaign**.

M23 items expressly **WAIVED and not reopened**: measured startup/worker/setup/IPC/checkpoint/fixed Batch overhead; dedicated 1–4 ms measurement-accuracy qualification; independent end-to-end Batch elapsed-time holdout campaigns and hour-scale ETA accuracy thresholds. Values previously treated as `assumedUnmeasured` or `assumedFrom5ms` remain honestly described.

## 3. Evidence inheritance: what M24 will NOT re-test as a separate campaign

The table records a required qualification judgment, not permission to ignore tests or fabricate evidence. During M24.1, cite the concrete test/journal/repository evidence and check that no intervening production change invalidated it.

| Requirement group | Prior substantive evidence | Lean M24 action |
|---|---|---|
| 72 profiles / 139 profile-operation pairs / 175 input-mode cases; correctness of 11 strategies | M07/M08 and subsequent full CTest; M20 canonical coverage | **Prior evidence + normal suite only**; no new per-algorithm campaign |
| Memory v2 phase boundaries, 5/2/1 ms sampler qualification, synthetic peak capture | M15–M19 qualification and later regressions | **Prior evidence**; no new measurement campaign |
| WorkerSession/IPC v2 and fresh-worker lifecycle, no-orphan behavior | M17–M19; real-worker `tests/BatchControllerIntegrationTests.cpp` | **Prior evidence**; one new long sequential Batch stress is the only missing scale case |
| Creator 1000 real QWidget rows, 1001 rejection, edit/move/finalize/export/reparse | M20 `tests/CreatorGuiTests.cpp` maximum-row test and `tests/MainWindowGuiTests.cpp` Creator integration; M20 journal | **Already qualified**; never repeat as a separate 1000-row stress |
| File/Creator canonical parity, draft/snapshot isolation | M20 and M22/M23 GUI tests | **Prior evidence + normal suite**; small clean-machine Creator route only |
| Strict JSON, pretty ResultDocument v2 and atomic checkpoints, failure/Save As/cancel states | M10–M18, M20, M22/M23 regressions | **Prior evidence + normal suite**; no complete fault-injection matrix |
| Hungarian Excel CSV v2: 77 columns, BOM, `;`, decimal comma, CRLF, semantic mapping | M21 CSV suite and subsequent regressions | **Prior evidence + normal suite**; simple portable export smoke only |
| ETA availability, no-mutation, numeric/partial/unavailable, fallback and warning | M22/M23 targeted suites + manual GUI acceptance | **Prior evidence + normal suite**; one portable context/smoke check only |
| Real-worker short mixed-family Batch, cancellation/reuse and checkpoint progression | M12/M18 real-worker integration + M20/22/23 tests | **Prior evidence**; no separate broad mixed-family/failure matrix |

**Evidence classification** for M24 closure:

- `PASS — PRIOR EVIDENCE`: specific, still-applicable evidence from M00–M23.
- `PASS — RC REGRESSION`: an existing registered test passing against the final release-candidate source.
- `PASS — M24 NEW`: an actually executed new release/stress/package check.
- `WAIVED`: only a requirement expressly waived by an approved scope decision.
- `FAIL / BLOCKED`: a required gate failed, was not performed, or lacks acceptable evidence.

A `PASS — PRIOR EVIDENCE` label must name the prior source and cannot be used if the relevant production code changed without adequate impact-focused requalification. The final release summary must not imply that an inherited check was rerun manually in M24.

## 4. Only new functional stress: one 1000-entry real Batch

### 4.1 Test fixture and execution

- Use **one** valid input-v1 **File Batch** document containing **exactly 1000 entries**, generated from an already accepted canonical SHA-256 Hash / 0-byte-input fixture using the production parser/builder semantics; do not invent or bypass the input schema.
- For each entry, use `M=1`, `N=1` and the same supported sampling setting (prefer the production/default 5 ms). This makes the test a **worker lifecycle and checkpoint stress**, not a crypto performance benchmark.
- Input size remains within the 4 MiB parser limit; input and output files are in an isolated local test directory with sufficient disk space.
- Execute the **actual application Batch path with 1000 real sequential entries**, not a fake worker, mocked controller, or repeated in-process synthetic operations.
- Accept the existing `<1 s` warning/confirmation normally; there is no requirement for a numeric ETA on an incompatible environment.
- Default approach: **no new harness or production instrumentation**. Use existing Batch execution, built-in logs/tests, the resulting structured JSON, and a basic external process check. An additional gated diagnostic harness is a separately approved fallback **only if** material evidence cannot otherwise be obtained. Never put an expensive 1000-worker test into default CTest by accident.

### 4.2 Hard PASS criteria

1. Exactly 1000 entries are accepted upfront; actual Batch execution starts and reaches terminal **Completed** without manual retries or silent skips.
2. The final, atomically persisted ResultDocument v2 is parseable and contains 1000 ordered, correctly indexed **Completed** entry results with canonical inputs and structurally valid result/environment data.
3. No overlapping benchmark/worker session and no orphan `CryptoBenchmarkWorker.exe` attributable to the test remain after GUI/Batch completion. A fresh worker per logical run is required by the already-tested production architecture; do **not** demand globally unique PIDs (Windows can reuse process IDs).
4. Existing checkpoint lifecycle is not bypassed; the known initial/terminal and progressive semantics are cross-checked against the already qualified real-worker integration test. The 1000-result final file is essential; a second 1000-step intrusive checkpoint trace is **not required**.
5. No application crash, deadlock, stuck running state, corrupt/partial final output, unexplained exception, or unrecovered required persistence failure occurs.
6. The evidence records the exact build/source SHA, environment/settings, fixture hash, final-output hash, approximate elapsed wall time and observed end state. Wall time is diagnostic only, **not a speed/ETA acceptance tolerance**.

### 4.3 Practical safety bounds, not new benchmark metrics

Preflight checks adequate disk space and host health. Operational guardrails proposed from planning: **60-minute stop/diagnosis watchdog**, **4 GiB free disk before starting**, and **2 GiB combined measured application/worker private-memory investigation threshold when reliable observation is available**. These are conservative resource-safety triggers, **not performance SLA gates**; exceeding one means pause, preserve evidence and review, rather than post hoc redefining acceptable benchmark speed. Do not introduce a monitoring subsystem solely to enforce the optional memory threshold. No high-`M`/high-`N` or repeated 1000-run variants are required.

A failed or aborted run is not `PASS`. Diagnose once with focused evidence; after an approved fix, rerun only the affected necessary check and release gates. Do not repeat a passing stress campaign merely for ceremonial confirmation.

## 5. Minimal smoke and existing-invariant reuse

### 5.1 No additional integration campaign

Do not schedule independent large campaigns for 1000-row Creator, all algorithm families, sampling intervals, File/Creator parity, JSON/CSV semantic equality, all persistence failures, cancellation race combinations, all ETA states, or full-Batch ETA accuracy. These requirements have historical evidence and/or registered regression tests.

### 5.2 Small clean-machine smoke, not exhaustive GUI matrix

After the final ZIP has been created, on a separate Windows x64 PC or suitably isolated Windows VM with **no dependency on installed development MSYS2, Qt or OpenSSL**:

1. Unpack ZIP and start the real `CryptoBenchmark.exe` normally.
2. Single SHA-256 with `M=2`, short `N`: verify both logical runs complete, GUI results display, and JSON **and CSV** exports can be opened and minimally inspected.
3. Execute a **small** valid File Batch with a few entries (ideally including at least two algorithm families), confirm sequential completion and readable final JSON.
4. Create a few Creator rows, `Use in Batch`, execute or validate a short real Creator-based Batch, and verify one export/reload path. This does **not** repeat the 1000-row Creator test.
5. Exercise **one** controlled Batch cancel path; check terminal semantics and worker cleanup. Other cancel/failure variants remain covered by registered tests.
6. Observe ETA as either correctly numeric `Available` on a compatible host **or** a correct nonnumeric `Inapplicable`/unavailable state on an incompatible one. A single declined confirmation may check the obvious no-start behavior; the exhaustive `No`/Escape side-effect matrix belongs to prior regression evidence.
7. Check no orphan worker attributable to this portable process after normal completion/cancellation and that portable resource files are actually found.

Perform this user-facing test **once on the final package**; if it passes and neither package nor source changes, there is no second clean-machine round. Do not insist on manual reproduction of every rare QSaveFile/IPC/error state in the clean environment.

## 6. Build, regression, and the smallest policy-compliant repetition

### 6.1 Prior evidence is accepted; no M24.1 blanket rerun

M24.1 performs baseline and scope/evidence preflight only. The historical M23 **69/69 Debug + 69/69 Release PASS** does not need a fresh rerun merely because M24 planning begins.

Use targeted tests during individual M24 source changes. There is no full CTest after every small documentation or version edit unless the diff/impact justifies it.

### 6.2 Final candidate and merge rules

Two independent requirements must both be respected:

- `MASTER_04` requires **full Debug and Release regression** for the final product.
- `MASTER_06` requires **full pre-merge CTest** and **fresh post-merge full CTest before pushing**. This workflow requirement cannot be silently waived in the name of simplification.

**Lean compliant minimum in the no-defect case:**

1. On the exact final release-candidate feature SHA, perform one complete **Debug CTest** and one complete **Release CTest** (all registered tests; M23 historical count was 69, but the actual discovered count governs). Do not remove or skip tests merely to obtain PASS.
2. Perform the **single** new 1000-entry real Batch stress on this final candidate (Release build); no separate Creator or mixed-family mega-campaign.
3. After user-controlled integration to `main`, do a **fresh post-merge build and one full Release CTest** before remote push. This is the minimum full post-merge CTest required by `MASTER_06`; a second post-merge Debug sweep is not a default M24 requirement if the merge tree is byte-identical to the already-qualified feature tree and no new risk is introduced.
4. If the merge changes the final source tree (or configuration/commit identity in a way relevant to the binary), or any test fails reproducibly, requalify the changed final source as necessary. Prefer a reviewed **fast-forward** merge to preserve the exact tested commit/SHA where the repository situation permits; never force history to achieve this.

Thus there is **one release-candidate Debug/Release qualification campaign, plus the mandatory minimum post-merge full CTest**, not repeated full rounds in M24.1/M24.2/M24.4/M24.5. Existing source changes after qualification invalidate only the affected evidence **unless** the final exact-source or required merge gate itself has changed.

### 6.3 Historical intermittent WorkerSession test

`CryptoBenchmarkWorkerSessionTests` has an **OPEN / NON-BLOCKING** occasional IPC/socket-write timing observation (`parent write timed out` in earlier milestones). It is **not** documented as fixed. On a new failure:

1. Stop declaring release PASS; record raw failure and exact build/source/environment.
2. Check for source/tree changes; run a focused bounded reproducibility set and associated lifecycle tests.
3. Follow the existing `MASTER_06` flaky-test investigation procedure; do not merely rerun until green.
4. If a reproducible release-impacting defect appears, **STOP / BLOCKED** pending a narrowly approved fix. Do not increase timeouts or add retries by default.
5. If nonreproducible after documented investigation and policy-required regression recheck, retain the **open historical observation** with the finding; do not relabel it resolved.

## 7. Final version, documentation and source freeze

**Approved final-release identity:**

```text
Application version:       1.0.0
Annotated Git tag:         v1.0.0
Portable directory:        CryptoBenchmark-1.0.0-win64/
Portable ZIP:              CryptoBenchmark-1.0.0-win64.zip
Platform:                  Windows 11 x64
```

Change the CMake project/application version from the current `0.1.0` to `1.0.0` only in the approved release task. Check the embedded `BuildInfo` fields and actual JSON `EnvironmentInfo` against the **same** final Git SHA, build type and OpenSSL runtime. Check that no hardcoded stale beta/release strings survive in shipped user-facing documentation. **Do not change crypto measured-block semantics, calibration coefficients, referenceAppVersion, dataset version, or strict compatibility just to display the final version.**

Prepare short, accurate user-facing documentation: Windows ZIP usage, where the GUI/worker/resource live, supported platform, Single/Batch/Creator basic workflow, JSON/CSV outputs, meaning/limitations of ETA, build/version provenance, licences and known limitations. Consolidate obsolete release-facing claims; do not rewrite historical normative documents merely for stylistic consistency. No additional feature or thesis measurement campaign is implied.

Final release-candidate source must be reviewable and clean. `CURRENT_TASK.md`, `.dev-private`, internal AI prompts, raw audit bundles, credentials, local paths and dev-only helper files are **not** part of the distribution.

## 8. Portable package acceptance and resource identity

Build **Release** from the exact final `main` commit (or an identical tested SHA prior to fast-forward) and create a **new, empty** staging directory. The canonical package contains at least:

```text
CryptoBenchmark-1.0.0-win64/
  CryptoBenchmark.exe
  CryptoBenchmarkWorker.exe
  calibration/
    runtime-calibration-v1.json
  platforms/
    qwindows.dll
  [actual Qt6, OpenSSL, GCC/C++ and transitive runtime DLL dependencies]
  [other Qt plugins required by the actual final build]
  [user-facing README, third-party notices and applicable licence texts]
```

The bracketed names are categories, **not** a hardcoded dependency list. Collect actual Qt dependencies with the installed `windeployqt` variant and verify non-Qt OpenSSL/compiler runtime dependencies against the final binaries. Check imports/transitive dependencies using available inspection methods, but **do not create a compulsory custom dependency-scanner script or CI system**. The independent Windows clean-machine launch is the essential real-world deployment proof.

Mandatory resource byte-for-byte check:

```text
SHA256(source calibration/runtime-calibration-v1.json)
= SHA256(build-staged bin/calibration/runtime-calibration-v1.json)
= SHA256(portable calibration/runtime-calibration-v1.json)
= d3f2cd021afebf742414ea7bf2a42aae99803ced8e9fef2f220c034d86d46129
```

Check size **92881 bytes** at all three locations. The resource must be loaded through the production strict loader; no build-path fallback or resource integrity bypass is allowed. A clean-machine with an incompatible calibration context may correctly show a nonnumeric ETA and still PASS deployment acceptance.

Package third-party notices and licence texts for the **actual binaries/distributions shipped**; determine them from installed package/licence metadata and do not assume the historical M14 dependency/licence list is exhaustive or still current. No admin rights are presumed for the build process, dependency review, ZIP extraction, or smoke test.

Create the final ZIP from the accepted staging directory and record its SHA-256. A checksum sidecar is recommended as a tiny release artifact, **not** an independent CI feature or a mandated GitHub Release page.

## 9. Phase gates and minimal evidence

| Phase | Scope and deliverable | Allowed new implementation | Minimum gate / evidence | Exclusions |
|---|---|---|---|---|
| **M24.P — Contract approval** | Complete document review and separate user approval | **None** | **PASS — APPROVED/FROZEN, 2026-11-03** | No branch, task, stress, packaging or tag during contract freeze |
| **M24.1 — Lightweight baseline preflight** | Verify clean local `main`, remote SHA, source inventory, existing M23 evidence and known intermittent note; identify release-only diffs | None by default | Git worktree/ancestry report, authority map, prior-evidence ledger and scoped release plan | No full test repetition or broad source review |
| **M24.2 — New gap preparation** | Prepare valid 1000-entry fixture and lean process/output checks; identify any release blocker before RC | Test fixture/helper only if actually necessary and separately reviewed; no production feature | Validated fixture, SHA, conditions, targeted checks; existing 1000-Creator proof referenced | No 1000-Creator replay; no default-CTest 1000-worker test |
| **M24.3 — Final release candidate** | Version/docs changes, exact RC SHA, final source review, single full Debug/Release regression, one real 1000-entry stress | Only approved release metadata/docs or a separately approved blocker fix | Full suites PASS; stress PASS; no unresolved reproducible blocker; source/tree frozen | No repeated crypto/memory/export/failure mega-campaigns |
| **M24.4 — Portable packaging** | Reviewed integration to `main`, mandatory fresh post-merge build/full CTest, build from final SHA; stage runtime, hash calibration, package licences and ZIP | Packaging/docs only if needed; no benchmark code changes | Fresh post-merge full CTest PASS; exact binary/worker/resource presence; dependency/licence evidence; ZIP/hash | No new CI/CD framework or second stress |
| **M24.5 — Independent smoke and freeze** | One clean-machine smoke of exact ZIP; verify final source/tag/ZIP identities; annotated tag/push and archive | None unless failure forces explicit stop/requalification | Smoke PASS; no orphan; clean main; remote SHA/tag verification; ZIP SHA and release checklist | No new full GUI/fault-injection matrix |

Phases may be consolidated operationally if the same evidence remains exact and traceable. The names are review gates, not an excuse to force five separate coding cycles or five repeated suites. **Do not create an M24.2 implementation harness unless the existing application cannot generate reliable stress evidence.**

### 9.1 Evidence package (lightweight)

Prefer one compact release-audit directory or report rather than many per-step bundles. Include:

- Baseline SHA, eventual final RC/main/tag SHA, clean Git status, relevant diff and version/build metadata.
- Evidence ledger pointing to inherited tests/journal sections, plus final full-suite CTest summaries and isolated failures/investigations if any.
- One 1000-entry input SHA, compact invocation/runtime record, final output SHA and structural 1000-row verification; worker cleanup observation.
- Source/build/portable calibration bytes and SHA values; DLL/dependency and applicable licence inventory.
- Exact final ZIP name, SHA-256, and concise clean-machine smoke checklist with actual environment and result.
- Explicit open limitations (`Inapplicable` ETA conditions and WorkerSession historical intermittent observation); any approved release waiver.

Do **not** require rerunning all historical raw evidence or collecting hundreds of screenshots/log files. If a claim lacks evidence, say `NOT VERIFIED`, not PASS.

## 10. Git, tag, ZIP and measurement-freeze order

The source/tag/ZIP must identify one reproducible final program state. Human-authorized steps, subject to all prior gates:

```text
Contract separately approved and frozen (2026-11-03)
  -> verify baseline; create M24 branch only when authorized
  -> small, reviewed release tasks / source diff
  -> exact feature RC; complete Debug and Release CTest; 1000 Batch stress
  -> user-controlled merge to main (fast-forward preferred where safe)
  -> mandatory fresh post-merge build and full CTest; no push if FAIL
  -> package Release from exact main SHA; resource/DLL/licence audit
  -> produce candidate ZIP and SHA-256
  -> independent clean-machine smoke on this exact ZIP
  -> recheck unchanged main SHA, source tree, ZIP and calibration identity
  -> user creates annotated v1.0.0 tag on exact qualified commit
  -> normal push main and tag, no force; verify remote refs and tag target
  -> archive release ZIP/hash and final concise evidence report
  -> freeze measurement/release program state; only then plan official thesis data collection
  -> update separate implementation journal AFTER verified final push
```

The `MASTER_05` conceptual diagram places tag before build; the above **verification-first tag** sequence is acceptable only because the tag points to the **same exact qualified commit**; no source or binary changes are allowed between packaging/smoke and tag creation. If a tag-first operation is required for organizational reasons, use the same immutable SHA and repeat identity checks accordingly. The release metadata must not falsely claim a tag that did not exist when the binary was built; the reproducibility anchor is the actual commit SHA.

Prefer fast-forward to avoid changing the commit embedded by `BuildInfo`; if a non-fast-forward integration is needed, the **merge commit** becomes the final release SHA, and packaging/testing must be based on it. If any executable, calibration resource, dependency set, or ZIP content changes after smoke, the old ZIP/smoke evidence is invalid and the affected packaging/smoke gates must be repeated.

`v1.0.0` is an **annotated** tag, created by the user; never by Copilot. Verify its peeled target and `origin/main` independently after push. GitHub Release publication is **optional**. A local ZIP plus manifest with actual SHA may satisfy artifact delivery, provided that its location and preservation are recorded.

The final tag freezes the **software and measurement implementation state**, not a claim that thesis measurement datasets already exist. Official measurements must use this frozen state and document their own environment and configs. A later measurement-affecting code fix requires a new identified release and requalification of the affected measurements.

## 11. STOP / escalation rules

Release cannot be declared PASS if any of these hold:

1. Local/remote baseline, final commit, binary `BuildInfo`, calibration SHA, ZIP, or remote tag identities disagree without resolution.
2. A required full CTest gate fails reproducibly or is replaced by a partial suite without explicit exception.
3. The unique 1000-entry stress does not complete honestly, loses/reorders/skips entries, corrupts output, deadlocks, or leaves an attributable worker orphan.
4. The actual portable package cannot launch cleanly or lacks the worker, required runtime DLL/plugin, resource, or applicable licence documentation.
5. A clean-machine output or visible state violates canonical Single/Batch/Creator/JSON/CSV semantics, or a corrupt/inapplicable ETA resource falsely produces trusted numeric estimates.
6. An M23-waived full-Batch ETA claim or precision threshold is silently reintroduced, or a legacy warning/waiver is falsely documented as resolved.
7. A newly found substantive defect requires production changes after freeze without targeted review and proportionate requalification.
8. A coding agent stages, commits, merges, pushes, tags, silently changes the milestone scope, or adds retries/timeout inflation to camouflage the open IPC observation.

On STOP, preserve concrete evidence and propose **one smallest reviewable corrective action**. Re-run the impacted checks plus any workflow-required final source/merge gates; do not reflexively restart all historical qualification campaigns.

## 12. Final exit checklist

The final milestone may be marked **CLOSED / PASS** only after all applicable points are explicitly evidenced:

- [x] Final M24 contract separately approved and frozen before implementation (2026-11-03).
- [ ] Baseline verified; Git changes limited to approved release work or narrow approved blockers.
- [ ] Prior evidence ledger complete; old M23 WAIVED items remain WAIVED.
- [ ] Final source qualified by full Debug and Release CTest; required fresh post-merge full CTest PASS.
- [ ] **One** 1000-entry sequential real-worker Batch stress PASS with correct final persisted 1000-result document and no attributable orphan.
- [ ] `1.0.0` application version, canonical runtime/build/result metadata, and M23 reference/dataset distinction verified.
- [ ] Source/build/portable production calibration resource: **92881 bytes** and exact agreed SHA-256 at each location.
- [ ] Final `CryptoBenchmark.exe` + `CryptoBenchmarkWorker.exe` + actual Qt/OpenSSL/compiler dependencies + licence notices staged.
- [ ] One independent Windows x64 clean-machine Single/Batch/Creator/export/cancel/ETA smoke PASS.
- [ ] Final ZIP hash recorded; unchanged exact final source and package identity verified.
- [ ] User-created annotated `v1.0.0` tag points to exact qualified release commit; remote main/tag verified, no force push.
- [ ] Known WorkerSession intermittent observation accurately retained or independently resolved with evidence; no known reproducible release blocker.
- [ ] Final release/measurement freeze recorded; **implementation journal updated only after verified push**.

## 13. Decisions incorporated from the 2026-11-03 streamlining approval

| Decision | Frozen disposition |
|---|---|
| No standalone repeat of M20 1000-row Creator stress | **Adopted**: previous tests are substantive evidence |
| No new full crypto, Memory v2, parity, ETA or failure-injection campaigns | **Adopted**: registered tests + inherited evidence |
| Still perform a genuine 1000-entry real Batch stress | **Adopted**: one new scale qualification |
| Final full Debug+Release suite | **Adopted once as one RC campaign**; the MASTER_06-required additional fresh post-merge full CTest remains mandatory |
| Small clean-machine smoke instead of exhaustive manual GUI suite | **Adopted**: one exact ZIP, focused end-to-end scenarios |
| Do not build a new 1000-worker test harness unless justified | **Adopted**: use existing production Batch as the primary stress vehicle |
| Release identity: `1.0.0`, `v1.0.0`, `CryptoBenchmark-1.0.0-win64.zip` | **APPROVED** |
| Final tag after exact ZIP smoke, on unchanged qualified commit | **APPROVED** |
| ZIP SHA-256 manifest; GitHub Release optional | **APPROVED** |

**Approval record (2026-11-03):** The user expressly approved this entire document after separately approving the streamlined M24 plan. The approval covers **one final RC Debug+Release regression campaign plus the workflow-mandated fresh post-merge full CTest**, one 1000-entry real-worker Batch stress, one small clean-machine smoke, the `1.0.0`/`v1.0.0` final-release identity and the verification-first tagging sequence. Preserve this frozen version and its external SHA-256 identity. The next allowed step is **M24.1 baseline preflight**; later implementation and release operations remain subject to their own workflow gates.
