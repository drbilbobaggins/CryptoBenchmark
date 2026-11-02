# M23 reduced-scope ETA acceptance (M23.5-B)

This records the final pre-merge acceptance evidence for the user-approved
2026-11-01 reduced-scope pragmatic Batch ETA. It does **not** close the original
full end-to-end calibration gates and is not an M24 release qualification.

## Acceptance matrix

| Area | Result | Evidence / limit |
|---|---|---|
| Approved resource identity | PASS | `m23-pragmatic-1`, `reducedScopeApproximate`, 175 canonical typed records |
| Canonical coverage | PASS | 78 constant and 97 anchored-affine records; strict inventory validation |
| Independent size holdouts | PASS for the reduced model | 291 rows were withheld from fitting and recomputed after integer-picosecond quantization |
| Model application | PASS within recorded legal ranges | Fixed per-operation values or minimum-size anchored affine values; no size extrapolation |
| Resource trust | PASS | Exact CMake-compiled SHA-256, strict parser, executable-relative CMake staging |
| Runtime compatibility | PASS under the strict policy | Release requires the recorded OS, architecture, OpenSSL, protocol and registry context; Debug and incompatible hosts are Inapplicable |
| Provider and M22 behavior | PASS | Typed provider, checked arithmetic and M22 aggregation remain in place; no-data fallback remains safe |
| GUI disclosure and No path | PASS in deterministic offscreen tests | Numeric Available estimates carry the reduced-scope disclosure; No leaves output absent and starts no worker |
| Interactive desktop smoke | **PASS (user-reported, 2026-11-01)** | Checklist below; an automated/offscreen test is not claimed as manual desktop evidence |

## Dataset and model evidence

- Candidate SHA-256: `d3f2cd021afebf742414ea7bf2a42aae99803ced8e9fef2f220c034d86d46129`
- Independent holdout report SHA-256: `2c6ad3f3553d4a8aaa09db322d7d28347f5219507f084f4c5e7a0bfafe15435c`
- Dataset identity: `cryptobenchmark-m23-pragmatic-2026-11-01-data1`, version `0.1.0-pragmatic.1`
- Holdout factor error: median **1.002893694415×**, P90 **1.032926489102×**, P95 **1.047109330605×**, maximum **1.259366478733×**; worst row `on26-c149-hold-64k`.
- Training uses 466 references only. The 291 size holdouts were excluded from fitting. The full report preserves the row-level predictions, ratios, intermediate-size diagnostics and endpoint checks.
- All 175 model records and all 291 row-level predictions/error factors were independently checked unchanged during the supplemental-exclusion accounting correction.

The estimate models measured cryptographic-operation time only, with exactly
one warm-up operation per logical run. Fixed-entry and Batch overhead are
modeled as zero only under explicit `assumedUnmeasured` tags; these values are
not measured overhead. The source timing context is 5 ms memory sampling.
Mapping requests at 1–4 ms reuses that source only under explicit
`assumedFrom5ms` assumptions; those intervals were not separately measured.
There is no startup, setup/preparation, IPC, checkpoint/persistence or other
end-to-end Batch timing model. Actual elapsed time can be longer, especially
for many short runs, and may vary by machine.

The following original M23 qualification work was **waived, not passed**:

- measured worker/startup, preparation, IPC, fixed-entry or Batch overhead;
- separate 1–4 ms sampling qualification;
- independent full-Batch elapsed-time holdouts and hour-scale accuracy gates.

The 291 size holdouts validate the per-operation size model only; they do not
validate total end-to-end Batch ETA.

## Runtime compatibility and packaging

The source asset is
`calibration/runtime-calibration-v1.json`. The existing CMake configure step
embeds its exact SHA-256 and copies the same bytes to the executable-relative
`calibration/` directory. Verified source, Debug staged, Release staged and
compiled BuildInfo hashes all equal the candidate digest above.

The strict loader was exercised with the explicit recorded reference context:
Windows 11 Version 25H2, x86_64, Release, OpenSSL 3.6.5 and
`memory-v2-calibration-v1` -> `Loaded`. The actual Debug context -> `Inapplicable`.
Wrong hash/corrupt temporary copies -> `Corrupt`; Missing remains distinct.
The loader never accepts a numeric estimate merely because a file is present.

## Test evidence

- Focused runtime-estimate, provider, resource and GUI CTests: **4/4 PASS** in
  Debug and **4/4 PASS** in Release.
- Full sequential Debug CTest: **69/69 PASS**.
- Full sequential Release CTest: **69/69 PASS**.
- GUI integration used the staged real resource with a reference-compatible
  test context for numeric File/Creator parity, then the actual host context
  for its correct Available/Inapplicable outcome. Both confirmation flows
  chose No; no output or worker execution occurred.
- The production application continues to use the strict loader and existing
  M23.4-A provider. No new calibration or benchmark observation was performed.

The first full Debug CTest run encountered the known intermittent
`CryptoBenchmarkWorkerSessionTests` socket-write failure during the
`v2-premature-start-measurement` scripted scenario: `waitForBytesWritten`
returned before its timeout after the peer had disconnected. The WorkerSession
and IPC sources were unchanged. Three fixed consecutive reruns of that test
passed, as did related worker lifecycle tests; the subsequent complete serial
Debug and Release suites both passed. The transient is documented, not claimed
as a source fix.

## Prior user-reported Windows GUI smoke — PASS (pre-M23.5-C copy)

Use the Release build only when its actual runtime context is compatible with
the recorded reference. Do not press Yes. This smoke was completed before
M23.5-C shortened the dialog copy; it is historical evidence for the prior
copy and does not verify the updated wording.

1. Launch `build-m23-release/bin/CryptoBenchmark.exe`.
2. In Batch Creator, create two SHA-256 Hash entries with 8-byte input, N=1,
   M=1; choose a fresh temporary output path and run the Batch.
3. Inspect the numeric order-of-magnitude estimate and disclosure: excluded
   overheads, potential underestimation, measured 5 ms source and assumed
   1–4 ms mapping. Choose **No** or Escape. Verify the Batch did not start and
   no output was created.
4. Export the equivalent Creator definition to Batch JSON, load it through the
   File Batch path, use the same settings and a separate temporary output
   path. Inspect equivalent estimate/disclosure, choose **No**, and verify no
   output was created.
5. Launch `build-m23-debug/bin/CryptoBenchmark.exe` and verify the same input
   is nonnumeric/unavailable because Debug is Inapplicable. Choose **No**.
6. Report observed Release/Debug compatibility, displayed text, File/Creator
   parity and no-output/no-execution results to the reviewer. If Release is
   Inapplicable on the actual host, record that honestly; do not override the
   loader or claim a numeric host-qualified estimate.

Manual interactive GUI smoke: PASS (user-reported, 2026-11-01). Release
numerical ETA and the then-current detailed disclosure, File/Creator parity,
No without execution or output, and Debug unavailable estimate were confirmed.
The offscreen GUI test is automated evidence only.

## M23.5-C post-change visual check — PASS (user-reported, 2026-11-02)

The user confirmed satisfactory interactive GUI behavior with the shortened warnings on 2026-11-02. This is user-reported manual evidence, separate from automated CTest results.

1. In a compatible Release build, create a two-entry, modest SHA-256 Batch in
   Creator, then repeat with the equivalent File Batch JSON.
2. Inspect the confirmation and the exact pragmatic disclosure:
   “Rough, order-of-magnitude estimate of cryptographic work, actual time may be longer.”
3. Choose **No** or Escape in both paths and verify no execution or output.
   Do not choose **Yes**.
4. In Debug, verify the estimate remains nonnumeric/unavailable and decline.
   If Release is Inapplicable on the actual host, report that honestly; do not
   bypass compatibility.
5. Post-change interactive GUI check: **PASS (user-reported, 2026-11-02)**. The user confirmed the updated GUI was satisfactory.

## Remaining work

M24 still owns final portable-package and clean-machine acceptance, formal
1000-entry stress, and any broader integrated/release qualification. None of
those items, nor the waived original M23 gates, is claimed complete here.
