# M23 pragmatic ETA activation (M23.4-B)

The application startup path loads the reviewed `m23-pragmatic-1` resource
relative to the application executable using the existing strict loader and
the compiled CMake SHA-256. It obtains operating system, architecture, build
type and OpenSSL version from `collectEnvironmentInfo()` and supplies the fixed
`memory-v2-calibration-v1` protocol identifier. It does not read the file again
for an estimate and never starts a calibration benchmark.

## Installed resource and integrity

The source asset is `calibration/runtime-calibration-v1.json`. It is copied
unchanged from the reviewed private DATA1 candidate:

| Artifact | SHA-256 |
|---|---|
| Calibration resource | `d3f2cd021afebf742414ea7bf2a42aae99803ced8e9fef2f220c034d86d46129` |
| Independent holdout report | `2c6ad3f3553d4a8aaa09db322d7d28347f5219507f084f4c5e7a0bfafe15435c` |

The existing application CMake logic calculates the expected hash from the
source bytes at configure time, embeds it in `BuildInfo.h`, and stages the same
bytes under the executable-relative `calibration/` directory. No second
packaging path or runtime-computed trust hash is used.

The resource contains 175 typed cases (78 constant and 97 anchored-affine).
The strict loader reports it `Loaded` only for the matching Release,
Windows/architecture, OpenSSL and registry context. Debug and incompatible
contexts are `Inapplicable`. Missing resources, corrupt bytes and provisional
resources safely produce no-data behavior; none can produce a numeric ETA.

## Confirmation disclosure

The production MainWindow is explicitly constructed with the
`PragmaticReducedScope` presentation mode. The disclosure is appended only
when the estimate has a numeric `Available` Batch total. It identifies the
number as a rough order-of-magnitude estimate based on cryptographic-operation
timings, says it is not end-to-end Batch timing, and explains that worker
startup, setup/preparation, IPC, checkpoint/persistence and fixed per-entry
and Batch overhead are excluded. It warns that actual elapsed time may be
longer, especially for many short runs, and that timing may vary by machine.

The resource is measured at 5 ms memory sampling. Reuse for 1–4 ms is an
explicit `assumedFrom5ms` approximation, not interval-specific measurement.
The existing `No` default, Escape/close behavior, M22 snapshot handling and
strict measured-block `<1 s` warning remain unchanged. The one-argument
presentation formatter and ordinary fake-provider tests remain in the
non-disclosing `Standard` mode.

This reduced-scope ETA is not a measured or qualified end-to-end completion
time. It may underestimate actual elapsed time because the omitted overheads
are modeled as assumed zero. No waived M23 qualification gate is claimed as
passed; additional M23.5/M24 qualification remains separate.

## Verification

`M23CalibrationResourceTests` verifies the compiled hash, staged bytes,
Release `Loaded`, Debug `Inapplicable`, temporary-copy corruption rejection,
synthetic strict-schema cases and executable-relative relocation. GUI tests
exercise the installed resource in the pre-run dialog, disclosure, unavailable
Debug behavior, File/Creator parity and No without starting a worker.
