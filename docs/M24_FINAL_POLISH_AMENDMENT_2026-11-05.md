# M24 Final Polish — Approved Scope Amendment and Evidence

**Date:** 2026-11-05
**Release:** CryptoBenchmark 1.0.0
**Status:** Two user-approved fixes implemented and committed; final release qualification pending.
**Branch:** feature/m24-final-polish

## 1. Authority and scope

This document records two explicit user-approved pre-release
changes made after the 2026-11-03 M24 FROZEN contract.

The original FROZEN M23/M24 documents remain unchanged as
historical normative records. This amendment supersedes only
the specific requirements identified below.

No new cryptographic algorithms, measurement semantics, IPC
protocol, result format or prediction model were authorized.

## 2. FIX-A: Runtime-independent pragmatic Batch ETA

Commit: a4b1dc2
Subject: fix(m24): allow pragmatic Batch ETA across runtime environments

Approved behavior:

- Use the existing pragmatic ETA calibration irrespective of
  the running machine's operating system version, architecture,
  build type or OpenSSL version.
- Do not require a match with the calibration's reference
  hardware/software runtime environment.
- Preserve the existing 175 calibration cases and model values.
- Preserve the existing user-facing warning verbatim:

  Rough, order-of-magnitude estimate of cryptographic work, actual time may be longer.

Safety and data-validity requirements retained:

- Strict calibration resource SHA-256 verification.
- Strict resource JSON/schema and provenance consistency checks.
- Canonical registry inventory verification.
- Fixed calibration protocol compatibility.
- Internal consistency of the historical measured context.
- No fabricated numeric ETA for missing, invalid, corrupt or
  unsupported model input.
- Provisional-dialect behavior remains unchanged.

The historical calibration reference context remains recorded
as provenance, not as a restriction on the executing machine.

This explicitly supersedes the M24 FROZEN contract's requirement
to return Inapplicable solely because the actual runtime
environment differs from the reference calibration environment.

Verification reported:
- Fresh targeted Debug tests: 2/2 PASS.
- M23 calibration resource tests: PASS.
- MainWindow GUI tests: PASS.
- Reviewed implementation patch: PASS.

## 3. FIX-B: Console-free production operation

Commit: 0958eec
Subject: fix(m24): suppress GUI and worker console windows

Approved behavior:

- CryptoBenchmark.exe uses the Windows GUI PE subsystem.
- GUI-launched worker processes use CREATE_NO_WINDOW.
- Contradictory CREATE_NEW_CONSOLE and DETACHED_PROCESS
  creation flags are cleared.
- Both legacy and v2 WindowsWorkerProcess launch paths are
  covered by the common QProcess configuration.
- CryptoBenchmarkWorker.exe retains its Windows console
  subsystem for standalone diagnostics.

Unchanged:
- Worker arguments, IPC and process lifecycle semantics.
- Measurement boundaries and memory/CPU measurement.
- Calibration data, ETA calculations and warning text.
- Application version 1.0.0.

Verification reported:
- Fresh targeted Debug tests: 3/3 PASS.
- GUI PE subsystem: 2 (Windows GUI).
- Worker PE subsystem: 3 (Windows CUI).
- Independent patch/diff identity review: PASS.
- Visual no-console smoke: PENDING.

## 4. Calibration identity

The canonical calibration asset is unchanged:

Path: calibration/runtime-calibration-v1.json
Size: 92881 bytes
SHA-256: d3f2cd021afebf742414ea7bf2a42aae99803ced8e9fef2f220c034d86d46129

No new calibration campaign, model fitting, coefficient changes
or full-Batch elapsed-time accuracy claims are authorized.

Historical M23 WAIVED items remain WAIVED, not PASS.

## 5. Release evidence and remaining gates

Earlier M24 qualification, prior to FIX-A and FIX-B:
- Full Debug CTest: 69/69 PASS.
- Full Release CTest: 69/69 PASS.
- Real-worker 1000-entry Batch stress: PASS.
- Fresh post-merge Release CTest: 69/69 PASS.
- Previous portable ZIP integrity: 122/122 PASS.

These results belong to the earlier source candidate.
They are inherited historical evidence, not assertions that
the two new commits have passed all final release gates.

Required before release acceptance:

1. Review and commit this amendment.
2. Full Debug and Release CTest on the amended candidate.
3. User-controlled integration to main and mandatory fresh
   post-merge Release CTest.
4. Rebuild Release binaries from the final exact commit.
5. Recreate portable staging, dependency/license inventory,
   ZIP and SHA-256. Do not publish the obsolete earlier ZIP.
6. Independent Windows x64 clean-machine smoke:
   GUI startup, Single, Batch, Creator, export, cancel,
   numeric ETA where covered, no console windows, no
   orphan worker process.
7. Resolve final third-party license/source-access obligations.
8. Verify exact source/build/ZIP identity before the user
   creates annotated tag v1.0.0 and performs the final push.

The earlier 1000-entry stress evidence is retained because
FIX-A changes ETA acceptance and FIX-B only changes Windows
process-creation window flags. These changes require focused
worker-lifecycle qualification and clean-machine smoke.
A repeat scale campaign is not planned unless new evidence
shows a regression affecting sequential Batch execution.

## 6. Release status

NOT YET RELEASED.

No final tag, remote publication or final measurement freeze
is claimed by this document. The historical intermittent
WorkerSession IPC timing observation remains open and is
not represented as resolved.
