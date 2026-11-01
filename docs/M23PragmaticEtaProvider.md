# M23 pragmatic runtime calibration provider (M23.4-A)

`makePragmaticRuntimeCalibrationProvider` accepts the typed result returned by
`loadRuntimeCalibrationResource`. Only a `Loaded` `m23-pragmatic-1` resource
with the expected reduced-scope policy and complete canonical inventory
constructs the real-data provider. The factory does not parse JSON or read a
file. Missing resources and the legacy provisional dialect use the existing
no-data provider; corrupt resources report `InvalidCalibrationData`, and
inapplicable resources report `MeasurementContextUnsupported`. No failure path
returns a numeric zero estimate.

The application still constructs `NoDataRuntimeCalibrationProvider`.
M23.4-A does not install the candidate, change resource staging or its compiled
SHA, inject this provider into the GUI, or activate a numerical ETA.

## Typed lookup and supported sizes

Lookup uses the existing M22 `RuntimeCalibrationKey` values:
`AlgorithmProfileId`, `BenchmarkOperation`, the typed input variant, and the
requested measurement settings. It matches the resource's canonical inventory
case; display names and serialized IDs are not lookup keys. Fixed cases require
their exact fixed input variant. Variable cases accept only the parser-validated
range: Message and AEAD are 1 byte through 256 MiB; Hash/XOF is 0 bytes through
256 MiB. Requests outside the record's range return
`CalibrationPointMissing`; no size extrapolation occurs.

The provider retains the validated typed resource snapshot and performs no
per-estimate file access or benchmark work. Its records and policy are
immutable after construction.

## Integer model and M22 ownership

For a fixed model, `t(s)` is its positive integer picoseconds per operation.
For an anchored affine model:

```text
t(s) = anchorPicosecondsPerOperation
     + slopePicosecondsPerBytePerOperation * (s - anchorInputBytes)
```

The parser and provider enforce checked unsigned arithmetic and the legal
endpoint. Conversion uses integer arithmetic and nearest-nanosecond,
half-up rounding:

```text
measured block per run = round_half_up(N * t(s) / 1000) ns
one warm-up per run    = round_half_up(t(s) / 1000) ns
```

Picoseconds are multiplied by `N` before conversion; an operation is never
rounded to nanoseconds before measured-block scaling. A rounded zero remains an
available `RuntimeDuration{0}`. Values outside signed nanosecond
representability return `ArithmeticOverflow`, without suppressing separately
available components.

The provider returns one warm-up as
`estimatedNonMeasuredDurationPerRun`. It returns fixed-entry and Batch
overhead as zero only when the loaded policy tags both as
`assumedUnmeasured`. These are explicit modeling assumptions, not measured
overhead. M22 `RuntimeEstimateService` continues to own `M` scaling, entry and
Batch aggregation, availability state and the strict measured-block `<1 s`
warning. Component rounding is separate by the frozen M22 DTO, so the sum of
rounded measured/warm-up components can differ by a few nanoseconds from
rounding the combined idealized picosecond quantity.

## Sampling context and limitations

The source model is measured at 5 ms. Requests at 1, 2, 3 or 4 ms use it only
when the typed policy contains the exact matching `assumedFrom5ms` mapping.
Those are assumptions, not interval-specific measurements. Other settings are
unavailable with `MeasurementContextUnsupported`.

The resource describes a reduced-scope approximate per-operation model. It
does not qualify end-to-end Batch elapsed time or measure worker startup,
preparation, fixed-entry cost or Batch persistence overhead. No waived M23
qualification gate is represented as passed. Production installation and GUI
activation require the separate reviewed M23.4-B task.

## Tests

`CryptoBenchmarkM23PragmaticProviderTests` runs synthetic typed-resource
coverage and arithmetic/fallback tests in ordinary CTest. Its optional
`--candidate` mode explicitly loads the private DATA1 candidate through the
strict production loader and checks direct arithmetic; it is not invoked by
CTest and has no default path to ignored local files.
