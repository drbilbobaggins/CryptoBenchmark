# CryptoBenchmark

CryptoBenchmark benchmarks classical and post-quantum cryptographic algorithms. The supported platform is Windows 11 x64.

## Run

Extract the supplied portable folder and launch `CryptoBenchmark.exe`. Keep `CryptoBenchmarkWorker.exe`, all supplied runtime DLLs and Qt plugins, and `calibration/runtime-calibration-v1.json` in their supplied relative locations. The GUI starts the worker and loads the calibration resource from this layout.

## Benchmark and export

- **Single Benchmark:** choose an algorithm, operation, and parameters, then run the benchmark.
- **File Batch:** load a Batch input-v1 JSON file and run its entries sequentially.
- **Batch Creator:** create and validate entries, then use them in a Batch or export the input as JSON.
- Export benchmark results as JSON or CSV where available. Keep each result's terminal status: `Completed`, `Cancelled`, and `Failed` are distinct; a cancelled or failed entry is not a completed measurement.

Batch input-v1 is strict JSON. This minimal example is one SHA-256 hash entry:

```json
{
  "format": "cryptobenchmark-batch-input",
  "schemaVersion": 1,
  "entries": [
    {
      "profileId": "sha256",
      "operation": "hash",
      "iterationsPerRun": 1,
      "runs": 1,
      "parameters": {
        "inputSizeBytes": 64
      }
    }
  ]
}
```

The pragmatic Batch ETA is an order-of-magnitude estimate of cryptographic work, not a prediction of total Batch elapsed time; actual time may be longer. Numeric estimates use the reviewed calibration across supported runtime environments.

## Version, provenance, and notices

The application version is **1.0.0**. Exported results include version and build/runtime provenance, including the source commit when available. Any portable distribution should include applicable third-party notices and licence texts for the dependencies it bundles; consult those files for their terms.
