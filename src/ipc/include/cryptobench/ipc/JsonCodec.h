#pragma once

#include <QByteArray>

#include <cryptobench/ipc/WireDtos.h>

namespace cryptobench::ipc {

QByteArray encodeWorkerReady(const WorkerReady& value);
WorkerReady decodeWorkerReady(const QByteArray& payload);

QByteArray encodeBenchmarkRequest(const BenchmarkRequest& value);
BenchmarkRequest decodeBenchmarkRequest(const QByteArray& payload);

QByteArray encodeBenchmarkRunRequest(const BenchmarkRunRequest& value);
BenchmarkRunRequest decodeBenchmarkRunRequest(const QByteArray& payload);

QByteArray encodeProgress(const Progress& value);
Progress decodeProgress(const QByteArray& payload);

QByteArray encodeWorkerRunMeasurement(const WorkerRunMeasurement& value);
WorkerRunMeasurement decodeWorkerRunMeasurement(const QByteArray& payload);

QByteArray encodeWorkerOutcome(const WorkerOutcome& value);
WorkerOutcome decodeWorkerOutcome(const QByteArray& payload);

} // namespace cryptobench::ipc
