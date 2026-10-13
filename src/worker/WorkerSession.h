#pragma once

class QString;

namespace cryptobench::worker {

int runWorkerSession(const QString& endpoint);
int runWorkerSessionV2(const QString& endpoint);

} // namespace cryptobench::worker
