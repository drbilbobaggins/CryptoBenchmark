#include <QCoreApplication>

#include "WorkerSession.h"

#include <iostream>
#include <stdexcept>

namespace {

struct WorkerArguments {
    QString endpoint;
    bool v2 = false;
};

WorkerArguments parseArguments(int argc, char* argv[])
{
    if ((argc != 3 && argc != 4) || argv[1] == nullptr || argv[2] == nullptr ||
        QString::fromLocal8Bit(argv[1]) != QStringLiteral("--ipc-endpoint")) {
        throw std::invalid_argument("expected --ipc-endpoint <sessionName> [--ipc-v2]");
    }

    const auto endpoint = QString::fromLocal8Bit(argv[2]);
    if (endpoint.isEmpty()) {
        throw std::invalid_argument("IPC endpoint must not be empty");
    }
    if (argc == 4 && (argv[3] == nullptr || QString::fromLocal8Bit(argv[3]) != QStringLiteral("--ipc-v2"))) {
        throw std::invalid_argument("expected --ipc-v2 as the optional protocol mode");
    }
    return {endpoint, argc == 4};
}

} // namespace

int main(int argc, char* argv[])
{
    QCoreApplication app(argc, argv);
    try {
        const auto arguments = parseArguments(argc, argv);
        return arguments.v2
            ? cryptobench::worker::runWorkerSessionV2(arguments.endpoint)
            : cryptobench::worker::runWorkerSession(arguments.endpoint);
    } catch (const std::exception& error) {
        std::cerr << "CryptoBenchmarkWorker bootstrap error: " << error.what() << '\n';
        return 1;
    }
}
