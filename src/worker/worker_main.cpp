#include <QCoreApplication>

#include "WorkerSession.h"

#include <iostream>
#include <stdexcept>

namespace {

QString parseEndpoint(int argc, char* argv[])
{
    if (argc != 3 || argv[1] == nullptr || argv[2] == nullptr ||
        QString::fromLocal8Bit(argv[1]) != QStringLiteral("--ipc-endpoint")) {
        throw std::invalid_argument("expected --ipc-endpoint <sessionName>");
    }

    const auto endpoint = QString::fromLocal8Bit(argv[2]);
    if (endpoint.isEmpty()) {
        throw std::invalid_argument("IPC endpoint must not be empty");
    }
    return endpoint;
}

} // namespace

int main(int argc, char* argv[])
{
    QCoreApplication app(argc, argv);
    try {
        return cryptobench::worker::runWorkerSession(parseEndpoint(argc, argv));
    } catch (const std::exception& error) {
        std::cerr << "CryptoBenchmarkWorker bootstrap error: " << error.what() << '\n';
        return 1;
    }
}
