#include <QCoreApplication>
#include <QTimer>

#include <cstdlib>

int main(int argc, char* argv[])
{
    QCoreApplication application(argc, argv);
    if (argc != 3 || QString::fromLocal8Bit(argv[1]) != QStringLiteral("--ipc-endpoint") ||
        QString::fromLocal8Bit(argv[2]).isEmpty()) {
        return 2;
    }

    const auto* scenario = std::getenv("CRYPTOBENCH_TEST_WORKER_SCENARIO");
    if (scenario != nullptr && QString::fromLocal8Bit(scenario) == QStringLiteral("wait")) {
        QTimer::singleShot(60'000, &application, &QCoreApplication::quit);
        return application.exec();
    }

    return 0;
}
