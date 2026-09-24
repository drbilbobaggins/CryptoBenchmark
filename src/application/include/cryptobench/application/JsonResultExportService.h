#pragma once

#include <QByteArray>

#include <cryptobench/application/ResultDocument.h>

namespace cryptobench::application {

class JsonResultExportService {
public:
    QByteArray serialize(const ResultDocument& document) const;
};

} // namespace cryptobench::application
