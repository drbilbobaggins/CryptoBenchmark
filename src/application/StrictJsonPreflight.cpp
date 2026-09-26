#include <cryptobench/application/StrictJsonPreflight.h>

#include <QSet>
#include <QString>

namespace cryptobench::application {
namespace {

constexpr int kMaximumNestingDepth = 512;

class JsonPreflightParser {
public:
    explicit JsonPreflightParser(const QByteArray& bytes)
        : bytes_(bytes)
    {
    }

    std::optional<BatchInputIssue> parse(std::vector<JsonNumberToken>* numberTokens = nullptr)
    {
        numberTokens_ = numberTokens;
        skipWhitespace();
        if (!parseValue({})) {
            return issue_;
        }
        skipWhitespace();
        if (position_ != bytes_.size()) {
            invalid("unexpected data after top-level JSON value");
            return issue_;
        }
        return std::nullopt;
    }

private:
    bool parseValue(const QString& path)
    {
        if (position_ >= bytes_.size()) {
            return invalid("expected JSON value");
        }
        if (bytes_[position_] == '{') {
            return parseObject(path);
        }
        if (bytes_[position_] == '[') {
            return parseArray(path);
        }
        if (bytes_[position_] == '"') {
            QString value;
            return parseString(value);
        }
        if (bytes_[position_] == 't') {
            return consumeLiteral("true");
        }
        if (bytes_[position_] == 'f') {
            return consumeLiteral("false");
        }
        if (bytes_[position_] == 'n') {
            return consumeLiteral("null");
        }
        if (bytes_[position_] == '-' || (bytes_[position_] >= '0' && bytes_[position_] <= '9')) {
            return parseNumber(path);
        }
        return invalid("expected JSON value");
    }

    bool parseObject(const QString& path)
    {
        if (!enterContainer()) {
            return false;
        }
        ++position_;
        skipWhitespace();
        QSet<QString> keys;
        if (consume('}')) {
            leaveContainer();
            return true;
        }

        while (true) {
            if (position_ >= bytes_.size() || bytes_[position_] != '"') {
                leaveContainer();
                return invalid("expected JSON object member name");
            }
            QString key;
            if (!parseString(key)) {
                leaveContainer();
                return false;
            }
            const auto memberPath = appendPath(path, key);
            if (keys.contains(key)) {
                leaveContainer();
                issue_ = {BatchInputIssueCode::DuplicateKey,
                          memberPath.toStdString(),
                          "duplicate JSON object member name",
                          std::nullopt};
                return false;
            }
            keys.insert(key);
            skipWhitespace();
            if (!consume(':')) {
                leaveContainer();
                return invalid("expected ':' after JSON object member name");
            }
            skipWhitespace();
            if (!parseValue(memberPath)) {
                leaveContainer();
                return false;
            }
            skipWhitespace();
            if (consume('}')) {
                leaveContainer();
                return true;
            }
            if (!consume(',')) {
                leaveContainer();
                return invalid("expected ',' or '}' after JSON object member");
            }
            skipWhitespace();
        }
    }

    bool parseArray(const QString& path)
    {
        if (!enterContainer()) {
            return false;
        }
        ++position_;
        skipWhitespace();
        if (consume(']')) {
            leaveContainer();
            return true;
        }

        qsizetype index = 0;
        while (true) {
            if (!parseValue(appendPath(path, QString::number(index)))) {
                leaveContainer();
                return false;
            }
            ++index;
            skipWhitespace();
            if (consume(']')) {
                leaveContainer();
                return true;
            }
            if (!consume(',')) {
                leaveContainer();
                return invalid("expected ',' or ']' after JSON array value");
            }
            skipWhitespace();
        }
    }

    bool parseString(QString& value)
    {
        value.clear();
        ++position_;
        while (position_ < bytes_.size()) {
            const auto byte = static_cast<unsigned char>(bytes_[position_]);
            if (byte == '"') {
                ++position_;
                return true;
            }
            if (byte < 0x20U) {
                return invalid("unescaped control character in JSON string");
            }
            if (byte == '\\') {
                if (!parseEscape(value)) {
                    return false;
                }
                continue;
            }
            const auto length = utf8SequenceLength(byte);
            if (length == 0 || position_ + length > bytes_.size()) {
                return invalid("invalid UTF-8 sequence in JSON string");
            }
            value.append(QString::fromUtf8(bytes_.constData() + position_, length));
            position_ += length;
        }
        return invalid("unterminated JSON string");
    }

    bool parseEscape(QString& value)
    {
        ++position_;
        if (position_ >= bytes_.size()) {
            return invalid("truncated JSON string escape");
        }
        switch (bytes_[position_]) {
        case '"':
            value.append('"');
            ++position_;
            return true;
        case '\\':
            value.append('\\');
            ++position_;
            return true;
        case '/':
            value.append('/');
            ++position_;
            return true;
        case 'b':
            value.append('\b');
            ++position_;
            return true;
        case 'f':
            value.append('\f');
            ++position_;
            return true;
        case 'n':
            value.append('\n');
            ++position_;
            return true;
        case 'r':
            value.append('\r');
            ++position_;
            return true;
        case 't':
            value.append('\t');
            ++position_;
            return true;
        case 'u':
            return parseUnicodeEscape(value);
        default:
            return invalid("invalid JSON string escape");
        }
    }

    bool parseUnicodeEscape(QString& value)
    {
        const auto first = parseHexQuad();
        if (!first.has_value()) {
            return false;
        }
        if (*first >= 0xDC00U && *first <= 0xDFFFU) {
            return invalid("unpaired low surrogate in JSON string escape");
        }
        if (*first >= 0xD800U && *first <= 0xDBFFU) {
            if (position_ + 1 >= bytes_.size() || bytes_[position_] != '\\' || bytes_[position_ + 1] != 'u') {
                return invalid("high surrogate is not followed by a low surrogate");
            }
            position_ += 1;
            const auto second = parseHexQuad();
            if (!second.has_value() || *second < 0xDC00U || *second > 0xDFFFU) {
                return invalid("invalid low surrogate in JSON string escape");
            }
            const auto codePoint = 0x10000U + ((*first - 0xD800U) << 10U) + (*second - 0xDC00U);
            value.append(QString::fromUcs4(&codePoint, 1));
            return true;
        }
        const auto codePoint = static_cast<uint>(*first);
        value.append(QChar::fromUcs2(static_cast<ushort>(codePoint)));
        return true;
    }

    std::optional<unsigned int> parseHexQuad()
    {
        if (position_ + 4 >= bytes_.size()) {
            invalid("truncated Unicode escape in JSON string");
            return std::nullopt;
        }
        unsigned int value = 0;
        for (int offset = 1; offset <= 4; ++offset) {
            const auto digit = hexValue(bytes_[position_ + offset]);
            if (!digit.has_value()) {
                invalid("invalid Unicode escape in JSON string");
                return std::nullopt;
            }
            value = (value << 4U) | *digit;
        }
        position_ += 5;
        return value;
    }

    bool parseNumber(const QString& path)
    {
        const auto numberStart = position_;
        if (consume('-') && position_ >= bytes_.size()) {
            return invalid("truncated JSON number");
        }
        if (consume('0')) {
            if (position_ < bytes_.size() && bytes_[position_] >= '0' && bytes_[position_] <= '9') {
                return invalid("leading zero in JSON number");
            }
        } else {
            if (position_ >= bytes_.size() || bytes_[position_] < '1' || bytes_[position_] > '9') {
                return invalid("invalid JSON number");
            }
            while (position_ < bytes_.size() && bytes_[position_] >= '0' && bytes_[position_] <= '9') {
                ++position_;
            }
        }
        if (consume('.')) {
            if (position_ >= bytes_.size() || bytes_[position_] < '0' || bytes_[position_] > '9') {
                return invalid("JSON number fraction has no digits");
            }
            while (position_ < bytes_.size() && bytes_[position_] >= '0' && bytes_[position_] <= '9') {
                ++position_;
            }
        }
        if (position_ < bytes_.size() && (bytes_[position_] == 'e' || bytes_[position_] == 'E')) {
            ++position_;
            if (position_ < bytes_.size() && (bytes_[position_] == '+' || bytes_[position_] == '-')) {
                ++position_;
            }
            if (position_ >= bytes_.size() || bytes_[position_] < '0' || bytes_[position_] > '9') {
                return invalid("JSON number exponent has no digits");
            }
            while (position_ < bytes_.size() && bytes_[position_] >= '0' && bytes_[position_] <= '9') {
                ++position_;
            }
        }
        if (numberTokens_ != nullptr) {
            numberTokens_->push_back(
                {path.toStdString(), bytes_.mid(numberStart, position_ - numberStart), numberStart, position_});
        }
        return true;
    }

    bool consumeLiteral(const char* literal)
    {
        const auto length = static_cast<qsizetype>(std::char_traits<char>::length(literal));
        if (position_ + length > bytes_.size()
            || QByteArray::fromRawData(bytes_.constData() + position_, length) != literal) {
            return invalid("invalid JSON literal");
        }
        position_ += length;
        return true;
    }

    bool consume(char expected)
    {
        if (position_ < bytes_.size() && bytes_[position_] == expected) {
            ++position_;
            return true;
        }
        return false;
    }

    void skipWhitespace()
    {
        while (position_ < bytes_.size() && (bytes_[position_] == ' ' || bytes_[position_] == '\t'
                                              || bytes_[position_] == '\r' || bytes_[position_] == '\n')) {
            ++position_;
        }
    }

    bool enterContainer()
    {
        if (++depth_ > kMaximumNestingDepth) {
            return invalid("JSON nesting depth exceeds the supported limit");
        }
        return true;
    }

    void leaveContainer()
    {
        --depth_;
    }

    bool invalid(const char* message)
    {
        issue_ = {BatchInputIssueCode::InvalidJson, {}, message, std::nullopt};
        return false;
    }

    static QString appendPath(const QString& path, const QString& segment)
    {
        QString escaped = segment;
        escaped.replace('~', "~0");
        escaped.replace('/', "~1");
        return path + '/' + escaped;
    }

    static int utf8SequenceLength(unsigned char first)
    {
        if (first <= 0x7FU) {
            return 1;
        }
        if (first >= 0xC2U && first <= 0xDFU) {
            return 2;
        }
        if (first >= 0xE0U && first <= 0xEFU) {
            return 3;
        }
        if (first >= 0xF0U && first <= 0xF4U) {
            return 4;
        }
        return 0;
    }

    static std::optional<unsigned int> hexValue(char value)
    {
        if (value >= '0' && value <= '9') {
            return static_cast<unsigned int>(value - '0');
        }
        if (value >= 'a' && value <= 'f') {
            return static_cast<unsigned int>(value - 'a' + 10);
        }
        if (value >= 'A' && value <= 'F') {
            return static_cast<unsigned int>(value - 'A' + 10);
        }
        return std::nullopt;
    }

    const QByteArray& bytes_;
    qsizetype position_ = 0;
    int depth_ = 0;
    std::optional<BatchInputIssue> issue_;
    std::vector<JsonNumberToken>* numberTokens_ = nullptr;
};

} // namespace

std::optional<BatchInputIssue> strictJsonPreflight(const QByteArray& utf8Bytes)
{
    return JsonPreflightParser(utf8Bytes).parse();
}

JsonNumberTokenResult inspectJsonNumberTokens(const QByteArray& utf8Bytes)
{
    std::vector<JsonNumberToken> numberTokens;
    if (const auto issue = JsonPreflightParser(utf8Bytes).parse(&numberTokens); issue.has_value()) {
        return *issue;
    }
    return numberTokens;
}

} // namespace cryptobench::application
