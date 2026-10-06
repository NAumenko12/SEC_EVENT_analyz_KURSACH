#include "security_analyzer/AuthLogParser.hpp"

#include <array>
#include <chrono>
#include <ctime>
#include <limits>
#include <regex>
#include <stdexcept>
#include <string>

using namespace std;

namespace security_analyzer{

int AuthLogParser::monthNumber(string_view name){
    static constexpr array<string_view, 12> monthNames{ "Jan", "Feb", "Mar", "Apr", "May", "Jun","Jul", "Aug", "Sep", "Oct", "Nov", "Dec",};
    for (size_t index = 0; index < monthNames.size(); ++index) {
        if (monthNames[index] == name) {
            return static_cast<int>(index);
        }
    }
    throw invalid_argument("Неизвестный месяц в auth.log");
}

chrono::system_clock::time_point AuthLogParser::parseTimestamp( string_view month,int day, int hour,  int minute,int second){
    const time_t nowTime = time(nullptr);
    tm now{};
#if defined(_WIN32)
    localtime_s(&now, &nowTime);
#else
    localtime_r(&nowTime, &now);
#endif
    tm value{};
    value.tm_year = now.tm_year;
    value.tm_mon = monthNumber(month);
    value.tm_mday = day;
    value.tm_hour = hour;
    value.tm_min = minute;
    value.tm_sec = second;
    value.tm_isdst = -1;
    time_t parsed = mktime(&value);
    if (parsed == static_cast<time_t>(-1)) {
        throw invalid_argument("Некорректная дата в auth.log");
    }
    constexpr time_t futureTolerance = 24 * 60 * 60;
    if (parsed > nowTime + futureTolerance){
        --value.tm_year;
        value.tm_isdst = -1;
        parsed = mktime(&value);
        if (parsed == static_cast<time_t>(-1)){
            throw invalid_argument("Некорректная дата в auth.log");
        }
    }
    return chrono::system_clock::from_time_t(parsed);
}

uint16_t AuthLogParser::parsePort(const string& value){
    const unsigned long port = stoul(value);
    if (port > numeric_limits<uint16_t>::max()) {
        throw invalid_argument("Порт в auth.log находится вне диапазона");
    }
    return static_cast<uint16_t>(port);
}

optional<NormalizedEvent> AuthLogParser::parseLine(string_view line,uint64_t lineNumber) const {
    const auto record = parseSyslogHeader(line);
    if (!record.has_value()) {
        return nullopt;
    }
    if (auto event = parseFailedLogin(record.value(), line, lineNumber)) {
        return event;
    }
    if (auto event = parseSuccessfulLogin(record.value(), line, lineNumber)) {
        return event;
    }
    if (auto event = parseInvalidUser(record.value(), line, lineNumber)) {
        return event;
    }
    return parseSudoCommand(record.value(), line, lineNumber);
}

optional<AuthLogParser::SyslogRecord> AuthLogParser::parseSyslogHeader(string_view line) const {
    static const regex pattern(R"(^([A-Z][a-z]{2})\s+([0-9]{1,2})\s+([0-9]{2}):([0-9]{2}):([0-9]{2})\s+([^\s]+)\s+([^:\[]+)(?:\[[0-9]+\])?:\s+(.*)$)");
    smatch match;
    const string value(line);
    if (!regex_match(value, match, pattern)) {
        return nullopt;
    }
    return SyslogRecord{
        parseTimestamp(
            match[1].str(),
            stoi(match[2].str()),
            stoi(match[3].str()),
            stoi(match[4].str()),
            stoi(match[5].str())
        ),
        match[6].str(),
        match[7].str(),
        match[8].str(),
    };
}

optional<NormalizedEvent> AuthLogParser::parseFailedLogin(const SyslogRecord& record,string_view rawEvent,uint64_t lineNumber ) const {
    static const regex pattern(R"(^Failed\s+\S+\s+for\s+(invalid user\s+)?(\S+)\s+from\s+(\S+)\s+port\s+([0-9]+)(?:\s+.*)?$)");
    smatch match;
    if (!regex_match(record.message, match, pattern)) {
        return nullopt;
    }

    auto event = createEvent(record, rawEvent, lineNumber);
    const bool invalidUser = match[1].matched;
    event.eventType = invalidUser ? "invalid_user_login" : "failed_ssh_login";
    event.severity = invalidUser ? "high" : "medium";
    event.outcome = "failure";
    event.username = match[2].str();
    event.sourceIp = match[3].str();
    event.sourcePort = parsePort(match[4].str());
    event.message = invalidUser ? "Неудачный SSH-вход неизвестного пользователя" : "Неудачный SSH-вход";
    return event;
}

optional<NormalizedEvent> AuthLogParser::parseSuccessfulLogin( const SyslogRecord& record, string_view rawEvent, uint64_t lineNumber) const {
    static const regex pattern( R"(^Accepted\s+\S+\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+([0-9]+)(?:\s+.*)?$)");
    smatch match;
    if (!regex_match(record.message, match, pattern)) {
        return nullopt;
    }
    auto event = createEvent(record, rawEvent, lineNumber);
    event.eventType = "successful_ssh_login";
    event.outcome = "success";
    event.username = match[1].str();
    event.sourceIp = match[2].str();
    event.sourcePort = parsePort(match[3].str());
    event.message = "Успешный SSH-вход";
    return event;
}

optional<NormalizedEvent> AuthLogParser::parseInvalidUser(const SyslogRecord& record,string_view rawEvent,uint64_t lineNumber) const {
    static const regex pattern(R"(^Invalid user\s+(\S+)\s+from\s+(\S+)(?:\s+port\s+([0-9]+))?(?:\s+.*)?$)");
    smatch match;
    if (!regex_match(record.message, match, pattern)) {
        return nullopt;
    }
    auto event = createEvent(record, rawEvent, lineNumber);
    event.eventType = "invalid_user_login";
    event.severity = "high";
    event.outcome = "failure";
    event.username = match[1].str();
    event.sourceIp = match[2].str();
    if (match[3].matched) {
        event.sourcePort = parsePort(match[3].str());
    }
    event.message = "Попытка входа неизвестного пользователя";
    return event;
}

optional<NormalizedEvent> AuthLogParser::parseSudoCommand(const SyslogRecord& record,string_view rawEvent,  uint64_t lineNumber) const {
    if (record.processName != "sudo") {
        return nullopt;
    }
    static const regex pattern(R"(^([^\s:]+)\s*:\s+.*COMMAND=(.*)$)");
    smatch match;
    if (!regex_match(record.message, match, pattern)) {
        return nullopt;
    }
    auto event = createEvent(record, rawEvent, lineNumber);
    event.eventType = "sudo_command";
    event.severity = "low";
    event.outcome = "success";
    event.username = match[1].str();
    event.message = "Выполнена команда sudo: " + match[2].str();
    return event;
}

NormalizedEvent AuthLogParser::createEvent(const SyslogRecord& record,string_view rawEvent,uint64_t lineNumber) const {
    NormalizedEvent event;
    event.occurredAt = record.occurredAt;
    event.hostname = record.hostname;
    event.processName = record.processName;
    event.rawEvent = rawEvent;
    event.sourceLineNumber = lineNumber;
    return event;
}

}  // namespace security_analyzer
