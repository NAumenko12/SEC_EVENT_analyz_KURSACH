#pragma once

#include "security_analyzer/EventParser.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace security_analyzer {

class AuthLogParser : public EventParser {
  public:
    std::optional<NormalizedEvent> parseLine(
        std::string_view line,
        std::uint64_t lineNumber
    ) const override;

  private:
    static int monthNumber(std::string_view name);
    static std::chrono::system_clock::time_point parseTimestamp(
        std::string_view month,
        int day,
        int hour,
        int minute,
        int second
    );
    static std::uint16_t parsePort(const std::string& value);

    struct SyslogRecord {
        std::chrono::system_clock::time_point occurredAt;
        std::string hostname;
        std::string processName;
        std::string message;
    };

    std::optional<SyslogRecord> parseSyslogHeader(std::string_view line) const;
    std::optional<NormalizedEvent> parseFailedLogin(const SyslogRecord& record, std::string_view rawEvent, std::uint64_t lineNumber) const;
    std::optional<NormalizedEvent> parseSuccessfulLogin(const SyslogRecord& record,   std::string_view rawEvent,  std::uint64_t lineNumber) const;
    std::optional<NormalizedEvent> parseInvalidUser( const SyslogRecord& record, std::string_view rawEvent,std::uint64_t lineNumber ) const;
    std::optional<NormalizedEvent> parseSudoCommand(const SyslogRecord& record, std::string_view rawEvent, std::uint64_t lineNumber ) const;
    NormalizedEvent createEvent(const SyslogRecord& record, std::string_view rawEvent, std::uint64_t lineNumber ) const;
};

}  // namespace security_analyzer
