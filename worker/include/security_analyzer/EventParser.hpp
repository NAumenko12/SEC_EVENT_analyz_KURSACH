#pragma once

#include "security_analyzer/NormalizedEvent.hpp"

#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

namespace security_analyzer {

struct ParseResult {
    std::uint64_t processedRecords{};
    std::vector<NormalizedEvent> events;
};

class EventParser {
  public:
    virtual ~EventParser() = default;
    virtual std::optional<NormalizedEvent> parseLine(std::string_view line, std::uint64_t lineNumber ) const = 0;
};

}  // namespace security_analyzer
