#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>

namespace security_analyzer {

struct NormalizedEvent {
    std::chrono::system_clock::time_point occurredAt{};
    std::string eventType;
    std::string severity{"info"};
    std::optional<std::string> outcome;
    std::optional<std::string> sourceIp;
    std::optional<std::string> destinationIp;
    std::optional<std::uint16_t> sourcePort;
    std::optional<std::uint16_t> destinationPort;
    std::optional<std::string> hostname;
    std::optional<std::string> username;
    std::optional<std::string> processName;
    std::string message;
    std::string rawEvent;
    std::uint64_t sourceLineNumber{};
};

}  // namespace security_analyzer
