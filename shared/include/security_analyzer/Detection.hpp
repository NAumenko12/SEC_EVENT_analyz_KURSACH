#pragma once

#include <chrono>
#include <cstddef>
#include <optional>
#include <string>
#include <vector>

namespace security_analyzer {

struct DetectionRule {
    long long id;
    std::string code;
    std::string severity;
    std::string name;
    std::string description;
    int thresholdValue;
    int timeWindowSeconds;
    std::optional<std::string> recommendation;
};

struct FindingCandidate {
    long long ruleId;
    std::string severity;
    std::string title;
    std::string description;
    std::optional<std::string> sourceIp;
    std::optional<std::string> destinationIp;
    std::optional<std::string> username;
    std::chrono::system_clock::time_point firstSeen;
    std::chrono::system_clock::time_point lastSeen;
    std::optional<std::string> recommendation;
    std::vector<std::size_t> eventIndexes;
};

}  // namespace security_analyzer
