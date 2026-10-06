#pragma once

#include "security_analyzer/Detection.hpp"
#include "security_analyzer/NormalizedEvent.hpp"

#include <vector>

namespace security_analyzer {

class DetectionEngine {
  public:
    std::vector<FindingCandidate> analyze( const std::vector<NormalizedEvent>& events, const std::vector<DetectionRule>& rules) const;
  private:
    static bool isFailedSshLogin(const NormalizedEvent& event);
    std::vector<FindingCandidate> detectSshBruteForce( const std::vector<NormalizedEvent>& events, const DetectionRule& rule) const;
};

}  // namespace security_analyzer
