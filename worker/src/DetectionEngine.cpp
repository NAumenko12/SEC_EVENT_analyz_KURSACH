#include "security_analyzer/DetectionEngine.hpp"

#include <algorithm>
#include <chrono>
#include <map>
#include <sstream>
#include <string>
#include <utility>

using namespace std;

namespace security_analyzer {
bool DetectionEngine::isFailedSshLogin(const NormalizedEvent& event){
    return event.sourceIp.has_value() && (event.eventType == "failed_ssh_login" || event.eventType == "invalid_user_login");
}
vector<FindingCandidate> DetectionEngine::analyze(const vector<NormalizedEvent>& events,const vector<DetectionRule>& rules) const { 
    vector<FindingCandidate> findings;
    for (const auto& rule : rules) {
        if (rule.code != "SSH_BRUTE_FORCE") {
            continue;
        }
        auto detected = detectSshBruteForce(events, rule);
        findings.insert( findings.end(), make_move_iterator(detected.begin()), make_move_iterator(detected.end()));
    }
    return findings;
}

vector<FindingCandidate> DetectionEngine::detectSshBruteForce(const vector<NormalizedEvent>& events,const DetectionRule& rule) const {
    map<string, vector<size_t>> eventsByAddress;
    for (size_t index = 0; index < events.size(); ++index) {
        if (isFailedSshLogin(events[index])) {
            eventsByAddress[events[index].sourceIp.value()].push_back(index);
        }
    }
    vector<FindingCandidate> findings;
    const auto window = chrono::seconds(rule.timeWindowSeconds);
    for (auto& [sourceIp, indexes] : eventsByAddress) {
        sort(indexes.begin(),indexes.end(),[&events](size_t left, size_t right) {
                return events[left].occurredAt < events[right].occurredAt;
            }
        );
        size_t left = 0;
        size_t bestLeft = 0;
        size_t bestRight = 0;
        size_t bestSize = 0;
        for (size_t right = 0; right < indexes.size(); ++right) {
            while (events[indexes[right]].occurredAt - events[indexes[left]].occurredAt > window) {
                ++left;
            }
            const size_t currentSize = right - left + 1;
            if (currentSize > bestSize) {
                bestLeft = left;
                bestRight = right;
                bestSize = currentSize;
            }
        }

        if (bestSize < static_cast<size_t>(rule.thresholdValue)) {
            continue;
        }

        vector<size_t> relatedEvents( indexes.begin() + static_cast<ptrdiff_t>(bestLeft), indexes.begin() + static_cast<ptrdiff_t>(bestRight + 1));
        ostringstream description;
        description << "Обнаружено " << relatedEvents.size() << " неудачных попыток SSH-входа с адреса "<< sourceIp << " за " << rule.timeWindowSeconds<< " секунд";
        findings.push_back(FindingCandidate{
            rule.id,
            rule.severity,
            "Возможный перебор пароля SSH",
            description.str(),
            sourceIp,
            nullopt,
            nullopt,
            events[relatedEvents.front()].occurredAt,
            events[relatedEvents.back()].occurredAt,
            rule.recommendation,
            move(relatedEvents),
        });
    }
    return findings;
}

}  // namespace security_analyzer
