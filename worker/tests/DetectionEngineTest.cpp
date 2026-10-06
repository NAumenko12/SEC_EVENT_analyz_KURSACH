#include "security_analyzer/DetectionEngine.hpp"

#include <cassert>
#include <chrono>
#include <iostream>
#include <string>

using namespace std;

static security_analyzer::NormalizedEvent failedLogin(
    const string& sourceIp,
    chrono::system_clock::time_point occurredAt
) {
    security_analyzer::NormalizedEvent event;
    event.occurredAt = occurredAt;
    event.eventType = "failed_ssh_login";
    event.outcome = "failure";
    event.sourceIp = sourceIp;
    event.message = "Неудачный SSH-вход";
    event.rawEvent = "test";
    return event;
}

int main() {
    using namespace chrono_literals;
    const auto start = chrono::system_clock::time_point{};
    const vector<security_analyzer::NormalizedEvent> events{
        failedLogin("192.0.2.10", start),
        failedLogin("192.0.2.10", start + 30s),
        failedLogin("192.0.2.20", start + 35s),
        failedLogin("192.0.2.10", start + 60s),
        failedLogin("192.0.2.10", start + 300s),
    };
    const security_analyzer::DetectionRule rule{
        7,
        "SSH_BRUTE_FORCE",
        "high",
        "Possible SSH Brute Force",
        "Много неудачных попыток входа по SSH",
        3,
        120,
        "Проверить источник соединений",
    };

    const auto findings = security_analyzer::DetectionEngine{}.analyze(
        events,
        {rule}
    );
    assert(findings.size() == 1);
    assert(findings.front().ruleId == 7);
    assert(findings.front().sourceIp == "192.0.2.10");
    assert(findings.front().eventIndexes.size() == 3);
    assert(findings.front().firstSeen == start);
    assert(findings.front().lastSeen == start + 60s);

    cout << "DetectionEngine: все проверки пройдены\n";
}
