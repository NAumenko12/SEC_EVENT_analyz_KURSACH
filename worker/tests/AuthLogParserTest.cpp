#include "security_analyzer/AuthLogParser.hpp"
#include "security_analyzer/ParserFactory.hpp"
#include "security_analyzer/TextLogReader.hpp"

#include <cassert>
#include <iostream>
#include <stdexcept>

using namespace std;

int main() {
    const security_analyzer::AuthLogParser parser;

    const auto failed = parser.parseLine(
        "Sep 29 18:01:12 server sshd[4201]: Failed password for root from 192.0.2.10 port 51234 ssh2",
        1
    );
    assert(failed.has_value());
    assert(failed->eventType == "failed_ssh_login");
    assert(failed->outcome == "failure");
    assert(failed->username == "root");
    assert(failed->sourceIp == "192.0.2.10");
    assert(failed->sourcePort == 51234);
    assert(failed->hostname == "server");
    assert(failed->processName == "sshd");
    assert(failed->sourceLineNumber == 1);

    const auto invalid = parser.parseLine(
        "Sep 29 18:02:00 server sshd[4202]: Failed password for invalid user admin from 2001:db8::10 port 40000 ssh2",
        2
    );
    assert(invalid.has_value());
    assert(invalid->eventType == "invalid_user_login");
    assert(invalid->severity == "high");
    assert(invalid->sourceIp == "2001:db8::10");

    const auto accepted = parser.parseLine(
        "Sep 29 18:03:00 server sshd[4203]: Accepted publickey for analyst from 192.0.2.20 port 51235 ssh2",
        3
    );
    assert(accepted.has_value());
    assert(accepted->eventType == "successful_ssh_login");
    assert(accepted->outcome == "success");

    const auto sudo = parser.parseLine(
        "Sep 29 18:04:00 server sudo: analyst : TTY=pts/0 ; PWD=/home/analyst ; USER=root ; COMMAND=/usr/bin/id",
        4
    );
    assert(sudo.has_value());
    assert(sudo->eventType == "sudo_command");
    assert(sudo->username == "analyst");
    assert(sudo->message == "Выполнена команда sudo: /usr/bin/id");

    const auto ignored = parser.parseLine(
        "Sep 29 18:05:00 server systemd[1]: Started Daily Cleanup.",
        5
    );
    assert(!ignored.has_value());

    const auto selectedParser = security_analyzer::createParser("auth_log");
    const auto parsed = security_analyzer::parseTextLog(
        "worker/tests/fixtures/auth.log",
        *selectedParser
    );
    assert(parsed.processedRecords == 5);
    assert(parsed.events.size() == 4);

    bool unsupportedTypeRejected = false;
    try {
        security_analyzer::createParser("nginx_access");
    } catch (const invalid_argument&) {
        unsupportedTypeRejected = true;
    }
    assert(unsupportedTypeRejected);

    cout << "AuthLogParser: все проверки пройдены\n";
}
