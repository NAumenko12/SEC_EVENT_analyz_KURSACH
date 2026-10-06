#include "security_analyzer/Database.hpp"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <utility>

using namespace std;

namespace security_analyzer {
runtime_error Database::connectionError(PGconn* connection) {
    const char* message = connection == nullptr ? "PostgreSQL connection could not be created" : PQerrorMessage(connection);
    return runtime_error(message);
}

runtime_error Database::resultError(PGresult* result, PGconn* connection) {
    if (result != nullptr) {
        const char* message = PQresultErrorMessage(result);
        if (message != nullptr && message[0] != '\0') {
            return runtime_error(message);
        }
    }
    return connectionError(connection);
}

string Database::timestampValue(
    const chrono::system_clock::time_point& timestamp
) {
    const time_t raw = chrono::system_clock::to_time_t(timestamp);
    tm utc{};
#if defined(_WIN32)
    gmtime_s(&utc, &raw);
#else
    gmtime_r(&raw, &utc);
#endif
    ostringstream output;
    output << put_time(&utc, "%Y-%m-%dT%H:%M:%SZ");
    return output.str();
}
Database::Database(Config config) : config_(move(config)) {
}

Database::~Database(){
    if (connection_ != nullptr){
        PQfinish(connection_);
    }
}

void Database::connect(){
    if (connection_ != nullptr){
        PQfinish(connection_);
        connection_ = nullptr;
    }
    const char* keywords[] ={
        "host",
        "port",
        "dbname",
        "user",
        "password",
        "connect_timeout",
        "application_name",
        nullptr,
    };
    const char* values[] ={
        config_.host.c_str(),
        config_.port.c_str(),
        config_.databaseName.c_str(),
        config_.user.c_str(),
        config_.password.c_str(),
        "3",
        config_.applicationName.c_str(),
        nullptr,
    };
    connection_ = PQconnectdbParams(keywords, values, 0);
    if (connection_ == nullptr || PQstatus(connection_) != CONNECTION_OK){
        throw connectionError(connection_);
    }
}

void Database::ensureConnected(){
    if (connection_ == nullptr || PQstatus(connection_) != CONNECTION_OK){
        connect();
    }
}
vector<SourceType> Database::getSourceTypes(){
    lock_guard<mutex> lock(mutex_);
    ensureConnected();
    ResultPtr result(
        PQexec(
            connection_,
            "SELECT code, name, description "
            "FROM source_types "
            "ORDER BY name"
        ), &PQclear
    );
    if (result == nullptr || PQresultStatus(result.get()) != PGRES_TUPLES_OK){
        throw connectionError(connection_);
    }
    const int codeColumn = PQfnumber(result.get(), "code");
    const int nameColumn = PQfnumber(result.get(), "name");
    const int descriptionColumn = PQfnumber(result.get(), "description");
    if (codeColumn < 0 || nameColumn < 0 || descriptionColumn < 0) {
        throw runtime_error("PostgreSQL returned an unexpected result");
    }
    vector<SourceType> sourceTypes;
    sourceTypes.reserve(static_cast<size_t>(PQntuples(result.get())));
    for (int row = 0; row < PQntuples(result.get()); ++row) {
        SourceType sourceType{
            PQgetvalue(result.get(), row, codeColumn),
            PQgetvalue(result.get(), row, nameColumn),
            nullopt,
        };
        if (PQgetisnull(result.get(), row, descriptionColumn) == 0) {
            sourceType.description =
                PQgetvalue(result.get(), row, descriptionColumn);
        }
        sourceTypes.push_back(move(sourceType));
    }
    return sourceTypes;
}

User Database::createUser(
    const string& username,
    const string& email,
    const string& passwordHash
) {
    lock_guard<mutex> lock(mutex_);
    ensureConnected();
    const char* values[]{username.c_str(), email.c_str(), passwordHash.c_str()};
    ResultPtr result(
        PQexecParams(
            connection_,
            "INSERT INTO users (username, email, password_hash) "
            "VALUES ($1, $2, $3) "
            "RETURNING id, username, email, fk_role_code",
            3, nullptr, values, nullptr, nullptr, 0
        ),
        &PQclear
    );
    if (result == nullptr || PQresultStatus(result.get()) != PGRES_TUPLES_OK) {
        const char* state = result == nullptr
            ? nullptr
            : PQresultErrorField(result.get(), PG_DIAG_SQLSTATE);
        if (state != nullptr && string(state) == "23505") {
            throw DatabaseConflictError(
                "Пользователь с таким именем или email уже существует"
            );
        }
        throw resultError(result.get(), connection_);
    }
    return User{
        stoll(PQgetvalue(result.get(), 0, 0)),
        PQgetvalue(result.get(), 0, 1),
        PQgetvalue(result.get(), 0, 2),
        PQgetvalue(result.get(), 0, 3),
    };
}

optional<UserCredentials> Database::findUserByLogin(
    const string& login
) {
    lock_guard<mutex> lock(mutex_);
    ensureConnected();
    const char* values[]{login.c_str()};
    ResultPtr result(
        PQexecParams(
            connection_,
            "SELECT id, username, email, fk_role_code, password_hash, is_active "
            "FROM users "
            "WHERE lower(username) = lower($1) OR lower(email) = lower($1) "
            "LIMIT 1",
            1, nullptr, values, nullptr, nullptr, 0
        ),
        &PQclear
    );
    if (result == nullptr || PQresultStatus(result.get()) != PGRES_TUPLES_OK) {
        throw resultError(result.get(), connection_);
    }
    if (PQntuples(result.get()) == 0) {
        return nullopt;
    }
    return UserCredentials{
        User{
            stoll(PQgetvalue(result.get(), 0, 0)),
            PQgetvalue(result.get(), 0, 1),
            PQgetvalue(result.get(), 0, 2),
            PQgetvalue(result.get(), 0, 3),
        },
        PQgetvalue(result.get(), 0, 4),
        string(PQgetvalue(result.get(), 0, 5)) == "t",
    };
}

void Database::createSession(
    long long userId,
    const string& tokenHash,
    long long lifetimeSeconds
) {
    lock_guard<mutex> lock(mutex_);
    ensureConnected();
    const string id = to_string(userId);
    const string lifetime = to_string(lifetimeSeconds);
    const char* values[]{id.c_str(), tokenHash.c_str(), lifetime.c_str()};
    ResultPtr result(
        PQexecParams(
            connection_,
            "INSERT INTO user_sessions (fk_user_id, token_hash, expires_at) "
            "VALUES ($1::BIGINT, $2, "
            "        CURRENT_TIMESTAMP + ($3::BIGINT * INTERVAL '1 second'))",
            3, nullptr, values, nullptr, nullptr, 0
        ),
        &PQclear
    );
    if (result == nullptr || PQresultStatus(result.get()) != PGRES_COMMAND_OK) {
        throw resultError(result.get(), connection_);
    }
}

optional<User> Database::findUserBySessionTokenHash(
    const string& tokenHash
) {
    lock_guard<mutex> lock(mutex_);
    ensureConnected();
    const char* values[]{tokenHash.c_str()};
    ResultPtr result(
        PQexecParams(
            connection_,
            "SELECT users.id, users.username, users.email, users.fk_role_code "
            "FROM user_sessions "
            "JOIN users ON users.id = user_sessions.fk_user_id "
            "WHERE user_sessions.token_hash = $1 "
            "  AND user_sessions.revoked_at IS NULL "
            "  AND user_sessions.expires_at > CURRENT_TIMESTAMP "
            "  AND users.is_active = TRUE",
            1, nullptr, values, nullptr, nullptr, 0
        ),
        &PQclear
    );
    if (result == nullptr || PQresultStatus(result.get()) != PGRES_TUPLES_OK) {
        throw resultError(result.get(), connection_);
    }
    if (PQntuples(result.get()) == 0) {
        return nullopt;
    }
    return User{
        stoll(PQgetvalue(result.get(), 0, 0)),
        PQgetvalue(result.get(), 0, 1),
        PQgetvalue(result.get(), 0, 2),
        PQgetvalue(result.get(), 0, 3),
    };
}

void Database::revokeSession(const string& tokenHash) {
    lock_guard<mutex> lock(mutex_);
    ensureConnected();
    const char* values[]{tokenHash.c_str()};
    ResultPtr result(
        PQexecParams(
            connection_,
            "UPDATE user_sessions SET revoked_at = CURRENT_TIMESTAMP "
            "WHERE token_hash = $1 AND revoked_at IS NULL",
            1, nullptr, values, nullptr, nullptr, 0
        ),
        &PQclear
    );
    if (result == nullptr || PQresultStatus(result.get()) != PGRES_COMMAND_OK) {
        throw resultError(result.get(), connection_);
    }
}

CreatedAnalysisJob Database::createUploadAndJob(
    long long userId,
    const UploadData& upload
) {
    lock_guard<mutex> lock(mutex_);
    ensureConnected();
    const string sizeBytes = to_string(upload.sizeBytes);
    const string user = to_string(userId);
    const char* values[] = {
        user.c_str(),
        upload.sourceTypeCode.c_str(),
        upload.originalFilename.c_str(),
        upload.storedFilename.c_str(),
        upload.filePath.c_str(),
        upload.mimeType.c_str(),
        sizeBytes.c_str(),
        upload.sha256.c_str(),
    };
    ResultPtr result(
        PQexecParams(
            connection_,
            "WITH new_upload AS ("
            "    INSERT INTO uploads ("
            "        fk_user_id, fk_source_type_code, original_filename, "
            "        stored_filename, file_path, mime_type, size_bytes, sha256"
            "    ) VALUES ("
            "        $1::BIGINT, $2, $3, $4, $5, $6, $7::BIGINT, $8"
            "    ) "
            "    RETURNING id"
            "), new_job AS ("
            "    INSERT INTO analysis_jobs (fk_upload_id) "
            "    SELECT id FROM new_upload "
            "    RETURNING id, fk_upload_id"
            "), history AS ("
            "    INSERT INTO job_status_history ("
            "        fk_job_id, fk_old_status_code, fk_new_status_code, message"
            "    ) "
            "    SELECT id, NULL, 'queued', 'Задание создано' FROM new_job "
            "    RETURNING fk_job_id"
            ") "
            "SELECT id, fk_upload_id FROM new_job "
            "WHERE EXISTS (SELECT 1 FROM history)",
            8,
            nullptr,
            values,
            nullptr,
            nullptr,
            0
        ),
        &PQclear
    );

    if (result == nullptr || PQresultStatus(result.get()) != PGRES_TUPLES_OK) {
        throw connectionError(connection_);
    }
    if (PQntuples(result.get()) != 1) {
        throw runtime_error("Не удалось создать задание анализа");
    }
    const int jobIdColumn = PQfnumber(result.get(), "id");
    const int uploadIdColumn = PQfnumber(result.get(), "fk_upload_id");
    if (jobIdColumn < 0 || uploadIdColumn < 0){
        throw runtime_error("PostgreSQL returned an unexpected result");
    }
    return CreatedAnalysisJob{
        stoll(PQgetvalue(result.get(), 0, uploadIdColumn)),
        stoll(PQgetvalue(result.get(), 0, jobIdColumn)),
    };
}

optional<AnalysisJob> Database::getAnalysisJob(
    long long jobId,
    long long userId
) {
    lock_guard<mutex> lock(mutex_);
    ensureConnected();
    const string id = to_string(jobId);
    const string user = to_string(userId);
    const char* values[]{id.c_str(), user.c_str()};
    ResultPtr result(
        PQexecParams(
            connection_,
            "SELECT job.id, job.fk_upload_id, job.fk_status_code, job.progress, "
            "job.processed_records, job.events_created, job.findings_created, "
            "job.error_message "
            "FROM analysis_jobs AS job "
            "JOIN uploads AS upload ON upload.id = job.fk_upload_id "
            "WHERE job.id = $1::BIGINT AND upload.fk_user_id = $2::BIGINT",
            2, nullptr, values, nullptr, nullptr, 0
        ),
        &PQclear
    );
    if (result == nullptr || PQresultStatus(result.get()) != PGRES_TUPLES_OK) {
        throw connectionError(connection_);
    }
    if (PQntuples(result.get()) == 0) {
        return nullopt;
    }

    AnalysisJob job{
        stoll(PQgetvalue(result.get(), 0, 0)),
        stoll(PQgetvalue(result.get(), 0, 1)),
        PQgetvalue(result.get(), 0, 2),
        stoi(PQgetvalue(result.get(), 0, 3)),
        stoll(PQgetvalue(result.get(), 0, 4)),
        stoll(PQgetvalue(result.get(), 0, 5)),
        stoi(PQgetvalue(result.get(), 0, 6)),
        nullopt,
    };
    if (PQgetisnull(result.get(), 0, 7) == 0) {
        job.errorMessage = PQgetvalue(result.get(), 0, 7);
    }
    return job;
}

optional<AnalysisTask> Database::startAnalysisJob(long long jobId) {
    lock_guard<mutex> lock(mutex_);
    ensureConnected();
    const string id = to_string(jobId);
    const char* values[]{id.c_str()};
    ResultPtr result( PQexecParams( connection_,
            "WITH changed AS ("
            "    UPDATE analysis_jobs SET "
            "        fk_status_code = 'processing', progress = 1, "
            "        error_message = NULL, started_at = CURRENT_TIMESTAMP, "
            "        finished_at = NULL "
            "    WHERE id = $1::BIGINT AND fk_status_code = 'queued' "
            "    RETURNING id, fk_upload_id"
            "), history AS ("
            "    INSERT INTO job_status_history ("
            "        fk_job_id, fk_old_status_code, fk_new_status_code, message"
            "    ) "
            "    SELECT id, 'queued', 'processing', 'Worker начал обработку' "
            "    FROM changed RETURNING fk_job_id"
            ") "
            "SELECT changed.id, changed.fk_upload_id, "
            "       uploads.fk_source_type_code, uploads.file_path "
            "FROM changed JOIN uploads ON uploads.id = changed.fk_upload_id "
            "WHERE EXISTS (SELECT 1 FROM history)",
            1, nullptr, values, nullptr, nullptr, 0
        ),
        &PQclear
    );
    if (result == nullptr || PQresultStatus(result.get()) != PGRES_TUPLES_OK) {
        throw connectionError(connection_);
    }
    if (PQntuples(result.get()) == 0) {
        return nullopt;
    }
    return AnalysisTask{
        stoll(PQgetvalue(result.get(), 0, 0)),
        stoll(PQgetvalue(result.get(), 0, 1)),
        PQgetvalue(result.get(), 0, 2),
        PQgetvalue(result.get(), 0, 3),
    };
}

vector<DetectionRule> Database::getEnabledDetectionRules(
    const string& sourceTypeCode
) {
    lock_guard<mutex> lock(mutex_);
    ensureConnected();
    const char* values[]{sourceTypeCode.c_str()};
    ResultPtr result(
        PQexecParams(
            connection_,
            "SELECT id, code, fk_severity_code, name, description, "
            "       threshold_value, time_window_seconds, recommendation "
            "FROM detection_rules "
            "WHERE is_enabled = TRUE "
            "  AND fk_source_type_code = $1 "
            "  AND threshold_value IS NOT NULL "
            "  AND time_window_seconds IS NOT NULL "
            "ORDER BY id",
            1, nullptr, values, nullptr, nullptr, 0
        ),
        &PQclear
    );
    if (result == nullptr || PQresultStatus(result.get()) != PGRES_TUPLES_OK) {
        throw resultError(result.get(), connection_);
    }

    vector<DetectionRule> rules;
    rules.reserve(static_cast<size_t>(PQntuples(result.get())));
    for (int row = 0; row < PQntuples(result.get()); ++row) {
        DetectionRule rule{
            stoll(PQgetvalue(result.get(), row, 0)),
            PQgetvalue(result.get(), row, 1),
            PQgetvalue(result.get(), row, 2),
            PQgetvalue(result.get(), row, 3),
            PQgetvalue(result.get(), row, 4),
            stoi(PQgetvalue(result.get(), row, 5)),
            stoi(PQgetvalue(result.get(), row, 6)),
            nullopt,
        };
        if (PQgetisnull(result.get(), row, 7) == 0) {
            rule.recommendation = PQgetvalue(result.get(), row, 7);
        }
        rules.push_back(move(rule));
    }
    return rules;
}

void Database::completeAnalysisJob(
    long long jobId,
    long long processedRecords,
    const vector<NormalizedEvent>& events,
    const vector<FindingCandidate>& findings
) {
    lock_guard<mutex> lock(mutex_);
    ensureConnected();
    ResultPtr begin(PQexec(connection_, "BEGIN"), &PQclear);
    if (begin == nullptr || PQresultStatus(begin.get()) != PGRES_COMMAND_OK) {
        throw resultError(begin.get(), connection_);
    }

    try {
        const auto eventIds = saveEvents(jobId, events);
        saveFindings(jobId, findings, eventIds);
        markAnalysisJobCompleted(
            jobId,
            processedRecords,
            events.size(),
            findings.size()
        );
        ResultPtr commit(PQexec(connection_, "COMMIT"), &PQclear);
        if (commit == nullptr ||
            PQresultStatus(commit.get()) != PGRES_COMMAND_OK) {
            throw resultError(commit.get(), connection_);
        }
    } catch (...) {
        ResultPtr rollback(PQexec(connection_, "ROLLBACK"), &PQclear);
        throw;
    }
}

vector<long long> Database::saveEvents(
    long long jobId,
    const vector<NormalizedEvent>& events
) {
    const string id = to_string(jobId);
    vector<long long> eventIds;
    eventIds.reserve(events.size());
    for (const auto& event : events) {
        const string occurredAt = timestampValue(event.occurredAt);
        const string sourcePort = event.sourcePort.has_value()
            ? to_string(event.sourcePort.value())
            : string();
        const string destinationPort = event.destinationPort.has_value()
            ? to_string(event.destinationPort.value())
            : string();
        const string lineNumber = to_string(event.sourceLineNumber);
        const char* values[]{
            id.c_str(),
            event.eventType.c_str(),
            event.severity.c_str(),
            event.outcome.has_value() ? event.outcome->c_str() : nullptr,
            occurredAt.c_str(),
            event.sourceIp.has_value() ? event.sourceIp->c_str() : nullptr,
            event.destinationIp.has_value()
                ? event.destinationIp->c_str()
                : nullptr,
            event.sourcePort.has_value() ? sourcePort.c_str() : nullptr,
            event.destinationPort.has_value()
                ? destinationPort.c_str()
                : nullptr,
            event.hostname.has_value() ? event.hostname->c_str() : nullptr,
            event.username.has_value() ? event.username->c_str() : nullptr,
            event.processName.has_value()
                ? event.processName->c_str()
                : nullptr,
            event.message.c_str(),
            event.rawEvent.c_str(),
            lineNumber.c_str(),
        };
        ResultPtr result(
            PQexecParams(
                connection_,
                "INSERT INTO events ("
                "fk_job_id, fk_event_type_code, fk_severity_code, "
                "fk_outcome_code, occurred_at, source_ip, destination_ip, "
                "source_port, destination_port, hostname, username, "
                "process_name, message, raw_event, source_line_number"
                ") VALUES ("
                "$1::BIGINT, $2, $3, $4, $5::TIMESTAMPTZ, $6::INET, "
                "$7::INET, $8::INTEGER, $9::INTEGER, $10, $11, $12, "
                "$13, $14, $15::BIGINT) RETURNING id",
                15, nullptr, values, nullptr, nullptr, 0
            ),
            &PQclear
        );
        if (result == nullptr ||
            PQresultStatus(result.get()) != PGRES_TUPLES_OK) {
            throw resultError(result.get(), connection_);
        }
        eventIds.push_back(stoll(PQgetvalue(result.get(), 0, 0)));
    }
    return eventIds;
}

void Database::saveFindings(
    long long jobId,
    const vector<FindingCandidate>& findings,
    const vector<long long>& eventIds
) {
    const string job = to_string(jobId);
    for (const auto& finding : findings) {
        const string rule = to_string(finding.ruleId);
        const string firstSeen = timestampValue(finding.firstSeen);
        const string lastSeen = timestampValue(finding.lastSeen);
        const char* values[]{
            job.c_str(),
            rule.c_str(),
            finding.severity.c_str(),
            finding.title.c_str(),
            finding.description.c_str(),
            finding.sourceIp.has_value() ? finding.sourceIp->c_str() : nullptr,
            finding.destinationIp.has_value()
                ? finding.destinationIp->c_str()
                : nullptr,
            finding.username.has_value() ? finding.username->c_str() : nullptr,
            firstSeen.c_str(),
            lastSeen.c_str(),
            finding.recommendation.has_value()
                ? finding.recommendation->c_str()
                : nullptr,
        };
        ResultPtr inserted(
            PQexecParams(
                connection_,
                "INSERT INTO findings ("
                "fk_job_id, fk_rule_id, fk_severity_code, title, description, "
                "source_ip, destination_ip, username, first_seen, last_seen, "
                "recommendation"
                ") VALUES ("
                "$1::BIGINT, $2::BIGINT, $3, $4, $5, $6::INET, $7::INET, "
                "$8, $9::TIMESTAMPTZ, $10::TIMESTAMPTZ, $11"
                ") RETURNING id",
                11, nullptr, values, nullptr, nullptr, 0
            ),
            &PQclear
        );
        if (inserted == nullptr ||
            PQresultStatus(inserted.get()) != PGRES_TUPLES_OK) {
            throw resultError(inserted.get(), connection_);
        }
        const string findingId =
            PQgetvalue(inserted.get(), 0, 0);

        for (const size_t eventIndex : finding.eventIndexes) {
            if (eventIndex >= eventIds.size()) {
                throw runtime_error(
                    "Finding ссылается на отсутствующее событие"
                );
            }
            const string eventId = to_string(eventIds[eventIndex]);
            const char* relationValues[]{findingId.c_str(), eventId.c_str()};
            ResultPtr relation(
                PQexecParams(
                    connection_,
                    "INSERT INTO finding_events (fk_finding_id, fk_event_id) "
                    "VALUES ($1::BIGINT, $2::BIGINT)",
                    2, nullptr, relationValues, nullptr, nullptr, 0
                ),
                &PQclear
            );
            if (relation == nullptr ||
                PQresultStatus(relation.get()) != PGRES_COMMAND_OK) {
                throw resultError(relation.get(), connection_);
            }
        }
    }
}

void Database::markAnalysisJobCompleted(
    long long jobId,
    long long processedRecords,
    size_t eventsCreated,
    size_t findingsCreated
) {
    const string id = to_string(jobId);
    const string records = to_string(processedRecords);
    const string eventCount = to_string(eventsCreated);
    const string findingCount = to_string(findingsCreated);
    const char* values[]{
        id.c_str(),
        records.c_str(),
        eventCount.c_str(),
        findingCount.c_str(),
    };
    ResultPtr result(
        PQexecParams(
            connection_,
            "WITH changed AS ("
            "    UPDATE analysis_jobs SET "
            "        fk_status_code = 'completed', progress = 100, "
            "        processed_records = $2::BIGINT, "
            "        events_created = $3::BIGINT, "
            "        findings_created = $4::INTEGER, "
            "        finished_at = CURRENT_TIMESTAMP "
            "    WHERE id = $1::BIGINT AND fk_status_code = 'processing' "
            "    RETURNING id"
            "), history AS ("
            "    INSERT INTO job_status_history ("
            "        fk_job_id, fk_old_status_code, fk_new_status_code, message"
            "    ) SELECT id, 'processing', 'completed', 'Обработка завершена' "
            "      FROM changed RETURNING fk_job_id"
            ") SELECT COUNT(*) FROM history",
            4, nullptr, values, nullptr, nullptr, 0
        ),
        &PQclear
    );
    if (result == nullptr || PQresultStatus(result.get()) != PGRES_TUPLES_OK) {
        throw resultError(result.get(), connection_);
    }
    if (stoll(PQgetvalue(result.get(), 0, 0)) != 1) {
        throw runtime_error("Задание нельзя завершить в текущем состоянии");
    }
}

void Database::failAnalysisJob(long long jobId, const string& message) {
    lock_guard<mutex> lock(mutex_);
    ensureConnected();
    const string id = to_string(jobId);
    const char* values[]{id.c_str(), message.c_str()};
    ResultPtr result(
        PQexecParams(
            connection_,
            "WITH changed AS ("
            "    UPDATE analysis_jobs SET "
            "        fk_status_code = 'failed', error_message = $2, "
            "        finished_at = CURRENT_TIMESTAMP "
            "    WHERE id = $1::BIGINT "
            "      AND fk_status_code IN ('queued', 'processing') "
            "    RETURNING id, fk_status_code"
            "), history AS ("
            "    INSERT INTO job_status_history ("
            "        fk_job_id, fk_old_status_code, fk_new_status_code, message"
            "    ) SELECT changed.id, "
            "             CASE WHEN analysis_jobs.started_at IS NULL "
            "                  THEN 'queued' ELSE 'processing' END, "
            "             'failed', $2 "
            "      FROM changed JOIN analysis_jobs ON analysis_jobs.id = changed.id "
            "    RETURNING fk_job_id"
            ") SELECT COUNT(*) FROM history",
            2, nullptr, values, nullptr, nullptr, 0
        ),
        &PQclear
    );
    if (result == nullptr || PQresultStatus(result.get()) != PGRES_TUPLES_OK) {
        throw connectionError(connection_);
    }
    if (stoll(PQgetvalue(result.get(), 0, 0)) != 1) {
        throw runtime_error("Задание нельзя перевести в состояние ошибки");
    }
}
}  // namespace security_analyzer
