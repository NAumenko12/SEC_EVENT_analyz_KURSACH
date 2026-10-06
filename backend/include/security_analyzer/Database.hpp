#pragma once
#include <libpq-fe.h>
#include "security_analyzer/Detection.hpp"
#include "security_analyzer/NormalizedEvent.hpp"
#include <cstddef>
#include <chrono>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace security_analyzer{

class DatabaseConflictError : public std::runtime_error {
  public:
    using std::runtime_error::runtime_error;
};

struct User{
    long long id;
    std::string username;
    std::string email;
    std::string roleCode;
};

struct UserCredentials{
    User user;
    std::string passwordHash;
    bool isActive;
};
struct SourceType{
    std::string code;
    std::string name;
    std::optional<std::string> description;
};

struct UploadData{
    std::string sourceTypeCode;
    std::string originalFilename;
    std::string storedFilename;
    std::string filePath;
    std::string mimeType;
    std::size_t sizeBytes;
    std::string sha256;
};

struct CreatedAnalysisJob{
    long long uploadId;
    long long jobId;
};

struct AnalysisJob{
    long long id;
    long long uploadId;
    std::string status;
    int progress;
    long long processedRecords;
    long long eventsCreated;
    int findingsCreated;
    std::optional<std::string> errorMessage;
};

struct AnalysisTask{
    long long jobId;
    long long uploadId;
    std::string sourceTypeCode;
    std::string filePath;
};

class Database{
  public:
    struct Config{
        std::string host;
        std::string port;
        std::string databaseName;
        std::string user;
        std::string password;
        std::string applicationName{"security-event-analyzer-api"};
    };
    explicit Database(Config config);
    ~Database();
    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;
    std::vector<SourceType> getSourceTypes();
    User createUser(
        const std::string& username,
        const std::string& email,
        const std::string& passwordHash
    );
    std::optional<UserCredentials> findUserByLogin(const std::string& login);
    void createSession(
        long long userId,
        const std::string& tokenHash,
        long long lifetimeSeconds
    );
    std::optional<User> findUserBySessionTokenHash(const std::string& tokenHash);
    void revokeSession(const std::string& tokenHash);
    CreatedAnalysisJob createUploadAndJob(
        long long userId,
        const UploadData& upload
    );
    std::optional<AnalysisJob> getAnalysisJob(long long jobId, long long userId);
    std::optional<AnalysisTask> startAnalysisJob(long long jobId);
    std::vector<DetectionRule> getEnabledDetectionRules(
        const std::string& sourceTypeCode
    );
    void completeAnalysisJob(
        long long jobId,
        long long processedRecords,
        const std::vector<NormalizedEvent>& events,
        const std::vector<FindingCandidate>& findings
    );
    void failAnalysisJob(long long jobId, const std::string& message);
  private:
    using ResultPtr = std::unique_ptr<PGresult, decltype(&PQclear)>;
    static std::runtime_error connectionError(PGconn* connection);
    static std::runtime_error resultError(PGresult* result, PGconn* connection);
    static std::string timestampValue(
        const std::chrono::system_clock::time_point& timestamp
    );
    void connect();
    void ensureConnected();
    std::vector<long long> saveEvents(
        long long jobId,
        const std::vector<NormalizedEvent>& events
    );
    void saveFindings(
        long long jobId,
        const std::vector<FindingCandidate>& findings,
        const std::vector<long long>& eventIds
    );
    void markAnalysisJobCompleted(
        long long jobId,
        long long processedRecords,
        std::size_t eventsCreated,
        std::size_t findingsCreated
    );
    Config config_;
    PGconn* connection_{nullptr};
    std::mutex mutex_;
};

}  // namespace security_analyzer
