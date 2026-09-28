#pragma once
#include <libpq-fe.h>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace security_analyzer{
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

class Database{
  public:
    struct Config{
        std::string host;
        std::string port;
        std::string databaseName;
        std::string user;
        std::string password;
    };

    explicit Database(Config config);
    ~Database();
    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;
    std::vector<SourceType> getSourceTypes();
    CreatedAnalysisJob createUploadAndJob(const UploadData& upload);
  private:
    void connect();
    void ensureConnected();
    Config config_;
    PGconn* connection_{nullptr};
    std::mutex mutex_;
};

}  // namespace security_analyzer
