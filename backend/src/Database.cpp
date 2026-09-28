#include "security_analyzer/Database.hpp"

#include <memory>
#include <stdexcept>
#include <utility>

namespace security_analyzer {
namespace {
using ResultPtr = std::unique_ptr<PGresult, decltype(&PQclear)>;
std::runtime_error connectionError(PGconn* connection) {
    const char* message = connection == nullptr ? "PostgreSQL connection could not be created" : PQerrorMessage(connection);
    return std::runtime_error(message);
}
}
Database::Database(Config config) : config_(std::move(config)) {
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
        "security-event-analyzer-api",
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
std::vector<SourceType> Database::getSourceTypes(){
    std::lock_guard<std::mutex> lock(mutex_);
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
        throw std::runtime_error("PostgreSQL returned an unexpected result");
    }
    std::vector<SourceType> sourceTypes;
    sourceTypes.reserve(static_cast<std::size_t>(PQntuples(result.get())));
    for (int row = 0; row < PQntuples(result.get()); ++row) {
        SourceType sourceType{
            PQgetvalue(result.get(), row, codeColumn),
            PQgetvalue(result.get(), row, nameColumn),
            std::nullopt,
        };
        if (PQgetisnull(result.get(), row, descriptionColumn) == 0) {
            sourceType.description =
                PQgetvalue(result.get(), row, descriptionColumn);
        }
        sourceTypes.push_back(std::move(sourceType));
    }
    return sourceTypes;
}

CreatedAnalysisJob Database::createUploadAndJob(const UploadData& upload) {
    std::lock_guard<std::mutex> lock(mutex_);
    ensureConnected();
    const std::string sizeBytes = std::to_string(upload.sizeBytes);
    const char* values[] = {
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
            "WITH local_user AS ("
            "    SELECT id FROM users "
            "    WHERE username = 'local_desktop' AND is_active = FALSE"
            "), new_upload AS ("
            "    INSERT INTO uploads ("
            "        fk_user_id, fk_source_type_code, original_filename, "
            "        stored_filename, file_path, mime_type, size_bytes, sha256"
            "    ) "
            "    SELECT id, $1, $2, $3, $4, $5, $6::BIGINT, $7 "
            "    FROM local_user "
            "    RETURNING id"
            ") "
            "INSERT INTO analysis_jobs (fk_upload_id) "
            "SELECT id FROM new_upload "
            "RETURNING id, fk_upload_id",
            7,
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
        throw std::runtime_error(
            "Локальный технический пользователь не найден"
        );
    }
    const int jobIdColumn = PQfnumber(result.get(), "id");
    const int uploadIdColumn = PQfnumber(result.get(), "fk_upload_id");
    if (jobIdColumn < 0 || uploadIdColumn < 0){
        throw std::runtime_error("PostgreSQL returned an unexpected result");
    }
    return CreatedAnalysisJob{
        std::stoll(PQgetvalue(result.get(), 0, uploadIdColumn)),
        std::stoll(PQgetvalue(result.get(), 0, jobIdColumn)),
    };
}
}  // namespace security_analyzer
