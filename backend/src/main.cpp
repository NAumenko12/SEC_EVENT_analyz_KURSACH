#include <drogon/drogon.h>

#include "security_analyzer/Database.hpp"
#include "security_analyzer/UploadService.hpp"

#include <charconv>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <system_error>

namespace {
std::string getEnvironmentValue(const char* name, const char* fallback){
    const char* value = std::getenv(name);
    return value == nullptr ? fallback : value;
}
int getApiPort(){
    const std::string value = getEnvironmentValue("API_PORT", "8080");
    int port = 0;
    const auto result = std::from_chars( value.data(), value.data() + value.size(), port );
    if (result.ec != std::errc{} || result.ptr != value.data() + value.size() || port < 1 || port > 65535) {
        throw std::runtime_error(
            "API_PORT должен быть целым числом от 1 до 65535"
        );
    }
    return port;
}

void allowDesktopClient(
    const drogon::HttpRequestPtr& request,
    const drogon::HttpResponsePtr& response
) {
    const std::string origin = request->getHeader("Origin");
    if (origin == "http://127.0.0.1:5173" ||
        origin == "http://localhost:5173" ||
        origin == "tauri://localhost" ||
        origin == "http://tauri.localhost") {
        response->addHeader("Access-Control-Allow-Origin", origin);
        response->addHeader("Vary", "Origin");
    }
}
}

int main() {
    const std::string host = getEnvironmentValue("API_HOST", "0.0.0.0");
    int port = 0;
    try {
        port = getApiPort();
    } catch (const std::exception& error) {
        std::cerr << "Ошибка конфигурации: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
    auto database = std::make_shared<security_analyzer::Database>(
        security_analyzer::Database::Config{
            getEnvironmentValue("DATABASE_HOST", "127.0.0.1"),
            getEnvironmentValue("DATABASE_PORT", "5433"),
            getEnvironmentValue("DATABASE_NAME", "sec_event_anal"),
            getEnvironmentValue("DATABASE_USER", "sea_admin"),
            getEnvironmentValue("DATABASE_PASSWORD", "sea_local_development"),
        }
    );
    auto uploadService = std::make_shared<security_analyzer::UploadService>(
        database,
        getEnvironmentValue("UPLOAD_DIRECTORY", "data/uploads")
    );
    drogon::app().registerHandler(
        "/api/health",
        [](const drogon::HttpRequestPtr&,
           std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
            Json::Value body;
            body["service"] = "security-event-analyzer-api";
            body["status"] = "ok";
            callback(drogon::HttpResponse::newHttpJsonResponse(body));
        },
        {drogon::Get}
    );
    drogon::app().registerHandler(
        "/api/source-types",
        [database]( const drogon::HttpRequestPtr& request, std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
            try {
                const auto sourceTypes = database->getSourceTypes();
                Json::Value body(Json::arrayValue);
                for (const auto& sourceType : sourceTypes) {
                    Json::Value item;
                    item["code"] = sourceType.code;
                    item["name"] = sourceType.name;
                    if (sourceType.description.has_value()) {
                        item["description"] = sourceType.description.value();
                    } else {
                        item["description"] = Json::nullValue;
                    }
                    body.append(std::move(item));
                }
                auto response = drogon::HttpResponse::newHttpJsonResponse(body);
                allowDesktopClient(request, response);
                callback(response);
            } catch (const std::exception& error) {
                LOG_ERROR << "Не удалось прочитать типы источников: " << error.what();
                Json::Value body;
                body["error"] = "database_unavailable";
                body["message"] = "Не удалось получить типы источников";
                auto response = drogon::HttpResponse::newHttpJsonResponse(body);
                response->setStatusCode(drogon::k503ServiceUnavailable);
                allowDesktopClient(request, response);
                callback(response);
            }
        }, {drogon::Get}
    );
    drogon::app().registerHandler(
        "/api/uploads",
        [uploadService](
            const drogon::HttpRequestPtr& request,
            std::function<void(const drogon::HttpResponsePtr&)>&& callback
        ) {
            try {
                drogon::MultiPartParser parser;
                if (parser.parse(request) != 0) {
                    throw std::invalid_argument(
                        "Ожидался запрос multipart/form-data"
                    );
                }
                const auto& files = parser.getFiles();
                if (files.size() != 1 || files.front().getItemName() != "file") {
                    throw std::invalid_argument(
                        "Необходимо передать ровно один файл в поле file"
                    );
                }
                const std::string sourceTypeCode =
                    parser.getParameter<std::string>("source_type");
                if (sourceTypeCode.empty()) {
                    throw std::invalid_argument("Тип источника не указан");
                }
                const auto created = uploadService->createAnalysisJob(
                    files.front(), sourceTypeCode
                );
                Json::Value body;
                body["uploadId"] = Json::Int64(created.uploadId);
                body["jobId"] = Json::Int64(created.jobId);
                body["status"] = "queued";
                auto response = drogon::HttpResponse::newHttpJsonResponse(body);
                response->setStatusCode(drogon::k201Created);
                allowDesktopClient(request, response);
                callback(response);
            } catch (const std::invalid_argument& error) {
                Json::Value body;
                body["error"] = "invalid_upload";
                body["message"] = error.what();
                auto response = drogon::HttpResponse::newHttpJsonResponse(body);
                response->setStatusCode(drogon::k400BadRequest);
                allowDesktopClient(request, response);
                callback(response);
            } catch (const std::exception& error) {
                LOG_ERROR << "Не удалось создать загрузку: " << error.what();
                Json::Value body;
                body["error"] = "upload_failed";
                body["message"] = "Не удалось сохранить файл и создать задание";
                auto response = drogon::HttpResponse::newHttpJsonResponse(body);
                response->setStatusCode(drogon::k500InternalServerError);
                allowDesktopClient(request, response);
                callback(response);
            }
        },
        {drogon::Post}
    );
    drogon::app()
        .addListener(host, port)
        .setClientMaxBodySize(21 * 1024 * 1024)
        .setThreadNum(2)
        .run();
}
