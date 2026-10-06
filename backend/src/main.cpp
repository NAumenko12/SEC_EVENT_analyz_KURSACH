#include <drogon/drogon.h>

#include "security_analyzer/AuthService.hpp"
#include "security_analyzer/Database.hpp"
#include "security_analyzer/KafkaProducer.hpp"
#include "security_analyzer/UploadService.hpp"

#include <charconv>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <system_error>

using namespace std;

namespace security_analyzer {

class BackendApplication {
  private:
    static string getEnvironmentValue(const char* name, const char* fallback){
    const char* value = getenv(name);
    return value == nullptr ? fallback : value;
}
    static int getApiPort(){
    const string value = getEnvironmentValue("API_PORT", "8080");
    int port = 0;
    const auto result = from_chars( value.data(), value.data() + value.size(), port );
    if (result.ec != errc{} || result.ptr != value.data() + value.size() || port < 1 || port > 65535) {
        throw runtime_error(
            "API_PORT должен быть целым числом от 1 до 65535"
        );
    }
    return port;
}

    static void allowDesktopClient(const drogon::HttpRequestPtr& request,const drogon::HttpResponsePtr& response){
    const string origin = request->getHeader("Origin");
    if (origin == "http://127.0.0.1:5173" || origin == "http://localhost:5173" || origin == "tauri://localhost" ||origin == "http://tauri.localhost") {
        response->addHeader("Access-Control-Allow-Origin", origin);
        response->addHeader("Vary", "Origin");
        response->addHeader( "Access-Control-Allow-Headers", "Authorization, Content-Type");
        response->addHeader( "Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    }
}

    static bool respondToOptions( const drogon::HttpRequestPtr& request, const function<void(const drogon::HttpResponsePtr&)>& callback){
    if (request->method() != drogon::Options){
        return false;
    }
    auto response = drogon::HttpResponse::newHttpResponse();
    response->setStatusCode(drogon::k204NoContent);
    allowDesktopClient(request, response);
    callback(response);
    return true;
}

    static string requireBearerToken(const drogon::HttpRequestPtr& request){
    const string authorization = request->getHeader("Authorization");
    constexpr const char* prefix = "Bearer ";
    if (authorization.rfind(prefix, 0) != 0){
        throw security_analyzer::AuthError( security_analyzer::AuthErrorCode::unauthorized,"Требуется авторизация"
        );
    }
    return authorization.substr(char_traits<char>::length(prefix));
}

    static string requiredJsonString(const Json::Value& body, const char* field) {
    if (!body.isObject() || !body.isMember(field) || !body[field].isString()) {
        throw security_analyzer::AuthError( security_analyzer::AuthErrorCode::invalidInput, string("Некорректное поле ") + field);
    }
    return body[field].asString();
}

    static Json::Value userJson(const security_analyzer::User& user) {
    Json::Value body;
    body["id"] = Json::Int64(user.id);
    body["username"] = user.username;
    body["email"] = user.email;
    body["role"] = user.roleCode;
    return body;
}

    static void sendAuthError( const security_analyzer::AuthError& error, const drogon::HttpRequestPtr& request, const function<void(const drogon::HttpResponsePtr&)>& callback){
    Json::Value body;
    body["message"] = error.what();
    auto response = drogon::HttpResponse::newHttpJsonResponse(body);
    switch (error.code()) {
        case security_analyzer::AuthErrorCode::invalidInput:
            body["error"] = "invalid_input";
            response = drogon::HttpResponse::newHttpJsonResponse(body);
            response->setStatusCode(drogon::k400BadRequest);
            break;
        case security_analyzer::AuthErrorCode::conflict:
            body["error"] = "user_conflict";
            response = drogon::HttpResponse::newHttpJsonResponse(body);
            response->setStatusCode(drogon::k409Conflict);
            break;
        case security_analyzer::AuthErrorCode::invalidCredentials:
            body["error"] = "invalid_credentials";
            response = drogon::HttpResponse::newHttpJsonResponse(body);
            response->setStatusCode(drogon::k401Unauthorized);
            break;
        case security_analyzer::AuthErrorCode::unauthorized:
            body["error"] = "unauthorized";
            response = drogon::HttpResponse::newHttpJsonResponse(body);
            response->setStatusCode(drogon::k401Unauthorized);
            break;
    }
    allowDesktopClient(request, response);
    callback(response);
}
  public:
    static int run(){
    const string host = getEnvironmentValue("API_HOST", "0.0.0.0");
    int port = 0;
    try {
        port = getApiPort();
    } catch (const exception& error) {
        cerr << "Ошибка конфигурации: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
    auto database = make_shared<security_analyzer::Database>(
        security_analyzer::Database::Config{
            getEnvironmentValue("DATABASE_HOST", "127.0.0.1"),
            getEnvironmentValue("DATABASE_PORT", "5433"),
            getEnvironmentValue("DATABASE_NAME", "sec_event_anal"),
            getEnvironmentValue("DATABASE_USER", "sea_admin"),
            getEnvironmentValue("DATABASE_PASSWORD", "sea_local_development"),
        }
    );
    auto kafkaProducer = make_shared<security_analyzer::KafkaProducer>( getEnvironmentValue("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"), getEnvironmentValue("KAFKA_TOPIC_ANALYSIS_JOBS", "analysis.jobs") );
    auto authService = make_shared<security_analyzer::AuthService>(database);
    auto uploadService = make_shared<security_analyzer::UploadService>( database, kafkaProducer, getEnvironmentValue("UPLOAD_DIRECTORY", "data/uploads"));
    drogon::app().registerHandler(
        "/api/health",
        [](const drogon::HttpRequestPtr&,
           function<void(const drogon::HttpResponsePtr&)>&& callback) {
            Json::Value body;
            body["service"] = "security-event-analyzer-api";
            body["status"] = "ok";
            callback(drogon::HttpResponse::newHttpJsonResponse(body));
        },
        {drogon::Get}
    );
    drogon::app().registerHandler(
        "/api/auth/register",
        [authService](
            const drogon::HttpRequestPtr& request,
            function<void(const drogon::HttpResponsePtr&)>&& callback
        ) {
            if (respondToOptions(request, callback)) {
                return;
            }
            try {
                if (request->body().size() > 4096) {
                    throw security_analyzer::AuthError(
                        security_analyzer::AuthErrorCode::invalidInput,
                        "Запрос регистрации слишком большой"
                    );
                }
                const auto json = request->getJsonObject();
                if (json == nullptr) {
                    throw security_analyzer::AuthError(
                        security_analyzer::AuthErrorCode::invalidInput,
                        "Ожидался корректный JSON"
                    );
                }
                const auto session = authService->registerUser(
                    requiredJsonString(*json, "username"),
                    requiredJsonString(*json, "email"),
                    requiredJsonString(*json, "password")
                );
                Json::Value body;
                body["token"] = session.token;
                body["user"] = userJson(session.user);
                auto response = drogon::HttpResponse::newHttpJsonResponse(body);
                response->setStatusCode(drogon::k201Created);
                allowDesktopClient(request, response);
                callback(response);
            } catch (const security_analyzer::AuthError& error) {
                sendAuthError(error, request, callback);
            } catch (const exception& error) {
                LOG_ERROR << "Ошибка регистрации: " << error.what();
                Json::Value body;
                body["error"] = "registration_failed";
                body["message"] = "Не удалось зарегистрировать пользователя";
                auto response = drogon::HttpResponse::newHttpJsonResponse(body);
                response->setStatusCode(drogon::k500InternalServerError);
                allowDesktopClient(request, response);
                callback(response);
            }
        },
        {drogon::Post, drogon::Options}
    );
    drogon::app().registerHandler(
        "/api/auth/login",
        [authService](
            const drogon::HttpRequestPtr& request,
            function<void(const drogon::HttpResponsePtr&)>&& callback
        ) {
            if (respondToOptions(request, callback)) {
                return;
            }
            try {
                if (request->body().size() > 4096) {
                    throw security_analyzer::AuthError(
                        security_analyzer::AuthErrorCode::invalidInput,
                        "Запрос входа слишком большой"
                    );
                }
                const auto json = request->getJsonObject();
                if (json == nullptr) {
                    throw security_analyzer::AuthError(
                        security_analyzer::AuthErrorCode::invalidInput,
                        "Ожидался корректный JSON"
                    );
                }
                const auto session = authService->login(
                    requiredJsonString(*json, "login"),
                    requiredJsonString(*json, "password")
                );
                Json::Value body;
                body["token"] = session.token;
                body["user"] = userJson(session.user);
                auto response = drogon::HttpResponse::newHttpJsonResponse(body);
                allowDesktopClient(request, response);
                callback(response);
            } catch (const security_analyzer::AuthError& error) {
                sendAuthError(error, request, callback);
            } catch (const exception& error) {
                LOG_ERROR << "Ошибка входа: " << error.what();
                Json::Value body;
                body["error"] = "login_failed";
                body["message"] = "Не удалось выполнить вход";
                auto response = drogon::HttpResponse::newHttpJsonResponse(body);
                response->setStatusCode(drogon::k500InternalServerError);
                allowDesktopClient(request, response);
                callback(response);
            }
        },
        {drogon::Post, drogon::Options}
    );
    drogon::app().registerHandler(
        "/api/auth/me",
        [authService](
            const drogon::HttpRequestPtr& request,
            function<void(const drogon::HttpResponsePtr&)>&& callback
        ) {
            if (respondToOptions(request, callback)) {
                return;
            }
            try {
                const auto user = authService->authenticate(
                    requireBearerToken(request)
                );
                Json::Value body;
                body["user"] = userJson(user);
                auto response = drogon::HttpResponse::newHttpJsonResponse(body);
                allowDesktopClient(request, response);
                callback(response);
            } catch (const security_analyzer::AuthError& error) {
                sendAuthError(error, request, callback);
            } catch (const exception& error) {
                LOG_ERROR << "Ошибка проверки сессии: " << error.what();
                Json::Value body;
                body["error"] = "session_failed";
                body["message"] = "Не удалось проверить сессию";
                auto response = drogon::HttpResponse::newHttpJsonResponse(body);
                response->setStatusCode(drogon::k500InternalServerError);
                allowDesktopClient(request, response);
                callback(response);
            }
        },
        {drogon::Get, drogon::Options}
    );
    drogon::app().registerHandler(
        "/api/auth/logout",
        [authService](
            const drogon::HttpRequestPtr& request,
            function<void(const drogon::HttpResponsePtr&)>&& callback
        ) {
            if (respondToOptions(request, callback)) {
                return;
            }
            try {
                authService->logout(requireBearerToken(request));
                auto response = drogon::HttpResponse::newHttpResponse();
                response->setStatusCode(drogon::k204NoContent);
                allowDesktopClient(request, response);
                callback(response);
            } catch (const security_analyzer::AuthError& error) {
                sendAuthError(error, request, callback);
            } catch (const exception& error) {
                LOG_ERROR << "Ошибка завершения сессии: " << error.what();
                Json::Value body;
                body["error"] = "logout_failed";
                body["message"] = "Не удалось завершить сессию";
                auto response = drogon::HttpResponse::newHttpJsonResponse(body);
                response->setStatusCode(drogon::k500InternalServerError);
                allowDesktopClient(request, response);
                callback(response);
            }
        },
        {drogon::Post, drogon::Options}
    );
    drogon::app().registerHandler(
        "/api/source-types",
        [database]( const drogon::HttpRequestPtr& request, function<void(const drogon::HttpResponsePtr&)>&& callback) {
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
                    body.append(move(item));
                }
                auto response = drogon::HttpResponse::newHttpJsonResponse(body);
                allowDesktopClient(request, response);
                callback(response);
            } catch (const exception& error) {
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
    drogon::app().registerHandler( "/api/jobs/{1}", [database, authService]( const drogon::HttpRequestPtr& request, function<void(const drogon::HttpResponsePtr&)>&& callback, long long jobId ){
            if (respondToOptions(request, callback)) {
                return;
            }
            try {
                const auto user = authService->authenticate(
                    requireBearerToken(request)
                );
                const auto job = database->getAnalysisJob(jobId, user.id);
                if (!job.has_value()) {
                    Json::Value body;
                    body["error"] = "job_not_found";
                    body["message"] = "Задание не найдено";
                    auto response = drogon::HttpResponse::newHttpJsonResponse(body);
                    response->setStatusCode(drogon::k404NotFound);
                    allowDesktopClient(request, response);
                    callback(response);
                    return;
                }
                Json::Value body;
                body["id"] = Json::Int64(job->id);
                body["uploadId"] = Json::Int64(job->uploadId);
                body["status"] = job->status;
                body["progress"] = job->progress;
                body["processedRecords"] = Json::Int64(job->processedRecords);
                body["eventsCreated"] = Json::Int64(job->eventsCreated);
                body["findingsCreated"] = job->findingsCreated;
                body["errorMessage"] = job->errorMessage.has_value() ? Json::Value(job->errorMessage.value()) : Json::Value(Json::nullValue);
                auto response = drogon::HttpResponse::newHttpJsonResponse(body);
                allowDesktopClient(request, response);
                callback(response);
            } catch (const security_analyzer::AuthError& error) {
                sendAuthError(error, request, callback);
            } catch (const exception& error){
                LOG_ERROR << "Не удалось получить задание: " << error.what();
                Json::Value body;
                body["error"] = "database_unavailable";
                body["message"] = "Не удалось получить состояние задания";
                auto response = drogon::HttpResponse::newHttpJsonResponse(body);
                response->setStatusCode(drogon::k503ServiceUnavailable);
                allowDesktopClient(request, response);
                callback(response);
            }
        },
        {drogon::Get, drogon::Options}
    );
    drogon::app().registerHandler(
        "/api/uploads",
        [uploadService, authService](
            const drogon::HttpRequestPtr& request,
            function<void(const drogon::HttpResponsePtr&)>&& callback
        ) {
            if (respondToOptions(request, callback)) {
                return;
            }
            try {
                const auto user = authService->authenticate(
                    requireBearerToken(request)
                );
                drogon::MultiPartParser parser;
                if (parser.parse(request) != 0) {
                    throw invalid_argument(
                        "Ожидался запрос multipart/form-data"
                    );
                }
                const auto& files = parser.getFiles();
                if (files.size() != 1 || files.front().getItemName() != "file") {
                    throw invalid_argument(
                        "Необходимо передать ровно один файл в поле file"
                    );
                }
                const string sourceTypeCode =
                    parser.getParameter<string>("source_type");
                if (sourceTypeCode.empty()) {
                    throw invalid_argument("Тип источника не указан");
                }
                const auto created = uploadService->createAnalysisJob(
                    user.id, files.front(), sourceTypeCode
                );
                Json::Value body;
                body["uploadId"] = Json::Int64(created.uploadId);
                body["jobId"] = Json::Int64(created.jobId);
                body["status"] = "queued";
                auto response = drogon::HttpResponse::newHttpJsonResponse(body);
                response->setStatusCode(drogon::k201Created);
                allowDesktopClient(request, response);
                callback(response);
            } catch (const security_analyzer::AuthError& error) {
                sendAuthError(error, request, callback);
            } catch (const invalid_argument& error) {
                Json::Value body;
                body["error"] = "invalid_upload";
                body["message"] = error.what();
                auto response = drogon::HttpResponse::newHttpJsonResponse(body);
                response->setStatusCode(drogon::k400BadRequest);
                allowDesktopClient(request, response);
                callback(response);
            } catch (const exception& error) {
                LOG_ERROR << "Не удалось создать загрузку: " << error.what();
                Json::Value body;
                body["error"] = "upload_failed";
                body["message"] = "Не удалось создать или поставить задание в очередь";
                auto response = drogon::HttpResponse::newHttpJsonResponse(body);
                response->setStatusCode(drogon::k500InternalServerError);
                allowDesktopClient(request, response);
                callback(response);
            }
        },
        {drogon::Post, drogon::Options}
    );
    drogon::app()
        .addListener(host, port)
        .setClientMaxBodySize(21 * 1024 * 1024)
        .setThreadNum(2)
        .run();
    return EXIT_SUCCESS;
}
};

} 

int main(){
    return security_analyzer::BackendApplication::run();
}
