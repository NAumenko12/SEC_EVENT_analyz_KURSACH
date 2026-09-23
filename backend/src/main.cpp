#include <drogon/drogon.h>

#include <cstdint>
#include <cstdlib>
#include <functional>
#include <string>

namespace {

std::string getEnvironmentValue(const char* name, const char* fallback) {
    const char* value = std::getenv(name);
    return value == nullptr ? fallback : value;
}

}  // namespace

int main() {
    const std::string host = getEnvironmentValue("API_HOST", "0.0.0.0");
    const auto port = static_cast<std::uint16_t>(
        std::stoi(getEnvironmentValue("API_PORT", "8080"))
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

    drogon::app()
        .addListener(host, port)
        .setThreadNum(2)
        .run();
}
