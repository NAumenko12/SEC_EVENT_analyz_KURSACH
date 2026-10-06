#include "security_analyzer/Database.hpp"
#include "security_analyzer/DetectionEngine.hpp"
#include "security_analyzer/ParserFactory.hpp"
#include "security_analyzer/TextLogReader.hpp"

#include <json/json.h>
#include <librdkafka/rdkafkacpp.h>

#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>

using namespace std;

namespace security_analyzer {

class WorkerApplication {
  private:
    static inline volatile sig_atomic_t running = 1;

    struct JobMessage {
    long long jobId;
    long long uploadId;
};
    static void stopWorker(int) {
    running = 0;
}

    static string getEnvironmentValue(const char* name, const char* fallback) {
    const char* value = getenv(name);
    return value == nullptr ? fallback : value;
}

    static void setConfig(RdKafka::Conf& config, const string& name, const string& value) {
    string error;
    if (config.set(name, value, error) != RdKafka::Conf::CONF_OK) {
        throw runtime_error("Ошибка настройки Kafka " + name + ": " + error);
    }
}
    static JobMessage parseJobMessage(const RdKafka::Message& message) {
    if (message.payload() == nullptr || message.len() == 0) {
        throw invalid_argument("Kafka передала пустое сообщение");
    }
    const string payload( static_cast<const char*>(message.payload()), message.len() );
    Json::CharReaderBuilder builder;
    unique_ptr<Json::CharReader> reader(builder.newCharReader());
    Json::Value body;
    string errors;
    if (!reader->parse( payload.data(), payload.data() + payload.size(), &body, &errors ) || !body["jobId"].isInt64() || !body["uploadId"].isInt64()) {
        throw invalid_argument("Некорректное сообщение Kafka: " + errors);
    }

    const long long jobId = body["jobId"].asInt64();
    const long long uploadId = body["uploadId"].asInt64();
    if (jobId <= 0 || uploadId <= 0) {
        throw invalid_argument("Идентификаторы задания должны быть положительными");
    }
    return JobMessage{jobId, uploadId};
}

    static security_analyzer::ParseResult parseTask(
    const security_analyzer::AnalysisTask& task
) {
    if (!filesystem::is_regular_file(task.filePath)) {
        throw runtime_error("Файл задания не найден: " + task.filePath);
    }
    const auto parser = security_analyzer::createParser(task.sourceTypeCode);
    return security_analyzer::parseTextLog(task.filePath, *parser);
}

    static void processMessage( security_analyzer::Database& database, const JobMessage& message ) {
    const auto task = database.startAnalysisJob(message.jobId);
    if (!task.has_value()) {
        cout << "Задание " << message.jobId << " уже обработано или взято другим worker\n";
        return;
    }
    if (task->uploadId != message.uploadId) {
        throw runtime_error("Сообщение Kafka ссылается на чужую загрузку");
    }
    const auto parsed = parseTask(task.value());
    const auto rules = database.getEnabledDetectionRules(task->sourceTypeCode);
    const auto findings = security_analyzer::DetectionEngine{}.analyze(
        parsed.events,
        rules
    );
    database.completeAnalysisJob(message.jobId,static_cast<long long>(parsed.processedRecords),parsed.events,findings);
    cout << "Задание " << message.jobId << " завершено, строк: " << parsed.processedRecords << ", событий: " << parsed.events.size() << ", находок: " << findings.size() << '\n';
}

  public:
    static int run() {
    signal(SIGINT, stopWorker);
    signal(SIGTERM, stopWorker);
    try {
        security_analyzer::Database database({
            getEnvironmentValue("DATABASE_HOST", "127.0.0.1"),
            getEnvironmentValue("DATABASE_PORT", "5433"),
            getEnvironmentValue("DATABASE_NAME", "sec_event_anal"),
            getEnvironmentValue("DATABASE_USER", "sea_admin"),
            getEnvironmentValue("DATABASE_PASSWORD", "sea_local_development"),
            "security-event-analyzer-worker",
        });
        unique_ptr<RdKafka::Conf> config( RdKafka::Conf::create(RdKafka::Conf::CONF_GLOBAL) );
        if (config == nullptr){
            throw runtime_error("Не удалось создать конфигурацию Kafka");
        }
        setConfig( *config, "bootstrap.servers", getEnvironmentValue("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"));
        setConfig(*config, "broker.address.family", "v4");
        setConfig(*config, "group.id", "security-analyzer-workers");
        setConfig(*config, "client.id", "security-event-analyzer-worker");
        setConfig(*config, "enable.auto.commit", "false");
        setConfig(*config, "enable.auto.offset.store", "false");
        setConfig(*config, "auto.offset.reset", "earliest");
        string error;
        unique_ptr<RdKafka::KafkaConsumer> consumer( RdKafka::KafkaConsumer::create(config.get(), error) );
        if (consumer == nullptr) {
            throw runtime_error("Не удалось создать Kafka consumer: " + error);
        }
        const string topic = getEnvironmentValue( "KAFKA_TOPIC_ANALYSIS_JOBS", "analysis.jobs" );
        const auto subscribeResult = consumer->subscribe({topic});
        if (subscribeResult != RdKafka::ERR_NO_ERROR) {
            throw runtime_error(
                "Не удалось подписаться на Kafka topic: " + RdKafka::err2str(subscribeResult));
        }
        cout << "Worker слушает Kafka topic " << topic << '\n';
        while (running) {
            unique_ptr<RdKafka::Message> kafkaMessage(consumer->consume(1000));
            if (kafkaMessage->err() == RdKafka::ERR__TIMED_OUT) {
                continue;
            }
            if (kafkaMessage->err() != RdKafka::ERR_NO_ERROR) {
                cerr << "Ошибка Kafka: " << kafkaMessage->errstr() << '\n';
                continue;
            }
            try {
                const JobMessage message = parseJobMessage(*kafkaMessage);
                try {
                    processMessage(database, message);
                } catch (const exception& processingError) {
                    database.failAnalysisJob( message.jobId, "Не удалось обработать загруженный файл");
                    cerr << "Задание " << message.jobId << " завершилось ошибкой: " << processingError.what() << '\n';
                }
                const auto commitResult = consumer->commitSync(kafkaMessage.get());
                if (commitResult != RdKafka::ERR_NO_ERROR) {
                    cerr << "Не удалось подтвердить Kafka-сообщение: " << RdKafka::err2str(commitResult) << '\n';
                }
            } catch (const invalid_argument& invalidMessage) {
                cerr << invalidMessage.what() << '\n';
                consumer->commitSync(kafkaMessage.get());
            }
        }
        consumer->close();
        consumer.reset();
        RdKafka::wait_destroyed(3000);
        cout << "Worker остановлен\n";
        return EXIT_SUCCESS;
    } catch (const exception& error) {
        cerr << "Worker не запущен: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
};

}  // namespace security_analyzer

int main() {
    return security_analyzer::WorkerApplication::run();
}
