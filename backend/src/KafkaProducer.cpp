#include "security_analyzer/KafkaProducer.hpp"

#include <librdkafka/rdkafkacpp.h>

#include <mutex>
#include <stdexcept>
#include <utility>

using namespace std;

namespace security_analyzer {
class KafkaProducer::Impl {
  public:
    class DeliveryCallback : public RdKafka::DeliveryReportCb {
      public:
        void reset(){
            delivered = false;
            error.clear();
        }
        void dr_cb(RdKafka::Message& message) override{
            delivered = message.err() == RdKafka::ERR_NO_ERROR;
            if (!delivered) {
                error = message.errstr();
            }
        }
        bool delivered{false};
        string error;
    };

    static void setConfig(RdKafka::Conf& config, const string& name, const string& value) {
        string error;
        if (config.set(name, value, error) != RdKafka::Conf::CONF_OK){
            throw runtime_error("Ошибка настройки Kafka " + name + ": " + error);
        }
    }

    Impl(string brokers, string topic) : topic_(move(topic)){
        unique_ptr<RdKafka::Conf> config( RdKafka::Conf::create(RdKafka::Conf::CONF_GLOBAL));
        if (config == nullptr) {
            throw runtime_error("Не удалось создать конфигурацию Kafka");
        }
        setConfig(*config, "bootstrap.servers", brokers);
        setConfig(*config, "broker.address.family", "v4");
        setConfig(*config, "client.id", "security-event-analyzer-api");
        setConfig(*config, "enable.idempotence", "true");
        setConfig(*config, "message.timeout.ms", "5000");
        string error;
        if (config->set("dr_cb", &deliveryCallback_, error) != RdKafka::Conf::CONF_OK) {
            throw runtime_error("Не удалось настроить подтверждение Kafka: " + error);
        }
        producer_.reset(RdKafka::Producer::create(config.get(), error));
        if (producer_ == nullptr) {
            throw runtime_error("Не удалось создать Kafka producer: " + error);
        }
    }

    ~Impl(){
        if (producer_ != nullptr){
            producer_->flush(1000);
        }
    }

    void publishAnalysisJob(long long jobId, long long uploadId){
        lock_guard<mutex> lock(mutex_);
        deliveryCallback_.reset();
        const string payload = "{\"jobId\":" + to_string(jobId) + ",\"uploadId\":" + to_string(uploadId) + "}";
        const auto result = producer_->produce( topic_, RdKafka::Topic::PARTITION_UA, RdKafka::Producer::RK_MSG_COPY, const_cast<char*>(payload.data()), payload.size(), nullptr, 0, 0, nullptr);
        if (result != RdKafka::ERR_NO_ERROR){
            throw runtime_error(
                "Kafka отклонила сообщение: " + RdKafka::err2str(result)
            );
        }
        const auto flushResult = producer_->flush(6000);
        if (flushResult != RdKafka::ERR_NO_ERROR || !deliveryCallback_.delivered){
            const string reason = deliveryCallback_.error.empty() ? RdKafka::err2str(flushResult) : deliveryCallback_.error;
            throw runtime_error("Kafka не подтвердила сообщение: " + reason);
        }
    }
  private:
    string topic_;
    DeliveryCallback deliveryCallback_;
    unique_ptr<RdKafka::Producer> producer_;
    mutex mutex_;
};

KafkaProducer::KafkaProducer(string brokers, string topic) : impl_(make_unique<Impl>(move(brokers), move(topic))) {
}

KafkaProducer::~KafkaProducer() = default;

void KafkaProducer::publishAnalysisJob(long long jobId, long long uploadId) {
    impl_->publishAnalysisJob(jobId, uploadId);
}

}  // namespace security_analyzer
