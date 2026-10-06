#pragma once

#include <memory>
#include <string>

namespace security_analyzer {

class KafkaProducer {
  public:
    KafkaProducer(std::string brokers, std::string topic);
    ~KafkaProducer();
    KafkaProducer(const KafkaProducer&) = delete;
    KafkaProducer& operator=(const KafkaProducer&) = delete;
    void publishAnalysisJob(long long jobId, long long uploadId);
  private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};
}  // namespace security_analyzer
