#pragma once

#include "security_analyzer/Database.hpp"

#include <drogon/MultiPart.h>

#include <filesystem>
#include <cstddef>
#include <memory>
#include <string>
#include <string_view>

namespace security_analyzer{

class KafkaProducer;

class UploadService{
  public:
    UploadService(
        std::shared_ptr<Database> database,
        std::shared_ptr<KafkaProducer> kafkaProducer,
        std::filesystem::path uploadDirectory
    );
    CreatedAnalysisJob createAnalysisJob(
        long long userId,
        const drogon::HttpFile& file,
        const std::string& sourceTypeCode
    );
  private:
    static constexpr std::size_t maxUploadSize = 20 * 1024 * 1024;
    static std::string lowerCase(std::string value);
    static std::string validateExtension(
        const std::filesystem::path& filename,
        const std::string& sourceTypeCode
    );
    static std::string mimeTypeFor(
        const std::string& sourceTypeCode,
        const std::string& extension
    );
    static void validateContent(std::string_view content, const std::string& sourceTypeCode);
    static std::string sha256(std::string_view content);
    std::shared_ptr<Database> database_;
    std::shared_ptr<KafkaProducer> kafkaProducer_;
    std::filesystem::path uploadDirectory_;
};

}  // namespace security_analyzer
