#pragma once

#include "security_analyzer/Database.hpp"

#include <drogon/MultiPart.h>

#include <filesystem>
#include <memory>
#include <string>

namespace security_analyzer{

class UploadService{
  public:
    UploadService( std::shared_ptr<Database> database, std::filesystem::path uploadDirectory );
    CreatedAnalysisJob createAnalysisJob( const drogon::HttpFile& file, const std::string& sourceTypeCode );
  private:
    std::shared_ptr<Database> database_;
    std::filesystem::path uploadDirectory_;
};

}  // namespace security_analyzer
