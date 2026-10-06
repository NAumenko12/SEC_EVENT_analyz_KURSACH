#pragma once

#include "security_analyzer/EventParser.hpp"

#include <filesystem>

namespace security_analyzer {

ParseResult parseTextLog(const std::filesystem::path& path,const EventParser& parser);

}  // namespace security_analyzer
