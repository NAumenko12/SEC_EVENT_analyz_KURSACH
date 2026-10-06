#pragma once

#include "security_analyzer/EventParser.hpp"

#include <memory>
#include <string>

namespace security_analyzer {

std::unique_ptr<EventParser> createParser(const std::string& sourceTypeCode);

}  // namespace security_analyzer
