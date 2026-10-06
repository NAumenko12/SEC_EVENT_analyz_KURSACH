#include "security_analyzer/ParserFactory.hpp"

#include "security_analyzer/AuthLogParser.hpp"

#include <memory>
#include <stdexcept>

using namespace std;

namespace security_analyzer{

unique_ptr<EventParser> createParser(const string& sourceTypeCode){
    if (sourceTypeCode == "auth_log"){
        return make_unique<AuthLogParser>();
    }
    throw invalid_argument(
        "Парсер для типа источника " + sourceTypeCode + " ещё не реализован"
    );
}

}  // namespace security_analyzer
