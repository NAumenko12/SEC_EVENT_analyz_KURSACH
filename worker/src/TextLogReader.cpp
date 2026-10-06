#include "security_analyzer/TextLogReader.hpp"

#include <fstream>
#include <stdexcept>
#include <string>
#include <utility>

using namespace std;

namespace security_analyzer {

ParseResult parseTextLog( const filesystem::path& path, const EventParser& parser){
    ifstream input(path);
    if (!input) {
        throw runtime_error("Не удалось открыть файл журнала");
    }
    ParseResult result;
    string line;
    while (getline(input, line)) {
        ++result.processedRecords;
        auto event = parser.parseLine(line, result.processedRecords);
        if (event.has_value()) {
            result.events.push_back(move(event.value()));
        }
    }
    if (input.bad()) {
        throw runtime_error("Ошибка чтения файла журнала");
    }
    return result;
}

}  // namespace security_analyzer
