#include "security_analyzer/UploadService.hpp"
#include "security_analyzer/KafkaProducer.hpp"

#include <drogon/utils/Utilities.h>
#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <iomanip>
#include <memory>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <system_error>
#include <utility>
using namespace std;

namespace security_analyzer {
string UploadService::lowerCase(string value){
        transform( value.begin(), value.end(), value.begin(), [](unsigned char character) {
            return static_cast<char>(tolower(character));
        }
    );
    return value;
}

string UploadService::validateExtension( const filesystem::path& filename, const string& sourceTypeCode){
    const string extension = lowerCase(filename.extension().string());
    static const set<string> logExtensions{ ".log", ".txt" };
    static const set<string> suricataExtensions{ ".json", ".jsonl", ".log"};
    static const set<string> pcapExtensions{ ".pcap", ".pcapng" };
    const set<string>* allowedExtensions = nullptr;
    if (sourceTypeCode == "auth_log" || sourceTypeCode == "nginx_access"){
        allowedExtensions = &logExtensions;
    } else if (sourceTypeCode == "suricata_eve"){
        allowedExtensions = &suricataExtensions;
    } else if (sourceTypeCode == "pcap") {
        allowedExtensions = &pcapExtensions;
    } else {
        throw invalid_argument("Неизвестный тип источника");
    }
    if (allowedExtensions->count(extension) == 0){
        throw invalid_argument(
            "Расширение файла не соответствует выбранному типу источника"
        );
    }
    return extension;
}

string UploadService::mimeTypeFor( const string& sourceTypeCode, const string& extension){
    if (sourceTypeCode == "suricata_eve"){
        return extension == ".json" ? "application/json" : "text/plain";
    }
    if (sourceTypeCode == "pcap"){
        return extension == ".pcap" ? "application/vnd.tcpdump.pcap" : "application/octet-stream";
    }
    return "text/plain";
}

void UploadService::validateContent(string_view content, const string& sourceTypeCode){
    if (sourceTypeCode == "pcap") {
        if (content.size() < 4) {
            throw invalid_argument("Файл не содержит заголовок PCAP");
        }
        const auto byte = [&content](size_t index) {
            return static_cast<unsigned char>(content[index]);
        };
        const array<array<unsigned char, 4>, 5> signatures{{ {{0xd4, 0xc3, 0xb2, 0xa1}}, {{0xa1, 0xb2, 0xc3, 0xd4}}, {{0x4d, 0x3c, 0xb2, 0xa1}}, {{0xa1, 0xb2, 0x3c, 0x4d}}, {{0x0a, 0x0d, 0x0d, 0x0a}},  }};
        const array<unsigned char, 4> header{ byte(0), byte(1), byte(2), byte(3) };
        if (find(signatures.begin(), signatures.end(), header) == signatures.end()) {
            throw invalid_argument("Сигнатура PCAP/PCAPNG не распознана");
        }
        return;
    }
    if (content.find('\0') != string_view::npos){
        throw invalid_argument("Ожидался текстовый файл журнала");
    }
    if (sourceTypeCode == "suricata_eve") {
        const auto firstContentCharacter = find_if( content.begin(), content.end(), [](unsigned char character) {
                return isspace(character) == 0;
            }
        );
        if (firstContentCharacter == content.end() || (*firstContentCharacter != '{' && *firstContentCharacter != '[')) {
            throw invalid_argument(
                "Файл Suricata не похож на JSON или JSONL"
            );
        }
    }
}

string UploadService::sha256(string_view content){
    using ContextPtr = unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
    ContextPtr context(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
    if (context == nullptr || EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1 || EVP_DigestUpdate(context.get(), content.data(), content.size()) != 1){
        throw runtime_error("Не удалось вычислить SHA-256 файла");
    }
    array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int digestLength = 0;
    if (EVP_DigestFinal_ex(context.get(), digest.data(), &digestLength) != 1){
        throw runtime_error("Не удалось завершить вычисление SHA-256");
    }
    ostringstream result;
    result << hex << setfill('0');
    for (unsigned int index = 0; index < digestLength; ++index){
        result << setw(2) << static_cast<int>(digest[index]);
    }
    return result.str();
}
UploadService::UploadService(
    shared_ptr<Database> database,
    shared_ptr<KafkaProducer> kafkaProducer,
    filesystem::path uploadDirectory
) : database_(move(database)),
    kafkaProducer_(move(kafkaProducer)),
    uploadDirectory_(move(uploadDirectory)) {
}

CreatedAnalysisJob UploadService::createAnalysisJob(
    long long userId,
    const drogon::HttpFile& file,
    const string& sourceTypeCode
){
    if (file.fileLength() == 0){
        throw invalid_argument("Файл пуст");
    }
    if (file.fileLength() > maxUploadSize){
        throw invalid_argument("Размер файла превышает 20 МБ");
    }
    const filesystem::path originalPath(file.getFileName());
    const string originalFilename = originalPath.filename().string();
    if (originalFilename.empty() || originalFilename.size() > 255){
        throw invalid_argument("Недопустимое имя файла");
    }
    const string extension = validateExtension(originalPath, sourceTypeCode);
    validateContent(file.fileContent(), sourceTypeCode);    
    const string storedFilename = drogon::utils::getUuid() + extension;
    error_code directoryError;
    const filesystem::path userDirectory =
        uploadDirectory_ / to_string(userId);
    filesystem::create_directories(userDirectory, directoryError);
    if (directoryError) {
        throw runtime_error("Не удалось создать каталог загрузок");
    }
    const filesystem::path filePath = userDirectory / storedFilename;
    const filesystem::path absoluteFilePath = filesystem::absolute(filePath);
    if (file.saveAs(absoluteFilePath.string()) != 0){
        throw runtime_error("Не удалось сохранить загруженный файл");
    }
    CreatedAnalysisJob created{};
    try {
        created = database_->createUploadAndJob(userId, UploadData{
            sourceTypeCode,
            originalFilename,
            storedFilename,
            filePath.generic_string(),
            mimeTypeFor(sourceTypeCode, extension),
            file.fileLength(),
            sha256(file.fileContent()),
        });
    } catch (...) {
        error_code removeError;
        filesystem::remove(absoluteFilePath, removeError);
        throw;
    }
    try {
        kafkaProducer_->publishAnalysisJob(created.jobId, created.uploadId);
    } catch (const exception&){
        database_->failAnalysisJob(
            created.jobId,
            "Не удалось передать задание в очередь Kafka"
        );
        throw;
    }
    return created;
}

}  // namespace security_analyzer
