#include "security_analyzer/UploadService.hpp"

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

namespace security_analyzer {
namespace {

constexpr std::size_t maxUploadSize = 20 * 1024 * 1024;

std::string lowerCase(std::string value){
    std::transform(
        value.begin(),
        value.end(),
        value.begin(),
        [](unsigned char character) {
            return static_cast<char>(std::tolower(character));
        }
    );
    return value;
}

std::string validateExtension( const std::filesystem::path& filename, const std::string& sourceTypeCode){
    const std::string extension = lowerCase(filename.extension().string());
    static const std::set<std::string> logExtensions{ ".log", ".txt" };
    static const std::set<std::string> suricataExtensions{
        ".json", ".jsonl", ".log"
    };
    static const std::set<std::string> pcapExtensions{ ".pcap", ".pcapng" };
    const std::set<std::string>* allowedExtensions = nullptr;
    if (sourceTypeCode == "auth_log" || sourceTypeCode == "nginx_access"){
        allowedExtensions = &logExtensions;
    } else if (sourceTypeCode == "suricata_eve"){
        allowedExtensions = &suricataExtensions;
    } else if (sourceTypeCode == "pcap") {
        allowedExtensions = &pcapExtensions;
    } else {
        throw std::invalid_argument("Неизвестный тип источника");
    }
    if (allowedExtensions->count(extension) == 0){
        throw std::invalid_argument(
            "Расширение файла не соответствует выбранному типу источника"
        );
    }
    return extension;
}

std::string mimeTypeFor( const std::string& sourceTypeCode, const std::string& extension){
    if (sourceTypeCode == "suricata_eve"){
        return extension == ".json" ? "application/json" : "text/plain";
    }
    if (sourceTypeCode == "pcap"){
        return extension == ".pcap" ? "application/vnd.tcpdump.pcap" : "application/octet-stream";
    }
    return "text/plain";
}

void validateContent(std::string_view content, const std::string& sourceTypeCode){
    if (sourceTypeCode == "pcap") {
        if (content.size() < 4) {
            throw std::invalid_argument("Файл не содержит заголовок PCAP");
        }
        const auto byte = [&content](std::size_t index) {
            return static_cast<unsigned char>(content[index]);
        };
        const std::array<std::array<unsigned char, 4>, 5> signatures{{
            {{0xd4, 0xc3, 0xb2, 0xa1}},
            {{0xa1, 0xb2, 0xc3, 0xd4}},
            {{0x4d, 0x3c, 0xb2, 0xa1}},
            {{0xa1, 0xb2, 0x3c, 0x4d}},
            {{0x0a, 0x0d, 0x0d, 0x0a}},
        }};
        const std::array<unsigned char, 4> header{
            byte(0), byte(1), byte(2), byte(3)
        };
        if (std::find(signatures.begin(), signatures.end(), header) == signatures.end()) {
            throw std::invalid_argument("Сигнатура PCAP/PCAPNG не распознана");
        }
        return;
    }
    if (content.find('\0') != std::string_view::npos){
        throw std::invalid_argument("Ожидался текстовый файл журнала");
    }
    if (sourceTypeCode == "suricata_eve") {
        const auto firstContentCharacter = std::find_if( content.begin(), content.end(), [](unsigned char character) {
                return std::isspace(character) == 0;
            }
        );
        if (firstContentCharacter == content.end() || (*firstContentCharacter != '{' && *firstContentCharacter != '[')) {
            throw std::invalid_argument(
                "Файл Suricata не похож на JSON или JSONL"
            );
        }
    }
}

std::string sha256(std::string_view content){
    using ContextPtr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
    ContextPtr context(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
    if (context == nullptr || EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1 || EVP_DigestUpdate(context.get(), content.data(), content.size()) != 1){
        throw std::runtime_error("Не удалось вычислить SHA-256 файла");
    }
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int digestLength = 0;
    if (EVP_DigestFinal_ex(context.get(), digest.data(), &digestLength) != 1){
        throw std::runtime_error("Не удалось завершить вычисление SHA-256");
    }
    std::ostringstream result;
    result << std::hex << std::setfill('0');
    for (unsigned int index = 0; index < digestLength; ++index){
        result << std::setw(2) << static_cast<int>(digest[index]);
    }
    return result.str();
}
}  // namespace

UploadService::UploadService( std::shared_ptr<Database> database, std::filesystem::path uploadDirectory ) : database_(std::move(database)), uploadDirectory_(std::move(uploadDirectory)) {
}

CreatedAnalysisJob UploadService::createAnalysisJob( const drogon::HttpFile& file, const std::string& sourceTypeCode ){
    if (file.fileLength() == 0){
        throw std::invalid_argument("Файл пуст");
    }
    if (file.fileLength() > maxUploadSize){
        throw std::invalid_argument("Размер файла превышает 20 МБ");
    }
    const std::filesystem::path originalPath(file.getFileName());
    const std::string originalFilename = originalPath.filename().string();
    if (originalFilename.empty() || originalFilename.size() > 255){
        throw std::invalid_argument("Недопустимое имя файла");
    }
    const std::string extension = validateExtension(originalPath, sourceTypeCode);
    validateContent(file.fileContent(), sourceTypeCode);    
    const std::string storedFilename = drogon::utils::getUuid() + extension;
    std::error_code directoryError;
    std::filesystem::create_directories(uploadDirectory_, directoryError);
    if (directoryError) {
        throw std::runtime_error("Не удалось создать каталог загрузок");
    }
    const std::filesystem::path filePath = uploadDirectory_ / storedFilename;
    const std::filesystem::path absoluteFilePath = std::filesystem::absolute(filePath);
    if (file.saveAs(absoluteFilePath.string()) != 0){
        throw std::runtime_error("Не удалось сохранить загруженный файл");
    }
    try {
        return database_->createUploadAndJob(UploadData{
            sourceTypeCode,
            originalFilename,
            storedFilename,
            filePath.generic_string(),
            mimeTypeFor(sourceTypeCode, extension),
            file.fileLength(),
            sha256(file.fileContent()),
        });
    } catch (...) {
        std::error_code removeError;
        std::filesystem::remove(filePath, removeError);
        throw;
    }
}

}  // namespace security_analyzer
