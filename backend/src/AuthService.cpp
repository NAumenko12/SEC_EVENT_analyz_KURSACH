#include "security_analyzer/AuthService.hpp"

#include <sodium.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <limits>
#include <stdexcept>
#include <utility>

using namespace std;

namespace security_analyzer {
bool AuthService::isAllowedUsernameCharacter(unsigned char character){
    return isalnum(character) != 0 || character == '_' || character == '-' || character == '.';
}

void AuthService::validateUsername(const string& username){
    if (username.size() < 3 || username.size() > 32 || !all_of( username.begin(), username.end(), isAllowedUsernameCharacter)){
        throw AuthError( AuthErrorCode::invalidInput, "Имя пользователя должно содержать от 3 до 32 латинских букв, " "цифр или символов _.-" );
    }
}

string AuthService::normalizeEmail(string email) {
    if (email.empty() || email.size() > 254 || any_of(email.begin(), email.end(), [](unsigned char character){
            return iscntrl(character) != 0 || isspace(character) != 0;
        })) {
        throw AuthError(AuthErrorCode::invalidInput, "Некорректный email");
    }
    const auto separator = email.find('@');
    if (separator == string::npos || separator == 0 || separator + 1 >= email.size() || email.find('@', separator + 1) != string::npos || email.find('.', separator + 1) == string::npos){
        throw AuthError(AuthErrorCode::invalidInput, "Некорректный email");
    }
    transform( email.begin(), email.end(), email.begin(), [](unsigned char character){
            return static_cast<char>(tolower(character));
        }
    );
    return email;
}

void AuthService::validatePassword(const string& password){
    if (password.size() < minimumPasswordLength || password.size() > maximumPasswordLength){
        throw AuthError( AuthErrorCode::invalidInput, "Пароль должен содержать от 15 до 128 символов" );
    }
    if (password.find('\0') != string::npos){
        throw AuthError(AuthErrorCode::invalidInput, "Пароль содержит недопустимый символ");
    }
}

AuthError::AuthError(AuthErrorCode code, const string& message) : runtime_error(message), code_(code){
}

AuthErrorCode AuthError::code() const noexcept{
    return code_;
}

AuthService::AuthService(shared_ptr<Database> database): database_(move(database)){
    if (sodium_init() < 0){
        throw runtime_error("Не удалось инициализировать libsodium");
    }
    dummyPasswordHash_ = hashPassword("this-is-a-dummy-password-value");
}

string AuthService::hashPassword(const string& password) const{
    array<char, crypto_pwhash_STRBYTES> output{};
    if (crypto_pwhash_str_alg(
            output.data(), password.data(), password.size(),
            crypto_pwhash_OPSLIMIT_INTERACTIVE,
            crypto_pwhash_MEMLIMIT_INTERACTIVE,
            crypto_pwhash_ALG_ARGON2ID13
        ) != 0) {
        throw runtime_error("Не удалось безопасно сохранить пароль");
    }
    return output.data();
}

string AuthService::createToken() const {
    array<unsigned char, 32> bytes{};
    array<char, 65> encoded{};
    randombytes_buf(bytes.data(), bytes.size());
    sodium_bin2hex(encoded.data(), encoded.size(), bytes.data(), bytes.size());
    sodium_memzero(bytes.data(), bytes.size());
    return encoded.data();
}

string AuthService::hashToken(const string& token) const {
    if (token.size() != 64 || !all_of(token.begin(), token.end(), [](unsigned char character) {
            return isdigit(character) != 0 || (character >= 'a' && character <= 'f');
        })){
        throw AuthError(AuthErrorCode::unauthorized, "Требуется авторизация");
    }
    array<unsigned char, crypto_hash_sha256_BYTES> digest{};
    array<char, crypto_hash_sha256_BYTES * 2 + 1> encoded{};
    crypto_hash_sha256( digest.data(), reinterpret_cast<const unsigned char*>(token.data()), static_cast<unsigned long long>(token.size()));
    sodium_bin2hex(encoded.data(), encoded.size(), digest.data(), digest.size());
    sodium_memzero(digest.data(), digest.size());
    return encoded.data();
}

AuthSession AuthService::createSessionFor(const User& user){
    const string token = createToken();
    database_->createSession(user.id, hashToken(token), sessionLifetimeSeconds);
    return AuthSession{token, user};
}

AuthSession AuthService::registerUser( const string& username, const string& email, const string& password){
    validateUsername(username);
    const string normalizedEmail = normalizeEmail(email);
    validatePassword(password);
    const string passwordHash = hashPassword(password);
    try {
        return createSessionFor( database_->createUser(username, normalizedEmail, passwordHash));
    } catch (const DatabaseConflictError& error){
        throw AuthError(AuthErrorCode::conflict, error.what());
    }
}

AuthSession AuthService::login( const string& login, const string& password){
    if (login.empty() || login.size() > 254 || password.size() > maximumPasswordLength){
        throw AuthError( AuthErrorCode::invalidCredentials, "Неверное имя пользователя или пароль" );
    }
    const auto credentials = database_->findUserByLogin(login);
    const string& storedHash = credentials.has_value() ? credentials->passwordHash : dummyPasswordHash_;
    const bool passwordMatches = crypto_pwhash_str_verify( storedHash.c_str(), password.data(), password.size() ) == 0;
    if (!credentials.has_value() || !credentials->isActive || !passwordMatches){
        throw AuthError( AuthErrorCode::invalidCredentials, "Неверное имя пользователя или пароль" );
    }
    return createSessionFor(credentials->user);
}

User AuthService::authenticate(const string& token){
    const auto user = database_->findUserBySessionTokenHash(hashToken(token));
    if (!user.has_value()) {
        throw AuthError(AuthErrorCode::unauthorized, "Требуется авторизация");
    }
    return user.value();
}

void AuthService::logout(const string& token) {
    database_->revokeSession(hashToken(token));
}

}  // namespace security_analyzer
