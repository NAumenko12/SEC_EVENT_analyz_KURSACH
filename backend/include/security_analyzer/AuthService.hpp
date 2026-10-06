#pragma once

#include "security_analyzer/Database.hpp"

#include <memory>
#include <cstddef>
#include <stdexcept>
#include <string>

namespace security_analyzer {

enum class AuthErrorCode {
    invalidInput,
    invalidCredentials,
    unauthorized,
    conflict,
};

class AuthError : public std::runtime_error {
  public:
    AuthError(AuthErrorCode code, const std::string& message);
    AuthErrorCode code() const noexcept;

  private:
    AuthErrorCode code_;
};

struct AuthSession {
    std::string token;
    User user;
};

class AuthService {
  public:
    explicit AuthService(std::shared_ptr<Database> database);
    AuthSession registerUser( const std::string& username, const std::string& email, const std::string& password );
    AuthSession login(const std::string& login, const std::string& password);
    User authenticate(const std::string& token);
    void logout(const std::string& token);

  private:
    static constexpr std::size_t minimumPasswordLength = 15;
    static constexpr std::size_t maximumPasswordLength = 128;
    static constexpr long long sessionLifetimeSeconds = 7 * 24 * 60 * 60;
    static bool isAllowedUsernameCharacter(unsigned char character);
    static void validateUsername(const std::string& username);
    static std::string normalizeEmail(std::string email);
    static void validatePassword(const std::string& password);
    std::string hashPassword(const std::string& password) const;
    std::string createToken() const;
    std::string hashToken(const std::string& token) const;
    AuthSession createSessionFor(const User& user);
    std::shared_ptr<Database> database_;
    std::string dummyPasswordHash_;
};

}  // namespace security_analyzer
