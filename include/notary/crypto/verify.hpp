#pragma once

#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <map>
#include "notary/types.hpp"
#include "notary/tuf/repo.hpp"
#include "notary/crypto/keys.hpp"
#include "notary/crypto/verifiers.hpp"

namespace notary {
namespace crypto {

// 基础签名错误
extern const std::string ErrNoSignatures;
extern const std::string ErrInvalid;
extern const std::string ErrWrongType;

// 签名验证错误类型
class ErrExpired : public std::exception {
public:
    ErrExpired(const std::string& role, const std::string& expired) 
        : role_(role), expired_(expired) {
        message_ = "TUF metadata for " + role + " expired on " + expired;
    }
    
    const char* what() const noexcept override { return message_.c_str(); }
    const std::string& getRole() const { return role_; }
    const std::string& getExpired() const { return expired_; }
    
private:
    const std::string& role_;
    std::string expired_;
    std::string message_;
};

class ErrLowVersion : public std::exception {
public:
    ErrLowVersion(int actual, int current) 
        : actual_(actual), current_(current) {
        message_ = "TUF metadata version " + std::to_string(actual) + 
                  " is lower than expected version " + std::to_string(current);
    }
    
    const char* what() const noexcept override { return message_.c_str(); }
    int getActual() const { return actual_; }
    int getCurrent() const { return current_; }
    
private:
    int actual_;
    int current_;
    std::string message_;
};

class ErrRoleThreshold : public std::exception {
public:
    ErrRoleThreshold() = default;
    explicit ErrRoleThreshold(const std::string& msg) : message_(msg) {}
    
    const char* what() const noexcept override { 
        return message_.empty() ? "role threshold not met" : message_.c_str(); 
    }
    
private:
    std::string message_;
};

class ErrInvalidKeyID : public std::exception {
public:
    const char* what() const noexcept override { 
        return "key ID does not match content ID of key"; 
    }
};

// 时间验证函数
bool IsExpired(const std::chrono::time_point<std::chrono::system_clock>& t);

// 过期时间验证
Error VerifyExpiry(const notary::tuf::SignedCommon& s, const std::string& role);

// 版本验证
Error VerifyVersion(const notary::tuf::SignedCommon& s, int minVersion);

// 签名验证
Error VerifySignatures(notary::tuf::Signed& s, const BaseRole& roleData);

// 单个签名验证
Error VerifySignature(const std::vector<uint8_t>& msg, 
                     notary::tuf::Signature& sig, 
                     std::shared_ptr<PublicKey> pk);

// 验证公私钥对是否匹配
Error VerifyPublicKeyMatchesPrivateKey(std::shared_ptr<PrivateKey> privKey, 
                                      std::shared_ptr<PublicKey> pubKey);



} // namespace crypto
} // namespace notary
