#pragma once

#include <string>
#include <vector>
#include <variant>
#include <memory>

namespace notary {

// 错误类型
class Error {
public:
    explicit Error(const std::string& message) : message_(message), isError_(true) {}
    Error() : isError_(false) {}
    const std::string& what() const { return message_; }
    bool ok() const { return !isError_; }
private:
    std::string message_;
    bool isError_;
};

// 结果类型
template<typename T>
class Result {
public:
    Result(const T& value) : value_(value), hasError_(false) {}
    Result(const Error& error) : error_(error), hasError_(true) {}
    
    bool ok() const { return !hasError_; }
    const T& value() const { return value_; }
    const Error& error() const { return error_; }
    
private:
    T value_;
    Error error_;
    bool hasError_;
};

// 角色名称
enum class RoleName {
    RootRole,
    TargetsRole,
    SnapshotRole,
    TimestampRole
};

// 密钥算法
enum class KeyAlgorithm {
    ECDSA,
    RSA,
    ED25519
};

// 公钥
class PublicKey {
public:
    virtual ~PublicKey() = default;
    virtual std::string ID() const = 0;
    virtual KeyAlgorithm Algorithm() const = 0;
    virtual std::vector<uint8_t> Bytes() const = 0;
};

// 私钥
class PrivateKey {
public:
    virtual ~PrivateKey() = default;
    virtual std::string ID() const = 0;
    virtual KeyAlgorithm Algorithm() const = 0;
    virtual Result<std::vector<uint8_t>> Sign(const std::vector<uint8_t>& data) = 0;
};

// 基础角色
class BaseRole {
public:
    BaseRole(RoleName name, int threshold, std::vector<std::shared_ptr<PublicKey>> keys)
        : name_(name), threshold_(threshold), keys_(std::move(keys)) {}
    
    RoleName Name() const { return name_; }
    int Threshold() const { return threshold_; }
    const std::vector<std::shared_ptr<PublicKey>>& Keys() const { return keys_; }
    
private:
    RoleName name_;
    int threshold_;
    std::vector<std::shared_ptr<PublicKey>> keys_;
};

// 全局唯一名称
using GUN = std::string;

} // namespace notary 