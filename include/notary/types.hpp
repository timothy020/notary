#pragma once

#include <string>
#include <vector>
#include <variant>
#include <memory>
#include "notary/crypto/keys.hpp"

namespace notary {

// 错误类型
class Error {
public:
    explicit Error(const std::string& message) : message_(message), isError_(true) {}
    Error() : isError_(false) {}
    
    const std::string& what() const { return message_; }
    bool ok() const { return !isError_; }
    bool hasError() const { return isError_; }
    
    // 添加message成员访问
    std::string message = "";
    
    // 保持向后兼容
    const std::string& getMessage() const { return message_; }
    
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

// 角色名称转换函数
inline std::string roleToString(RoleName role) {
    switch (role) {
        case RoleName::RootRole: return "root";
        case RoleName::TargetsRole: return "targets";
        case RoleName::SnapshotRole: return "snapshot";
        case RoleName::TimestampRole: return "timestamp";
        default: return "unknown";
    }
}

inline RoleName stringToRole(const std::string& roleStr) {
    if (roleStr == "root") return RoleName::RootRole;
    if (roleStr == "targets") return RoleName::TargetsRole;
    if (roleStr == "snapshot") return RoleName::SnapshotRole;
    if (roleStr == "timestamp") return RoleName::TimestampRole;
    return RoleName::TargetsRole; // 默认值
}

// 密钥算法
enum class KeyAlgorithm {
    ECDSA,
    RSA,
    ED25519
};


// 基础角色
class BaseRole {
public:
    // 默认构造函数 - 为了满足std::map的要求
    BaseRole() : name_(RoleName::RootRole), threshold_(0) {}
    
    BaseRole(RoleName name, int threshold, std::vector<std::shared_ptr<crypto::PublicKey>> keys)
        : name_(name), threshold_(threshold), keys_(std::move(keys)) {}
    
    RoleName Name() const { return name_; }
    int Threshold() const { return threshold_; }
    const std::vector<std::shared_ptr<crypto::PublicKey>>& Keys() const { return keys_; }
    std::vector<std::shared_ptr<crypto::PublicKey>>& Keys() { return keys_; }
    
private:
    RoleName name_;
    int threshold_;
    std::vector<std::shared_ptr<crypto::PublicKey>> keys_;
};

// 全局唯一名称
using GUN = std::string;

} // namespace notary 