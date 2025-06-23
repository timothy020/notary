#pragma once

#include <string>
#include <vector>
#include <variant>
#include <memory>

// 前向声明避免循环依赖
namespace notary {
namespace crypto {
    class PublicKey;
}
}

namespace notary {

// 签名算法常量
const std::string EDDSASignature        = "eddsa";
const std::string RSAPSSSignature       = "rsapss";
const std::string RSAPKCS1v15Signature  = "rsapkcs1v15";
const std::string ECDSASignature        = "ecdsa";
const std::string PyCryptoSignature     = "pycrypto-pkcs#1 pss";

// 密钥算法常量
const std::string ED25519_KEY       = "ed25519";
const std::string RSA_KEY           = "rsa";
const std::string RSA_X509_KEY      = "rsa-x509";
const std::string ECDSA_KEY         = "ecdsa";
const std::string ECDSA_X509_KEY    = "ecdsa-x509";

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
    Result() : hasError_(true) {}
    Result(const T& value) : value_(value), hasError_(false) {}
    Result(T&& value) : value_(std::move(value)), hasError_(false) {}
    Result(const Error& error) : error_(error), hasError_(true) {}
    
    bool ok() const { return !hasError_; }
    const T& value() const & { return value_; }
    T&& value() && { return std::move(value_); }
    const Error& error() const { return error_; }
    
private:
    T value_;
    Error error_;
    bool hasError_;
};


// 角色名称常量
const std::string ROOT_ROLE = "root";
const std::string TARGETS_ROLE = "targets";
const std::string SNAPSHOT_ROLE = "snapshot";
const std::string TIMESTAMP_ROLE = "timestamp";

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
        case RoleName::RootRole: return ROOT_ROLE;
        case RoleName::TargetsRole: return TARGETS_ROLE;
        case RoleName::SnapshotRole: return SNAPSHOT_ROLE;
        case RoleName::TimestampRole: return TIMESTAMP_ROLE;
        default: return "unknown";
    }
}

inline RoleName stringToRole(const std::string& roleStr) {
    if (roleStr == ROOT_ROLE) return RoleName::RootRole;
    if (roleStr == TARGETS_ROLE) return RoleName::TargetsRole;
    if (roleStr == SNAPSHOT_ROLE) return RoleName::SnapshotRole;
    if (roleStr == TIMESTAMP_ROLE) return RoleName::TimestampRole;
    return RoleName::TargetsRole; // 默认值
}


// 基础角色
class BaseRole {
public:
    // 默认构造函数 - 为了满足std::map的要求
    BaseRole() : name_(RoleName::RootRole), threshold_(0) {}
    
    // 完整构造函数
    BaseRole(RoleName name, int threshold, const std::vector<std::shared_ptr<crypto::PublicKey>>& keys)
        : name_(name), threshold_(threshold), keys_(keys) {}
    
    RoleName Name() const { return name_; }
    int Threshold() const { return threshold_; }
    const std::vector<std::shared_ptr<crypto::PublicKey>>& Keys() const { return keys_; }
    std::vector<std::shared_ptr<crypto::PublicKey>>& Keys() { return keys_; }
    
    // 添加设置方法
    void SetName(RoleName name) { name_ = name; }
    void SetThreshold(int threshold) { threshold_ = threshold; }
    void SetKeys(const std::vector<std::shared_ptr<crypto::PublicKey>>& keys) { keys_ = keys; }
    
    // 添加Equals方法
    bool Equals(const BaseRole& other) const;
    
private:
    RoleName name_;
    int threshold_;
    std::vector<std::shared_ptr<crypto::PublicKey>> keys_; // TODO: 需要修改为map
};

// 全局唯一名称
using GUN = std::string;

// TUF相关常量
const int64_t MAX_TIMESTAMP_SIZE = 1024 * 1024; // 1MB
const int64_t NO_SIZE_LIMIT = -1;
const int64_t MAX_DOWNLOAD_SIZE = 100 * 1024 * 1024; // 100MB，对应Go版本的notary.MaxDownloadSize

} // namespace notary 