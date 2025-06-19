#pragma once

#include <string>
#include <chrono>
#include <memory>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include "notary/crypto/keys.hpp"
#include "notary/types.hpp"

namespace notary {
namespace utils {

// 证书生成错误类
class CertificateError : public std::runtime_error {
public:
    explicit CertificateError(const std::string& message) 
        : std::runtime_error("Certificate error: " + message) {}
};

// X509证书包装类
class Certificate {
public:
    Certificate() = default;
    explicit Certificate(X509* cert);
    ~Certificate();
    
    // 禁用拷贝构造和拷贝赋值
    Certificate(const Certificate&) = delete;
    Certificate& operator=(const Certificate&) = delete;
    
    // 支持移动构造和移动赋值
    Certificate(Certificate&& other) noexcept;
    Certificate& operator=(Certificate&& other) noexcept;
    
    // 获取原始X509证书指针
    X509* GetX509() const { return cert_; }
    
    // 获取证书的通用名称(Common Name)
    std::string GetCommonName() const;
    
    // 获取证书的有效期开始时间
    std::chrono::system_clock::time_point GetNotBefore() const;
    
    // 获取证书的有效期结束时间  
    std::chrono::system_clock::time_point GetNotAfter() const;
    
    // 获取证书的公钥
    std::shared_ptr<crypto::PublicKey> GetPublicKey() const;
    
    // 将证书转换为PEM格式
    std::vector<uint8_t> ToPEM() const;
    
    // 将证书转换为DER格式
    std::vector<uint8_t> ToDER() const;
    
    // 验证证书是否有效
    bool IsValid() const;

private:
    X509* cert_ = nullptr;
};

// 从PEM数据解析证书
std::shared_ptr<utils::Certificate> LoadCertificateFromPEM(const std::vector<uint8_t>& pemData);

// 从文件加载证书
std::shared_ptr<utils::Certificate> LoadCertificateFromFile(const std::string& filename);

// 创建证书模板 - 对应Go版本utils.NewCertificate函数  
// 参数说明:
// - commonName: 证书的通用名称
// - startTime: 证书有效期开始时间
// - endTime: 证书有效期结束时间
// 返回值:
// - X509*: 证书模板对象
X509* NewCertificateTemplate(
    const std::string& commonName,
    const std::chrono::system_clock::time_point& startTime,
    const std::chrono::system_clock::time_point& endTime
);

// X509扩展辅助函数
X509_EXTENSION* createKeyUsageExtension();
X509_EXTENSION* createExtKeyUsageExtension();
X509_EXTENSION* createBasicConstraintsExtension();

// LoadCertFromPEM loads the first certificate from the PEM data provided
// 对应Go版本的utils.LoadCertFromPEM函数
// 参数说明:
// - pemBytes: PEM格式的证书数据
// 返回值:
// - X509*: 解析出的第一个证书，调用者负责释放内存
// - 如果解析失败，返回nullptr
X509* LoadCertFromPEM(const std::vector<uint8_t>& pemBytes);

// X509PublicKeyID returns a public key ID as a string, given a
// PublicKey that contains an X509 Certificate
// 对应Go版本的utils.X509PublicKeyID函数
// 参数说明:
// - certPubKey: 包含X509证书的公钥对象
// 返回值:
// - std::string: 公钥ID，如果操作失败返回空字符串
std::string X509PublicKeyID(std::shared_ptr<crypto::PublicKey> certPubKey);

// CanonicalKeyID returns the ID of the public bytes version of a TUF key.
// On regular RSA/ECDSA TUF keys, this is just the key ID. On X509 RSA/ECDSA
// TUF keys, this is the key ID of the public key part of the key in the leaf cert
// 对应Go版本的utils.CanonicalKeyID函数
// 参数说明:
// - k: 公钥对象
// 返回值:
// - std::string: 规范化的公钥ID，如果操作失败返回空字符串
std::string CanonicalKeyID(std::shared_ptr<crypto::PublicKey> k);

// CertToKey transforms a single input certificate into its corresponding
// PublicKey - 对应Go版本的utils.CertToKey函数
// 参数说明:
// - cert: X509证书指针或Certificate对象
// 返回值:
// - std::shared_ptr<crypto::PublicKey>: 对应的公钥对象
std::shared_ptr<crypto::PublicKey> CertToKey(X509* cert);
std::shared_ptr<crypto::PublicKey> CertToKey(const Certificate& cert);

}
}