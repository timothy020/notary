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

// Notary相关常量 - 对应Go版本的notary.MinRSABitSize
const int MinRSABitSize = 2048;

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
    
    // 检查证书是否为CA证书 - 对应Go版本的cert.IsCA
    bool IsCA() const;

private:
    X509* cert_ = nullptr;
};

// 从PEM数据解析证书
std::shared_ptr<utils::Certificate> LoadCertificateFromPEM(const std::vector<uint8_t>& pemData);

// 从文件加载证书
std::shared_ptr<utils::Certificate> LoadCertificateFromFile(const std::string& filename);

// LoadCertBundleFromPEM loads certificates from the PEM data provided.
// The data is expected to be PEM Encoded and contain one or more certificates
// with PEM type "CERTIFICATE" - 对应Go版本的utils.LoadCertBundleFromPEM函数
// 参数说明:
// - pemBytes: PEM格式的证书束数据
// 返回值:
// - std::vector<std::shared_ptr<Certificate>>: 解析出的证书列表
// - 如果解析失败或没有找到证书，抛出CertificateError异常
std::vector<std::shared_ptr<Certificate>> LoadCertBundleFromPEM(const std::vector<uint8_t>& pemBytes);

// LoadCertBundleFromFile loads certificates from the file provided.
// The data is expected to be PEM Encoded and contain one or more certificates
// with PEM type "CERTIFICATE" - 对应Go版本的utils.LoadCertBundleFromFile函数
// 参数说明:
// - filename: 包含证书束的文件路径
// 返回值:
// - std::vector<std::shared_ptr<Certificate>>: 解析出的证书列表
// - 如果解析失败或没有找到证书，抛出CertificateError异常
std::vector<std::shared_ptr<Certificate>> LoadCertBundleFromFile(const std::string& filename);

// GetLeafCerts parses a list of x509 Certificates and returns all of them
// that aren't CA - 对应Go版本的utils.GetLeafCerts函数
// 参数说明:
// - certs: 证书列表
// 返回值:
// - std::vector<std::shared_ptr<Certificate>>: 所有叶子证书（非CA证书）的列表
std::vector<std::shared_ptr<Certificate>> GetLeafCerts(const std::vector<std::shared_ptr<Certificate>>& certs);

// GetIntermediateCerts parses a list of x509 Certificates and returns all of the
// ones marked as a CA, to be used as intermediates - 对应Go版本的utils.GetIntermediateCerts函数
// 参数说明:
// - certs: 证书列表
// 返回值:
// - std::vector<std::shared_ptr<Certificate>>: 所有中间证书（CA证书）的列表
std::vector<std::shared_ptr<Certificate>> GetIntermediateCerts(const std::vector<std::shared_ptr<Certificate>>& certs);

// ValidateCertificate returns an error if the certificate is not valid for notary
// Currently this is only ensuring the public key has a large enough modulus if RSA,
// using a non SHA1 signature algorithm, and an optional time expiry check
// 对应Go版本的utils.ValidateCertificate函数
// 参数说明:
// - cert: 要验证的证书
// - checkExpiry: 是否检查证书过期时间
// 返回值:
// - Error: 如果证书无效返回错误信息，否则返回空的Error对象
Error ValidateCertificate(const Certificate& cert, bool checkExpiry);
Error ValidateCertificate(X509* cert, bool checkExpiry);

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

// CertChainToPEM is a utility function returns a PEM encoded chain of x509 Certificates
// 对应Go版本的utils.CertChainToPEM函数
// 参数说明:
// - certChain: 证书链列表（按顺序排列）
// 返回值:
// - std::pair<std::vector<uint8_t>, Error>: PEM编码的证书链和错误信息
std::pair<std::vector<uint8_t>, Error> CertChainToPEM(const std::vector<std::shared_ptr<Certificate>>& certChain);

// CertBundleToKey creates a TUF key from a leaf cert and a list of intermediates
// 对应Go版本的utils.CertBundleToKey函数
// 参数说明:
// - leafCert: 叶子证书
// - intCerts: 中间证书列表
// 返回值:
// - std::pair<std::shared_ptr<crypto::PublicKey>, Error>: 创建的公钥对象和错误信息
std::pair<std::shared_ptr<crypto::PublicKey>, Error> CertBundleToKey(
    std::shared_ptr<Certificate> leafCert,
    const std::vector<std::shared_ptr<Certificate>>& intCerts);

// CertsToKeys transforms each of the input certificate chains into its corresponding PublicKey
// 对应Go版本的utils.CertsToKeys函数
// 参数说明:
// - leafCerts: 叶子证书映射 (key ID -> 证书)
// - intCerts: 中间证书映射 (key ID -> 中间证书列表)
// 返回值:
// - std::map<std::string, std::shared_ptr<crypto::PublicKey>>: 公钥映射 (key ID -> 公钥)
std::map<std::string, std::shared_ptr<crypto::PublicKey>> CertsToKeys(
    const std::map<std::string, std::shared_ptr<Certificate>>& leafCerts,
    const std::map<std::string, std::vector<std::shared_ptr<Certificate>>>& intCerts);

}
}