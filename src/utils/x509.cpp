#include "notary/utils/x509.hpp"
#include "notary/types.hpp"
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/asn1.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <cstring>
#include <fstream>
#include <iterator>

namespace notary {
namespace utils {

// Certificate类实现

Certificate::Certificate(X509* cert) : cert_(cert) {
    if (cert_) {
        X509_up_ref(cert_); // 增加引用计数
    }
}

Certificate::~Certificate() {
    if (cert_) {
        X509_free(cert_);
    }
}

Certificate::Certificate(Certificate&& other) noexcept : cert_(other.cert_) {
    other.cert_ = nullptr;
}

Certificate& Certificate::operator=(Certificate&& other) noexcept {
    if (this != &other) {
        if (cert_) {
            X509_free(cert_);
        }
        cert_ = other.cert_;
        other.cert_ = nullptr;
    }
    return *this;
}

std::string Certificate::GetCommonName() const {
    if (!cert_) return "";
    
    X509_NAME* subject = X509_get_subject_name(cert_);
    if (!subject) return "";
    
    int idx = X509_NAME_get_index_by_NID(subject, NID_commonName, -1);
    if (idx < 0) return "";
    
    X509_NAME_ENTRY* entry = X509_NAME_get_entry(subject, idx);
    if (!entry) return "";
    
    ASN1_STRING* data = X509_NAME_ENTRY_get_data(entry);
    if (!data) return "";
    
    const unsigned char* str = ASN1_STRING_get0_data(data);
    return std::string(reinterpret_cast<const char*>(str), ASN1_STRING_length(data));
}

std::chrono::system_clock::time_point Certificate::GetNotBefore() const {
    if (!cert_) return std::chrono::system_clock::time_point{};
    
    const ASN1_TIME* notBefore = X509_get0_notBefore(cert_);
    if (!notBefore) return std::chrono::system_clock::time_point{};
    
    // 简化的时间转换，实际实现可能需要更复杂的ASN1时间解析
    time_t t = 0;
    struct tm tm_info = {};
    ASN1_TIME_to_tm(notBefore, &tm_info);
    t = mktime(&tm_info);
    
    return std::chrono::system_clock::from_time_t(t);
}

std::chrono::system_clock::time_point Certificate::GetNotAfter() const {
    if (!cert_) return std::chrono::system_clock::time_point{};
    
    const ASN1_TIME* notAfter = X509_get0_notAfter(cert_);
    if (!notAfter) return std::chrono::system_clock::time_point{};
    
    time_t t = 0;
    struct tm tm_info = {};
    ASN1_TIME_to_tm(notAfter, &tm_info);
    t = mktime(&tm_info);
    
    return std::chrono::system_clock::from_time_t(t);
}

std::shared_ptr<crypto::PublicKey> Certificate::GetPublicKey() const {
    if (!cert_) return nullptr;
    
    // 这里需要根据证书中的公钥创建对应的PublicKey对象
    // 暂时返回nullptr，具体实现需要结合keys.hpp中的类型
    return nullptr;
}

std::vector<uint8_t> Certificate::ToPEM() const {
    if (!cert_) return {};
    
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return {};
    
    if (PEM_write_bio_X509(bio, cert_) != 1) {
        BIO_free(bio);
        return {};
    }
    
    char* pemData;
    long pemLen = BIO_get_mem_data(bio, &pemData);
    
    std::vector<uint8_t> result(pemData, pemData + pemLen);
    BIO_free(bio);
    
    return result;
}

std::vector<uint8_t> Certificate::ToDER() const {
    if (!cert_) return {};
    
    int derLen = i2d_X509(cert_, nullptr);
    if (derLen <= 0) return {};
    
    std::vector<uint8_t> derData(derLen);
    unsigned char* derPtr = derData.data();
    
    if (i2d_X509(cert_, &derPtr) != derLen) {
        return {};
    }
    
    return derData;
}

bool Certificate::IsValid() const {
    return cert_ != nullptr;
}

// 从PEM数据加载证书
std::shared_ptr<utils::Certificate> LoadCertificateFromPEM(const std::vector<uint8_t>& pemData) {
    BIO* bio = BIO_new_mem_buf(pemData.data(), static_cast<int>(pemData.size()));
    if (!bio) return nullptr;
    
    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    
    if (!cert) return nullptr;
    
    return std::make_shared<utils::Certificate>(cert);
}

// 从文件加载证书
std::shared_ptr<utils::Certificate> LoadCertificateFromFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        throw utils::CertificateError("Cannot open file: " + filename);
    }
    
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)),
                              std::istreambuf_iterator<char>());
    
    return LoadCertificateFromPEM(data);
}


// 创建证书模板 - 对应Go版本utils.NewCertificate
X509* NewCertificateTemplate(
    const std::string& commonName,
    const std::chrono::system_clock::time_point& startTime,
    const std::chrono::system_clock::time_point& endTime
) {
    X509* cert = X509_new();
    if (!cert) return nullptr;
    
    // 设置版本号（v3 = 2）
    X509_set_version(cert, 2);
    
    // 生成随机序列号
    BIGNUM* serial_bn = BN_new();
    if (!serial_bn) {
        X509_free(cert);
        return nullptr;
    }
    
    // 生成128位随机序列号
    if (BN_rand(serial_bn, 128, -1, 0) != 1) {
        BN_free(serial_bn);
        X509_free(cert);
        return nullptr;
    }
    
    ASN1_INTEGER* serial = X509_get_serialNumber(cert);
    BN_to_ASN1_INTEGER(serial_bn, serial);
    BN_free(serial_bn);
    
    // 设置主题名称（Common Name）
    X509_NAME* subject = X509_NAME_new();
    if (!subject) {
        X509_free(cert);
        return nullptr;
    }
    
    if (X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
                                   reinterpret_cast<const unsigned char*>(commonName.c_str()),
                                   -1, -1, 0) != 1) {
        X509_NAME_free(subject);
        X509_free(cert);
        return nullptr;
    }
    
    X509_set_subject_name(cert, subject);
    X509_set_issuer_name(cert, subject); // 自签名证书
    X509_NAME_free(subject);
    
    // 设置有效期
    ASN1_TIME* not_before = ASN1_TIME_new();
    ASN1_TIME* not_after = ASN1_TIME_new();
    
    time_t start_t = std::chrono::system_clock::to_time_t(startTime);
    time_t end_t = std::chrono::system_clock::to_time_t(endTime);
    
    ASN1_TIME_set(not_before, start_t);
    ASN1_TIME_set(not_after, end_t);
    
    X509_set1_notBefore(cert, not_before);
    X509_set1_notAfter(cert, not_after);
    
    ASN1_TIME_free(not_before);
    ASN1_TIME_free(not_after);
    
    // 设置密钥用途（对应Go版本的KeyUsage设置）
    // KeyUsageKeyEncipherment | KeyUsageDigitalSignature
    X509_EXTENSION* keyUsageExt = createKeyUsageExtension();
    if (keyUsageExt) {
        X509_add_ext(cert, keyUsageExt, -1);
        X509_EXTENSION_free(keyUsageExt);
    }
    
    // 设置扩展密钥用途（对应Go版本的ExtKeyUsageCodeSigning）
    X509_EXTENSION* extKeyUsageExt = createExtKeyUsageExtension();
    if (extKeyUsageExt) {
        X509_add_ext(cert, extKeyUsageExt, -1);
        X509_EXTENSION_free(extKeyUsageExt);
    }
    
    // 设置基础约束（对应Go版本的BasicConstraintsValid）
    X509_EXTENSION* basicConstraintsExt = createBasicConstraintsExtension();
    if (basicConstraintsExt) {
        X509_add_ext(cert, basicConstraintsExt, -1);
        X509_EXTENSION_free(basicConstraintsExt);
    }
    
    return cert;
}

// 辅助函数：创建密钥用途扩展
X509_EXTENSION* createKeyUsageExtension() {
    const char* keyUsage = "digitalSignature,keyEncipherment";
    return X509V3_EXT_conf_nid(nullptr, nullptr, NID_key_usage, const_cast<char*>(keyUsage));
}

// 辅助函数：创建扩展密钥用途扩展
X509_EXTENSION* createExtKeyUsageExtension() {
    const char* extKeyUsage = "codeSigning";
    return X509V3_EXT_conf_nid(nullptr, nullptr, NID_ext_key_usage, const_cast<char*>(extKeyUsage));
}

// 辅助函数：创建基础约束扩展
X509_EXTENSION* createBasicConstraintsExtension() {
    const char* basicConstraints = "CA:FALSE";
    return X509V3_EXT_conf_nid(nullptr, nullptr, NID_basic_constraints, const_cast<char*>(basicConstraints));
}

// CertToKey transforms a single input certificate into its corresponding
// PublicKey - 对应Go版本的utils.CertToKey函数
std::shared_ptr<crypto::PublicKey> CertToKey(X509* cert) {
    if (!cert) {
        utils::GetLogger().Error("Certificate is null");
        return nullptr;
    }
    
    // 获取证书的DER格式字节数据（对应Go版本的cert.Raw）
    int derLen = i2d_X509(cert, nullptr);
    if (derLen <= 0) {
        utils::GetLogger().Error("Failed to get certificate DER length");
        return nullptr;
    }
    
    std::vector<uint8_t> derData(derLen);
    unsigned char* derPtr = derData.data();
    if (i2d_X509(cert, &derPtr) != derLen) {
        utils::GetLogger().Error("Failed to encode certificate to DER");
        return nullptr;
    }
    
    // 将DER数据转换为PEM格式（对应Go版本的pem.EncodeToMemory）
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        utils::GetLogger().Error("Failed to create BIO");
        return nullptr;
    }
    
    if (PEM_write_bio_X509(bio, cert) != 1) {
        utils::GetLogger().Error("Failed to write certificate to PEM");
        BIO_free(bio);
        return nullptr;
    }
    
    // 从BIO中获取PEM数据
    char* pemData;
    long pemLen = BIO_get_mem_data(bio, &pemData);
    std::vector<uint8_t> pemBytes(pemData, pemData + pemLen);
    BIO_free(bio);
    
    // 获取证书的公钥算法类型
    EVP_PKEY* pkey = X509_get_pubkey(cert);
    if (!pkey) {
        utils::GetLogger().Error("Failed to extract public key from certificate");
        return nullptr;
    }
    
    int keyType = EVP_PKEY_id(pkey);
    EVP_PKEY_free(pkey);
    
    // 根据公钥算法类型创建对应的PublicKey对象
    switch (keyType) {
        case EVP_PKEY_RSA:
            utils::GetLogger().Debug("Certificate contains RSA public key");
            return crypto::NewRSAx509PublicKey(pemBytes);
            
        case EVP_PKEY_EC:
            utils::GetLogger().Debug("Certificate contains ECDSA public key");
            return crypto::NewECDSAx509PublicKey(pemBytes);
            
        default:
            utils::GetLogger().Error("Unknown key type parsed from certificate: " + std::to_string(keyType));
            return nullptr;
    }
}

// Certificate对象版本的重载
std::shared_ptr<crypto::PublicKey> CertToKey(const Certificate& cert) {
    return CertToKey(cert.GetX509());
}

// LoadCertFromPEM loads the first certificate from the PEM data provided
// 对应Go版本的utils.LoadCertFromPEM函数
X509* LoadCertFromPEM(const std::vector<uint8_t>& pemBytes) {
    if (pemBytes.empty()) {
        utils::GetLogger().Error("PEM data is empty");
        return nullptr;
    }
    
    // 创建内存BIO用于读取PEM数据
    BIO* bio = BIO_new_mem_buf(pemBytes.data(), static_cast<int>(pemBytes.size()));
    if (!bio) {
        utils::GetLogger().Error("Failed to create memory BIO for PEM data");
        return nullptr;
    }
    
    char* name = nullptr;
    char* header = nullptr;
    unsigned char* data = nullptr;
    long len = 0;
    X509* result = nullptr;
    
    // 循环读取PEM块，直到找到第一个有效的证书
    // 这个逻辑完全对应Go版本的 for len(pemBytes) > 0 循环
    while (PEM_read_bio(bio, &name, &header, &data, &len) == 1) {
        bool foundValidCert = false;
        
        // 检查PEM块类型是否为"CERTIFICATE"（对应Go版本的 block.Type != "CERTIFICATE"）
        if (name && strcmp(name, "CERTIFICATE") == 0) {
            // 检查是否没有额外的头部信息（对应Go版本的 len(block.Headers) != 0）
            if (!header || strlen(header) == 0) {
                // 尝试解析证书（对应Go版本的 x509.ParseCertificate(block.Bytes)）
                const unsigned char* p = data;
                X509* cert = d2i_X509(nullptr, &p, len);
                
                if (cert) {
                    // 成功解析证书，这是我们要返回的结果
                    result = cert;
                    foundValidCert = true;
                    utils::GetLogger().Debug("Successfully loaded certificate from PEM data");
                }
            } else {
                utils::GetLogger().Debug("Skipping certificate block with headers");
            }
        } else {
            if (name) {
                utils::GetLogger().Debug("Skipping PEM block of type: " + std::string(name));
            } else {
                utils::GetLogger().Debug("Skipping PEM block with null type");
            }
        }
        
        // 释放当前PEM块的资源
        if (name) {
            OPENSSL_free(name);
            name = nullptr;
        }
        if (header) {
            OPENSSL_free(header);
            header = nullptr;
        }
        if (data) {
            OPENSSL_free(data);
            data = nullptr;
        }
        
        // 如果找到了有效证书，跳出循环
        if (foundValidCert) {
            break;
        }
        
        // 继续下一个PEM块（对应Go版本的continue）
    }
    
    // 释放BIO资源
    BIO_free(bio);
    
    if (!result) {
        utils::GetLogger().Error("No valid certificates found in PEM data");
    }
    
    return result;
}

// X509PublicKeyID returns a public key ID as a string, given a
// PublicKey that contains an X509 Certificate
// 对应Go版本的utils.X509PublicKeyID函数
std::string X509PublicKeyID(std::shared_ptr<crypto::PublicKey> certPubKey) {
    if (!certPubKey) {
        utils::GetLogger().Error("certPubKey is null");
        return "";
    }
    
    // 1. 获取公钥数据（X509证书的PEM格式）（对应Go版本的certPubKey.Public()）
    std::vector<uint8_t> certData = certPubKey->Public();
    if (certData.empty()) {
        utils::GetLogger().Error("Certificate data is empty");
        return "";
    }
    
    utils::GetLogger().Debug("Loading certificate from PEM data for X509PublicKeyID");
    
    // 2. 从PEM数据中加载第一个证书（对应Go版本的LoadCertFromPEM(certPubKey.Public())）
    X509* cert = LoadCertFromPEM(certData);
    if (!cert) {
        utils::GetLogger().Error("Failed to load certificate from PEM data in X509PublicKeyID");
        return "";
    }
    
    // 使用RAII管理X509证书资源
    struct X509Deleter {
        void operator()(X509* x) { if (x) X509_free(x); }
    };
    std::unique_ptr<X509, X509Deleter> certGuard(cert);
    
    // 3. 获取证书的公钥（对应Go版本的cert.PublicKey）
    EVP_PKEY* pkey = X509_get_pubkey(cert);
    if (!pkey) {
        utils::GetLogger().Error("Failed to extract public key from certificate");
        return "";
    }
    
    // 使用RAII管理EVP_PKEY资源
    struct EVP_PKEY_Deleter {
        void operator()(EVP_PKEY* p) { if (p) EVP_PKEY_free(p); }
    };
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> pkeyGuard(pkey);
    
    // 将公钥序列化为PKIX格式（对应Go版本的x509.MarshalPKIXPublicKey(cert.PublicKey)）
    utils::GetLogger().Debug("Marshaling public key to PKIX format");
    
    // 首先获取所需的缓冲区大小
    int pubKeyBytesLen = i2d_PUBKEY(pkey, nullptr);
    if (pubKeyBytesLen <= 0) {
        utils::GetLogger().Error("Failed to determine public key DER encoding size");
        return "";
    }
    
    // 分配缓冲区并编码公钥
    std::vector<uint8_t> pubKeyBytes(pubKeyBytesLen);
    unsigned char* pubKeyPtr = pubKeyBytes.data();
    int encodedLen = i2d_PUBKEY(pkey, &pubKeyPtr);
    
    if (encodedLen != pubKeyBytesLen || encodedLen <= 0) {
        utils::GetLogger().Error("Failed to encode public key to DER format");
        return "";
    }
    
    utils::GetLogger().Debug("Successfully encoded public key to DER format, size: " + 
                           std::to_string(encodedLen) + " bytes");
    
    // 4. 根据原始证书公钥的算法类型创建对应的PublicKey对象
    // （对应Go版本的switch certPubKey.Algorithm()）
    std::string algorithm = certPubKey->Algorithm();
    std::shared_ptr<crypto::PublicKey> key;
    
    if (algorithm == ECDSA_X509_KEY) {
        utils::GetLogger().Debug("Creating ECDSA public key from marshaled data");
        key = crypto::NewECDSAPublicKey(pubKeyBytes);
    } else if (algorithm == RSA_X509_KEY) {
        utils::GetLogger().Debug("Creating RSA public key from marshaled data");
        key = crypto::NewRSAPublicKey(pubKeyBytes);
    } else {
        utils::GetLogger().Error("Unsupported certificate public key algorithm: " + algorithm);
        return "";
    }
    
    if (!key) {
        utils::GetLogger().Error("Failed to create public key from marshaled certificate data");
        return "";
    }
    
    // 返回公钥的ID（对应Go版本的key.ID()）
    std::string keyID = key->ID();
    if (keyID.empty()) {
        utils::GetLogger().Error("Generated key ID is empty");
        return "";
    }
    
    utils::GetLogger().Debug("Successfully generated X509 public key ID: " + keyID);
    return keyID;
}

// CanonicalKeyID returns the ID of the public bytes version of a TUF key.
// On regular RSA/ECDSA TUF keys, this is just the key ID. On X509 RSA/ECDSA
// TUF keys, this is the key ID of the public key part of the key in the leaf cert
// 对应Go版本的utils.CanonicalKeyID函数
std::string CanonicalKeyID(std::shared_ptr<crypto::PublicKey> k) {
    if (!k) {
        utils::GetLogger().Error("public key is null");
        return "";
    }
    
    // 获取密钥算法类型
    std::string algorithm = k->Algorithm();
    
    // 根据算法类型决定如何处理
    if (algorithm == ECDSA_X509_KEY || algorithm == RSA_X509_KEY) {
        // 对于X509类型的密钥，使用X509PublicKeyID函数
        return X509PublicKeyID(k);
    } else {
        // 对于常规的RSA/ECDSA密钥，直接返回密钥ID
        return k->ID();
    }
}

}
}

