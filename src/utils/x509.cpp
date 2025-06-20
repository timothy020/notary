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

bool Certificate::IsCA() const {
    if (!cert_) return false;
    
    // 使用X509_check_ca函数检查证书是否为CA证书
    // 这个函数返回值：1表示是CA，0表示不是CA，-1表示错误
    int result = X509_check_ca(cert_);
    return (result == 1);
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

// LoadCertBundleFromPEM loads certificates from the PEM data provided.
// The data is expected to be PEM Encoded and contain one or more certificates
// with PEM type "CERTIFICATE" - 对应Go版本的utils.LoadCertBundleFromPEM函数
std::vector<std::shared_ptr<Certificate>> LoadCertBundleFromPEM(const std::vector<uint8_t>& pemBytes) {
    if (pemBytes.empty()) {
        throw CertificateError("PEM data is empty");
    }
    
    std::vector<std::shared_ptr<Certificate>> certificates;
    
    // 创建内存BIO用于读取PEM数据
    BIO* bio = BIO_new_mem_buf(pemBytes.data(), static_cast<int>(pemBytes.size()));
    if (!bio) {
        throw CertificateError("Failed to create memory BIO for PEM data");
    }
    
    char* name = nullptr;
    char* header = nullptr;
    unsigned char* data = nullptr;
    long len = 0;
    
    // 循环读取所有PEM块，对应Go版本的 for ; block != nil; block, pemBytes = pem.Decode(pemBytes)
    while (PEM_read_bio(bio, &name, &header, &data, &len) == 1) {
        // 检查PEM块类型是否为"CERTIFICATE"（对应Go版本的 if block.Type == "CERTIFICATE"）
        if (name && strcmp(name, "CERTIFICATE") == 0) {
            // 解析证书（对应Go版本的 x509.ParseCertificate(block.Bytes)）
            const unsigned char* p = data;
            X509* cert = d2i_X509(nullptr, &p, len);
            
            if (cert) {
                // 创建Certificate对象并添加到结果列表中
                // （对应Go版本的 certificates = append(certificates, cert)）
                auto certWrapper = std::make_shared<Certificate>(cert);
                certificates.push_back(certWrapper);
                utils::GetLogger().Debug("Successfully loaded certificate from PEM bundle");
            } else {
                // 清理资源
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
                BIO_free(bio);
                
                // 对应Go版本的解析错误处理
                throw CertificateError("Failed to parse certificate from PEM data");
            }
        } else {
            // 遇到非证书类型的PEM块，对应Go版本的 
            // return nil, fmt.Errorf("invalid pem block type: %s", block.Type)
            std::string blockType = name ? name : "unknown";
            
            // 清理资源
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
            BIO_free(bio);
            
            throw CertificateError("Invalid PEM block type: " + blockType + ", expected CERTIFICATE");
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
    }
    
    // 释放BIO资源
    BIO_free(bio);
    
    // 检查是否找到了任何证书，对应Go版本的
    // if len(certificates) == 0 { return nil, fmt.Errorf("no valid certificates found") }
    if (certificates.empty()) {
        throw CertificateError("No valid certificates found in PEM data");
    }
    
    utils::GetLogger().Debug("Successfully loaded " + std::to_string(certificates.size()) + 
                           " certificates from PEM bundle");
    
    return certificates;
}

// LoadCertBundleFromFile loads certificates from the file provided.
// The data is expected to be PEM Encoded and contain one or more certificates
// with PEM type "CERTIFICATE" - 对应Go版本的utils.LoadCertBundleFromFile函数
std::vector<std::shared_ptr<Certificate>> LoadCertBundleFromFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        throw CertificateError("Cannot open file: " + filename);
    }
    
    // 读取文件内容到vector
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)),
                              std::istreambuf_iterator<char>());
    
    if (data.empty()) {
        throw CertificateError("File is empty: " + filename);
    }
    
    return LoadCertBundleFromPEM(data);
}

// GetLeafCerts parses a list of x509 Certificates and returns all of them
// that aren't CA - 对应Go版本的utils.GetLeafCerts函数
std::vector<std::shared_ptr<Certificate>> GetLeafCerts(const std::vector<std::shared_ptr<Certificate>>& certs) {
    std::vector<std::shared_ptr<Certificate>> leafCerts;
    
    for (const auto& cert : certs) {
        if (!cert) {
            utils::GetLogger().Warn("Skipping null certificate in GetLeafCerts");
            continue;
        }
        
        if (cert->IsCA()) {
            continue;
        }
        
        leafCerts.push_back(cert);
    }
    
    utils::GetLogger().Debug("GetLeafCerts: Found " + std::to_string(leafCerts.size()) + 
                           " leaf certificates out of " + std::to_string(certs.size()) + " total certificates");
    
    return leafCerts;
}

// GetIntermediateCerts parses a list of x509 Certificates and returns all of the
// ones marked as a CA, to be used as intermediates - 对应Go版本的utils.GetIntermediateCerts函数
std::vector<std::shared_ptr<Certificate>> GetIntermediateCerts(const std::vector<std::shared_ptr<Certificate>>& certs) {
    std::vector<std::shared_ptr<Certificate>> intCerts;
    
    for (const auto& cert : certs) {
        if (!cert) {
            utils::GetLogger().Warn("Skipping null certificate in GetIntermediateCerts");
            continue;
        }
        
        if (cert->IsCA()) {
            intCerts.push_back(cert);
        }
    }
    
    utils::GetLogger().Debug("GetIntermediateCerts: Found " + std::to_string(intCerts.size()) + 
                           " intermediate certificates out of " + std::to_string(certs.size()) + " total certificates");
    
    return intCerts;
}

// ValidateCertificate returns an error if the certificate is not valid for notary
// Currently this is only ensuring the public key has a large enough modulus if RSA,
// using a non SHA1 signature algorithm, and an optional time expiry check
// 对应Go版本的utils.ValidateCertificate函数
Error ValidateCertificate(X509* cert, bool checkExpiry) {
    if (!cert) {
        return Error("Certificate is null");
    }
    
    // 对应Go版本的 if (c.NotBefore).After(c.NotAfter)
    const ASN1_TIME* notBefore = X509_get0_notBefore(cert);
    const ASN1_TIME* notAfter = X509_get0_notAfter(cert);
    
    if (!notBefore || !notAfter) {
        return Error("Certificate validity times are invalid");
    }
    
    // 比较NotBefore和NotAfter时间
    int cmp = ASN1_TIME_compare(notBefore, notAfter);
    if (cmp >= 0) { // NotBefore >= NotAfter
        return Error("Certificate validity window is invalid");
    }
    
    // 对应Go版本的签名算法检查
    // Can't have SHA1 sig algorithm
    int signatureNid = X509_get_signature_nid(cert);
    if (signatureNid == NID_sha1WithRSAEncryption || 
        signatureNid == NID_dsaWithSHA1 || 
        signatureNid == NID_ecdsa_with_SHA1) {
        
        return Error("Certificate uses invalid SHA1 signature algorithm");
    }
    
    // 对应Go版本的RSA密钥长度检查
    // If we have an RSA key, make sure it's long enough
    EVP_PKEY* pkey = X509_get_pubkey(cert);
    if (pkey) {
        int keyType = EVP_PKEY_id(pkey);
        if (keyType == EVP_PKEY_RSA) {
            // 使用EVP_PKEY_get_bits来获取密钥位长度（OpenSSL 3.0推荐方法）
            int keyBits = EVP_PKEY_get_bits(pkey);
            if (keyBits < MinRSABitSize) {
                EVP_PKEY_free(pkey);
                return Error("RSA bit length is too short");
            }
        }
        EVP_PKEY_free(pkey);
    }
    
    // 对应Go版本的过期时间检查
    if (checkExpiry) {
        // 使用 OpenSSL 的原生函数进行时间比较，这是最安全、最健壮的方式
        // X509_cmp_current_time 返回:
        //  0: 如果当前时间等于证书时间
        // -1: 如果当前时间在证书时间之前
        //  1: 如果当前时间在证书时间之后
        // X509_cmp_time 比较指定时间与证书时间

        // Give one day leeway on creation "before" time
        // 检查证书是否在24小时后才生效 (对应Go版本的tomorrow.Before(c.NotBefore))
        time_t tomorrow = time(nullptr) + 24 * 3600;
        if (X509_cmp_time(notBefore, &tomorrow) > 0) {
            return Error("Certificate is not yet valid");
        }
        
        // 检查证书是否已经过期 (对应Go版本的now.After(c.NotAfter))
        if (X509_cmp_current_time(notAfter) < 0) {
            return Error("Certificate has expired");
        }

        // 检查证书是否在6个月内到期 (对应Go版本的6个月警告)
        // 6个月约等于 15552000 秒 (6 * 30 * 24 * 3600)
        time_t sixMonthsFromNow = time(nullptr) + 15552000;
        if (X509_cmp_time(notAfter, &sixMonthsFromNow) < 0) {
            utils::GetLogger().Warn("Certificate is near expiry (expires within 6 months)");
        }
    }
    
    // 对应Go版本的 return nil (无错误)
    return Error(); // 空的Error对象表示成功
}

// Certificate对象版本的重载
Error ValidateCertificate(const Certificate& cert, bool checkExpiry) {
    return ValidateCertificate(cert.GetX509(), checkExpiry);
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

// CertChainToPEM is a utility function returns a PEM encoded chain of x509 Certificates
// 对应Go版本的utils.CertChainToPEM函数
std::pair<std::vector<uint8_t>, Error> CertChainToPEM(const std::vector<std::shared_ptr<Certificate>>& certChain) {
    if (certChain.empty()) {
        utils::GetLogger().Error("Certificate chain is empty");
        return std::make_pair(std::vector<uint8_t>(), Error("certificate chain is empty"));
    }
    
    utils::GetLogger().Debug("Converting certificate chain of " + std::to_string(certChain.size()) + " certificates to PEM");
    
    // 创建内存BIO用于累积PEM数据
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        utils::GetLogger().Error("Failed to create memory BIO for certificate chain");
        return std::make_pair(std::vector<uint8_t>(), Error("failed to create memory BIO"));
    }
    
    // 使用RAII管理BIO资源
    struct BIODeleter {
        void operator()(BIO* b) { if (b) BIO_free(b); }
    };
    std::unique_ptr<BIO, BIODeleter> bioGuard(bio);
    
    // 遍历证书链，直接使用OpenSSL的PEM_write_bio_X509函数（对应Go版本的for循环）
    for (const auto& cert : certChain) {
        if (!cert || !cert->IsValid()) {
            utils::GetLogger().Error("Invalid certificate found in chain");
            return std::make_pair(std::vector<uint8_t>(), Error("invalid certificate in chain"));
        }
        
        X509* x509 = cert->GetX509();
        if (!x509) {
            utils::GetLogger().Error("Failed to get X509 certificate from Certificate object");
            return std::make_pair(std::vector<uint8_t>(), Error("failed to get X509 certificate"));
        }
        
        // 直接使用OpenSSL的PEM_write_bio_X509函数写入PEM格式
        // 这比先转换为ToPEM再写入更高效（对应Go版本的pem.Encode）
        if (PEM_write_bio_X509(bio, x509) != 1) {
            utils::GetLogger().Error("Failed to write certificate to PEM format");
            return std::make_pair(std::vector<uint8_t>(), Error("failed to write certificate to PEM format"));
        }
    }
    
    // 从BIO中获取累积的PEM数据
    char* pemData;
    long pemLen = BIO_get_mem_data(bio, &pemData);
    if (pemLen <= 0) {
        utils::GetLogger().Error("No PEM data generated from certificate chain");
        return std::make_pair(std::vector<uint8_t>(), Error("no PEM data generated"));
    }
    
    // 复制数据到结果向量
    std::vector<uint8_t> result(pemData, pemData + pemLen);
    
    utils::GetLogger().Debug("Successfully converted certificate chain to PEM, total size: " + std::to_string(result.size()) + " bytes");
    
    return std::make_pair(result, Error()); // 空Error表示成功
}

// CertBundleToKey creates a TUF key from a leaf cert and a list of intermediates
// 对应Go版本的utils.CertBundleToKey函数
std::pair<std::shared_ptr<crypto::PublicKey>, Error> CertBundleToKey(
    std::shared_ptr<Certificate> leafCert,
    const std::vector<std::shared_ptr<Certificate>>& intCerts) {
    
    if (!leafCert || !leafCert->IsValid()) {
        utils::GetLogger().Error("Leaf certificate is null or invalid");
        return std::make_pair(nullptr, Error("leaf certificate is null or invalid"));
    }
    
    utils::GetLogger().Debug("Creating TUF key from certificate bundle with " + 
                           std::to_string(intCerts.size()) + " intermediate certificates");
    
    // 构建证书链（对应Go版本的certBundle := []*x509.Certificate{leafCert}）
    std::vector<std::shared_ptr<Certificate>> certBundle;
    certBundle.push_back(leafCert);
    
    // 添加中间证书（对应Go版本的certBundle = append(certBundle, intCerts...)）
    certBundle.insert(certBundle.end(), intCerts.begin(), intCerts.end());
    
    // 使用CertChainToPEM函数将证书链转换为PEM格式（对应Go版本的CertChainToPEM(certBundle)）
    auto [certChainPEM, err] = CertChainToPEM(certBundle);
    if (!err.ok()) {
        utils::GetLogger().Error("Failed to convert certificate bundle to PEM: " + err.getMessage());
        return std::make_pair(nullptr, err);
    }
    
    // 获取叶子证书的公钥算法类型
    X509* leafX509 = leafCert->GetX509();
    if (!leafX509) {
        utils::GetLogger().Error("Failed to get X509 from leaf certificate");
        return std::make_pair(nullptr, Error("failed to get X509 from leaf certificate"));
    }
    
    EVP_PKEY* pkey = X509_get_pubkey(leafX509);
    if (!pkey) {
        utils::GetLogger().Error("Failed to extract public key from leaf certificate");
        return std::make_pair(nullptr, Error("failed to extract public key from leaf certificate"));
    }
    
    // 使用RAII管理EVP_PKEY资源
    struct EVP_PKEY_Deleter {
        void operator()(EVP_PKEY* p) { if (p) EVP_PKEY_free(p); }
    };
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> pkeyGuard(pkey);
    
    int keyType = EVP_PKEY_id(pkey);
    
    // 根据叶子证书的公钥算法创建对应的PublicKey对象（对应Go版本的switch语句）
    std::shared_ptr<crypto::PublicKey> newKey;
    switch (keyType) {
        case EVP_PKEY_RSA:
            utils::GetLogger().Debug("Creating RSA X509 public key from certificate bundle");
            newKey = crypto::NewRSAx509PublicKey(certChainPEM);
            break;
            
        case EVP_PKEY_EC:
            utils::GetLogger().Debug("Creating ECDSA X509 public key from certificate bundle");
            newKey = crypto::NewECDSAx509PublicKey(certChainPEM);
            break;
            
        default:
            utils::GetLogger().Error("Unknown key type parsed from leaf certificate: " + std::to_string(keyType));
            return std::make_pair(nullptr, Error("unsupported key algorithm in leaf certificate"));
    }
    
    if (!newKey) {
        utils::GetLogger().Error("Failed to create public key from certificate bundle");
        return std::make_pair(nullptr, Error("failed to create public key from certificate bundle"));
    }
    
    utils::GetLogger().Debug("Successfully created TUF key from certificate bundle, key ID: " + newKey->ID());
    
    return std::make_pair(newKey, Error()); // 空Error表示成功
}

// CertsToKeys transforms each of the input certificate chains into its corresponding PublicKey
// 对应Go版本的utils.CertsToKeys函数
std::map<std::string, std::shared_ptr<crypto::PublicKey>> CertsToKeys(
    const std::map<std::string, std::shared_ptr<Certificate>>& leafCerts,
    const std::map<std::string, std::vector<std::shared_ptr<Certificate>>>& intCerts) {
    
    utils::GetLogger().Debug("Converting " + std::to_string(leafCerts.size()) + " certificate chains to public keys");
    
    // 创建结果映射（对应Go版本的keys := make(map[string]data.PublicKey)）
    std::map<std::string, std::shared_ptr<crypto::PublicKey>> keys;
    
    // 遍历每个叶子证书（对应Go版本的for id, leafCert := range leafCerts）
    for (const auto& [id, leafCert] : leafCerts) {
        if (!leafCert || !leafCert->IsValid()) {
            utils::GetLogger().Warn("Skipping invalid leaf certificate for ID: " + id);
            continue;
        }
        
        utils::GetLogger().Debug("Processing certificate chain for ID: " + id);
        
        // 获取该ID对应的中间证书列表，使用引用避免拷贝（对应Go版本的intCerts[id]）
        const std::vector<std::shared_ptr<Certificate>>* intCertsForId = nullptr;
        auto intCertIt = intCerts.find(id);
        if (intCertIt != intCerts.end()) {
            intCertsForId = &(intCertIt->second);
        }
        
        // 使用空vector作为默认值，避免条件分支
        static const std::vector<std::shared_ptr<Certificate>> emptyIntCerts;
        const std::vector<std::shared_ptr<Certificate>>& actualIntCerts = 
            intCertsForId ? *intCertsForId : emptyIntCerts;
        
        // 尝试将证书束转换为公钥（对应Go版本的if key, err := CertBundleToKey(leafCert, intCerts[id]); err == nil）
        auto [key, err] = CertBundleToKey(leafCert, actualIntCerts);
        if (err.ok() && key) {
            // 成功创建公钥，添加到结果映射中（对应Go版本的keys[key.ID()] = key）
            std::string keyID = key->ID();
            if (!keyID.empty()) {
                // 使用emplace避免不必要的拷贝
                keys.emplace(std::move(keyID), std::move(key));
                utils::GetLogger().Debug("Successfully created public key for certificate ID " + id + 
                                       ", public key ID: " + keyID);
            } else {
                utils::GetLogger().Warn("Generated public key has empty ID for certificate ID: " + id);
            }
        } else {
            // 转换失败，记录警告但继续处理其他证书（对应Go版本中的隐式跳过）
            const std::string& errorMsg = err.getMessage();
            if (!errorMsg.empty()) {
                utils::GetLogger().Warn("Failed to create public key for certificate ID " + id + 
                                      ": " + errorMsg);
            } else {
                utils::GetLogger().Warn("Failed to create public key for certificate ID " + id + 
                                      ": unknown error");
            }
        }
    }
    
    utils::GetLogger().Debug("Successfully converted " + std::to_string(keys.size()) + 
                           " certificate chains to public keys out of " + 
                           std::to_string(leafCerts.size()) + " total chains");
    
    return keys;
}

}
}

