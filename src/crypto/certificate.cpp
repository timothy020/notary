#include "notary/crypto/certificate.hpp"
#include "notary/utils/logger.hpp"
#include "notary/utils/x509.hpp"
#include "notary/utils/tools.hpp"
#include "notary/types.hpp"
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <fstream>
#include <sstream>
#include <iomanip>

namespace notary {
namespace crypto {


// 生成证书的主函数 - 对应Go版本的GenerateCertificate
std::shared_ptr<utils::Certificate> GenerateCertificate(
    std::shared_ptr<PrivateKey> rootKey,
    const std::string& gun,
    const std::chrono::system_clock::time_point& startTime,
    const std::chrono::system_clock::time_point& endTime
) {
    if (!rootKey) {
        throw utils::CertificateError("root key is null");
    }
    
    // 检查密钥类型是否支持证书生成
    std::string algorithm = rootKey->Algorithm();
    if (algorithm != ECDSA_KEY && algorithm != RSA_KEY) {
        throw utils::CertificateError("key type not supported for Certificate generation: " + algorithm);
    }
    
    return generateCertificateInternal(rootKey, gun, startTime, endTime);
}

// 内部证书生成函数 - 对应Go版本的generateCertificate
std::shared_ptr<utils::Certificate> generateCertificateInternal(
    std::shared_ptr<PrivateKey> privateKey,
    const std::string& gun,
    const std::chrono::system_clock::time_point& startTime,
    const std::chrono::system_clock::time_point& endTime
) {
    // 创建证书模板
    X509* template_cert = utils::NewCertificateTemplate(gun, startTime, endTime);
    if (!template_cert) {
        throw utils::CertificateError("failed to create certificate template for: " + gun);
    }
    
    // 创建EVP_PKEY用于签名
    EVP_PKEY* pkey = utils::ConvertPrivateKeyToEVPKey(privateKey);
    if (!pkey) {
        X509_free(template_cert);
        throw utils::CertificateError("failed to create EVP_PKEY from private key");
    }
    
    // 设置证书的公钥
    if (X509_set_pubkey(template_cert, pkey) != 1) {
        EVP_PKEY_free(pkey);
        X509_free(template_cert);
        throw utils::CertificateError("failed to set public key");
    }
    
    // 自签名证书（使用相同的证书作为模板和父证书）
    if (X509_sign(template_cert, pkey, EVP_sha256()) == 0) {
        EVP_PKEY_free(pkey);
        X509_free(template_cert);
        throw utils::CertificateError("failed to sign certificate for: " + gun);
    }
    
    EVP_PKEY_free(pkey);
    
    return std::make_shared<utils::Certificate>(template_cert);
}


// 验证证书有效性 - 对应Go版本utils.ValidateCertificate
bool ValidateCertificate(const utils::Certificate& cert, bool checkExpiry) {
    if (!cert.IsValid()) return false;
    
    X509* x509 = cert.GetX509();
    if (!x509) return false;
    
    // 检查有效期窗口是否合理
    auto notBefore = cert.GetNotBefore();
    auto notAfter = cert.GetNotAfter();
    
    if (notBefore > notAfter) {
        utils::Logger::GetInstance().Error("Certificate validity window is invalid");
        return false;
    }
    
    // 检查签名算法（禁止SHA1）
    int sigAlg = X509_get_signature_nid(x509);
    if (sigAlg == NID_sha1WithRSAEncryption || 
        sigAlg == NID_dsaWithSHA1 || 
        sigAlg == NID_ecdsa_with_SHA1) {
        utils::Logger::GetInstance().Error("Certificate uses invalid SHA1 signature algorithm");
        return false;
    }
    
    // 检查RSA密钥长度
    EVP_PKEY* pkey = X509_get_pubkey(x509);
    if (pkey) {
        if (EVP_PKEY_base_id(pkey) == EVP_PKEY_RSA) {
            RSA* rsa = EVP_PKEY_get1_RSA(pkey);
            if (rsa) {
                int keySize = RSA_size(rsa) * 8; // 转换为位数
                RSA_free(rsa);
                if (keySize < 2048) { // 最小RSA密钥长度
                    EVP_PKEY_free(pkey);
                    utils::Logger::GetInstance().Error("RSA key length is too short");
                    return false;
                }
            }
        }
        EVP_PKEY_free(pkey);
    }
    
    // 检查过期时间
    if (checkExpiry) {
        auto now = std::chrono::system_clock::now();
        auto tomorrow = now + std::chrono::hours(24);
        
        // 给创建时间一天的宽限期，检查结束时间是否已过期
        if (tomorrow < notBefore || now > notAfter) {
            utils::Logger::GetInstance().Error("Certificate is expired");
            return false;
        }
        
        // 如果证书在6个月内过期，发出警告
        auto sixMonthsLater = now + std::chrono::hours(24 * 30 * 6);
        if (notAfter < sixMonthsLater) {
            utils::Logger::GetInstance().Warn("Certificate is near expiry: " + cert.GetCommonName());
        }
    }
    
    return true;
}

}
}
