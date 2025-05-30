#include "notary/crypto/verifiers.hpp"
#include "notary/utils/tools.hpp"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <set>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

using json = nlohmann::json;

namespace notary {
namespace crypto {

// 常量定义
constexpr int MIN_RSA_KEY_SIZE_BIT = 2048;  // 2048 bits = 256 bytes
constexpr int MIN_RSA_KEY_SIZE_BYTE = MIN_RSA_KEY_SIZE_BIT / 8;
constexpr int ED25519_PUBLIC_KEY_SIZE = 32;
constexpr int ED25519_SIGNATURE_SIZE = 64;

// 全局静态映射表
const std::unordered_map<std::string, std::shared_ptr<Verifier>> Verifiers = {
    {RSAPSSSignature, std::make_shared<RSAPSSVerifier>()},
    {RSAPKCS1v15Signature, std::make_shared<RSAPKCS1v15Verifier>()},
    {PyCryptoSignature, std::make_shared<RSAPyCryptoVerifier>()},
    {ECDSASignature, std::make_shared<ECDSAVerifier>()},
    {EDDSASignature, std::make_shared<Ed25519Verifier>()},
};

// 辅助函数：获取RSA公钥
std::pair<EVP_PKEY*, Error> getRSAPubKey(std::shared_ptr<PublicKey> key) {
    std::string algorithm = key->Algorithm();
    EVP_PKEY* pubKey = nullptr;
    
    if (algorithm == RSA_X509_KEY) {
        // 解析X509证书
        std::vector<uint8_t> pubData = key->Public();
        const unsigned char* data = pubData.data();
        
        BIO* bio = BIO_new_mem_buf(data, static_cast<int>(pubData.size()));
        if (!bio) {
            return {nullptr, Error("Failed to create BIO for X509 certificate")};
        }
        
        X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        
        if (!cert) {
            return {nullptr, Error("Failed to parse X509 certificate")};
        }
        
        pubKey = X509_get_pubkey(cert);
        X509_free(cert);
        
        if (!pubKey) {
            return {nullptr, Error("Failed to extract public key from certificate")};
        }
    } else if (algorithm == RSA_KEY) {
        // 解析PKIX公钥
        std::vector<uint8_t> pubData = key->Public();
        const unsigned char* data = pubData.data();
        
        pubKey = d2i_PUBKEY(nullptr, &data, static_cast<long>(pubData.size()));
        if (!pubKey) {
            return {nullptr, Error("Failed to parse PKIX public key")};
        }
    } else {
        return {nullptr, Error("Invalid key type for RSA verifier: " + algorithm)};
    }
    
    return {pubKey, Error()};
}

// 辅助函数：验证RSA PSS签名
Error verifyPSS(EVP_PKEY* key, const std::vector<uint8_t>& digest, const std::vector<uint8_t>& sig) {
    // 验证是RSA密钥 - 与Go版本等价检查
    if (EVP_PKEY_id(key) != EVP_PKEY_RSA) {
        return Error("value was not an RSA public key");
    }
    
    // 检查RSA密钥长度
    int keySize = EVP_PKEY_bits(key);
    if (keySize < MIN_RSA_KEY_SIZE_BIT) {
        return Error("RSA keys less than " + std::to_string(MIN_RSA_KEY_SIZE_BIT) + " bits are not acceptable, provided key has length " + std::to_string(keySize));
    }
    
    if (sig.size() < MIN_RSA_KEY_SIZE_BYTE) {
        return Error("RSA signature too short, provided signature has length " + std::to_string(sig.size()));
    }
    
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(key, nullptr);
    if (!ctx) {
        return Error("Failed to create verification context");
    }
    
    if (EVP_PKEY_verify_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return Error("Failed to initialize verification");
    }
    
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return Error("Failed to set PSS padding");
    }
    
    if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return Error("Failed to set signature hash");
    }
    
    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, 32) <= 0) { // SHA256 size
        EVP_PKEY_CTX_free(ctx);
        return Error("Failed to set PSS salt length");
    }
    
    int result = EVP_PKEY_verify(ctx, sig.data(), sig.size(), digest.data(), digest.size());
    EVP_PKEY_CTX_free(ctx);
    
    if (result != 1) {
        return Error("failed RSAPSS verification");
    }
    
    return Error();
}

// RSA PSS验证器实现
Error RSAPSSVerifier::Verify(std::shared_ptr<PublicKey> key, 
                         const std::vector<uint8_t>& signature, 
                         const std::vector<uint8_t>& message) {
    auto [pubKey, err] = getRSAPubKey(key);
    if (err.hasError()) {
        return err;
    }
    
    // 计算SHA256哈希
    std::vector<uint8_t> digest(SHA256_DIGEST_LENGTH);
    SHA256(message.data(), message.size(), digest.data());
    
    Error result = verifyPSS(pubKey, digest, signature);
    EVP_PKEY_free(pubKey);
    
    return result;
}

// RSA PKCS1v15验证器实现
Error RSAPKCS1v15Verifier::Verify(std::shared_ptr<PublicKey> key, 
                         const std::vector<uint8_t>& signature, 
                         const std::vector<uint8_t>& message) {
    auto [pubKey, err] = getRSAPubKey(key);
    if (err.hasError()) {
        return err;
    }
    
    // 计算SHA256哈希
    std::vector<uint8_t> digest(SHA256_DIGEST_LENGTH);
    SHA256(message.data(), message.size(), digest.data());
    
    // 验证是RSA密钥 - 与Go版本检查逻辑一致
    if (EVP_PKEY_id(pubKey) != EVP_PKEY_RSA) {
        EVP_PKEY_free(pubKey);
        return Error("value was not an RSA public key");
    }
    
    // 检查RSA密钥长度
    int keySize = EVP_PKEY_bits(pubKey);
    if (keySize < MIN_RSA_KEY_SIZE_BIT) {
        EVP_PKEY_free(pubKey);
        return Error("RSA keys less than " + std::to_string(MIN_RSA_KEY_SIZE_BIT) + " bits are not acceptable, provided key has length " + std::to_string(keySize));
    }
    
    if (signature.size() < MIN_RSA_KEY_SIZE_BYTE) {
        EVP_PKEY_free(pubKey);
        return Error("RSA signature too short, provided signature has length " + std::to_string(signature.size()));
    }
    
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pubKey, nullptr);
    if (!ctx) {
        EVP_PKEY_free(pubKey);
        return Error("Failed to create verification context");
    }
    
    if (EVP_PKEY_verify_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pubKey);
        return Error("Failed to initialize verification");
    }
    
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pubKey);
        return Error("Failed to set PKCS1 padding");
    }
    
    if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pubKey);
        return Error("Failed to set signature hash");
    }
    
    int result = EVP_PKEY_verify(ctx, signature.data(), signature.size(), digest.data(), digest.size());
    
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pubKey);
    
    if (result != 1) {
        return Error("Failed verification");
    }
    
    return Error();
}

// RSA PyCrypto验证器实现（使用PSS）
Error RSAPyCryptoVerifier::Verify(std::shared_ptr<PublicKey> key, 
                         const std::vector<uint8_t>& signature, 
                         const std::vector<uint8_t>& message) {
    // 计算SHA256哈希 - 与Go版本顺序一致
    std::vector<uint8_t> digest(SHA256_DIGEST_LENGTH);
    SHA256(message.data(), message.size(), digest.data());
    
    if (key->Algorithm() != RSA_KEY) {
        return Error("Key type must be RSA for PyCrypto verifier");
    }
    
    // 解析PEM格式的公钥
    std::vector<uint8_t> pubData = key->Public();
    const unsigned char* data = pubData.data();
    
    BIO* bio = BIO_new_mem_buf(data, static_cast<int>(pubData.size()));
    if (!bio) {
        return Error("Failed to create BIO for PEM key");
    }
    
    EVP_PKEY* pubKey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    
    if (!pubKey) {
        return Error("Failed to parse PEM public key");
    }
    
    Error result = verifyPSS(pubKey, digest, signature);
    EVP_PKEY_free(pubKey);
    
    return result;
}

// ECDSA验证器实现
Error ECDSAVerifier::Verify(std::shared_ptr<PublicKey> key, 
                           const std::vector<uint8_t>& signature, 
                           const std::vector<uint8_t>& message) {
    std::string algorithm = key->Algorithm();
    EVP_PKEY* pubKey = nullptr;
    
    if (algorithm == ECDSA_X509_KEY) {
        // 解析X509证书
        std::vector<uint8_t> pubData = key->Public();
        const unsigned char* data = pubData.data();
        
        BIO* bio = BIO_new_mem_buf(data, static_cast<int>(pubData.size()));
        if (!bio) {
            return Error("Failed to create BIO for X509 certificate");
        }
        
        X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        
        if (!cert) {
            return Error("Failed to parse X509 certificate");
        }
        
        pubKey = X509_get_pubkey(cert);
        X509_free(cert);
        
        if (!pubKey) {
            return Error("Failed to extract public key from certificate");
        }
    } else if (algorithm == ECDSA_KEY) {
        // 解析PKIX公钥
        std::vector<uint8_t> pubData = key->Public();
        const unsigned char* data = pubData.data();
        
        pubKey = d2i_PUBKEY(nullptr, &data, static_cast<long>(pubData.size()));
        if (!pubKey) {
            return Error("Failed to parse PKIX public key");
        }
    } else {
        return Error("Invalid key type for ECDSA verifier: " + algorithm);
    }
    
    // 验证是EC密钥
    if (EVP_PKEY_id(pubKey) != EVP_PKEY_EC) {
        EVP_PKEY_free(pubKey);
        return Error("Key is not an ECDSA key");
    }
    
    EC_KEY* ecKey = EVP_PKEY_get1_EC_KEY(pubKey);
    if (!ecKey) {
        EVP_PKEY_free(pubKey);
        return Error("Failed to extract EC key");
    }
    
    const EC_GROUP* group = EC_KEY_get0_group(ecKey);
    int fieldSize = (EC_GROUP_get_degree(group) + 7) / 8;
    int expectedSigLength = 2 * fieldSize;
    
    if (static_cast<int>(signature.size()) != expectedSigLength) {
        EC_KEY_free(ecKey);
        EVP_PKEY_free(pubKey);
        return Error("ECDSA signature has unexpected length");
    }
    
    // 将签名分割为r和s
    std::vector<uint8_t> rBytes(signature.begin(), signature.begin() + fieldSize);
    std::vector<uint8_t> sBytes(signature.begin() + fieldSize, signature.end());
    
    // 创建ECDSA_SIG结构
    ECDSA_SIG* ecdsaSig = ECDSA_SIG_new();
    if (!ecdsaSig) {
        EC_KEY_free(ecKey);
        EVP_PKEY_free(pubKey);
        return Error("Failed to create ECDSA_SIG structure");
    }
    
    BIGNUM* r = BN_bin2bn(rBytes.data(), static_cast<int>(rBytes.size()), nullptr);
    BIGNUM* s = BN_bin2bn(sBytes.data(), static_cast<int>(sBytes.size()), nullptr);
    
    if (!r || !s) {
        if (r) BN_free(r);
        if (s) BN_free(s);
        ECDSA_SIG_free(ecdsaSig);
        EC_KEY_free(ecKey);
        EVP_PKEY_free(pubKey);
        return Error("Failed to convert signature components to BIGNUM");
    }
    
    ECDSA_SIG_set0(ecdsaSig, r, s);
    
    // 计算SHA256哈希
    std::vector<uint8_t> digest(SHA256_DIGEST_LENGTH);
    SHA256(message.data(), message.size(), digest.data());
    
    // 验证签名
    int result = ECDSA_do_verify(digest.data(), static_cast<int>(digest.size()), ecdsaSig, ecKey);
    
    ECDSA_SIG_free(ecdsaSig);
    EC_KEY_free(ecKey);
    EVP_PKEY_free(pubKey);
    
    if (result != 1) {
        return Error("ECDSA signature verification failed");
    }
    
    return Error();
}

// Ed25519验证器实现
Error Ed25519Verifier::Verify(std::shared_ptr<PublicKey> key, 
                             const std::vector<uint8_t>& signature, 
                             const std::vector<uint8_t>& message) {
    if (key->Algorithm() != ED25519_KEY) {
        return Error("Key type must be Ed25519");
    }
    
    // 创建签名字节数组并检查长度 - 与Go版本一致
    std::vector<uint8_t> sigBytes(ED25519_SIGNATURE_SIZE);
    if (signature.size() != ED25519_SIGNATURE_SIZE) {
        return Error("signature length is incorrect, must be " + std::to_string(ED25519_SIGNATURE_SIZE) + ", was " + std::to_string(signature.size()));
    }
    std::copy(signature.begin(), signature.end(), sigBytes.begin());
    
    // 创建密钥字节数组并检查长度 - 与Go版本一致
    std::vector<uint8_t> keyBytes(ED25519_PUBLIC_KEY_SIZE);
    std::vector<uint8_t> pubData = key->Public();
    if (pubData.size() != ED25519_PUBLIC_KEY_SIZE) {
        return Error("public key is incorrect size, must be " + std::to_string(ED25519_PUBLIC_KEY_SIZE) + ", was " + std::to_string(pubData.size()));
    }
    size_t n = std::copy(pubData.begin(), pubData.end(), keyBytes.begin()) - keyBytes.begin();
    if (n < ED25519_PUBLIC_KEY_SIZE) {
        return Error("failed to copy the key, must have " + std::to_string(ED25519_PUBLIC_KEY_SIZE) + " bytes, copied " + std::to_string(n) + " bytes");
    }
    
    // 使用OpenSSL的Ed25519验证
    EVP_PKEY_CTX* ctx = nullptr;
    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, keyBytes.data(), keyBytes.size());
    
    if (!pkey) {
        return Error("Failed to create Ed25519 public key");
    }
    
    ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx) {
        EVP_PKEY_free(pkey);
        return Error("Failed to create verification context");
    }
    
    if (EVP_PKEY_verify_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return Error("Failed to initialize verification");
    }
    
    int result = EVP_PKEY_verify(ctx, sigBytes.data(), sigBytes.size(), message.data(), message.size());
    
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    
    if (result != 1) {
        return Error("failed ed25519 verification");
    }
    
    return Error();
}

} // namespace crypto
} // namespace notary