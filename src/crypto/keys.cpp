#include "notary/crypto/keys.hpp"
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <stdexcept>

namespace notary {
namespace crypto {

nlohmann::json tufKeyToJson(const TUFKey& key) {
    nlohmann::json j;
    j["keytype"] = key.Algorithm();

    nlohmann::json keyval;
    keyval["public"] = key.Public();

    j["keyval"] = keyval;
    return j;
}

// Algorithm returns the algorithm of the key
std::string TUFKey::Algorithm() const {
    return type;
}

// ID efficiently generates if necessary, and caches the ID of the key
std::string TUFKey::ID() {
    if (id == "") {
		TUFKey pubK = TUFKey(Algorithm(), this->Public(), std::vector<uint8_t>());
		std::string data = utils::MarshalCanonical(tufKeyToJson(pubK));
		auto digest = utils::CalculateSHA256Hash(std::vector<uint8_t>(data.begin(), data.end()));
		if (digest.ok()) {
			id = utils::HexEncode(digest.value());
		} else {
			utils::GetLogger().Error("Error generating key ID");
		}
	}
    return id;
}

// Public returns the public bytes
std::vector<uint8_t> TUFKey::Public() const {
    return value.public_key;
}

std::vector<uint8_t> ECDSAPrivateKey::Sign(const std::vector<uint8_t>& message) const {
    // 计算消息的SHA256哈希
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(message.data(), message.size(), hash);
    
    // 解析私钥
    const unsigned char* p = privateData_.data();
    EC_KEY* ecKey = d2i_ECPrivateKey(nullptr, &p, privateData_.size());
    if (!ecKey) {
        throw std::runtime_error("无法解析ECDSA私钥");
    }
    
    // 创建ASN.1格式的签名
    unsigned int sigLen = ECDSA_size(ecKey);
    std::vector<uint8_t> asn1Signature(sigLen);
    
    if (ECDSA_sign(0, hash, SHA256_DIGEST_LENGTH, asn1Signature.data(), &sigLen, ecKey) != 1) {
        EC_KEY_free(ecKey);
        throw std::runtime_error("ECDSA签名失败");
    }
    
    asn1Signature.resize(sigLen);
    
    // 解析ASN.1签名以提取R和S值
    const unsigned char* sigPtr = asn1Signature.data();
    ECDSA_SIG* ecdsaSig = d2i_ECDSA_SIG(nullptr, &sigPtr, asn1Signature.size());
    if (!ecdsaSig) {
        EC_KEY_free(ecKey);
        throw std::runtime_error("无法解析ECDSA签名");
    }
    
    // 获取R和S值
    const BIGNUM* r = nullptr;
    const BIGNUM* s = nullptr;
    ECDSA_SIG_get0(ecdsaSig, &r, &s);
    
    // 获取曲线参数以确定字节长度
    const EC_GROUP* group = EC_KEY_get0_group(ecKey);
    int degree = EC_GROUP_get_degree(group);
    int octetLength = (degree + 7) / 8;  // 等价于Go中的 (BitSize + 7) >> 3
    
    // 将R和S转换为固定长度的字节数组
    std::vector<uint8_t> rBytes(octetLength, 0);
    std::vector<uint8_t> sBytes(octetLength, 0);
    
    int rLen = BN_num_bytes(r);
    int sLen = BN_num_bytes(s);
    
    // 确保有足够的空间
    if (rLen > octetLength || sLen > octetLength) {
        ECDSA_SIG_free(ecdsaSig);
        EC_KEY_free(ecKey);
        throw std::runtime_error("R或S值超出预期长度");
    }
    
    // 将R和S写入字节数组（右对齐，左边补零）
    BN_bn2bin(r, rBytes.data() + (octetLength - rLen));
    BN_bn2bin(s, sBytes.data() + (octetLength - sLen));
    
    // 清理资源
    ECDSA_SIG_free(ecdsaSig);
    EC_KEY_free(ecKey);
    
    // 组合R和S为最终签名 (R || S)
    std::vector<uint8_t> signature;
    signature.reserve(octetLength * 2);
    signature.insert(signature.end(), rBytes.begin(), rBytes.end());
    signature.insert(signature.end(), sBytes.begin(), sBytes.end());
    
    return signature;
}

std::string ECDSAPrivateKey::GetSignatureAlgorithm() const {
    return ECDSA_KEY;
}

// 工厂函数实现
std::shared_ptr<PublicKey> NewPublicKey(const std::string& algorithm, const std::vector<uint8_t>& publicData) {
    if (algorithm == ECDSA_KEY) {
        return std::make_shared<ECDSAPublicKey>(publicData);
    } else {
        throw std::runtime_error("未知密钥类型");
    }
}

std::shared_ptr<PrivateKey> NewPrivateKey(std::shared_ptr<PublicKey> publicKey, const std::vector<uint8_t>& privateData) {
    const std::string& algorithm = publicKey->Algorithm();
    
    if (algorithm == ECDSA_KEY || algorithm == ECDSA_X509_KEY) {
        return std::make_shared<ECDSAPrivateKey>(publicKey, privateData);
    } else {
        throw std::runtime_error("未知密钥类型");
    }
    // } else if (algorithm == RSA_KEY || algorithm == RSA_X509_KEY) {
    //     return std::make_shared<RSAPrivateKey>(publicKey, privateData);
    // } else if (algorithm == ED25519_KEY) {
    //     auto ed25519Public = std::dynamic_pointer_cast<ED25519PublicKey>(publicKey);
    //     if (ed25519Public) {
    //         return std::make_shared<ED25519PrivateKey>(ed25519Public, privateData);
    // }
    //     return std::make_shared<UnknownPrivateKey>(publicKey, privateData);
    // } else {
    //     return std::make_shared<UnknownPrivateKey>(publicKey, privateData);
    // }
}

// // ECDSAPublicKey实现
// ECDSAPublicKey::ECDSAPublicKey(const std::vector<uint8_t>& derData) : derData_(derData) {}

// std::string ECDSAPublicKey::ID() const {
//     if (id_.empty()) {
//         id_ = CalculateKeyID(Algorithm(), derData_);
//     }
//     return id_;
// }

// // ECDSAx509PublicKey实现
// ECDSAx509PublicKey::ECDSAx509PublicKey(const std::vector<uint8_t>& x509Data) : x509Data_(x509Data) {}

// std::string ECDSAx509PublicKey::ID() const {
//     if (id_.empty()) {
//         id_ = CalculateKeyID(Algorithm(), x509Data_);
//     }
//     return id_;
// }

// // RSAPublicKey实现
// RSAPublicKey::RSAPublicKey(const std::vector<uint8_t>& derData) : derData_(derData) {}

// std::string RSAPublicKey::ID() const {
//     if (id_.empty()) {
//         id_ = CalculateKeyID(Algorithm(), derData_);
//     }
//     return id_;
// }

// // RSAx509PublicKey实现
// RSAx509PublicKey::RSAx509PublicKey(const std::vector<uint8_t>& x509Data) : x509Data_(x509Data) {}

// std::string RSAx509PublicKey::ID() const {
//     if (id_.empty()) {
//         id_ = CalculateKeyID(Algorithm(), x509Data_);
//     }
//     return id_;
// }

// // ED25519PublicKey实现
// ED25519PublicKey::ED25519PublicKey(const std::vector<uint8_t>& publicData) : publicData_(publicData) {}

// std::string ED25519PublicKey::ID() const {
//     if (id_.empty()) {
//         id_ = CalculateKeyID(Algorithm(), publicData_);
//     }
//     return id_;
// }

// // UnknownPublicKey实现
// UnknownPublicKey::UnknownPublicKey(const std::string& algorithm, const std::vector<uint8_t>& publicData) 
//     : algorithm_(algorithm), publicData_(publicData) {}

// std::string UnknownPublicKey::ID() const {
//     if (id_.empty()) {
//         id_ = CalculateKeyID(algorithm_, publicData_);
//     }
//     return id_;
// }

// // ECDSAPrivateKey实现
// ECDSAPrivateKey::ECDSAPrivateKey(std::shared_ptr<PublicKey> publicKey, const std::vector<uint8_t>& privateData)
//     : publicKey_(publicKey), privateData_(privateData) {}

// std::vector<uint8_t> ECDSAPrivateKey::Sign(const std::vector<uint8_t>& message) const {
//     // 计算消息的SHA256哈希
//     unsigned char hash[SHA256_DIGEST_LENGTH];
//     SHA256(message.data(), message.size(), hash);
    
//     // 解析私钥
//     const unsigned char* p = privateData_.data();
//     EC_KEY* ecKey = d2i_ECPrivateKey(nullptr, &p, privateData_.size());
//     if (!ecKey) {
//         throw std::runtime_error("无法解析ECDSA私钥");
//     }
    
//     // 创建签名
//     unsigned int sigLen = ECDSA_size(ecKey);
//     std::vector<uint8_t> signature(sigLen);
    
//     if (ECDSA_sign(0, hash, SHA256_DIGEST_LENGTH, signature.data(), &sigLen, ecKey) != 1) {
//         EC_KEY_free(ecKey);
//         throw std::runtime_error("ECDSA签名失败");
//     }
    
//     EC_KEY_free(ecKey);
//     signature.resize(sigLen);
//     return signature;
// }

// // RSAPrivateKey实现
// RSAPrivateKey::RSAPrivateKey(std::shared_ptr<PublicKey> publicKey, const std::vector<uint8_t>& privateData)
//     : publicKey_(publicKey), privateData_(privateData) {}

// std::vector<uint8_t> RSAPrivateKey::Sign(const std::vector<uint8_t>& message) const {
//     // 计算消息的SHA256哈希
//     unsigned char hash[SHA256_DIGEST_LENGTH];
//     SHA256(message.data(), message.size(), hash);
    
//     // 解析私钥
//     const unsigned char* p = privateData_.data();
//     RSA* rsaKey = d2i_RSAPrivateKey(nullptr, &p, privateData_.size());
//     if (!rsaKey) {
//         throw std::runtime_error("无法解析RSA私钥");
//     }
    
//     // 创建EVP密钥
//     EVP_PKEY* pkey = EVP_PKEY_new();
//     if (!pkey || EVP_PKEY_set1_RSA(pkey, rsaKey) != 1) {
//         RSA_free(rsaKey);
//         if (pkey) EVP_PKEY_free(pkey);
//         throw std::runtime_error("无法创建EVP密钥");
//     }
    
//     // 创建签名上下文
//     EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
//     if (!ctx) {
//         RSA_free(rsaKey);
//         EVP_PKEY_free(pkey);
//         throw std::runtime_error("无法创建签名上下文");
//     }
    
//     // 初始化签名
//     if (EVP_PKEY_sign_init(ctx) <= 0) {
//         EVP_PKEY_CTX_free(ctx);
//         RSA_free(rsaKey);
//         EVP_PKEY_free(pkey);
//         throw std::runtime_error("无法初始化RSA签名");
//     }
    
//     // 设置PSS填充
//     if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) <= 0) {
//         EVP_PKEY_CTX_free(ctx);
//         RSA_free(rsaKey);
//         EVP_PKEY_free(pkey);
//         throw std::runtime_error("无法设置RSA PSS填充");
//     }
    
//     // 设置哈希算法
//     if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0) {
//         EVP_PKEY_CTX_free(ctx);
//         RSA_free(rsaKey);
//         EVP_PKEY_free(pkey);
//         throw std::runtime_error("无法设置哈希算法");
//     }
    
//     // 获取签名长度
//     size_t sigLen;
//     if (EVP_PKEY_sign(ctx, nullptr, &sigLen, hash, SHA256_DIGEST_LENGTH) <= 0) {
//         EVP_PKEY_CTX_free(ctx);
//         RSA_free(rsaKey);
//         EVP_PKEY_free(pkey);
//         throw std::runtime_error("无法获取签名长度");
//     }
    
//     // 创建签名
//     std::vector<uint8_t> signature(sigLen);
//     if (EVP_PKEY_sign(ctx, signature.data(), &sigLen, hash, SHA256_DIGEST_LENGTH) <= 0) {
//         EVP_PKEY_CTX_free(ctx);
//         RSA_free(rsaKey);
//         EVP_PKEY_free(pkey);
//         throw std::runtime_error("RSA签名失败");
//     }
    
//     EVP_PKEY_CTX_free(ctx);
//     RSA_free(rsaKey);
//     EVP_PKEY_free(pkey);
    
//     signature.resize(sigLen);
//     return signature;
// }

// // ED25519PrivateKey实现
// ED25519PrivateKey::ED25519PrivateKey(std::shared_ptr<ED25519PublicKey> publicKey, const std::vector<uint8_t>& privateData)
//     : publicKey_(publicKey), privateData_(privateData) {}

// std::vector<uint8_t> ED25519PrivateKey::Sign(const std::vector<uint8_t>& message) const {
//     // ED25519签名需要64字节的私钥（32字节种子 + 32字节公钥）
//     if (privateData_.size() != 64) {
//         throw std::runtime_error("ED25519私钥长度不正确");
//     }
    
//     // 创建EVP密钥
//     EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, 
//                                                   privateData_.data(), 32); // 只使用前32字节种子
//     if (!pkey) {
//         throw std::runtime_error("无法创建ED25519私钥");
//     }
    
//     // 创建签名上下文
//     EVP_MD_CTX* ctx = EVP_MD_CTX_new();
//     if (!ctx) {
//         EVP_PKEY_free(pkey);
//         throw std::runtime_error("无法创建签名上下文");
//     }
    
//     // 初始化签名
//     if (EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pkey) <= 0) {
//         EVP_MD_CTX_free(ctx);
//         EVP_PKEY_free(pkey);
//         throw std::runtime_error("无法初始化ED25519签名");
//     }
    
//     // 获取签名长度
//     size_t sigLen;
//     if (EVP_DigestSign(ctx, nullptr, &sigLen, message.data(), message.size()) <= 0) {
//         EVP_MD_CTX_free(ctx);
//         EVP_PKEY_free(pkey);
//         throw std::runtime_error("无法获取ED25519签名长度");
//     }
    
//     // 创建签名
//     std::vector<uint8_t> signature(sigLen);
//     if (EVP_DigestSign(ctx, signature.data(), &sigLen, message.data(), message.size()) <= 0) {
//         EVP_MD_CTX_free(ctx);
//         EVP_PKEY_free(pkey);
//         throw std::runtime_error("ED25519签名失败");
//     }
    
//     EVP_MD_CTX_free(ctx);
//     EVP_PKEY_free(pkey);
    
//     signature.resize(sigLen);
//     return signature;
// }

// // UnknownPrivateKey实现
// UnknownPrivateKey::UnknownPrivateKey(std::shared_ptr<PublicKey> publicKey, const std::vector<uint8_t>& privateData)
//     : publicKey_(publicKey), privateData_(privateData) {}

// std::vector<uint8_t> UnknownPrivateKey::Sign(const std::vector<uint8_t>& message) const {
//     throw std::runtime_error("未知密钥类型，无法签名");
// }

} // namespace crypto
} // namespace notary 