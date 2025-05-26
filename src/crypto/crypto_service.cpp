#include "notary/crypto/crypto_service.hpp"
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <sys/stat.h>
#include <iostream>

namespace notary {
namespace crypto {

namespace {
// 生成随机字节
std::vector<uint8_t> generateRandomBytes(size_t length) {
    std::vector<uint8_t> bytes(length);
    if (RAND_bytes(bytes.data(), length) != 1) {
        throw std::runtime_error("Failed to generate random bytes");
    }
    return bytes;
}

// 计算 SHA256 哈希
std::string calculateSHA256(const std::vector<uint8_t>& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data.data(), data.size());
    SHA256_Final(hash, &sha256);
    
    std::stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

// 将 EC_KEY 转换为 DER 格式
std::vector<uint8_t> ecKeyToDER(EC_KEY* key, bool isPrivate) {
    std::vector<uint8_t> derData;
    if (isPrivate) {
        // 获取私钥 DER 编码长度
        int len = i2d_ECPrivateKey(key, nullptr);
        if (len <= 0) {
            throw std::runtime_error("Failed to get private key DER length");
        }
        
        // 分配内存并编码
        derData.resize(len);
        unsigned char* p = derData.data();
        if (i2d_ECPrivateKey(key, &p) <= 0) {
            throw std::runtime_error("Failed to encode private key to DER");
        }
    } else {
        // 获取公钥 DER 编码长度
        int len = i2d_EC_PUBKEY(key, nullptr);
        if (len <= 0) {
            throw std::runtime_error("Failed to get public key DER length");
        }
        
        // 分配内存并编码
        derData.resize(len);
        unsigned char* p = derData.data();
        if (i2d_EC_PUBKEY(key, &p) <= 0) {
            throw std::runtime_error("Failed to encode public key to DER");
        }
    }
    return derData;
}

} // namespace

Result<std::shared_ptr<PublicKey>> CryptoService::Create(RoleName role, 
                                                        const GUN& gun, 
                                                        KeyAlgorithm algo) {
    return CreateWithPassphrase(role, gun, algo, defaultPassphrase_);
}

Result<std::shared_ptr<PublicKey>> CryptoService::CreateWithPassphrase(
    RoleName role, const GUN& gun, KeyAlgorithm algo, const std::string& passphrase) {
    // 生成密钥对
    auto keyPairResult = generateKeyPair(algo);
    if (!keyPairResult.ok()) {
        return Result<std::shared_ptr<PublicKey>>(keyPairResult.error());
    }
    
    auto keyPair = keyPairResult.value();
    
    // 加密私钥
    auto encryptedKeyResult = encryptPrivateKey(keyPair.privateKey, passphrase);
    if (!encryptedKeyResult.ok()) {
        return Result<std::shared_ptr<PublicKey>>(encryptedKeyResult.error());
    }
    
    // 获取公钥的ID（哈希值）
    std::string keyID = keyPair.publicKey->ID();
    
    // 保存加密的私钥
    Error err = keyStore_.Save(role, keyID, encryptedKeyResult.value());
    if (!err.ok()) {
        return Result<std::shared_ptr<PublicKey>>(err);
    }
    
    return Result<std::shared_ptr<PublicKey>>(keyPair.publicKey);
}

Result<std::shared_ptr<PrivateKey>> CryptoService::GetPrivateKey(const std::string& keyID) {
    return GetPrivateKeyWithPassphrase(keyID, defaultPassphrase_);
}

Result<std::shared_ptr<PrivateKey>> CryptoService::GetPrivateKeyWithPassphrase(
    const std::string& keyID, const std::string& passphrase) {
    // 从存储中加载加密的私钥
    auto encryptedKeyResult = keyStore_.Load(keyID);
    if (!encryptedKeyResult.ok()) {
        return Result<std::shared_ptr<PrivateKey>>(encryptedKeyResult.error());
    }
    
    try {
        const auto& encryptedData = encryptedKeyResult.value();
        size_t offset = 0;
        
        // 解析salt
        if (encryptedData.size() < 2) {
            return Result<std::shared_ptr<PrivateKey>>(Error("Invalid encrypted key format"));
        }
        uint16_t saltLen = (encryptedData[offset] << 8) | encryptedData[offset + 1];
        offset += 2;
        
        if (encryptedData.size() < offset + saltLen) {
            return Result<std::shared_ptr<PrivateKey>>(Error("Invalid encrypted key format"));
        }
        std::vector<uint8_t> salt(encryptedData.begin() + offset, 
                                 encryptedData.begin() + offset + saltLen);
        offset += saltLen;
        
        // 解析IV
        if (encryptedData.size() < offset + 2) {
            return Result<std::shared_ptr<PrivateKey>>(Error("Invalid encrypted key format"));
        }
        uint16_t ivLen = (encryptedData[offset] << 8) | encryptedData[offset + 1];
        offset += 2;
        
        if (encryptedData.size() < offset + ivLen) {
            return Result<std::shared_ptr<PrivateKey>>(Error("Invalid encrypted key format"));
        }
        std::vector<uint8_t> iv(encryptedData.begin() + offset, 
                               encryptedData.begin() + offset + ivLen);
        offset += ivLen;
        
        // 解析tag
        if (encryptedData.size() < offset + 2) {
            return Result<std::shared_ptr<PrivateKey>>(Error("Invalid encrypted key format"));
        }
        uint16_t tagLen = (encryptedData[offset] << 8) | encryptedData[offset + 1];
        offset += 2;
        
        if (encryptedData.size() < offset + tagLen) {
            return Result<std::shared_ptr<PrivateKey>>(Error("Invalid encrypted key format"));
        }
        std::vector<uint8_t> tag(encryptedData.begin() + offset, 
                                encryptedData.begin() + offset + tagLen);
        offset += tagLen;
        
        // 获取密文
        if (offset >= encryptedData.size()) {
            return Result<std::shared_ptr<PrivateKey>>(Error("Invalid encrypted key format"));
        }
        std::vector<uint8_t> ciphertext(encryptedData.begin() + offset, encryptedData.end());
        
        // 使用PBKDF2从密码派生密钥
        unsigned char derivedKey[32]; // AES-256需要32字节密钥
        if (PKCS5_PBKDF2_HMAC(passphrase.c_str(), passphrase.length(),
                              salt.data(), salt.size(),
                              10000, // 迭代次数
                              EVP_sha256(),
                              sizeof(derivedKey), derivedKey) != 1) {
            return Result<std::shared_ptr<PrivateKey>>(Error("Failed to derive key from passphrase"));
        }
        
        // 解密私钥
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            return Result<std::shared_ptr<PrivateKey>>(Error("Failed to create cipher context"));
        }
        
        // 初始化解密操作
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, derivedKey, iv.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return Result<std::shared_ptr<PrivateKey>>(Error("Failed to initialize decryption"));
        }
        
        // 设置认证标签
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), tag.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return Result<std::shared_ptr<PrivateKey>>(Error("Failed to set authentication tag"));
        }
        
        // 分配输出缓冲区
        std::vector<uint8_t> plaintext(ciphertext.size());
        int len = 0, plaintext_len = 0;
        
        // 解密数据
        if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, 
                             ciphertext.data(), ciphertext.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return Result<std::shared_ptr<PrivateKey>>(Error("Failed to decrypt data"));
        }
        plaintext_len = len;
        
        // 验证并完成解密
        int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
        EVP_CIPHER_CTX_free(ctx);
        
        if (ret != 1) {
            return Result<std::shared_ptr<PrivateKey>>(Error("Authentication failed or decryption error"));
        }
        plaintext_len += len;
        plaintext.resize(plaintext_len);
        
        // 解析DER编码的私钥
        // 创建EC_KEY对象
        EC_KEY* ecKey = nullptr;
        const unsigned char* p = plaintext.data();
        ecKey = d2i_ECPrivateKey(nullptr, &p, plaintext.size());
        
        if (!ecKey) {
            return Result<std::shared_ptr<PrivateKey>>(Error("Failed to parse private key"));
        }
        
        // 获取公钥
        std::vector<uint8_t> pubKeyDer = ecKeyToDER(ecKey, false);
        EC_KEY_free(ecKey);
        
        // 创建公钥和私钥对象
        auto pubKey = std::make_shared<ECDSAPublicKey>(pubKeyDer);
        auto privKey = std::make_shared<ECDSAPrivateKey>(pubKey, plaintext);
        
        return Result<std::shared_ptr<PrivateKey>>(privKey);
    } catch (const std::exception& e) {
        return Result<std::shared_ptr<PrivateKey>>(Error(std::string("Decryption error: ") + e.what()));
    }
}

Result<std::shared_ptr<PublicKey>> CryptoService::GetKey(const std::string& keyID) {
    // 从存储中获取私钥
    auto privateKeyResult = GetPrivateKey(keyID);
    if (!privateKeyResult.ok()) {
        return Result<std::shared_ptr<PublicKey>>(privateKeyResult.error());
    }
    
    // 从私钥中提取公钥
    return Result<std::shared_ptr<PublicKey>>(privateKeyResult.value()->GetPublicKey());
}

std::vector<std::string> CryptoService::ListKeys(RoleName role) {
    return keyStore_.ListKeys(role);
}

std::map<std::string, RoleName> CryptoService::ListAllKeys() {
    return keyStore_.ListAllKeys();
}

Result<CryptoService::KeyPair> CryptoService::generateKeyPair(KeyAlgorithm algo) {
    switch (algo) {
        case KeyAlgorithm::ECDSA: {
            // 创建 EC_KEY 对象
            std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)> ecKey(
                EC_KEY_new_by_curve_name(NID_X9_62_prime256v1),
                EC_KEY_free);
            
            if (!ecKey) {
                return Result<KeyPair>(Error("Failed to create EC key"));
            }
            
            // 生成密钥对
            if (EC_KEY_generate_key(ecKey.get()) != 1) {
                return Result<KeyPair>(Error("Failed to generate EC key pair"));
            }
            
            try {
                // 检查EC_KEY的有效性
                if (!EC_KEY_check_key(ecKey.get())) {
                    return Result<KeyPair>(Error("Generated EC key is invalid"));
                }
                
                // 获取公钥和私钥的 DER 编码
                std::vector<uint8_t> pubKeyDer;
                std::vector<uint8_t> privKeyDer;
                
                try {
                    pubKeyDer = ecKeyToDER(ecKey.get(), false);
                    privKeyDer = ecKeyToDER(ecKey.get(), true);
                } catch (const std::exception& e) {
                    return Result<KeyPair>(Error(std::string("Failed to encode key to DER: ") + e.what()));
                }
                
                // 验证DER数据长度
                if (pubKeyDer.empty()) {
                    return Result<KeyPair>(Error("Generated EC public key DER data is empty"));
                }
                if (privKeyDer.empty()) {
                    return Result<KeyPair>(Error("Generated EC private key DER data is empty"));
                }
                
                // 创建公钥和私钥对象
                auto pubKey = std::make_shared<ECDSAPublicKey>(pubKeyDer);
                auto privKey = std::make_shared<ECDSAPrivateKey>(pubKey, privKeyDer);
                
                // 验证密钥ID生成
                std::string keyID = pubKey->ID();
                if (keyID.empty()) {
                    return Result<KeyPair>(Error("Failed to generate key ID"));
                }
                
                return Result<KeyPair>(KeyPair{pubKey, privKey});
            } catch (const std::exception& e) {
                return Result<KeyPair>(Error(std::string("Failed to create key objects: ") + e.what()));
            }
        }
        case KeyAlgorithm::ED25519: {
            // TODO: 实现 ED25519 密钥对生成
            return Result<KeyPair>(Error("ED25519 not implemented"));
        }
        case KeyAlgorithm::RSA: {
            // TODO: 实现 RSA 密钥对生成
            return Result<KeyPair>(Error("RSA not implemented"));
        }
        default:
            return Result<KeyPair>(Error("Unsupported key algorithm"));
    }
}

Result<std::vector<uint8_t>> CryptoService::encryptPrivateKey(
    const std::shared_ptr<PrivateKey>& key,
    const std::string& passphrase) {
    try {
        // 1. 获取私钥数据
        auto privateKeyData = std::static_pointer_cast<ECDSAPrivateKey>(key)->Private();
        
        // 2. 生成随机盐和IV
        std::vector<uint8_t> salt = generateRandomBytes(16);
        std::vector<uint8_t> iv = generateRandomBytes(12); // GCM模式推荐12字节IV
        
        // 3. 使用PBKDF2从密码派生密钥
        unsigned char derivedKey[32]; // AES-256需要32字节密钥
        if (PKCS5_PBKDF2_HMAC(passphrase.c_str(), passphrase.length(),
                              salt.data(), salt.size(),
                              10000, // 迭代次数
                              EVP_sha256(),
                              sizeof(derivedKey), derivedKey) != 1) {
            return Result<std::vector<uint8_t>>(Error("Failed to derive key from passphrase"));
        }
        
        // 4. 使用AES-256-GCM加密私钥
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            return Result<std::vector<uint8_t>>(Error("Failed to create cipher context"));
        }
        
        // 初始化加密操作
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, derivedKey, iv.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return Result<std::vector<uint8_t>>(Error("Failed to initialize encryption"));
        }
        
        // 分配输出缓冲区 (大小可能比输入稍大)
        std::vector<uint8_t> ciphertext(privateKeyData.size() + EVP_MAX_BLOCK_LENGTH);
        int len = 0, ciphertext_len = 0;
        
        // 加密数据
        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, 
                            privateKeyData.data(), privateKeyData.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return Result<std::vector<uint8_t>>(Error("Failed to encrypt data"));
        }
        ciphertext_len = len;
        
        // 处理最后一个块
        if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return Result<std::vector<uint8_t>>(Error("Failed to finalize encryption"));
        }
        ciphertext_len += len;
        ciphertext.resize(ciphertext_len);
        
        // 获取认证标签(GCM模式)
        std::vector<uint8_t> tag(16);
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return Result<std::vector<uint8_t>>(Error("Failed to get authentication tag"));
        }
        
        EVP_CIPHER_CTX_free(ctx);
        
        // 5. 构造输出格式: salt + iv + tag + ciphertext
        std::vector<uint8_t> result;
        result.reserve(2 + salt.size() + 2 + iv.size() + 2 + tag.size() + ciphertext.size());
        
        // 添加salt(长度+数据)
        result.push_back(static_cast<uint8_t>(salt.size() >> 8));
        result.push_back(static_cast<uint8_t>(salt.size()));
        result.insert(result.end(), salt.begin(), salt.end());
        
        // 添加iv(长度+数据)
        result.push_back(static_cast<uint8_t>(iv.size() >> 8));
        result.push_back(static_cast<uint8_t>(iv.size()));
        result.insert(result.end(), iv.begin(), iv.end());
        
        // 添加tag(长度+数据)
        result.push_back(static_cast<uint8_t>(tag.size() >> 8));
        result.push_back(static_cast<uint8_t>(tag.size()));
        result.insert(result.end(), tag.begin(), tag.end());
        
        // 添加密文
        result.insert(result.end(), ciphertext.begin(), ciphertext.end());
        
        return Result<std::vector<uint8_t>>(result);
    } catch (const std::exception& e) {
        return Result<std::vector<uint8_t>>(Error(std::string("Encryption error: ") + e.what()));
    }
}

std::string CryptoService::getPassphrase(RoleName role) {
    // 直接返回默认密码
    return defaultPassphrase_;
}


} // namespace crypto
} // namespace notary 