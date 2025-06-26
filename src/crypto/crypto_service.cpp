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
#include "notary/storage/keystore.hpp"

namespace notary {
namespace crypto {

// EmptyService的定义，对应Go版本的EmptyService = NewCryptoService()
std::shared_ptr<CryptoService> EmptyService = std::make_shared<CryptoService>();

namespace {
// 生成随机字节
std::vector<uint8_t> generateRandomBytes(size_t length) {
    std::vector<uint8_t> bytes(length);
    if (RAND_bytes(bytes.data(), length) != 1) {
        throw std::runtime_error("Failed to generate random bytes");
    }
    return bytes;
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

Result<std::shared_ptr<PublicKey>> CryptoService::Create(const std::string& role, 
                                                        const std::string& gun, 
                                                        const std::string& algorithm) {
    // RSA密钥只能导入，不能生成
    if (algorithm == "rsa") {
        return Result<std::shared_ptr<PublicKey>>(Error("rsa keys can only be imported"));
    }
    
    // 生成密钥对
    auto privateKeyResult = GeneratePrivateKey(algorithm);
    if (!privateKeyResult.ok()) {
        return Result<std::shared_ptr<PublicKey>>(privateKeyResult.error());
    }
    
    auto privateKey = privateKeyResult.value();
    
    // 添加密钥到存储
    auto addResult = AddKey(role, gun, privateKey);
    if (addResult.hasError()) {
        return Result<std::shared_ptr<PublicKey>>(addResult);
    }
    
    return Result<std::shared_ptr<PublicKey>>(privateKey->GetPublicKey());
}

Result<std::tuple<std::shared_ptr<PrivateKey>, std::string>> CryptoService::GetPrivateKey(const std::string& keyID) {
    // 遍历所有密钥存储
    for (auto& keyStore : keyStores_) {
        auto result = keyStore->GetKey(keyID);
        if (result.ok()) {
            return result;
        }
        // 如果是密码错误或尝试次数超限，直接返回
        // 其他错误继续尝试下一个存储
    }
    return Result<std::tuple<std::shared_ptr<PrivateKey>, std::string>>(Error("Key not found in any keystore"));
}

std::shared_ptr<PublicKey> CryptoService::GetKey(const std::string& keyID) {
    // 获取私钥
    auto privateKeyResult = GetPrivateKey(keyID);
    if (!privateKeyResult.ok()) {
        return nullptr;
    }
    
    // 从私钥中提取公钥
    auto [privKey, role] = privateKeyResult.value();
    return privKey->GetPublicKey();
}

Result<storage::KeyInfo> CryptoService::GetKeyInfo(const std::string& keyID) {
    for (auto& keyStore : keyStores_) {
        auto result = keyStore->GetKeyInfo(keyID);
        if (result.ok()) {
            return result;
        }
    }
    return Result<storage::KeyInfo>(Error("could not find info for keyID " + keyID));
}

Error CryptoService::AddKey(const std::string&role, const std::string& gun, std::shared_ptr<PrivateKey> key) {
    // 首先检查密钥是否已存在于任何keyStore中
    for (auto& keyStore : keyStores_) {
        auto existingKeyInfo = keyStore->GetKeyInfo(key->ID());
        if (existingKeyInfo.ok()) {
            if (existingKeyInfo.value().role != role) {
                return Error("key with same ID already exists for role: " + existingKeyInfo.value().role);
            }
            // 密钥已存在且角色相同，直接返回成功
            return Error(); // 成功
        }
    }
    
    // 如果密钥不存在于任何keyStore中，尝试添加到第一个成功的keyStore
    storage::KeyInfo keyInfo(role, gun);
    for (auto& keyStore : keyStores_) {
        auto result = keyStore->AddKey(keyInfo, key);
        if (!result.hasError()) {
            return Error(); // 成功
        }
    }
    
    return Error("Failed to add key to any keystore");
}

Error CryptoService::RemoveKey(const std::string& keyID) {
    // 从所有keyStore中删除密钥
    for (auto& keyStore : keyStores_) {
        keyStore->RemoveKey(keyID);
    }
    return Error(); // 成功
}

std::vector<std::string> CryptoService::ListKeys(const std::string& role) {
    std::vector<std::string> result;
    
    // 遍历所有keyStore
    for (auto& keyStore : keyStores_) {
        auto allKeys = keyStore->ListKeys();
        
        // 过滤指定角色的密钥
        for (const auto& [keyID, keyInfo] : allKeys) {
            if (keyInfo.role == role) {
                result.push_back(keyID);
            }
        }
    }
    
    return result;
}

std::map<std::string, std::string> CryptoService::ListAllKeys() {
    std::map<std::string, std::string> result;
    
    // 遍历所有keyStore
    for (auto& keyStore : keyStores_) {
        auto allKeys = keyStore->ListKeys();
        
        // 提取密钥ID到角色的映射
        for (const auto& [keyID, keyInfo] : allKeys) {
            result[keyID] = keyInfo.role; // 密钥是内容寻址的，所以不关心覆盖
        }
    }
    
    return result;
}

Result<std::shared_ptr<PrivateKey>> CryptoService::GeneratePrivateKey(const std::string& algorithm) {
    if (algorithm == ECDSA_KEY) {
            // 创建 EC_KEY 对象
            std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)> ecKey(
                EC_KEY_new_by_curve_name(NID_X9_62_prime256v1),
                EC_KEY_free);
            
            if (!ecKey) {
            return Result<std::shared_ptr<PrivateKey>>(Error("Failed to create EC key"));
            }
            
            // 生成密钥对
            if (EC_KEY_generate_key(ecKey.get()) != 1) {
            return Result<std::shared_ptr<PrivateKey>>(Error("Failed to generate EC key pair"));
            }
            
            try {
                // 检查EC_KEY的有效性
                if (!EC_KEY_check_key(ecKey.get())) {
                return Result<std::shared_ptr<PrivateKey>>(Error("Generated EC key is invalid"));
                }
                
                // 获取公钥和私钥的 DER 编码
                std::vector<uint8_t> pubKeyDer;
                std::vector<uint8_t> privKeyDer;
                
                try {
                    pubKeyDer = ecKeyToDER(ecKey.get(), false);
                    privKeyDer = ecKeyToDER(ecKey.get(), true);
                } catch (const std::exception& e) {
                return Result<std::shared_ptr<PrivateKey>>(Error(std::string("Failed to encode key to DER: ") + e.what()));
                }
                
                // 验证DER数据长度
                if (pubKeyDer.empty()) {
                return Result<std::shared_ptr<PrivateKey>>(Error("Generated EC public key DER data is empty"));
                }
                if (privKeyDer.empty()) {
                return Result<std::shared_ptr<PrivateKey>>(Error("Generated EC private key DER data is empty"));
                }
                
                // 创建公钥和私钥对象
                auto pubKey = std::make_shared<ECDSAPublicKey>(pubKeyDer);
                auto privKey = std::make_shared<ECDSAPrivateKey>(pubKey, privKeyDer);
                
                // 验证密钥ID生成
                std::string keyID = pubKey->ID();
                if (keyID.empty()) {
                return Result<std::shared_ptr<PrivateKey>>(Error("Failed to generate key ID"));
                }
                
            return Result<std::shared_ptr<PrivateKey>>(privKey);
            } catch (const std::exception& e) {
            return Result<std::shared_ptr<PrivateKey>>(Error(std::string("Failed to create key objects: ") + e.what()));
        }
    } else if (algorithm == ED25519_KEY) {
            // TODO: 实现 ED25519 密钥对生成
        return Result<std::shared_ptr<PrivateKey>>(Error("Unsupported key algorithm: " + algorithm));
    } else if (algorithm == RSA_KEY) {
            // TODO: 实现 RSA 密钥对生成
        return Result<std::shared_ptr<PrivateKey>>(Error("Unsupported key algorithm: " + algorithm));
    } else {
        return Result<std::shared_ptr<PrivateKey>>(Error("Unsupported key algorithm: " + algorithm));
    }
}

Error CryptoService::CheckRootKeyIsEncrypted(const std::vector<uint8_t>& pemBytes) {
    // 解析PEM数据
    BIO* bio = BIO_new_mem_buf(pemBytes.data(), pemBytes.size());
    if (!bio) {
        return Error("Failed to create BIO from PEM data");
    }
    
    char* name = nullptr;
    char* header = nullptr;
    unsigned char* data = nullptr;
    long len = 0;
    
    // 读取PEM块
    int result = PEM_read_bio(bio, &name, &header, &data, &len);
    BIO_free(bio);
    
    if (result != 1) {
        return Error("no valid private key found");
    }
    
    // 检查PEM块类型
    std::string pemType(name);
    bool isEncrypted = false;
    
    if (pemType == "ENCRYPTED PRIVATE KEY") {
        isEncrypted = true;
    } else if (pemType == "PRIVATE KEY" || 
               pemType == "RSA PRIVATE KEY" || 
               pemType == "EC PRIVATE KEY") {
        // 检查是否有加密头部信息
        if (header && strlen(header) > 0) {
            std::string headerStr(header);
            if (headerStr.find("Proc-Type: 4,ENCRYPTED") != std::string::npos) {
                isEncrypted = true;
            }
        }
    }
    
    // 清理内存
    OPENSSL_free(name);
    OPENSSL_free(header);
    OPENSSL_free(data);
    
    if (!isEncrypted) {
        return Error("only encrypted root keys may be imported");
    }
    
    return Error(); // 成功
}

} // namespace crypto
} // namespace notary 