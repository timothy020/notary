#pragma once

#include "notary/crypto/keys.hpp"
#include "notary/types.hpp"
#include <string>
#include <memory>
#include <vector>
#include <map>

namespace notary {
namespace crypto {

class CryptoService {
public:
    CryptoService() : defaultPassphrase_("changeme") {}
    
    // 设置默认密码
    void SetDefaultPassphrase(const std::string& passphrase) {
        defaultPassphrase_ = passphrase;
    }
    
    // 创建新密钥
    Result<std::shared_ptr<PublicKey>> Create(RoleName role, 
                                            const GUN& gun, 
                                            KeyAlgorithm algo);
    
    // 使用指定密码创建新密钥
    Result<std::shared_ptr<PublicKey>> CreateWithPassphrase(RoleName role, 
                                                          const GUN& gun, 
                                                          KeyAlgorithm algo,
                                                          const std::string& passphrase);
    
    // 获取私钥
    Result<std::shared_ptr<PrivateKey>> GetPrivateKey(const std::string& keyID);
    
    // 使用指定密码获取私钥
    Result<std::shared_ptr<PrivateKey>> GetPrivateKeyWithPassphrase(
        const std::string& keyID, const std::string& passphrase);
    
    // 获取公钥
    Result<std::shared_ptr<PublicKey>> GetKey(const std::string& keyID);
    
    // 列出指定角色的所有密钥
    std::vector<std::string> ListKeys(RoleName role);
    
    // 列出所有密钥
    std::map<std::string, RoleName> ListAllKeys();
    
private:
    // 生成密钥对
    struct KeyPair {
        std::shared_ptr<PublicKey> publicKey;
        std::shared_ptr<PrivateKey> privateKey;
    };
    Result<KeyPair> generateKeyPair(KeyAlgorithm algo);
    
    // 加密私钥
    Result<std::vector<uint8_t>> encryptPrivateKey(
        const std::shared_ptr<PrivateKey>& key,
        const std::string& passphrase);
    
    // 获取密码
    std::string getPassphrase(RoleName role);
    
private:
    std::string defaultPassphrase_;

    class KeyStore {
    public:
        Error Save(RoleName role, const std::string& keyID,
                  const std::vector<uint8_t>& encryptedKey);
        Result<std::vector<uint8_t>> Load(const std::string& keyID);
        
        // 生成密钥ID已不再需要，改为保存映射关系
        void MapRoleToKeyID(RoleName role, const std::string& keyID);
        
        // 列出指定角色的所有密钥
        std::vector<std::string> ListKeys(RoleName role);
        
        // 列出所有密钥
        std::map<std::string, RoleName> ListAllKeys();
        
    private:
        static constexpr auto KEY_ENCRYPTION_ALGO = "AES-256-GCM";
        std::vector<uint8_t> deriveKey(const std::string& passphrase);
        
        std::vector<uint8_t> salt_;
        int iterations_ = 100000;
        
        // 内存中密钥存储
        std::map<std::string, std::vector<uint8_t>> keyStorage_;
        std::map<std::string, RoleName> roleMap_;
    };
    
    KeyStore keyStore_;
};

} // namespace crypto
} // namespace notary 