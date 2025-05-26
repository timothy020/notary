#pragma once

#include "notary/crypto/keys.hpp"
#include "notary/types.hpp"
#include "notary/storage/key_storage.hpp"
#include <string>
#include <memory>
#include <vector>
#include <map>

namespace notary {
namespace crypto {

class CryptoService {
public:
    explicit CryptoService(std::shared_ptr<storage::GenericKeyStore> keyStore) : keyStore_(keyStore) {}
    
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
    
    std::shared_ptr<storage::GenericKeyStore> keyStore_;
};

} // namespace crypto
} // namespace notary 