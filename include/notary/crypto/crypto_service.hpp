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
    // 构造函数支持多个keyStore
    explicit CryptoService(std::vector<std::shared_ptr<storage::GenericKeyStore>> keyStores = {}) 
        : keyStores_(keyStores) {}
    
    // 添加keyStore
    void AddKeyStore(std::shared_ptr<storage::GenericKeyStore> keyStore) {
        keyStores_.push_back(keyStore);
    }
    
    
    // 创建新密钥
    Result<std::shared_ptr<PublicKey>> Create(RoleName role, 
                                            const std::string& gun, 
                                            const std::string& algorithm);
    
    // 获取私钥（返回私钥和角色）
    Result<std::tuple<std::shared_ptr<PrivateKey>, RoleName>> GetPrivateKey(const std::string& keyID);
    
    // 获取公钥
    std::shared_ptr<PublicKey> GetKey(const std::string& keyID);
    
    // 获取密钥信息
    Result<storage::KeyInfo> GetKeyInfo(const std::string& keyID);
    
    // 添加密钥
    Error AddKey(RoleName role, const std::string& gun, std::shared_ptr<PrivateKey> key);
    
    // 删除密钥
    Error RemoveKey(const std::string& keyID);
    
    // 列出指定角色的所有密钥
    std::vector<std::string> ListKeys(RoleName role);
    
    // 列出所有密钥
    std::map<std::string, RoleName> ListAllKeys();
    
    // 检查根密钥是否加密（静态方法）
    static Error CheckRootKeyIsEncrypted(const std::vector<uint8_t>& pemBytes);
    
    // 创建空的CryptoService（类似Go版本的EmptyService）
    static std::shared_ptr<CryptoService> NewCryptoService(
        std::vector<std::shared_ptr<storage::GenericKeyStore>> keyStores = {}) {
        return std::make_shared<CryptoService>(keyStores);
    }

private:
    // 生成密钥对
    struct KeyPair {
        std::shared_ptr<PublicKey> publicKey;
        std::shared_ptr<PrivateKey> privateKey;
    };
    Result<std::shared_ptr<PrivateKey>> generatePrivateKey(const std::string& algorithm);
    
private:
    std::vector<std::shared_ptr<storage::GenericKeyStore>> keyStores_;
};

} // namespace crypto
} // namespace notary 