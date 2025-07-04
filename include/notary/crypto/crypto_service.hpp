#pragma once

#include "notary/crypto/keys.hpp"
#include "notary/types.hpp"
#include "notary/storage/keystore.hpp"
#include <string>
#include <memory>
#include <vector>
#include <map>

namespace notary {
namespace crypto {

// 前向声明
class CryptoService;

// EmptyService是一个空的crypto service实例，对应Go版本的EmptyService
extern std::shared_ptr<CryptoService> EmptyService;

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
    Result<std::shared_ptr<PublicKey>> Create(const std::string& role, 
                                            const std::string& gun, 
                                            const std::string& algorithm);
    
    // 获取私钥（返回私钥和角色）
    Result<std::tuple<std::shared_ptr<PrivateKey>, std::string>> GetPrivateKey(const std::string& keyID);
    
    // 获取公钥
    std::shared_ptr<PublicKey> GetKey(const std::string& keyID);
    
    // 获取密钥信息
    Result<storage::KeyInfo> GetKeyInfo(const std::string& keyID);
    
    // 添加密钥
    Error AddKey(const std::string& role, const std::string& gun, std::shared_ptr<PrivateKey> key);
    
    // 删除密钥
    Error RemoveKey(const std::string& keyID);
    
    // 列出指定角色的所有密钥
    std::vector<std::string> ListKeys(const std::string& role);
    
    // 列出所有密钥
    std::map<std::string, std::string> ListAllKeys();
    
    // 检查根密钥是否加密（静态方法）
    static Error CheckRootKeyIsEncrypted(const std::vector<uint8_t>& pemBytes);
    
    // 创建空的CryptoService（类似Go版本的EmptyService）
    static std::shared_ptr<CryptoService> NewCryptoService(
        std::vector<std::shared_ptr<storage::GenericKeyStore>> keyStores = {}) {
        return std::make_shared<CryptoService>(keyStores);
    }

    // 生成私钥（对应Go版本的tufutils.GenerateKey）
    Result<std::shared_ptr<PrivateKey>> GeneratePrivateKey(const std::string& algorithm);

private:
    // 生成密钥对
    struct KeyPair {
        std::shared_ptr<PublicKey> publicKey;
        std::shared_ptr<PrivateKey> privateKey;
    };
private:
    std::vector<std::shared_ptr<storage::GenericKeyStore>> keyStores_;
};

} // namespace crypto
} // namespace notary 