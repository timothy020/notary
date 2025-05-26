#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <functional>
#include <notary/types.hpp>
#include <notary/crypto/keys.hpp>
#include "notary/storage/storage.hpp"

namespace notary {
namespace storage {

// 密钥信息结构（不包含私钥内容）
struct KeyInfo {
    RoleName role;
    std::string gun;  // Gun (Globally Unique Name) - 仓库标识符
    
    KeyInfo() = default;
    KeyInfo(RoleName r, const std::string& g = "") : role(r), gun(g) {}
};

// 缓存的密钥结构
struct CachedKey {
    RoleName role;
    std::shared_ptr<crypto::PrivateKey> key;
    
    CachedKey(RoleName r, std::shared_ptr<crypto::PrivateKey> k) : role(r), key(k) {}
};

// 密码获取器接口
using PassRetriever = std::function<std::tuple<std::string, bool, Error>(
    const std::string& keyName, 
    const std::string& alias, 
    bool createNew, 
    int numAttempts
)>;


// 通用密钥存储（对应Go的GenericKeyStore）
class GenericKeyStore {
public:
    // 创建文件存储的密钥存储
    static std::unique_ptr<GenericKeyStore> NewKeyFileStore(
        const std::string& baseDir, 
        PassRetriever passRetriever
    );
    
    // 创建内存存储的密钥存储
    static std::unique_ptr<GenericKeyStore> NewKeyMemoryStore(
        PassRetriever passRetriever
    );
    
    // 创建通用密钥存储
    GenericKeyStore(std::unique_ptr<Storage> storage, PassRetriever passRetriever);
    
    ~GenericKeyStore() = default;

    // 添加密钥
    Error AddKey(const KeyInfo& keyInfo, std::shared_ptr<crypto::PrivateKey> privKey);
    
    // 获取密钥
    Result<std::tuple<std::shared_ptr<crypto::PrivateKey>, RoleName>> GetKey(const std::string& keyID);
    
    // 获取密钥信息
    Result<KeyInfo> GetKeyInfo(const std::string& keyID);
    
    // 列出所有密钥
    std::map<std::string, KeyInfo> ListKeys();
    
    // 删除密钥
    Error RemoveKey(const std::string& keyID);
    
    // 获取存储名称
    std::string Name() const;

private:
    std::unique_ptr<Storage> store_;
    PassRetriever passRetriever_;
    std::mutex mutex_;
    
    // 缓存已解密的私钥
    std::map<std::string, std::unique_ptr<CachedKey>> cachedKeys_;
    
    // 密钥元信息映射
    std::map<std::string, KeyInfo> keyInfoMap_;
    
    // 加载密钥信息
    void loadKeyInfo();
    
    // 生成密钥信息映射
    std::map<std::string, KeyInfo> generateKeyInfoMap();
    
    // 从PEM获取密钥信息
    Result<std::tuple<std::string, KeyInfo>> keyInfoFromPEM(
        const std::vector<uint8_t>& pemBytes, 
        const std::string& filename
    );
    
    // 获取密钥角色
    Result<RoleName> getKeyRole(const std::string& keyID);
    
    // 密码解密
    Result<std::tuple<std::shared_ptr<crypto::PrivateKey>, std::string>> getPasswdDecryptBytes(
        const std::vector<uint8_t>& pemBytes,
        const std::string& name,
        const std::string& alias
    );
};

// 工厂函数
std::unique_ptr<GenericKeyStore> NewKeyFileStore(
    const std::string& baseDir, 
    PassRetriever passRetriever
);

std::unique_ptr<GenericKeyStore> NewKeyMemoryStore(
    PassRetriever passRetriever
);

} // namespace storage
} // namespace notary