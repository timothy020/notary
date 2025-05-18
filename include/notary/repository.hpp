#pragma once

#include <string>
#include <vector>
#include <memory>
#include "notary/crypto/crypto_service.hpp"
#include "notary/storage/metadata_store.hpp"
#include "notary/types.hpp"

namespace notary {

using crypto::CryptoService;
using storage::MetadataStore;
using storage::RemoteStore;

class Repository {
public:
    Repository(const std::string& trustDir, const std::string& serverURL);
    
    // 设置密码
    void SetPassphrase(const std::string& passphrase);
    
    // 初始化仓库
    Error Initialize(const std::vector<std::string>& rootKeyIDs,
                    const std::vector<RoleName>& serverManagedRoles = {});
    
    // 获取加密服务
    CryptoService& GetCryptoService() { return cryptoService_; }
    
    // 获取GUN
    const GUN& GetGUN() const { return gun_; }
    
    // 设置GUN
    void SetGUN(const GUN& gun) { gun_ = gun; }

private:
    // 初始化角色
    std::tuple<BaseRole, BaseRole, BaseRole, BaseRole> 
    initializeRoles(const std::vector<std::shared_ptr<PublicKey>>& rootKeys,
                   const std::vector<RoleName>& localRoles,
                   const std::vector<RoleName>& remoteRoles);
    
    // 初始化TUF元数据
    Error initializeTUFMetadata(const BaseRole& root,
                              const BaseRole& targets,
                              const BaseRole& snapshot,
                              const BaseRole& timestamp);

    // 创建公钥对象
    std::shared_ptr<PublicKey> CreatePublicKey(const std::vector<uint8_t>& keyBytes, 
                                              const std::string& keyType);

private:
    GUN gun_;                    // 全局唯一名称
    std::string baseURL_;        // 服务器URL
    CryptoService cryptoService_;// 加密服务
    MetadataStore cache_;        // 元数据缓存
    RemoteStore remoteStore_;    // 远程存储
};

} // namespace notary 