#pragma once

#include <vector>
#include <memory>
#include "notary/types.hpp"
#include "notary/tuf/repo.hpp"
#include "notary/changelist/changelist.hpp"
#include "notary/crypto/crypto_service.hpp"
#include "notary/storage/httpstore.hpp"

namespace notary {
namespace utils {
    std::chrono::system_clock::time_point getDefaultExpiry(const std::string& role);
    std::vector<uint8_t> serializeCanonicalRole(std::shared_ptr<tuf::Repo> tufRepo, const std::string& role, const std::vector<std::shared_ptr<crypto::PublicKey>>& extraSigningKeys);
     
    // 从角色列表中移除指定角色 (对应Go的RoleNameSliceRemove)
    std::vector<std::string> roleNameSliceRemove(const std::vector<std::string>& roles, const std::string& roleToRemove);
    
    // applyChangelist相关函数声明 (对应Go的applyChangelist函数族)
    Error applyChangelist(std::shared_ptr<tuf::Repo> repo, 
                         std::shared_ptr<tuf::Repo> invalid, 
                         std::shared_ptr<changelist::Changelist> cl);
    
    Error applyTargetsChange(std::shared_ptr<tuf::Repo> repo, 
                            std::shared_ptr<tuf::Repo> invalid, 
                            std::shared_ptr<changelist::Change> change);
    
    Error changeTargetMeta(std::shared_ptr<tuf::Repo> repo, 
                          std::shared_ptr<changelist::Change> change);
    
    Error changeTargetsDelegation(std::shared_ptr<tuf::Repo> repo, 
                                 std::shared_ptr<changelist::Change> change);
    
    Error applyRootChange(std::shared_ptr<tuf::Repo> repo, 
                         std::shared_ptr<changelist::Change> change);
    
    Error applyRootRoleChange(std::shared_ptr<tuf::Repo> repo, 
                             std::shared_ptr<changelist::Change> change);
    
    Error witnessTargets(std::shared_ptr<tuf::Repo> repo, 
                        std::shared_ptr<tuf::Repo> invalid, 
                        const std::string& scope);

    // getAllPrivKeys函数声明 (对应Go的getAllPrivKeys函数)
    Result<std::vector<std::shared_ptr<crypto::PrivateKey>>> getAllPrivKeys(
        const std::vector<std::string>& rootKeyIDs, 
        std::shared_ptr<crypto::CryptoService> cryptoService);

    // 检查是否接近过期 (对应Go的nearExpiry函数)
    bool nearExpiry(const std::chrono::system_clock::time_point& expires);

    // warnRolesNearExpiry 检查接近过期的角色并发出警告
    // 对应Go版本的warnRolesNearExpiry函数
    void warnRolesNearExpiry(const std::shared_ptr<tuf::Repo>& repo);

    // rotateRemoteKey函数声明 - 对应Go版本的rotateRemoteKey函数
    // 请求服务器轮转指定角色的密钥
    Result<std::shared_ptr<crypto::PublicKey>> rotateRemoteKey(const std::string& role, 
                                                              std::shared_ptr<storage::RemoteStore> remoteStore,
                                                              const std::string& gun);

}
}