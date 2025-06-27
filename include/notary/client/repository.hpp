#pragma once

#include <string>
#include <vector>
#include <memory>
#include <map>
#include "notary/crypto/crypto_service.hpp"
#include "notary/storage/httpstore.hpp"
#include "notary/storage/filestore.hpp"
#include "notary/types.hpp"
#include "notary/tuf/repo.hpp"
#include <nlohmann/json.hpp>
#include "notary/changelist/changelist.hpp"


namespace notary {

using crypto::CryptoService;
using storage::RemoteStore;
using json = nlohmann::json;

// 目标结构体
struct Target {
    std::string name;             // 目标名称
    std::map<std::string, std::vector<uint8_t>> hashes; // 哈希值 (算法 -> 哈希值)
    int64_t length;               // 目标大小
    json custom;                  // 自定义数据
};

// 带角色信息的目标结构体 (对应Go的TargetWithRole)
struct TargetWithRole {
    Target target;                // 目标信息
    std::string role;                // 角色名称
};


class Repository {
public:
    Repository(const GUN& gun, const std::string& trustDir, const std::string& serverURL);
    
    
    // 初始化仓库
    Error Initialize(const std::vector<std::string>& rootKeyIDs,
                    const std::vector<std::shared_ptr<crypto::PublicKey>>& rootCerts = {},
                    const std::vector<std::string>& serverManagedRoles = {});
    
    // 获取加密服务
    std::shared_ptr<CryptoService> GetCryptoService() { return cryptoService_; }
    
    // 获取GUN
    const GUN& GetGUN() const { return gun_; }

    // 初始化角色
    std::tuple<BaseRole, BaseRole, BaseRole, BaseRole> 
    initializeRoles(const std::vector<std::shared_ptr<crypto::PublicKey>>& rootKeys,
                   const std::vector<std::string>& localRoles,
                   const std::vector<std::string>& remoteRoles);

    // 更新TUF元数据
    Error updateTUF(bool force = false);

    // 引导仓库
    Error bootstrapRepo();
    
    // 保存元数据
    Error saveMetadata(bool ignoreSnapshot = false);
    
    // 添加目标文件
    Error AddTarget(const Target& target, const std::vector<std::string>& roles = {});
    
    // 移除目标文件 (对应Go的RemoveTarget)
    Error RemoveTarget(const std::string& targetName, const std::vector<std::string>& roles = {});
    
    // 列出所有目标 (对应Go的ListTargets)
    Result<std::vector<TargetWithRole>> ListTargets(const std::vector<std::string>& roles = {});
                                   
    // 获取changelist的公共接口 (对应Go的GetChangelist)
    std::shared_ptr<changelist::Changelist> GetChangelistPublic() const { return changelist_; }
    
    // 发布更改
    Error Publish();
    
    // 创建目标对象
    static Result<Target> NewTarget(const std::string& targetName, 
                                   const std::string& targetPath,
                                   const json& customData = {});
    
    // 通过名称获取目标 (对应Go的GetTargetByName)
    Result<Target> GetTargetByName(const std::string& targetName);

    // 删除信任数据 (对应Go的DeleteTrustData)
    static Error DeleteTrustData(const std::string& baseDir, const GUN& gun, 
                                 const std::string& serverURL = "", 
                                 bool deleteRemote = false);

    // 密钥轮转操作 (对应Go的RotateKey)
    // 移除角色关联的所有现有密钥。如果keyList中没有指定密钥，则创建并添加一个新密钥或委托服务器管理密钥。
    // 如果keyList指定了密钥，则使用这些密钥来签名角色。
    // 这些更改暂存在changelist中，直到调用publish为止。
    Error RotateKey(const std::string& role, bool serverManagesKey, const std::vector<std::string>& keyList = {});

    // 发布方法 (对应Go的publish方法)
    // 使用提供的changelist发布变更到远程服务器  
    Error publish(std::shared_ptr<changelist::Changelist> cl);

    // 委托管理方法 (对应Go的delegations.go)
    
    // AddDelegation - 创建changelist条目来添加提供的委托公钥和路径 (对应Go的AddDelegation)
    // 此方法组合了AddDelegationRoleAndKeys和AddDelegationPaths（如果调用的话，每个都会创建一个changelist）
    Error AddDelegation(const std::string& name, 
                       const std::vector<std::shared_ptr<crypto::PublicKey>>& delegationKeys, 
                       const std::vector<std::string>& paths);

    // AddDelegationRoleAndKeys - 创建changelist条目来添加提供的委托公钥 (对应Go的AddDelegationRoleAndKeys)
    // 这是创建新委托的最简单方法，因为委托在创建时必须至少有一个密钥才能有效，
    // 因为我们在验证阈值时会拒绝changelist
    Error AddDelegationRoleAndKeys(const std::string& name, 
                                  const std::vector<std::shared_ptr<crypto::PublicKey>>& delegationKeys);

    // AddDelegationPaths - 创建changelist条目来将提供的路径添加到现有委托 (对应Go的AddDelegationPaths)
    // 此方法本身无法创建新的委托，因为角色在创建时必须满足密钥阈值
    Error AddDelegationPaths(const std::string& name, const std::vector<std::string>& paths);

    // RemoveDelegationKeysAndPaths - 创建changelist条目来移除提供的委托密钥ID和路径 (对应Go的RemoveDelegationKeysAndPaths)
    // 此方法组合了RemoveDelegationPaths和RemoveDelegationKeys（如果调用的话，每个都会创建一个changelist条目）
    Error RemoveDelegationKeysAndPaths(const std::string& name, 
                                      const std::vector<std::string>& keyIDs, 
                                      const std::vector<std::string>& paths);

    // RemoveDelegationRole - 创建changelist来移除角色的所有路径和密钥，并完全删除角色 (对应Go的RemoveDelegationRole)
    Error RemoveDelegationRole(const std::string& name);

    // RemoveDelegationPaths - 创建changelist条目来从现有委托移除提供的路径 (对应Go的RemoveDelegationPaths)
    Error RemoveDelegationPaths(const std::string& name, const std::vector<std::string>& paths);

    // RemoveDelegationKeys - 创建changelist条目来从现有委托移除提供的密钥 (对应Go的RemoveDelegationKeys)
    // 当应用此changelist时，如果指定的密钥是角色中唯一剩余的密钥，
    // 角色本身将被完全删除。
    // 它还可以使用以通配符结尾的名称从父级下的所有委托中删除密钥
    Error RemoveDelegationKeys(const std::string& name, const std::vector<std::string>& keyIDs);

    // ClearDelegationPaths - 创建changelist条目来从现有委托移除所有路径 (对应Go的ClearDelegationPaths)
    Error ClearDelegationPaths(const std::string& name);

private:

    // 应用changelist
    Error applyChangelist();

    // 签署root
    Error signRootIfNecessary(std::map<std::string, std::vector<uint8_t>>& updatedFiles, bool initialPublish);

    // 签署targets
    Error signTargets(std::map<std::string, std::vector<uint8_t>>& updates, bool initialPublish);

    // createNewPublicKeyFromKeyIDs函数声明 - 对应Go版本的createNewPublicKeyFromKeyIDs函数
    // 根据给定的密钥ID列表生成一组对应的公钥
    // 这些密钥ID存在于仓库的CryptoService中
    // 返回的公钥顺序与输入的keyIDs顺序一一对应
    Result<std::vector<std::shared_ptr<crypto::PublicKey>>> createNewPublicKeyFromKeyIDs(
        const std::vector<std::string>& keyIDs);

    // publicKeysOfKeyIDs函数声明 - 对应Go版本的publicKeysOfKeyIDs函数  
    // 确认公钥和私钥（通过密钥ID）形成有效的、严格有序的密钥对
    // (例如 keyIDs[0] 必须匹配 pubKeys[0]，keyIDs[1] 必须匹配 pubKeys[1]，以此类推)
    // 或者在不匹配时抛出错误
    Result<std::vector<std::shared_ptr<crypto::PublicKey>>> publicKeysOfKeyIDs(
        const std::vector<std::string>& keyIDs, 
        const std::vector<std::shared_ptr<crypto::PublicKey>>& pubKeys);

    // matchKeyIdsWithPubKeys函数声明 - 对应Go版本的matchKeyIdsWithPubKeys函数
    // 验证私钥（通过其ID表示）和公钥形成匹配的密钥对
    Error matchKeyIdsWithPubKeys(const std::vector<std::string>& ids, 
                                const std::vector<std::shared_ptr<crypto::PublicKey>>& pubKeys);

    // pubKeyListForRotation函数声明 - 对应Go版本的pubKeyListForRotation函数
    // 给定一组新密钥和要轮转的角色，返回要使用的当前密钥列表
    Result<std::vector<std::shared_ptr<crypto::PublicKey>>> pubKeyListForRotation(
        const std::string& role, bool serverManaged, const std::vector<std::string>& newKeys);



    // pubKeysToCerts函数声明 - 对应Go版本的pubKeysToCerts函数
    // 将公钥转换为证书（对于根密钥）
    Result<std::vector<std::shared_ptr<crypto::PublicKey>>> pubKeysToCerts(
        const std::string& role, const std::vector<std::shared_ptr<crypto::PublicKey>>& pubKeys);

    // rootFileKeyChange函数声明 - 对应Go版本的rootFileKeyChange函数
    // 为根文件创建密钥变更
    Error rootFileKeyChange(std::shared_ptr<changelist::Changelist> cl, const std::string& role, 
                           const std::string& action, const std::vector<std::shared_ptr<crypto::PublicKey>>& keyList);

    // 委托管理的辅助函数 (对应Go的delegations.go中的辅助函数)
    
    // newUpdateDelegationChange - 创建更新委托的变更 (对应Go的newUpdateDelegationChange)
    std::shared_ptr<changelist::TUFChange> newUpdateDelegationChange(
        const std::string& name, const std::vector<uint8_t>& content);

    // newCreateDelegationChange - 创建新建委托的变更 (对应Go的newCreateDelegationChange)
    std::shared_ptr<changelist::TUFChange> newCreateDelegationChange(
        const std::string& name, const std::vector<uint8_t>& content);

    // newDeleteDelegationChange - 创建删除委托的变更 (对应Go的newDeleteDelegationChange)
    std::shared_ptr<changelist::TUFChange> newDeleteDelegationChange(
        const std::string& name, const std::vector<uint8_t>& content);


private:
    GUN gun_;
    std::string trustDir_;
    std::string serverURL_;
    std::shared_ptr<storage::FileStore> cache_;
    std::shared_ptr<storage::RemoteStore> remoteStore_;
    std::shared_ptr<changelist::Changelist> changelist_;
    std::shared_ptr<crypto::CryptoService> cryptoService_;
    std::shared_ptr<tuf::Repo> tufRepo_; // 元数据的内存表示
    std::shared_ptr<tuf::Repo> invalidRepo_; // 无效的元数据
};

} // namespace notary 