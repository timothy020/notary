#pragma once

#include <string>
#include <vector>
#include <memory>
#include <map>
#include "notary/crypto/crypto_service.hpp"
#include "notary/storage/metadata_store.hpp"
#include "notary/types.hpp"
#include "notary/tuf/repo.hpp"
#include <nlohmann/json.hpp>
#include "notary/changelist/changelist.hpp"


namespace notary {

using crypto::CryptoService;
using storage::MetadataStore;
using storage::RemoteStore;
using json = nlohmann::json;

// 目标结构体
struct Target {
    std::string name;             // 目标名称
    std::map<std::string, std::vector<uint8_t>> hashes; // 哈希值 (算法 -> 哈希值)
    int64_t length;               // 目标大小
    json custom;                  // 自定义数据
};

// // Changelist 相关类型和接口定义
// namespace changelist {

// // 操作类型
// const std::string ActionCreate = "create";
// const std::string ActionUpdate = "update";
// const std::string ActionDelete = "delete";

// // 内容类型
// const std::string TypeTargetsTarget = "target";
// const std::string TypeTargetsDelegation = "delegation";

// // Change类接口
// class Change {
// public:
//     virtual ~Change() = default;
//     virtual std::string Action() const = 0;
//     virtual std::string Scope() const = 0;
//     virtual std::string Type() const = 0;
//     virtual std::string Path() const = 0;
//     virtual std::vector<uint8_t> Content() const = 0;
// };

// // TUF Change实现类
// class TUFChange : public Change {
// public:
//     TUFChange(const std::string& action, const std::string& role, 
//               const std::string& changeType, const std::string& changePath,
//               const std::vector<uint8_t>& content)
//         : action_(action), role_(role), changeType_(changeType), 
//           changePath_(changePath), content_(content) {}

//     std::string Action() const override { return action_; }
//     std::string Scope() const override { return role_; }
//     std::string Type() const override { return changeType_; }
//     std::string Path() const override { return changePath_; }
//     std::vector<uint8_t> Content() const override { return content_; }

// private:
//     std::string action_;
//     std::string role_;
//     std::string changeType_;
//     std::string changePath_;
//     std::vector<uint8_t> content_;
// };

// // Changelist接口
// class Changelist {
// public:
//     virtual ~Changelist() = default;
//     virtual std::vector<std::shared_ptr<Change>> List() const = 0;
//     virtual Error Add(const std::shared_ptr<Change>& change) = 0;
//     virtual Error Clear(const std::string& archive = "") = 0;
//     virtual Error Close() = 0;
//     virtual std::string Location() const = 0;
// };

// // FileChangelist实现类
// class FileChangelist : public Changelist {
// public:
//     FileChangelist(const std::string& dir);
//     std::vector<std::shared_ptr<Change>> List() const override;
//     Error Add(const std::shared_ptr<Change>& change) override;
//     Error Clear(const std::string& archive = "") override;
//     Error Close() override;
//     std::string Location() const override { return dir_; }

// private:
//     std::string dir_;
// };

// } // namespace changelist

class Repository {
public:
    Repository(const GUN& gun, const std::string& trustDir, const std::string& serverURL);
    
    
    // 初始化仓库
    Error Initialize(const std::vector<std::string>& rootKeyIDs,
                    const std::vector<RoleName>& serverManagedRoles = {});
    
    // 获取加密服务
    std::shared_ptr<CryptoService> GetCryptoService() { return cryptoService_; }
    
    // 获取GUN
    const GUN& GetGUN() const { return gun_; }

    // 初始化角色
    std::tuple<BaseRole, BaseRole, BaseRole, BaseRole> 
    initializeRoles(const std::vector<std::shared_ptr<crypto::PublicKey>>& rootKeys,
                   const std::vector<RoleName>& localRoles,
                   const std::vector<RoleName>& remoteRoles);

    // 更新TUF元数据
    Error updateTUF(bool force = false); // TODO： 需要修改

    // 引导仓库
    Error bootstrapRepo();  // TODO： 需要修改
    
    // 保存元数据
    Error saveMetadata(bool ignoreSnapshot = false);
    
    // 添加目标文件
    Error AddTarget(const Target& target, const std::vector<std::string>& roles = {});
    
                                   
    // 获取changelist
    changelist::Changelist& GetChangelist() { return *changelist_; }
    
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

private:

    // 应用changelist
    Error applyChangelist();

    // 签署root
    Error signRootIfNecessary(std::map<std::string, std::vector<uint8_t>>& updatedFiles, bool initialPublish);

    // 签署targets
    Error signTargets(std::map<std::string, std::vector<uint8_t>>& updates, bool initialPublish);

private:
    GUN gun_;
    std::string trustDir_;
    std::string serverURL_;
    std::shared_ptr<storage::FileSystemStorage> cache_;
    std::shared_ptr<storage::RemoteStore> remoteStore_;
    std::shared_ptr<changelist::Changelist> changelist_;
    std::shared_ptr<crypto::CryptoService> cryptoService_;
    std::shared_ptr<tuf::Repo> tufRepo_; // 元数据的内存表示
    std::shared_ptr<tuf::Repo> invalidRepo_; // 无效的元数据
};

} // namespace notary 