#pragma once

#include <string>
#include <vector>
#include <memory>
#include <map>
#include "notary/crypto/crypto_service.hpp"
#include "notary/storage/metadata_store.hpp"
#include "notary/types.hpp"
#include "notary/tuf/repo.hpp"

namespace notary {

using crypto::CryptoService;
using storage::MetadataStore;
using storage::RemoteStore;

// 目标结构体
struct Target {
    std::string name;             // 目标名称
    std::map<std::string, std::vector<uint8_t>> hashes; // 哈希值 (算法 -> 哈希值)
    int64_t length;               // 目标大小
    std::vector<uint8_t> custom;  // 自定义数据
};

// Changelist 相关类型和接口定义
namespace changelist {

// 操作类型
const std::string ActionCreate = "create";
const std::string ActionUpdate = "update";
const std::string ActionDelete = "delete";

// 内容类型
const std::string TypeTargetsTarget = "target";
const std::string TypeTargetsDelegation = "delegation";

// Change类接口
class Change {
public:
    virtual ~Change() = default;
    virtual std::string Action() const = 0;
    virtual std::string Scope() const = 0;
    virtual std::string Type() const = 0;
    virtual std::string Path() const = 0;
    virtual std::vector<uint8_t> Content() const = 0;
};

// TUF Change实现类
class TUFChange : public Change {
public:
    TUFChange(const std::string& action, const std::string& role, 
              const std::string& changeType, const std::string& changePath,
              const std::vector<uint8_t>& content)
        : action_(action), role_(role), changeType_(changeType), 
          changePath_(changePath), content_(content) {}

    std::string Action() const override { return action_; }
    std::string Scope() const override { return role_; }
    std::string Type() const override { return changeType_; }
    std::string Path() const override { return changePath_; }
    std::vector<uint8_t> Content() const override { return content_; }

private:
    std::string action_;
    std::string role_;
    std::string changeType_;
    std::string changePath_;
    std::vector<uint8_t> content_;
};

// Changelist接口
class Changelist {
public:
    virtual ~Changelist() = default;
    virtual std::vector<std::shared_ptr<Change>> List() const = 0;
    virtual Error Add(const std::shared_ptr<Change>& change) = 0;
    virtual Error Clear(const std::string& archive = "") = 0;
    virtual Error Close() = 0;
    virtual std::string Location() const = 0;
};

// FileChangelist实现类
class FileChangelist : public Changelist {
public:
    FileChangelist(const std::string& dir);
    std::vector<std::shared_ptr<Change>> List() const override;
    Error Add(const std::shared_ptr<Change>& change) override;
    Error Clear(const std::string& archive = "") override;
    Error Close() override;
    std::string Location() const override { return dir_; }

private:
    std::string dir_;
};

} // namespace changelist

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
    
    // 添加目标文件
    Error AddTarget(const Target& target, const std::vector<std::string>& roles = {});
    
    // 创建目标对象
    static Result<Target> NewTarget(const std::string& targetName, 
                                   const std::string& targetPath,
                                   const std::vector<uint8_t>& customData = {});
                                   
    // 获取changelist
    changelist::Changelist& GetChangelist() { return *changelist_; }
    
    // 发布更改
    Error Publish();
    
    // 获取TUF Repo对象
    std::shared_ptr<tuf::Repo> GetTUFRepo() { return tufRepo_; }

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
                                              
    // 应用changelist
    Error applyChangelist();

    // 更新TUF元数据
    Error updateTUF(bool force = false);
    
    // 引导仓库
    Error bootstrapRepo();
    
    // 检查元数据是否需要重新签名
    bool needsResigning(const std::vector<uint8_t>& metadata);
    
    // 重新签名元数据
    Result<std::vector<uint8_t>> resignMetadata(const std::vector<uint8_t>& metadata, 
                                              const std::string& role);
    
    // 初始化Snapshot
    Error initializeSnapshot();

private:
    GUN gun_;
    std::string trustDir_;
    std::string serverURL_;
    std::shared_ptr<storage::MetadataStore> cache_;
    std::shared_ptr<storage::RemoteStore> remoteStore_;
    std::shared_ptr<changelist::Changelist> changelist_;
    crypto::CryptoService cryptoService_;
    std::shared_ptr<tuf::Repo> tufRepo_; // 元数据的内存表示
    std::shared_ptr<tuf::Repo> invalidRepo_; // 无效的元数据
};

} // namespace notary 