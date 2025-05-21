#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <chrono>
#include "../types.hpp"
#include "../crypto/crypto_service.hpp"

namespace notary {
namespace tuf {

// 前向声明
class SignedRoot;
class SignedTargets;
class SignedSnapshot;
class SignedTimestamp;

// TUF元数据类型
enum class MetadataType {
    Root,
    Targets,
    Snapshot,
    Timestamp,
    Delegation
};

// 签名数据
class Signed {
public:
    virtual ~Signed() = default;
    virtual std::vector<uint8_t> Serialize() const = 0;
    virtual bool Deserialize(const std::vector<uint8_t>& data) = 0;
    bool Dirty = false;
};

// 签名的Root元数据
class SignedRoot : public Signed {
public:
    // Root特有的属性和方法
    std::map<std::string, std::shared_ptr<PublicKey>> Keys;
    std::map<RoleName, BaseRole> Roles;
    
    virtual std::vector<uint8_t> Serialize() const override;
    virtual bool Deserialize(const std::vector<uint8_t>& data) override;
};

// 签名的Targets元数据
class SignedTargets : public Signed {
public:
    // Targets特有的属性和方法
    std::map<std::string, std::vector<uint8_t>> Targets;
    
    virtual std::vector<uint8_t> Serialize() const override;
    virtual bool Deserialize(const std::vector<uint8_t>& data) override;
};

// 签名的Snapshot元数据
class SignedSnapshot : public Signed {
public:
    // Snapshot特有的属性和方法
    std::map<std::string, std::vector<uint8_t>> Meta;
    
    virtual std::vector<uint8_t> Serialize() const override;
    virtual bool Deserialize(const std::vector<uint8_t>& data) override;
};

// 签名的Timestamp元数据
class SignedTimestamp : public Signed {
public:
    // Timestamp特有的属性和方法
    std::map<std::string, std::vector<uint8_t>> Meta;
    
    virtual std::vector<uint8_t> Serialize() const override;
    virtual bool Deserialize(const std::vector<uint8_t>& data) override;
};

// TUF Repo类 - 元数据的内存表示
class Repo {
public:
    // 构造函数
    Repo(crypto::CryptoService& cryptoService);
    
    // 获取/设置元数据
    std::shared_ptr<SignedRoot> GetRoot() const { return root_; }
    void SetRoot(std::shared_ptr<SignedRoot> root) { root_ = root; }
    
    std::shared_ptr<SignedTargets> GetTargets(RoleName role = RoleName::TargetsRole) const;
    void SetTargets(std::shared_ptr<SignedTargets> targets, RoleName role = RoleName::TargetsRole);
    
    std::shared_ptr<SignedSnapshot> GetSnapshot() const { return snapshot_; }
    void SetSnapshot(std::shared_ptr<SignedSnapshot> snapshot) { snapshot_ = snapshot; }
    
    std::shared_ptr<SignedTimestamp> GetTimestamp() const { return timestamp_; }
    void SetTimestamp(std::shared_ptr<SignedTimestamp> timestamp) { timestamp_ = timestamp; }
    
    // 初始化方法
    Error InitRoot(const BaseRole& root, const BaseRole& targets, 
                  const BaseRole& snapshot, const BaseRole& timestamp);
    
    Error InitTargets(RoleName role = RoleName::TargetsRole);
    Error InitSnapshot();
    Error InitTimestamp();
    
    // 签名方法
    Result<std::shared_ptr<Signed>> SignRoot(const std::chrono::time_point<std::chrono::system_clock>& expires);
    Result<std::shared_ptr<Signed>> SignTargets(RoleName role, const std::chrono::time_point<std::chrono::system_clock>& expires);
    Result<std::shared_ptr<Signed>> SignSnapshot(const std::chrono::time_point<std::chrono::system_clock>& expires);
    Result<std::shared_ptr<Signed>> SignTimestamp(const std::chrono::time_point<std::chrono::system_clock>& expires);
    
    // 目标管理
    Error AddTarget(const std::string& targetName, const std::vector<uint8_t>& targetData, 
                   RoleName role = RoleName::TargetsRole);
    Error RemoveTarget(const std::string& targetName, RoleName role = RoleName::TargetsRole);
    
    // 密钥管理
    Error AddBaseKeys(RoleName role, const std::vector<std::shared_ptr<PublicKey>>& keys);
    Error RemoveBaseKeys(RoleName role, const std::vector<std::string>& keyIDs);
    
private:
    std::shared_ptr<SignedRoot> root_;
    std::map<RoleName, std::shared_ptr<SignedTargets>> targets_;
    std::shared_ptr<SignedSnapshot> snapshot_;
    std::shared_ptr<SignedTimestamp> timestamp_;
    crypto::CryptoService& cryptoService_;
    
    // 角色标记为需要重新签名
    void markRoleDirty(RoleName role);
};

} // namespace tuf
} // namespace notary 