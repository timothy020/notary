#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <chrono>
#include <functional>
#include <nlohmann/json.hpp>
#include "../types.hpp"
#include "../crypto/crypto_service.hpp"

namespace notary {
namespace tuf {

// 前向声明
class SignedRoot;
class SignedTargets;
class SignedSnapshot;
class SignedTimestamp;

// 为方便使用
using json = nlohmann::json;

// TUF元数据类型
enum class MetadataType {
    Root,
    Targets,
    Snapshot,
    Timestamp,
    Delegation
};

// 签名结构
struct Signature {
    std::string KeyID;
    std::string Method;
    std::vector<uint8_t> Sig;
    bool IsValid = false; // 运行时标记，不序列化
    
    // JSON 序列化支持
    json toJson() const;
    void fromJson(const json& j);
};

// 通用签名元数据字段
struct SignedCommon {
    std::string Type;
    std::chrono::time_point<std::chrono::system_clock> Expires;
    int Version = 1;
    
    // JSON 序列化支持
    json toJson() const;
    void fromJson(const json& j);
};

// 文件元数据
struct FileMeta {
    int64_t Length;
    std::map<std::string, std::vector<uint8_t>> Hashes;
    json Custom; // 可选的自定义数据
    
    // JSON 序列化支持
    json toJson() const;
    void fromJson(const json& j);
    
    // 比较方法
    bool equals(const FileMeta& other) const;
};

// 委托角色
class DelegationRole {
public:
    BaseRole BaseRoleInfo;
    std::vector<std::string> Paths;
    RoleName Name;
    
    bool CheckPaths(const std::string& path) const;
    
    // JSON 序列化支持
    json toJson() const;
    void fromJson(const json& j);
};

// 委托信息
struct Delegations {
    std::map<std::string, std::shared_ptr<PublicKey>> Keys;
    std::vector<DelegationRole> Roles;
    
    // JSON 序列化支持
    json toJson() const;
    void fromJson(const json& j);
};

// 签名数据
class Signed {
public:
    virtual ~Signed() = default;
    virtual std::vector<uint8_t> Serialize() const = 0;
    virtual bool Deserialize(const std::vector<uint8_t>& data) = 0;
    virtual json toJson() const = 0;
    virtual void fromJson(const json& j) = 0;
    
    bool Dirty = false;
    std::vector<Signature> Signatures;
};

// 签名的Root元数据
class SignedRoot : public Signed {
public:
    // Root特有的属性和方法
    std::map<std::string, std::shared_ptr<PublicKey>> Keys;
    std::map<RoleName, BaseRole> Roles;
    SignedCommon Common;
    
    virtual std::vector<uint8_t> Serialize() const override;
    virtual bool Deserialize(const std::vector<uint8_t>& data) override;
    virtual json toJson() const override;
    virtual void fromJson(const json& j) override;
    
    // 构建完整的带签名的JSON
    json toSignedJson() const;
};

// 签名的Targets元数据
class SignedTargets : public Signed {
public:
    // Targets特有的属性和方法
    std::map<std::string, FileMeta> Targets;  // Files类型：map[string]FileMeta
    Delegations Delegations;  // 委托信息
    SignedCommon Common;
    
    virtual std::vector<uint8_t> Serialize() const override;
    virtual bool Deserialize(const std::vector<uint8_t>& data) override;
    virtual json toJson() const override;
    virtual void fromJson(const json& j) override;
    
    // 构建完整的带签名的JSON
    json toSignedJson() const;
    
    // Targets特有方法
    FileMeta* GetMeta(const std::string& path);
    void AddTarget(const std::string& path, const FileMeta& meta);
    std::vector<DelegationRole> GetValidDelegations(const DelegationRole& parent) const;
    Result<DelegationRole> BuildDelegationRole(RoleName roleName) const;
};

// 签名的Snapshot元数据
class SignedSnapshot : public Signed {
public:
    // Snapshot特有的属性和方法
    std::map<std::string, FileMeta> Meta;  // Files类型：map[string]FileMeta
    SignedCommon Common;
    
    virtual std::vector<uint8_t> Serialize() const override;
    virtual bool Deserialize(const std::vector<uint8_t>& data) override;
    virtual json toJson() const override;
    virtual void fromJson(const json& j) override;
    
    // 构建完整的带签名的JSON
    json toSignedJson() const;
    
    // Snapshot特有方法
    void AddMeta(RoleName role, const FileMeta& meta);
    Result<FileMeta> GetMeta(RoleName role) const;
    void DeleteMeta(RoleName role);
};

// 签名的Timestamp元数据
class SignedTimestamp : public Signed {
public:
    // Timestamp特有的属性和方法
    std::map<std::string, FileMeta> Meta;  // Files类型：map[string]FileMeta
    SignedCommon Common;
    
    virtual std::vector<uint8_t> Serialize() const override;
    virtual bool Deserialize(const std::vector<uint8_t>& data) override;
    virtual json toJson() const override;
    virtual void fromJson(const json& j) override;
    
    // 构建完整的带签名的JSON
    json toSignedJson() const;
    
    // Timestamp特有方法
    Result<FileMeta> GetSnapshot() const;
};

// 访问者函数类型
using WalkVisitorFunc = std::function<bool(std::shared_ptr<SignedTargets>, const DelegationRole&)>;

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
    Result<std::shared_ptr<SignedRoot>> InitRoot(const BaseRole& root, const BaseRole& targets, 
                  const BaseRole& snapshot, const BaseRole& timestamp);
    
    Result<std::shared_ptr<SignedTargets>> InitTargets(RoleName role = RoleName::TargetsRole);
    Result<std::shared_ptr<SignedSnapshot>> InitSnapshot();
    Result<std::shared_ptr<SignedTimestamp>> InitTimestamp();
    
    // 签名方法
    Result<std::shared_ptr<Signed>> SignRoot(const std::chrono::time_point<std::chrono::system_clock>& expires);
    Result<std::shared_ptr<Signed>> SignTargets(RoleName role, const std::chrono::time_point<std::chrono::system_clock>& expires);
    Result<std::shared_ptr<Signed>> SignSnapshot(const std::chrono::time_point<std::chrono::system_clock>& expires);
    Result<std::shared_ptr<Signed>> SignTimestamp(const std::chrono::time_point<std::chrono::system_clock>& expires);
    
    // 目标管理
    Error AddTarget(const std::string& targetName, const std::vector<uint8_t>& targetData, 
                   RoleName role = RoleName::TargetsRole);
    Error RemoveTarget(const std::string& targetName, RoleName role = RoleName::TargetsRole);
    
    // 批量目标管理
    Error AddTargets(RoleName role, const std::map<std::string, FileMeta>& targets);
    Error RemoveTargets(RoleName role, const std::vector<std::string>& targets);
    
    // 密钥管理
    Error AddBaseKeys(RoleName role, const std::vector<std::shared_ptr<PublicKey>>& keys);
    Error ReplaceBaseKeys(RoleName role, const std::vector<std::shared_ptr<PublicKey>>& keys);
    Error RemoveBaseKeys(RoleName role, const std::vector<std::string>& keyIDs);
    
    // 角色管理
    Result<BaseRole> GetBaseRole(RoleName name) const;
    Result<DelegationRole> GetDelegationRole(RoleName name) const;
    std::vector<BaseRole> GetAllLoadedRoles() const;
    
    // 委托管理
    Error UpdateDelegationKeys(RoleName roleName, const std::vector<std::shared_ptr<PublicKey>>& addKeys, 
                              const std::vector<std::string>& removeKeys, int newThreshold);
    Error PurgeDelegationKeys(RoleName role, const std::vector<std::string>& removeKeys);
    Error UpdateDelegationPaths(RoleName roleName, const std::vector<std::string>& addPaths, 
                               const std::vector<std::string>& removePaths, bool clearPaths);
    Error DeleteDelegation(RoleName roleName);
    
    // 验证和查询
    Error VerifyCanSign(RoleName roleName) const;
    FileMeta* TargetMeta(RoleName role, const std::string& path);
    std::vector<DelegationRole> TargetDelegations(RoleName role, const std::string& path) const;
    
    // 遍历
    Error WalkTargets(const std::string& targetPath, RoleName rolePath, 
                     WalkVisitorFunc visitTargets, const std::vector<RoleName>& skipRoles = {});
    
    // 元数据更新
    Error UpdateSnapshot(RoleName role, const std::shared_ptr<Signed>& s);
    Error UpdateTimestamp(const std::shared_ptr<Signed>& s);

private:
    std::shared_ptr<SignedRoot> root_;
    std::map<RoleName, std::shared_ptr<SignedTargets>> targets_;
    std::shared_ptr<SignedSnapshot> snapshot_;
    std::shared_ptr<SignedTimestamp> timestamp_;
    crypto::CryptoService& cryptoService_;
    
    // 原始root角色（用于密钥轮换）
    BaseRole originalRootRole_;
    
    // 角色标记为需要重新签名
    void markRoleDirty(RoleName role);
    
    // 内部签名方法
    Result<std::shared_ptr<Signed>> sign(std::shared_ptr<Signed> signedData, 
                                        const std::vector<BaseRole>& roles, 
                                        const std::vector<std::shared_ptr<PublicKey>>& optionalKeys = {});
    
    // 辅助方法
    bool isValidPath(const std::string& candidatePath, const DelegationRole& delgRole) const;
    bool isAncestorRole(RoleName candidateChild, RoleName candidateAncestor) const;
};

// 辅助函数：角色名称转换
std::string roleNameToString(RoleName role);
RoleName stringToRoleName(const std::string& roleStr);

// 辅助函数：角色验证
bool IsDelegation(RoleName role);
bool IsValidTargetsRole(RoleName role);

// 辅助函数：创建新的TUF对象
std::shared_ptr<SignedRoot> NewRoot(const std::map<std::string, std::shared_ptr<PublicKey>>& keys,
                                   const std::map<RoleName, BaseRole>& roles, 
                                   bool consistent = false);

std::shared_ptr<SignedTargets> NewTargets();

Result<std::shared_ptr<SignedSnapshot>> NewSnapshot(const std::shared_ptr<Signed>& root,
                                                    const std::shared_ptr<Signed>& targets);

Result<std::shared_ptr<SignedTimestamp>> NewTimestamp(const std::shared_ptr<Signed>& snapshot);

// 辅助函数：时间格式转换
std::string timeToISO8601(const std::chrono::time_point<std::chrono::system_clock>& time);
std::chrono::time_point<std::chrono::system_clock> iso8601ToTime(const std::string& timeStr);

// 辅助函数：创建FileMeta对象
Result<FileMeta> NewFileMeta(const std::vector<uint8_t>& data, 
                            const std::vector<std::string>& hashAlgorithms = {"sha256"});

} // namespace tuf
} // namespace notary 