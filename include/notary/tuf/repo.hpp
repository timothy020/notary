#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <chrono>
#include <functional>
#include <nlohmann/json.hpp>
#include "notary/types.hpp"
#include <variant>
#include "notary/utils/tools.hpp"

// 前向声明避免循环依赖
namespace notary {
namespace crypto {
    class CryptoService;
}
}

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

// StopWalk - 用于访问者函数信号WalkTargets停止遍历
struct StopWalk {};

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
    int64_t Length = 0; // 默认为0，与Go版本保持一致
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
    // 默认构造函数
    DelegationRole() = default;
    
    // 拷贝构造函数
    DelegationRole(const DelegationRole& other) = default;
    
    // 赋值操作符
    DelegationRole& operator=(const DelegationRole& other) = default;
    
    // 移动构造函数
    DelegationRole(DelegationRole&& other) = default;
    
    // 移动赋值操作符
    DelegationRole& operator=(DelegationRole&& other) = default;
    
    BaseRole BaseRoleInfo;
    std::vector<std::string> Paths;
    std::string Name;
    
    bool CheckPaths(const std::string& path) const;
    
    // 限制子角色的路径，返回限制后的角色副本
    Result<DelegationRole> Restrict(const DelegationRole& child) const;
    
    // 检查是否是指定角色的直接父角色
    bool IsParentOf(const DelegationRole& child) const;
    
    // JSON 序列化支持
    json toJson() const;
    void fromJson(const json& j);
};

// 委托信息
struct Delegations {
    std::map<std::string, std::shared_ptr<crypto::PublicKey>> Keys;
    std::vector<DelegationRole> Roles;
    
    // JSON 序列化支持
    json toJson() const;
    void fromJson(const json& j);
};

struct Signed {
    std::vector<uint8_t> signedData;  // 存储规范化的JSON数据 (类似Go的json.RawMessage)
    std::vector<Signature> Signatures;
    
    // JSON 序列化支持
    std::vector<uint8_t> Serialize() const;
    bool Deserialize(const std::vector<uint8_t>& data);
    json toJson() const;
    void fromJson(const json& j);
};

// Root元数据内容（对应Go的Root结构体）
struct Root {
    SignedCommon Common;
    std::map<std::string, std::shared_ptr<crypto::PublicKey>> Keys;
    std::map<std::string, BaseRole> Roles;
    bool ConsistentSnapshot = false;
    
    // JSON 序列化支持
    json toJson() const;
    void fromJson(const json& j);
};

// Targets元数据内容（对应Go的Targets结构体）
struct Targets {
    SignedCommon Common;
    std::map<std::string, FileMeta> targets;  // Files类型：map[string]FileMeta
    Delegations delegations;  // 委托信息
    
    // JSON 序列化支持
    json toJson() const;
    void fromJson(const json& j);
};

// Snapshot元数据内容（对应Go的Snapshot结构体）
struct Snapshot {
    SignedCommon Common;
    std::map<std::string, FileMeta> Meta;  // Files类型：map[string]FileMeta
    
    // JSON 序列化支持
    json toJson() const;
    void fromJson(const json& j);
};

// Timestamp元数据内容（对应Go的Timestamp结构体）
struct Timestamp {
    SignedCommon Common;
    std::map<std::string, FileMeta> Meta;  // Files类型：map[string]FileMeta
    
    // JSON 序列化支持
    json toJson() const;
    void fromJson(const json& j);
};

// 签名的Root元数据（对应Go的SignedRoot结构体）
class SignedRoot{
public:
    Root Signed;  // 对应Go的Signed Root字段
    bool Dirty = false;
    std::vector<Signature> Signatures;
    
    virtual std::vector<uint8_t> Serialize() const;
    virtual bool Deserialize(const std::vector<uint8_t>& data);
    virtual json toJson() const;
    virtual void fromJson(const json& j);
    
    // 对应Go的ToSigned方法 - 用于签名流程
    Result<std::shared_ptr<notary::tuf::Signed>> ToSigned() const;
    
    // Root特有方法
    Result<BaseRole> BuildBaseRole(const std::string& roleName) const;
};

// 签名的Targets元数据（对应Go的SignedTargets结构体）
class SignedTargets{
public:
    Targets Signed;  // 对应Go的Signed Targets字段
    bool Dirty = false;
    std::vector<Signature> Signatures;
    
    virtual std::vector<uint8_t> Serialize() const;
    virtual bool Deserialize(const std::vector<uint8_t>& data);
    virtual json toJson() const;
    virtual void fromJson(const json& j);
    
    // 构建完整的带签名的JSON
    json toSignedJson() const;
    
    // 对应Go的ToSigned方法 - 用于签名流程
    Result<std::shared_ptr<notary::tuf::Signed>> ToSigned() const;
    
    // Targets特有方法
    FileMeta* GetMeta(const std::string& path);
    void AddTarget(const std::string& path, const FileMeta& meta);
    std::vector<DelegationRole> GetValidDelegations(const DelegationRole& parent) const;
    Result<DelegationRole> BuildDelegationRole(const std::string& roleName) const;
    
private:
    // 辅助方法：构建所有委托角色
    std::vector<DelegationRole> buildDelegationRoles() const;
};

// 签名的Snapshot元数据（对应Go的SignedSnapshot结构体）
class SignedSnapshot{
public:
    Snapshot Signed;  // 对应Go的Signed Snapshot字段
    bool Dirty = false;
    std::vector<Signature> Signatures;
    
    virtual std::vector<uint8_t> Serialize() const;
    virtual bool Deserialize(const std::vector<uint8_t>& data);
    virtual json toJson() const;
    virtual void fromJson(const json& j);
    
    // 构建完整的带签名的JSON
    json toSignedJson() const;
    
    // 对应Go的ToSigned方法 - 用于签名流程
    Result<std::shared_ptr<notary::tuf::Signed>> ToSigned() const;
    
    // Snapshot特有方法
    void AddMeta(const std::string& role, const FileMeta& meta);
    Result<FileMeta> GetMeta(const std::string& role) const;
    void DeleteMeta(const std::string& role);
};

// 签名的Timestamp元数据（对应Go的SignedTimestamp结构体）
class SignedTimestamp{
public:
    Timestamp Signed;  // 对应Go的Signed Timestamp字段
    bool Dirty = false;
    std::vector<Signature> Signatures;
    
    virtual std::vector<uint8_t> Serialize() const;
    virtual bool Deserialize(const std::vector<uint8_t>& data);
    virtual json toJson() const;
    virtual void fromJson(const json& j);
    
    // 构建完整的带签名的JSON
    json toSignedJson() const;
    
    // 对应Go的ToSigned方法 - 用于签名流程
    Result<std::shared_ptr<notary::tuf::Signed>> ToSigned() const;
    
    // Timestamp特有方法
    Result<FileMeta> GetSnapshot() const;
};

// 访问者函数返回类型
using WalkResult = std::variant<std::monostate, StopWalk, Error>;

// 访问者函数类型
using WalkVisitorFunc = std::function<WalkResult(std::shared_ptr<SignedTargets>, const DelegationRole&)>;

// 验证方法
bool isValidSnapshot(const Snapshot& snapshot);
bool isValidTimestamp(const Timestamp& timestamp);

// TUF Repo类 - 元数据的内存表示
class Repo {
public:
    // 构造函数
    Repo(std::shared_ptr<crypto::CryptoService> cryptoService);
    
    // 获取/设置元数据
    std::shared_ptr<SignedRoot> GetRoot() const { return root_; }
    void SetRoot(std::shared_ptr<SignedRoot> root) { root_ = root; }
    
    std::shared_ptr<SignedTargets> GetTargets(const std::string& role) const;
    void SetTargets(std::shared_ptr<SignedTargets> targets, const std::string& role = TARGETS_ROLE);
    std::map<std::string, std::shared_ptr<SignedTargets>>& GetTargets() { return targets_; }
    void SetTargets(std::map<std::string, std::shared_ptr<SignedTargets>> targets) { targets_ = targets; }
    
    std::shared_ptr<SignedSnapshot> GetSnapshot() const { return snapshot_; }
    void SetSnapshot(std::shared_ptr<SignedSnapshot> snapshot) { snapshot_ = snapshot; }
    
    std::shared_ptr<SignedTimestamp> GetTimestamp() const { return timestamp_; }
    void SetTimestamp(std::shared_ptr<SignedTimestamp> timestamp) { timestamp_ = timestamp; }
    
    // 获取CryptoService
    std::shared_ptr<crypto::CryptoService> GetCryptoService() const { return cryptoService_; }
    void SetOriginalRootRole(const BaseRole& originalRootRole) { originalRootRole_ = originalRootRole; }

    // 初始化方法
    Result<std::shared_ptr<SignedRoot>> InitRoot(const BaseRole& root, const BaseRole& targets, 
                  const BaseRole& snapshot, const BaseRole& timestamp);
    
    Result<std::shared_ptr<SignedTargets>> InitTargets(const std::string& role = TARGETS_ROLE);
    Result<std::shared_ptr<SignedSnapshot>> InitSnapshot();
    Result<std::shared_ptr<SignedTimestamp>> InitTimestamp();
    
    // 签名方法
    Result<std::shared_ptr<Signed>> SignRoot(const std::chrono::time_point<std::chrono::system_clock>& expires);
    Result<std::shared_ptr<Signed>> SignTargets(const std::string& role, const std::chrono::time_point<std::chrono::system_clock>& expires);
    Result<std::shared_ptr<Signed>> SignSnapshot(const std::chrono::time_point<std::chrono::system_clock>& expires);
    Result<std::shared_ptr<Signed>> SignTimestamp(const std::chrono::time_point<std::chrono::system_clock>& expires);
    
    // 批量目标管理
    Error AddTargets(const std::string& role, const std::map<std::string, FileMeta>& targets);
    Error RemoveTargets(const std::string& role, const std::vector<std::string>& targets);
    
    // 密钥管理
    Error AddBaseKeys(const std::string& role, const std::vector<std::shared_ptr<crypto::PublicKey>>& keys);
    Error ReplaceBaseKeys(const std::string& role, const std::vector<std::shared_ptr<crypto::PublicKey>>& keys);
    Error RemoveBaseKeys(const std::string& role, const std::vector<std::string>& keyIDs);
    
    // 角色管理
    Result<BaseRole> GetBaseRole(const std::string& name) const;
    Result<DelegationRole> GetDelegationRole(const std::string& name) const;
    std::vector<BaseRole> GetAllLoadedRoles() const;
    
    // 委托管理
    Error UpdateDelegationKeys(const std::string& roleName, const std::vector<std::shared_ptr<crypto::PublicKey>>& addKeys, 
                              const std::vector<std::string>& removeKeys, int newThreshold);
    Error PurgeDelegationKeys(const std::string& role, const std::vector<std::string>& removeKeys);
    Error UpdateDelegationPaths(const std::string& roleName, const std::vector<std::string>& addPaths, 
                               const std::vector<std::string>& removePaths, bool clearPaths);
    Error DeleteDelegation(const std::string& roleName);
    
    // 验证和查询
    Error VerifyCanSign(const std::string& roleName) const;
    FileMeta* TargetMeta(const std::string& role, const std::string& path);
    std::vector<DelegationRole> TargetDelegations(const std::string& role, const std::string& path) const;
    
    // 遍历
    Error WalkTargets(const std::string& targetPath, const std::string& rolePath, 
                     WalkVisitorFunc visitTargets, const std::vector<std::string>& skipRoles = {});
    
    // 元数据更新
    Error UpdateSnapshot(const std::string& role, const std::shared_ptr<Signed>& s);
    Error UpdateTimestamp(const std::shared_ptr<Signed>& s);

private:
    std::shared_ptr<SignedRoot> root_;
    std::map<std::string, std::shared_ptr<SignedTargets>> targets_;
    std::shared_ptr<SignedSnapshot> snapshot_;
    std::shared_ptr<SignedTimestamp> timestamp_;
    std::shared_ptr<crypto::CryptoService> cryptoService_;
    
    // 原始root角色（用于密钥轮换）
    BaseRole originalRootRole_;
    
    // 角色标记为需要重新签名
    void markRoleDirty(const std::string& role);
    
    // 内部签名方法
    Result<std::shared_ptr<Signed>> sign(std::shared_ptr<Signed> signedData, 
                                        const std::vector<BaseRole>& roles, 
                                        const std::vector<std::shared_ptr<crypto::PublicKey>>& optionalKeys = {});
    
    // 委托更新辅助方法
    WalkVisitorFunc createDelegationUpdateVisitor(
        const std::string& roleName,
        const std::vector<std::shared_ptr<crypto::PublicKey>>& addKeys,
        const std::vector<std::string>& removeKeys,
        const std::vector<std::string>& addPaths,
        const std::vector<std::string>& removePaths,
        bool clearAllPaths,
        int newThreshold);
    
    void removeUnusedKeys(std::shared_ptr<SignedTargets> tgt);
    
    // 辅助方法
    bool isValidPath(const std::string& candidatePath, const DelegationRole& delgRole) const;
    bool isAncestorRole(const std::string& candidateChild, const std::string& candidateAncestor) const;
};

// 辅助函数：角色验证
bool IsDelegation(const std::string& role);
bool IsWildDelegation(const std::string& role);
bool IsValidTargetsRole(const std::string& role);

// 辅助函数：创建新的TUF对象
std::shared_ptr<SignedRoot> NewRoot(const std::map<std::string, std::shared_ptr<crypto::PublicKey>>& keys,
                                   const std::map<std::string, BaseRole>& roles, 
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
                            const std::vector<std::string>& hashAlgorithms = {"sha256","sha512"});

// 辅助函数：检查哈希结构的有效性
Error CheckValidHashStructures(const std::map<std::string, std::vector<uint8_t>>& hashes);

// RootFromSigned fully unpacks a Signed object into a SignedRoot and ensures
// that it is a valid SignedRoot - 对应Go版本的data.RootFromSigned函数
Result<std::shared_ptr<SignedRoot>> RootFromSigned(std::shared_ptr<Signed> s);

} // namespace tuf
} // namespace notary 