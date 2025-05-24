#include "notary/tuf/repo.hpp"
#include <stdexcept>
#include <algorithm>
#include <set>
#include <sstream>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

namespace notary {
namespace tuf {

// 辅助函数实现
std::string roleNameToString(RoleName role) {
    switch (role) {
        case RoleName::RootRole: return "root";
        case RoleName::TargetsRole: return "targets";
        case RoleName::SnapshotRole: return "snapshot";
        case RoleName::TimestampRole: return "timestamp";
        default: return "unknown";
    }
}

RoleName stringToRoleName(const std::string& roleStr) {
    if (roleStr == "root") return RoleName::RootRole;
    if (roleStr == "targets") return RoleName::TargetsRole;
    if (roleStr == "snapshot") return RoleName::SnapshotRole;
    if (roleStr == "timestamp") return RoleName::TimestampRole;
    return RoleName::RootRole; // 默认值
}

std::string timeToISO8601(const std::chrono::time_point<std::chrono::system_clock>& time) {
    auto time_t = std::chrono::system_clock::to_time_t(time);
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

std::chrono::time_point<std::chrono::system_clock> iso8601ToTime(const std::string& timeStr) {
    std::tm tm = {};
    std::istringstream ss(timeStr);
    ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return std::chrono::system_clock::from_time_t(std::mktime(&tm));
}

// 实现base64编码函数
std::string base64Encode(const std::vector<uint8_t>& data) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new(BIO_s_mem());
    BIO_push(b64, mem);
    BIO_write(b64, data.data(), data.size());
    BIO_flush(b64);
    
    BUF_MEM* bptr;
    BIO_get_mem_ptr(b64, &bptr);
    std::string result(bptr->data, bptr->length);
    
    // 移除可能存在的换行符
    result.erase(std::remove(result.begin(), result.end(), '\n'), result.end());
    
    BIO_free_all(b64);
    return result;
}


// Base64解码函数
std::vector<uint8_t> base64Decode(const std::string& data) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new_mem_buf(data.data(), data.size());
    BIO_push(b64, mem);
    
    std::vector<uint8_t> result(data.size());
    int decodedSize = BIO_read(b64, result.data(), data.size());
    if (decodedSize > 0) {
        result.resize(decodedSize);
    } else {
        result.clear();
    }
    
    BIO_free_all(b64);
    return result;
}

// Signature 实现
json Signature::toJson() const {
    json j;
    j["keyid"] = KeyID;
    j["method"] = Method;
    j["sig"] = base64Encode(Sig);
    return j;
}

void Signature::fromJson(const json& j) {
    KeyID = j.at("keyid").get<std::string>();
    Method = j.at("method").get<std::string>();
    Sig = base64Decode(j.at("sig").get<std::string>());
}

// SignedCommon 实现
json SignedCommon::toJson() const {
    json j;
    j["_type"] = Type;
    j["version"] = Version;
    j["expires"] = timeToISO8601(Expires);
    return j;
}

void SignedCommon::fromJson(const json& j) {
    Type = j.at("_type").get<std::string>();
    Version = j.at("version").get<int>();
    Expires = iso8601ToTime(j.at("expires").get<std::string>());
}

// FileMeta 实现
json FileMeta::toJson() const {
    json j;
    j["length"] = Length;
    
    json hashes;
    for (const auto& [algo, hash] : Hashes) {
        hashes[algo] = base64Encode(hash);
    }
    j["hashes"] = hashes;
    
    if (!Custom.is_null()) {
        j["custom"] = Custom;
    }
    
    return j;
}

void FileMeta::fromJson(const json& j) {
    Length = j.at("length").get<int64_t>();
    
    if (j.contains("hashes")) {
        for (const auto& [algo, hashStr] : j.at("hashes").items()) {
            Hashes[algo] = base64Decode(hashStr.get<std::string>());
        }
    }
    
    if (j.contains("custom")) {
        Custom = j.at("custom");
    }
}

bool FileMeta::equals(const FileMeta& other) const {
    return Length == other.Length && Hashes == other.Hashes;
}

// DelegationRole 实现
json DelegationRole::toJson() const {
    json j;
    j["name"] = roleNameToString(Name);
    j["threshold"] = BaseRoleInfo.Threshold();
    
    json keyids = json::array();
    for (const auto& key : BaseRoleInfo.Keys()) {
        keyids.push_back(key->ID());
    }
    j["keyids"] = keyids;
    
    if (!Paths.empty()) {
        j["paths"] = Paths;
    }
    
    return j;
}

void DelegationRole::fromJson(const json& j) {
    Name = stringToRoleName(j.at("name").get<std::string>());
    // 注意：这里需要从外部设置BaseRoleInfo，因为需要密钥信息
    if (j.contains("paths")) {
        Paths = j.at("paths").get<std::vector<std::string>>();
    }
}

// Delegations 实现
json Delegations::toJson() const {
    json j;
    
    json keys;
    for (const auto& [keyId, key] : Keys) {
        json keyJson;
        keyJson["keytype"] = "ecdsa"; // 简化处理
        keyJson["keyval"] = json::object();
        keyJson["keyval"]["public"] = base64Encode(key->Bytes());
        keys[keyId] = keyJson;
    }
    j["keys"] = keys;
    
    json roles = json::array();
    for (const auto& role : Roles) {
        roles.push_back(role.toJson());
    }
    j["roles"] = roles;
    
    return j;
}

void Delegations::fromJson(const json& j) {
    // 注意：密钥反序列化需要特殊处理，这里简化
    if (j.contains("roles")) {
        for (const auto& roleJson : j.at("roles")) {
            DelegationRole role;
            role.fromJson(roleJson);
            Roles.push_back(role);
        }
    }
}

// SignedRoot 实现
json SignedRoot::toJson() const {
    json j = Common.toJson();
    
    // 添加keys
    json keys;
    for (const auto& [keyId, key] : Keys) {
        json keyJson;
        keyJson["keytype"] = "ecdsa"; // 简化处理
        keyJson["keyval"] = json::object();
        keyJson["keyval"]["public"] = base64Encode(key->Bytes());
        keys[keyId] = keyJson;
    }
    j["keys"] = keys;
    
    // 添加roles
    json roles;
    for (const auto& [roleName, role] : Roles) {
        json roleJson;
        roleJson["threshold"] = role.Threshold();
        
        json keyids = json::array();
        for (const auto& key : role.Keys()) {
            keyids.push_back(key->ID());
        }
        roleJson["keyids"] = keyids;
        
        roles[roleNameToString(roleName)] = roleJson;
    }
    j["roles"] = roles;
    
    return j;
}

void SignedRoot::fromJson(const json& j) {
    Common.fromJson(j);
    
    // 解析keys（简化处理）
    if (j.contains("keys")) {
        // 需要从外部提供密钥解析逻辑
    }
    
    // 解析roles（简化处理）
    if (j.contains("roles")) {
        // 需要从外部提供角色解析逻辑
    }
}

json SignedRoot::toSignedJson() const {
    json j;
    j["signed"] = toJson();
    
    json signatures = json::array();
    for (const auto& sig : Signatures) {
        signatures.push_back(sig.toJson());
    }
    j["signatures"] = signatures;
    
    return j;
}

std::vector<uint8_t> SignedRoot::Serialize() const {
    std::string jsonStr = toSignedJson().dump();
    return std::vector<uint8_t>(jsonStr.begin(), jsonStr.end());
}

bool SignedRoot::Deserialize(const std::vector<uint8_t>& data) {
    try {
        std::string jsonStr(data.begin(), data.end());
        json j = json::parse(jsonStr);
        
        if (j.contains("signed")) {
            fromJson(j["signed"]);
        }
        
        if (j.contains("signatures")) {
            Signatures.clear();
            for (const auto& sigJson : j["signatures"]) {
                Signature sig;
                sig.fromJson(sigJson);
                Signatures.push_back(sig);
            }
        }
        
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

// SignedTargets 实现
json SignedTargets::toJson() const {
    json j = Common.toJson();
    
    // 添加targets
    json targets;
    for (const auto& [name, meta] : Targets) {
        targets[name] = meta.toJson();
    }
    j["targets"] = targets;
    
    // 添加delegations（如果有）
    if (!Delegations.Keys.empty() || !Delegations.Roles.empty()) {
        j["delegations"] = Delegations.toJson();
    }
    
    return j;
}

void SignedTargets::fromJson(const json& j) {
    Common.fromJson(j);
    
    if (j.contains("targets")) {
        // 简化处理
    }
}

json SignedTargets::toSignedJson() const {
    json j;
    j["signed"] = toJson();
    
    json signatures = json::array();
    for (const auto& sig : Signatures) {
        signatures.push_back(sig.toJson());
    }
    j["signatures"] = signatures;
    
    return j;
}

std::vector<uint8_t> SignedTargets::Serialize() const {
    std::string jsonStr = toSignedJson().dump();
    return std::vector<uint8_t>(jsonStr.begin(), jsonStr.end());
}

bool SignedTargets::Deserialize(const std::vector<uint8_t>& data) {
    try {
        std::string jsonStr(data.begin(), data.end());
        json j = json::parse(jsonStr);
        
        if (j.contains("signed")) {
            fromJson(j["signed"]);
        }
        
        if (j.contains("signatures")) {
            Signatures.clear();
            for (const auto& sigJson : j["signatures"]) {
                Signature sig;
                sig.fromJson(sigJson);
                Signatures.push_back(sig);
            }
        }
        
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

// SignedTargets 新方法实现
FileMeta* SignedTargets::GetMeta(const std::string& path) {
    auto it = Targets.find(path);
    if (it != Targets.end()) {
        return &(it->second);
    }
    return nullptr;
}

void SignedTargets::AddTarget(const std::string& path, const FileMeta& meta) {
    Targets[path] = meta;
    Dirty = true;
}

std::vector<DelegationRole> SignedTargets::GetValidDelegations(const DelegationRole& parent) const {
    // TODO: 实现委托角色过滤逻辑
    // 这需要检查当前targets的delegations，并与parent角色进行路径限制
    return {};
}

Result<DelegationRole> SignedTargets::BuildDelegationRole(RoleName roleName) const {
    // TODO: 实现委托角色构建逻辑
    // 需要从delegations中查找指定的角色，并构建DelegationRole对象
    return Result<DelegationRole>(Error("BuildDelegationRole not implemented"));
}

// SignedSnapshot 实现
json SignedSnapshot::toJson() const {
    json j = Common.toJson();
    
    // 添加meta
    json meta;
    for (const auto& [name, fileMeta] : Meta) {
        meta[name] = fileMeta.toJson();
    }
    j["meta"] = meta;
    
    return j;
}

void SignedSnapshot::fromJson(const json& j) {
    Common.fromJson(j);
    
    if (j.contains("meta")) {
        // 简化处理
    }
}

json SignedSnapshot::toSignedJson() const {
    json j;
    j["signed"] = toJson();
    
    json signatures = json::array();
    for (const auto& sig : Signatures) {
        signatures.push_back(sig.toJson());
    }
    j["signatures"] = signatures;
    
    return j;
}

std::vector<uint8_t> SignedSnapshot::Serialize() const {
    std::string jsonStr = toSignedJson().dump();
    return std::vector<uint8_t>(jsonStr.begin(), jsonStr.end());
}

bool SignedSnapshot::Deserialize(const std::vector<uint8_t>& data) {
    try {
        std::string jsonStr(data.begin(), data.end());
        json j = json::parse(jsonStr);
        
        if (j.contains("signed")) {
            fromJson(j["signed"]);
        }
        
        if (j.contains("signatures")) {
            Signatures.clear();
            for (const auto& sigJson : j["signatures"]) {
                Signature sig;
                sig.fromJson(sigJson);
                Signatures.push_back(sig);
            }
        }
        
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

// SignedSnapshot 新方法实现
void SignedSnapshot::AddMeta(RoleName role, const FileMeta& meta) {
    Meta[roleNameToString(role) + ".json"] = meta;
    Dirty = true;
}

Result<FileMeta> SignedSnapshot::GetMeta(RoleName role) const {
    std::string roleName = roleNameToString(role) + ".json";
    auto it = Meta.find(roleName);
    if (it != Meta.end()) {
        return Result<FileMeta>(it->second);
    }
    return Result<FileMeta>(Error("Meta not found for role: " + roleNameToString(role)));
}

void SignedSnapshot::DeleteMeta(RoleName role) {
    std::string roleName = roleNameToString(role) + ".json";
    auto it = Meta.find(roleName);
    if (it != Meta.end()) {
        Meta.erase(it);
        Dirty = true;
    }
}

// SignedTimestamp 实现
json SignedTimestamp::toJson() const {
    json j = Common.toJson();
    
    // 添加meta
    json meta;
    for (const auto& [name, fileMeta] : Meta) {
        meta[name] = fileMeta.toJson();
    }
    j["meta"] = meta;
    
    return j;
}

void SignedTimestamp::fromJson(const json& j) {
    Common.fromJson(j);
    
    if (j.contains("meta")) {
        // 简化处理
    }
}

json SignedTimestamp::toSignedJson() const {
    json j;
    j["signed"] = toJson();
    
    json signatures = json::array();
    for (const auto& sig : Signatures) {
        signatures.push_back(sig.toJson());
    }
    j["signatures"] = signatures;
    
    return j;
}

std::vector<uint8_t> SignedTimestamp::Serialize() const {
    std::string jsonStr = toSignedJson().dump();
    return std::vector<uint8_t>(jsonStr.begin(), jsonStr.end());
}

bool SignedTimestamp::Deserialize(const std::vector<uint8_t>& data) {
    try {
        std::string jsonStr(data.begin(), data.end());
        json j = json::parse(jsonStr);
        
        if (j.contains("signed")) {
            fromJson(j["signed"]);
        }
        
        if (j.contains("signatures")) {
            Signatures.clear();
            for (const auto& sigJson : j["signatures"]) {
                Signature sig;
                sig.fromJson(sigJson);
                Signatures.push_back(sig);
            }
        }
        
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

// SignedTimestamp 新方法实现
Result<FileMeta> SignedTimestamp::GetSnapshot() const {
    auto it = Meta.find("snapshot.json");
    if (it != Meta.end()) {
        return Result<FileMeta>(it->second);
    }
    return Result<FileMeta>(Error("Snapshot meta not found in timestamp"));
}

// DelegationRole 实现
bool DelegationRole::CheckPaths(const std::string& path) const {
    if (Paths.empty()) {
        return true; // 空路径列表表示接受所有路径
    }
    
    for (const auto& allowedPath : Paths) {
        if (path.find(allowedPath) == 0) { // 路径前缀匹配
            return true;
        }
    }
    return false;
}

// Repo 实现
Repo::Repo(crypto::CryptoService& cryptoService) 
    : cryptoService_(cryptoService) {
}

std::shared_ptr<SignedTargets> Repo::GetTargets(RoleName role) const {
    auto it = targets_.find(role);
    if (it != targets_.end()) {
        return it->second;
    }
    return nullptr;
}

void Repo::SetTargets(std::shared_ptr<SignedTargets> targets, RoleName role) {
    targets_[role] = targets;
}

// 初始化方法实现：暂时不考虑consitent
Result<std::shared_ptr<SignedRoot>> Repo::InitRoot(const BaseRole& root, const BaseRole& targets, 
                    const BaseRole& snapshot, const BaseRole& timestamp) {
    // 收集所有密钥
    std::map<std::string, std::shared_ptr<PublicKey>> keys;
    std::map<RoleName, BaseRole> roles;
    
    auto addKeysFromRole = [&](const BaseRole& role, RoleName roleName) {
        for (const auto& key : role.Keys()) {
            keys[key->ID()] = key;
        }
        roles[roleName] = role;
    };
    
    addKeysFromRole(root, RoleName::RootRole);
    addKeysFromRole(targets, RoleName::TargetsRole);
    addKeysFromRole(snapshot, RoleName::SnapshotRole);
    addKeysFromRole(timestamp, RoleName::TimestampRole);
    
    // 使用NewRoot辅助函数创建新的SignedRoot对象
    auto newRoot = NewRoot(keys, roles, false); // 暂时不支持consistent snapshot
    
    root_ = newRoot;
    originalRootRole_ = root;
    
    return Result<std::shared_ptr<SignedRoot>>(newRoot);
}

Result<std::shared_ptr<SignedTargets>> Repo::InitTargets(RoleName role) {
    // 角色验证：检查是否是有效的targets角色
    if (!IsValidTargetsRole(role)) {
        return Result<std::shared_ptr<SignedTargets>>(
            Error("Role is not a valid targets role name: " + roleNameToString(role))
        );
    }
    
    // 使用NewTargets辅助函数创建新的SignedTargets对象
    auto newTargets = NewTargets();
    
    // 存储到targets映射中
    targets_[role] = newTargets;
    
    return Result<std::shared_ptr<SignedTargets>>(newTargets);
}

Result<std::shared_ptr<SignedSnapshot>> Repo::InitSnapshot() {
    if (!root_) {
        return Result<std::shared_ptr<SignedSnapshot>>(Error("Root metadata not loaded"));
    }
    
    // 获取targets元数据
    auto targets = GetTargets(RoleName::TargetsRole);
    if (!targets) {
        return Result<std::shared_ptr<SignedSnapshot>>(Error("Targets metadata not loaded"));
    }
    
    // 使用NewSnapshot辅助函数创建新的SignedSnapshot对象
    auto snapshotResult = NewSnapshot(root_, targets);
    if (!snapshotResult.ok()) {
        return snapshotResult;
    }
    
    snapshot_ = snapshotResult.value();
    return snapshotResult;
}

Result<std::shared_ptr<SignedTimestamp>> Repo::InitTimestamp() {
    if (!snapshot_) {
        return Result<std::shared_ptr<SignedTimestamp>>(Error("Snapshot metadata not loaded"));
    }
    
    // 使用NewTimestamp辅助函数创建新的SignedTimestamp对象
    auto timestampResult = NewTimestamp(snapshot_);
    if (!timestampResult.ok()) {
        return timestampResult;
    }
    
    timestamp_ = timestampResult.value();
    return timestampResult;
}

// 密钥管理方法实现
Error Repo::AddBaseKeys(RoleName role, const std::vector<std::shared_ptr<PublicKey>>& keys) {
    if (!root_) {
        return Error("Root metadata not loaded");
    }
    
    for (const auto& key : keys) {
        // 添加密钥到根元数据
        root_->Keys[key->ID()] = key;
        // 添加密钥ID到角色
        root_->Roles[role].Keys().push_back(key);
    }
    
    root_->Dirty = true;
    markRoleDirty(role);
    return Error();
}

Error Repo::ReplaceBaseKeys(RoleName role, const std::vector<std::shared_ptr<PublicKey>>& keys) {
    if (!root_) {
        return Error("Root metadata not loaded");
    }
    
    // 获取旧的密钥ID列表
    std::vector<std::string> oldKeyIDs;
    for (const auto& key : root_->Roles[role].Keys()) {
        oldKeyIDs.push_back(key->ID());
    }
    
    // 移除旧密钥
    Error err = RemoveBaseKeys(role, oldKeyIDs);
    if (!err.ok()) {
        return err;
    }
    
    // 添加新密钥
    return AddBaseKeys(role, keys);
}

Error Repo::RemoveBaseKeys(RoleName role, const std::vector<std::string>& keyIDs) {
    if (!root_) {
        return Error("Root metadata not loaded");
    }
    
    // 从角色中移除密钥ID
    auto& roleKeys = root_->Roles[role].Keys();
    roleKeys.erase(
        std::remove_if(roleKeys.begin(), roleKeys.end(),
            [&keyIDs](const std::shared_ptr<PublicKey>& key) {
                return std::find(keyIDs.begin(), keyIDs.end(), key->ID()) != keyIDs.end();
            }),
        roleKeys.end()
    );
    
    // 检查密钥是否仍被其他角色使用
    std::set<std::string> usedKeyIDs;
    for (const auto& [roleName, roleInfo] : root_->Roles) {
        if (roleName == role) continue; // 跳过当前角色
        for (const auto& key : roleInfo.Keys()) {
            usedKeyIDs.insert(key->ID());
        }
    }
    
    // 从根密钥中移除不再使用的密钥（除了root角色的密钥）
    if (role != RoleName::RootRole) {
        for (const auto& keyID : keyIDs) {
            if (usedKeyIDs.find(keyID) == usedKeyIDs.end()) {
                root_->Keys.erase(keyID);
                // 从加密服务中移除密钥
                // cryptoService_.RemoveKey(keyID); // 需要实现此方法
            }
        }
    }
    
    root_->Dirty = true;
    markRoleDirty(role);
    return Error();
}

// 角色管理方法实现
Result<BaseRole> Repo::GetBaseRole(RoleName name) const {
    if (!root_) {
        return Result<BaseRole>(Error("Root metadata not loaded"));
    }
    
    auto it = root_->Roles.find(name);
    if (it == root_->Roles.end()) {
        return Result<BaseRole>(Error("Role not found"));
    }
    
    return Result<BaseRole>(it->second);
}

Result<DelegationRole> Repo::GetDelegationRole(RoleName name) const {
    // TODO: 实现委托角色查找逻辑
    // 需要遍历targets元数据中的委托信息
    return Result<DelegationRole>(Error("Delegation role lookup not implemented"));
}

std::vector<BaseRole> Repo::GetAllLoadedRoles() const {
    std::vector<BaseRole> roles;
    
    if (root_) {
        for (const auto& [roleName, role] : root_->Roles) {
            roles.push_back(role);
        }
    }
    
    return roles;
}

// 验证方法实现
Error Repo::VerifyCanSign(RoleName roleName) const {
    auto roleResult = GetBaseRole(roleName);
    if (!roleResult.ok()) {
        return Error("Role does not exist: " + std::to_string(static_cast<int>(roleName)));
    }
    
    const auto& role = roleResult.value();
    
    // 检查是否至少有一个可用的私钥
    for (const auto& key : role.Keys()) {
        auto privateKeyResult = cryptoService_.GetPrivateKey(key->ID());
        if (privateKeyResult.ok()) {
            return Error(); // 找到可用的私钥
        }
    }
    
    return Error("No signing keys available for role");
}

// 目标管理方法实现
Error Repo::AddTarget(const std::string& targetName, const std::vector<uint8_t>& targetData, RoleName role) {
    auto targets = GetTargets(role);
    if (!targets) {
        // 如果目标元数据不存在，则创建
        auto result = InitTargets(role);
        if (!result.ok()) {
            return result.error();
        }
        targets = GetTargets(role);
    }
    
    // 使用NewFileMeta函数创建FileMeta对象并计算真正的哈希值
    auto metaResult = NewFileMeta(targetData, {"sha256", "sha512"});
    if (!metaResult.ok()) {
        return Error("Failed to create target meta: " + metaResult.error().what());
    }
    
    targets->Targets[targetName] = metaResult.value();
    targets->Dirty = true;
    return Error();
}

Error Repo::RemoveTarget(const std::string& targetName, RoleName role) {
    auto targets = GetTargets(role);
    if (!targets) {
        return Error("Targets metadata not found for role");
    }
    
    targets->Targets.erase(targetName);
    targets->Dirty = true;
    return Error();
}

Error Repo::AddTargets(RoleName role, const std::map<std::string, FileMeta>& targets) {
    // TODO: 实现批量添加目标
    return Error("AddTargets not implemented");
}

Error Repo::RemoveTargets(RoleName role, const std::vector<std::string>& targets) {
    auto targetsMetadata = GetTargets(role);
    if (!targetsMetadata) {
        return Error("Targets metadata not found for role");
    }
    
    for (const auto& targetName : targets) {
        targetsMetadata->Targets.erase(targetName);
    }
    
    targetsMetadata->Dirty = true;
    return Error();
}

// 查询方法实现
FileMeta* Repo::TargetMeta(RoleName role, const std::string& path) {
    // TODO: 实现目标元数据查找
    return nullptr;
}

std::vector<DelegationRole> Repo::TargetDelegations(RoleName role, const std::string& path) const {
    // TODO: 实现目标委托查找
    return {};
}

// 遍历方法实现
Error Repo::WalkTargets(const std::string& targetPath, RoleName rolePath, 
                       WalkVisitorFunc visitTargets, const std::vector<RoleName>& skipRoles) {
    // TODO: 实现目标遍历逻辑
    return Error("WalkTargets not implemented");
}

// 委托管理方法实现
Error Repo::UpdateDelegationKeys(RoleName roleName, const std::vector<std::shared_ptr<PublicKey>>& addKeys, 
                                 const std::vector<std::string>& removeKeys, int newThreshold) {
    // TODO: 实现委托密钥更新
    return Error("UpdateDelegationKeys not implemented");
}

Error Repo::PurgeDelegationKeys(RoleName role, const std::vector<std::string>& removeKeys) {
    // TODO: 实现委托密钥清理
    return Error("PurgeDelegationKeys not implemented");
}

Error Repo::UpdateDelegationPaths(RoleName roleName, const std::vector<std::string>& addPaths, 
                                  const std::vector<std::string>& removePaths, bool clearPaths) {
    // TODO: 实现委托路径更新
    return Error("UpdateDelegationPaths not implemented");
}

Error Repo::DeleteDelegation(RoleName roleName) {
    // TODO: 实现委托删除
    return Error("DeleteDelegation not implemented");
}

// 元数据更新方法实现
Error Repo::UpdateSnapshot(RoleName role, const std::shared_ptr<Signed>& s) {
    if (!snapshot_) {
        return Error("Snapshot metadata not loaded");
    }
    
    // TODO: 实现快照更新逻辑
    snapshot_->Dirty = true;
    return Error();
}

Error Repo::UpdateTimestamp(const std::shared_ptr<Signed>& s) {
    if (!timestamp_) {
        return Error("Timestamp metadata not loaded");
    }
    
    // TODO: 实现时间戳更新逻辑
    timestamp_->Dirty = true;
    return Error();
}

// 签名方法实现
Result<std::shared_ptr<Signed>> Repo::SignRoot(const std::chrono::time_point<std::chrono::system_clock>& expires) {
    if (!root_) {
        return Result<std::shared_ptr<Signed>>(Error("Root metadata not loaded"));
    }
    
    // TODO: 实现root签名逻辑
    return Result<std::shared_ptr<Signed>>(Error("SignRoot not implemented"));
}

Result<std::shared_ptr<Signed>> Repo::SignTargets(RoleName role, const std::chrono::time_point<std::chrono::system_clock>& expires) {
    auto targets = GetTargets(role);
    if (!targets) {
        return Result<std::shared_ptr<Signed>>(Error("Targets metadata not found for role"));
    }
    
    // TODO: 实现targets签名逻辑
    return Result<std::shared_ptr<Signed>>(Error("SignTargets not implemented"));
}

Result<std::shared_ptr<Signed>> Repo::SignSnapshot(const std::chrono::time_point<std::chrono::system_clock>& expires) {
    if (!snapshot_) {
        return Result<std::shared_ptr<Signed>>(Error("Snapshot metadata not loaded"));
    }
    
    // TODO: 实现snapshot签名逻辑
    return Result<std::shared_ptr<Signed>>(Error("SignSnapshot not implemented"));
}

Result<std::shared_ptr<Signed>> Repo::SignTimestamp(const std::chrono::time_point<std::chrono::system_clock>& expires) {
    if (!timestamp_) {
        return Result<std::shared_ptr<Signed>>(Error("Timestamp metadata not loaded"));
    }
    
    // TODO: 实现timestamp签名逻辑
    return Result<std::shared_ptr<Signed>>(Error("SignTimestamp not implemented"));
}

// 私有方法实现
void Repo::markRoleDirty(RoleName role) {
    switch (role) {
        case RoleName::SnapshotRole:
            if (snapshot_) {
                snapshot_->Dirty = true;
            }
            break;
        case RoleName::TargetsRole:
            if (auto targets = GetTargets(RoleName::TargetsRole)) {
                targets->Dirty = true;
            }
            break;
        case RoleName::TimestampRole:
            if (timestamp_) {
                timestamp_->Dirty = true;
            }
            break;
        default:
            break;
    }
}

Result<std::shared_ptr<Signed>> Repo::sign(std::shared_ptr<Signed> signedData, 
                                          const std::vector<BaseRole>& roles, 
                                          const std::vector<std::shared_ptr<PublicKey>>& optionalKeys) {
    // TODO: 实现通用签名逻辑
    return Result<std::shared_ptr<Signed>>(Error("sign method not implemented"));
}

bool Repo::isValidPath(const std::string& candidatePath, const DelegationRole& delgRole) const {
    return candidatePath.empty() || delgRole.CheckPaths(candidatePath);
}

bool Repo::isAncestorRole(RoleName candidateChild, RoleName candidateAncestor) const {
    // TODO: 实现角色层次检查
    // 需要根据具体的角色命名规则来实现
    return true; // 简化实现
}

// 角色验证函数实现
bool IsDelegation(RoleName role) {
    // 在这个简化版本中，我们只有基础角色，没有委托角色
    // 委托角色通常以 "targets/" 开头，但我们的枚举只包含基础角色
    // 在完整实现中，这里需要检查角色名称是否以 "targets/" 开头
    return false; // 目前简化实现，没有委托角色
}

bool IsValidTargetsRole(RoleName role) {
    return IsDelegation(role) || role == RoleName::TargetsRole;
}

// TUF对象创建辅助函数实现
std::shared_ptr<SignedRoot> NewRoot(const std::map<std::string, std::shared_ptr<PublicKey>>& keys,
                                   const std::map<RoleName, BaseRole>& roles, 
                                   bool consistent) {
    auto newRoot = std::make_shared<SignedRoot>();
    
    // 初始化通用字段
    newRoot->Common.Type = "root";
    newRoot->Common.Version = 0; // Go版本中初始版本为0
    newRoot->Common.Expires = std::chrono::system_clock::now() + std::chrono::hours(24 * 365 * 10); // 10年过期
    
    // 设置密钥
    newRoot->Keys = keys;
    
    // 设置角色
    newRoot->Roles = roles;
    
    // 设置一致性快照标志（在当前结构中没有这个字段，需要扩展SignedRoot）
    // newRoot->ConsistentSnapshot = consistent;
    
    // 初始化签名数组
    newRoot->Signatures.clear();
    
    // 标记为dirty
    newRoot->Dirty = true;
    
    return newRoot;
}

std::shared_ptr<SignedTargets> NewTargets() {
    auto newTargets = std::make_shared<SignedTargets>();
    
    // 初始化通用字段
    newTargets->Common.Type = "targets";
    newTargets->Common.Version = 0; // Go版本中初始版本为0
    newTargets->Common.Expires = std::chrono::system_clock::now() + std::chrono::hours(24 * 365); // 1年过期
    
    // 初始化targets为空
    newTargets->Targets.clear();
    
    // 初始化签名数组
    newTargets->Signatures.clear();
    
    // 标记为dirty
    newTargets->Dirty = true;
    
    return newTargets;
}

Result<std::shared_ptr<SignedSnapshot>> NewSnapshot(const std::shared_ptr<Signed>& root,
                                                    const std::shared_ptr<Signed>& targets) {
    auto newSnapshot = std::make_shared<SignedSnapshot>();
    
    // 初始化通用字段
    newSnapshot->Common.Type = "snapshot";
    newSnapshot->Common.Version = 0; // Go版本中初始版本为0
    newSnapshot->Common.Expires = std::chrono::system_clock::now() + std::chrono::hours(24 * 365 * 3); // 3年过期
    
    // 序列化root和targets以计算元数据
    auto rootBytes = root->Serialize();
    auto targetsBytes = targets->Serialize();
    
    if (rootBytes.empty() || targetsBytes.empty()) {
        return Result<std::shared_ptr<SignedSnapshot>>(
            Error("Failed to serialize root or targets for snapshot creation")
        );
    }
    
    // 使用NewFileMeta函数创建FileMeta对象并计算真正的哈希值
    auto rootMetaResult = NewFileMeta(rootBytes, {"sha256", "sha512"});
    if (!rootMetaResult.ok()) {
        return Result<std::shared_ptr<SignedSnapshot>>(
            Error("Failed to create root meta: " + rootMetaResult.error().what())
        );
    }
    
    auto targetsMetaResult = NewFileMeta(targetsBytes, {"sha256", "sha512"});
    if (!targetsMetaResult.ok()) {
        return Result<std::shared_ptr<SignedSnapshot>>(
            Error("Failed to create targets meta: " + targetsMetaResult.error().what())
        );
    }
    
    // 设置文件元数据映射
    newSnapshot->Meta["root.json"] = rootMetaResult.value();
    newSnapshot->Meta["targets.json"] = targetsMetaResult.value();
    
    // 初始化签名数组
    newSnapshot->Signatures.clear();
    
    // 标记为dirty
    newSnapshot->Dirty = true;
    
    return Result<std::shared_ptr<SignedSnapshot>>(newSnapshot);
}

Result<std::shared_ptr<SignedTimestamp>> NewTimestamp(const std::shared_ptr<Signed>& snapshot) {
    auto newTimestamp = std::make_shared<SignedTimestamp>();
    
    // 初始化通用字段
    newTimestamp->Common.Type = "timestamp";
    newTimestamp->Common.Version = 0; // Go版本中初始版本为0
    newTimestamp->Common.Expires = std::chrono::system_clock::now() + std::chrono::hours(24 * 14); // 14天过期
    
    // 序列化snapshot以计算元数据
    auto snapshotBytes = snapshot->Serialize();
    
    if (snapshotBytes.empty()) {
        return Result<std::shared_ptr<SignedTimestamp>>(
            Error("Failed to serialize snapshot for timestamp creation")
        );
    }
    
    // 使用NewFileMeta函数创建FileMeta对象并计算真正的哈希值
    auto snapshotMetaResult = NewFileMeta(snapshotBytes, {"sha256", "sha512"});
    if (!snapshotMetaResult.ok()) {
        return Result<std::shared_ptr<SignedTimestamp>>(
            Error("Failed to create snapshot meta: " + snapshotMetaResult.error().what())
        );
    }
    
    // 设置文件元数据映射
    newTimestamp->Meta["snapshot.json"] = snapshotMetaResult.value();
    
    // 初始化签名数组
    newTimestamp->Signatures.clear();
    
    // 标记为dirty
    newTimestamp->Dirty = true;
    
    return Result<std::shared_ptr<SignedTimestamp>>(newTimestamp);
}

// NewFileMeta 函数实现
Result<FileMeta> NewFileMeta(const std::vector<uint8_t>& data, 
                            const std::vector<std::string>& hashAlgorithms) {
    FileMeta fileMeta;
    fileMeta.Length = static_cast<int64_t>(data.size());
    
    // 支持的哈希算法
    std::vector<std::string> algorithms = hashAlgorithms;
    if (algorithms.empty()) {
        algorithms = {"sha256"}; // 默认算法
    }
    
    for (const auto& algorithm : algorithms) {
        std::vector<uint8_t> hash;
        
        if (algorithm == "sha256") {
            hash.resize(SHA256_DIGEST_LENGTH);
            SHA256_CTX ctx;
            SHA256_Init(&ctx);
            SHA256_Update(&ctx, data.data(), data.size());
            SHA256_Final(hash.data(), &ctx);
        } else if (algorithm == "sha512") {
            hash.resize(SHA512_DIGEST_LENGTH);
            SHA512_CTX ctx;
            SHA512_Init(&ctx);
            SHA512_Update(&ctx, data.data(), data.size());
            SHA512_Final(hash.data(), &ctx);
        } else {
            return Result<FileMeta>(Error("Unknown hash algorithm: " + algorithm));
        }
        
        fileMeta.Hashes[algorithm] = hash;
    }
    
    return Result<FileMeta>(fileMeta);
}

} // namespace tuf
} // namespace notary 