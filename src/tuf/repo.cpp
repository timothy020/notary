#include "notary/tuf/repo.hpp"
#include "notary/utils/tools.hpp"
#include "notary/utils/x509.hpp"
#include "notary/crypto/sign.hpp"
#include <stdexcept>
#include <algorithm>
#include <set>
#include <sstream>
#include <iomanip>
#include <variant>
#include <cstdlib>  // 添加：for setenv, unsetenv
#include <ctime>    // 添加：for tzset, timegm
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

namespace notary {
namespace tuf {

std::string timeToISO8601(const std::chrono::time_point<std::chrono::system_clock>& time) {
    auto time_t = std::chrono::system_clock::to_time_t(time);
    std::stringstream ss;
    // 使用本地时间而不是UTC时间，移除Z后缀
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%dT%H:%M:%S");
    return ss.str();
}

std::chrono::time_point<std::chrono::system_clock> iso8601ToTime(const std::string& timeStr) {
    std::tm tm = {};
    std::istringstream ss(timeStr);
    // 解析本地时间格式（不带Z后缀）
    ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");
    
    // 使用本地时间转换（mktime假设输入是本地时间）
    return std::chrono::system_clock::from_time_t(std::mktime(&tm));
}


// Signature 实现
json Signature::toJson() const {
    json j;
    j["keyid"] = KeyID;
    j["method"] = Method;
    j["sig"] = utils::Base64Encode(Sig);
    return j;
}

void Signature::fromJson(const json& j) {
    KeyID = j.at("keyid").get<std::string>();
    Method = j.at("method").get<std::string>();
    Sig = utils::Base64Decode(j.at("sig").get<std::string>());
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
        // 使用base64编码哈希值，而不是十六进制，与Go版本兼容
        hashes[algo] = utils::Base64Encode(hash);
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
        Hashes.clear();
        for (const auto& [algo, hashValue] : j.at("hashes").items()) {
            // 根据JSON中存储的类型来解析哈希值
            if (hashValue.is_string()) {
                // 如果是字符串，首先尝试base64解码（与Go版本兼容）
                std::string hashStr = hashValue.get<std::string>();
                try {
                    Hashes[algo] = utils::Base64Decode(hashStr);
                } catch (const std::exception& e) {
                    // 如果base64解码失败，尝试十六进制解码作为后备
                    try {
                        Hashes[algo] = utils::HexDecode(hashStr);
                    } catch (const std::exception& hex_e) {
                        // 如果都失败了，跳过这个哈希值
                        utils::GetLogger().Warn("Failed to decode hash", utils::LogContext()
                            .With("algorithm", algo)
                            .With("value", hashStr));
                        continue;
                    }
                }
            } else if (hashValue.is_array()) {
                // 如果是数组，直接转换为vector<uint8_t>
                Hashes[algo] = hashValue.get<std::vector<uint8_t>>();
            }
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
    j["name"] = Name;
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
    Name = j.at("name").get<std::string>();
    
    // 解析threshold（如果存在）
    int threshold = 1; // 默认值
    if (j.contains("threshold")) {
        threshold = j.at("threshold").get<int>();
    }
    
    // 解析paths
    if (j.contains("paths")) {
        Paths = j.at("paths").get<std::vector<std::string>>();
    }
    
    // 注意：BaseRoleInfo需要在外部设置，因为需要密钥信息
    // 这里只设置基本信息，密钥信息由调用者在Delegations::fromJson中设置
    std::vector<std::shared_ptr<crypto::PublicKey>> emptyKeys;
    BaseRoleInfo = BaseRole(Name, threshold, emptyKeys);
}

// Delegations 实现
json Delegations::toJson() const {
    json j;
    
    json keys;
    for (const auto& [keyId, key] : Keys) {
        json keyJson;
        keyJson["keytype"] = key->Algorithm();
        keyJson["keyval"] = json::object();
        keyJson["keyval"]["public"] = utils::Base64Encode(key->Public());
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
    // 解析keys
    if (j.contains("keys")) {
        Keys.clear();
        const auto& keysJson = j.at("keys");
        
        for (const auto& [keyId, keyJson] : keysJson.items()) {
            try {
                // 解析密钥类型
                std::string keyType;
                if (keyJson.contains("keytype")) {
                    keyType = keyJson.at("keytype").get<std::string>();
                } else {
                    continue; // 跳过没有keytype的密钥
                }
                
                // 解析公钥数据
                std::vector<uint8_t> publicData;
                if (keyJson.contains("keyval") && keyJson["keyval"].contains("public")) {
                    std::string publicStr = keyJson["keyval"]["public"].get<std::string>();
                    publicData = utils::Base64Decode(publicStr);
                } else {
                    continue; // 跳过没有公钥数据的密钥
                }
                
                // 创建公钥对象
                auto publicKey = crypto::NewPublicKey(keyType, publicData);
                if (publicKey) {
                    Keys[keyId] = publicKey;
                }
                
            } catch (const std::exception& e) {
                // 跳过解析失败的密钥
                continue;
            }
        }
    }
    
    // 解析roles
    if (j.contains("roles")) {
        Roles.clear();
        for (const auto& roleJson : j.at("roles")) {
            try {
                DelegationRole role;
                role.fromJson(roleJson);
                
                // 需要根据解析的keyids从Keys中构建BaseRoleInfo
                if (roleJson.contains("keyids") && roleJson.contains("threshold")) {
                    std::vector<std::shared_ptr<crypto::PublicKey>> roleKeys;
                    const auto& keyidsJson = roleJson.at("keyids");
                    for (const auto& keyidJson : keyidsJson) {
                        std::string keyId = keyidJson.get<std::string>();
                        auto keyIt = Keys.find(keyId);
                        if (keyIt != Keys.end()) {
                            roleKeys.push_back(keyIt->second);
                        }
                    }
                    
                    int threshold = roleJson.at("threshold").get<int>();
                    BaseRole baseRole(role.Name, threshold, roleKeys);
                    role.BaseRoleInfo = baseRole;
                }
                
                Roles.push_back(role);
            } catch (const std::exception& e) {
                // 跳过解析失败的角色
                continue;
            }
        }
    }
}

// Root 实现
json Root::toJson() const {
    json j = Common.toJson();
    
    // 添加keys
    json keys;
    for (const auto& [keyId, key] : Keys) {
        json keyJson;
        keyJson["keytype"] = key->Algorithm();
        keyJson["keyval"] = json::object();
        keyJson["keyval"]["public"] = utils::Base64Encode(key->Public());
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
        
        roles[roleName] = roleJson;
    }
    j["roles"] = roles;
    
    j["consistent_snapshot"] = ConsistentSnapshot;
    
    return j;
}

void Root::fromJson(const json& j) {
    Common.fromJson(j);
    
    if (j.contains("consistent_snapshot")) {
        ConsistentSnapshot = j.at("consistent_snapshot").get<bool>();
    }
    
    // 解析keys
    if (j.contains("keys")) {
        Keys.clear();
        const auto& keysJson = j.at("keys");
        
        for (const auto& [keyId, keyJson] : keysJson.items()) {
            try {
                // 解析密钥类型
                std::string keyType;
                if (keyJson.contains("keytype")) {
                    keyType = keyJson.at("keytype").get<std::string>();
                } else {
                    continue; // 跳过没有keytype的密钥
                }
                
                // 解析公钥数据
                std::vector<uint8_t> publicData;
                if (keyJson.contains("keyval") && keyJson["keyval"].contains("public")) {
                    std::string publicStr = keyJson["keyval"]["public"].get<std::string>();
                    publicData = utils::Base64Decode(publicStr);
                } else {
                    continue; // 跳过没有公钥数据的密钥
                }
                
                // 创建公钥对象
                auto publicKey = crypto::NewPublicKey(keyType, publicData);
                if (publicKey) {
                    Keys[keyId] = publicKey;
                }
                
            } catch (const std::exception& e) {
                // 跳过解析失败的密钥
                continue;
            }
        }
    }
    
    // 解析roles
    if (j.contains("roles")) {
        Roles.clear();
        const auto& rolesJson = j.at("roles");
        
        for (const auto& [roleNameStr, roleJson] : rolesJson.items()) {
            try {
                // 解析角色名
                std::string  roleName = roleNameStr;
                
                // 解析threshold
                int threshold = 1; // 默认值
                if (roleJson.contains("threshold")) {
                    threshold = roleJson.at("threshold").get<int>();
                }
                
                // 解析keyids并构建密钥列表
                std::vector<std::shared_ptr<crypto::PublicKey>> roleKeys;
                if (roleJson.contains("keyids")) {
                    const auto& keyidsJson = roleJson.at("keyids");
                    for (const auto& keyidJson : keyidsJson) {
                        std::string keyId = keyidJson.get<std::string>();
                        auto keyIt = Keys.find(keyId);
                        if (keyIt != Keys.end()) {
                            roleKeys.push_back(keyIt->second);
                        }
                    }
                }
                
                // 创建BaseRole对象
                BaseRole baseRole(roleName, threshold, roleKeys);
                Roles[roleName] = baseRole;
                
            } catch (const std::exception& e) {
                // 跳过解析失败的角色
                continue;
            }
        }
    }
}

// Targets 实现
json Targets::toJson() const {
    json j = Common.toJson();
    
    // 添加targets
    json targetsJson;
    for (const auto& [name, meta] : targets) {
        targetsJson[name] = meta.toJson();
    }
    j["targets"] = targetsJson;
    
    // 添加delegations（如果有）
    if (!delegations.Keys.empty() || !delegations.Roles.empty()) {
        j["delegations"] = delegations.toJson();
    }
    
    return j;
}

void Targets::fromJson(const json& j) {
    Common.fromJson(j);
    
    if (j.contains("targets")) {
        targets.clear();
        const auto& targetsJson = j.at("targets");
        
        for (const auto& [name, metaJson] : targetsJson.items()) {
            try {
                FileMeta meta;
                meta.fromJson(metaJson);
                targets[name] = meta;
            } catch (const std::exception& e) {
                // 跳过解析失败的目标
                continue;
            }
        }
    }
    
    if (j.contains("delegations")) {
        delegations.fromJson(j.at("delegations"));
    }
}

// Snapshot 实现
json Snapshot::toJson() const {
    json j = Common.toJson();
    
    // 添加meta
    json meta;
    for (const auto& [name, fileMeta] : Meta) {
        meta[name] = fileMeta.toJson();
    }
    j["meta"] = meta;
    
    return j;
}

void Snapshot::fromJson(const json& j) {
    Common.fromJson(j);
    
    if (j.contains("meta")) {
        Meta.clear();
        const auto& metaJson = j.at("meta");
        
        for (const auto& [name, fileMetaJson] : metaJson.items()) {
            try {
                FileMeta fileMeta;
                fileMeta.fromJson(fileMetaJson);
                Meta[name] = fileMeta;
            } catch (const std::exception& e) {
                // 跳过解析失败的元数据
                continue;
            }
        }
    }
}

// Timestamp 实现
json Timestamp::toJson() const {
    json j = Common.toJson();
    
    // 添加meta
    json meta;
    for (const auto& [name, fileMeta] : Meta) {
        meta[name] = fileMeta.toJson();
    }
    j["meta"] = meta;
    
    return j;
}

void Timestamp::fromJson(const json& j) {
    Common.fromJson(j);
    
    if (j.contains("meta")) {
        Meta.clear();
        const auto& metaJson = j.at("meta");
        
        for (const auto& [name, fileMetaJson] : metaJson.items()) {
            try {
                FileMeta fileMeta;
                fileMeta.fromJson(fileMetaJson);
                Meta[name] = fileMeta;
            } catch (const std::exception& e) {
                // 跳过解析失败的元数据
                continue;
            }
        }
    }
}

// SignedRoot 实现
json SignedRoot::toJson() const {
    json j;
    j["signed"] = Signed.toJson();
    j["signatures"] = json::array();
    for (const auto& sig : Signatures) {
        j["signatures"].push_back(sig.toJson());
    }
    return j;
}

void SignedRoot::fromJson(const json& j) {
    Signed.fromJson(j["signed"]);
    Signatures.clear();
    for (const auto& sigJson : j["signatures"]) {
        Signature sig;
        sig.fromJson(sigJson);
        Signatures.push_back(sig);
    }
}

// SignedRoot ToSigned 方法 - 对应Go版本的ToSigned
Result<std::shared_ptr<notary::tuf::Signed>> SignedRoot::ToSigned() const {
    // 对内部Signed结构进行规范化JSON编码（类似Go的MarshalCanonical）
    json signedJson = Signed.toJson();
    // 生成规范化的JSON字符串（sorted keys, no whitespace）
    std::string canonicalJson = signedJson.dump(-1, ' ', false, json::error_handler_t::strict);
    
    // 转换为字节数组
    std::vector<uint8_t> signedBytes(canonicalJson.begin(), canonicalJson.end());
    
    // 创建新的Signed对象
    auto result = std::make_shared<notary::tuf::Signed>();
    
    // 拷贝已有签名
    result->Signatures = Signatures;
    
    // 存储规范化的JSON数据（类似Go的json.RawMessage）
    result->signedData = signedBytes;
    
    return Result<std::shared_ptr<notary::tuf::Signed>>(result);
}

std::vector<uint8_t> SignedRoot::Serialize() const {
    std::string jsonStr = toJson().dump();
    return std::vector<uint8_t>(jsonStr.begin(), jsonStr.end());
}

bool SignedRoot::Deserialize(const std::vector<uint8_t>& data) {
    try {
        std::string jsonStr(data.begin(), data.end());
        json j = json::parse(jsonStr);
        fromJson(j);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

// SignedRoot BuildBaseRole 方法
Result<BaseRole> SignedRoot::BuildBaseRole(const std::string& roleName) const {
    auto it = Signed.Roles.find(roleName);
    if (it == Signed.Roles.end()) {
        return Result<BaseRole>(Error("Role not found in root file"));
    }
    
    // Get all public keys for the base role from TUF metadata
    const auto& role = it->second;
    std::vector<std::shared_ptr<crypto::PublicKey>> pubKeys;
    
    for (const auto& key : role.Keys()) {
        std::string keyID = key->ID();
        auto keyIt = Signed.Keys.find(keyID);
        if (keyIt == Signed.Keys.end()) {
            return Result<BaseRole>(Error("Key with ID " + keyID + " was not found in root metadata"));
        }
        pubKeys.push_back(keyIt->second);
    }
    
    BaseRole baseRole(roleName, role.Threshold(), pubKeys);
    return Result<BaseRole>(baseRole);
}

// SignedTargets 实现
json SignedTargets::toJson() const {
    return Signed.toJson();
}

void SignedTargets::fromJson(const json& j) {
    Signed.fromJson(j);
}

json SignedTargets::toSignedJson() const {
    json j;
    j["signed"] = Signed.toJson();
    
    json signatures = json::array();
    for (const auto& sig : Signatures) {
        signatures.push_back(sig.toJson());
    }
    j["signatures"] = signatures;
    
    return j;
}

// SignedTargets ToSigned 方法 - 对应Go版本的ToSigned
Result<std::shared_ptr<notary::tuf::Signed>> SignedTargets::ToSigned() const {
    // 对内部Signed结构进行规范化JSON编码
    json signedJson = Signed.toJson();
    
    // 生成规范化的JSON字符串
    std::string canonicalJson = signedJson.dump(-1, ' ', false, json::error_handler_t::strict);
    
    // 创建新的Signed对象
    auto result = std::make_shared<notary::tuf::Signed>();
    
    // 拷贝已有签名
    result->Signatures = Signatures;
    
    // 存储规范化的JSON数据
    result->signedData = std::vector<uint8_t>(canonicalJson.begin(), canonicalJson.end());
    
    return Result<std::shared_ptr<notary::tuf::Signed>>(result);
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
            Signed.fromJson(j["signed"]);
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
    auto it = Signed.targets.find(path);
    if (it != Signed.targets.end()) {
        return &(it->second);
    }
    return nullptr;
}

void SignedTargets::AddTarget(const std::string& path, const FileMeta& meta) {
    Signed.targets[path] = meta;
    Dirty = true;
}

// buildDelegationRoles辅助方法 - 对应Go版本的SignedTargets.buildDelegationRoles
std::vector<DelegationRole> SignedTargets::buildDelegationRoles() const {
    std::vector<DelegationRole> roles;
    
    // 遍历所有委托角色数据，构建DelegationRole对象
    for (const auto& roleData : Signed.delegations.Roles) {
        auto delegationRoleResult = BuildDelegationRole(roleData.Name);
        if (delegationRoleResult.ok()) {
            roles.push_back(delegationRoleResult.value());
        }
        // 如果构建失败，跳过这个角色（对应Go版本的continue）
    }
    
    return roles;
}

std::vector<DelegationRole> SignedTargets::GetValidDelegations(const DelegationRole& parent) const {
    // 对应Go版本的SignedTargets.GetValidDelegations方法
    // 过滤委托角色，只返回直接子角色并限制其路径
    
    std::vector<DelegationRole> roles = buildDelegationRoles();
    std::vector<DelegationRole> result;
    
    for (const auto& role : roles) {
        // 调用parent的Restrict方法来验证和限制子角色
        auto validRoleResult = parent.Restrict(role);
        if (validRoleResult.ok()) {
            result.push_back(validRoleResult.value());
        }
        // 如果限制失败，跳过这个角色（对应Go版本的continue）
    }
    
    return result;
}

Result<DelegationRole> SignedTargets::BuildDelegationRole(const std::string& roleName) const {
    // 对应Go版本的SignedTargets.BuildDelegationRole方法
    // 从委托中查找指定角色并构建DelegationRole对象
    
    // 遍历所有委托角色，查找匹配的角色名
    for (const auto& role : Signed.delegations.Roles) {
        if (role.Name == roleName) {
            // 找到匹配的角色，现在需要构建完整的DelegationRole对象
            
            // 获取角色的所有公钥
            std::map<std::string, std::shared_ptr<crypto::PublicKey>> pubKeys;
            for (const auto& key : role.BaseRoleInfo.Keys()) {
                std::string keyID = key->ID();
                auto keyIt = Signed.delegations.Keys.find(keyID);
                if (keyIt == Signed.delegations.Keys.end()) {
                    // 找不到密钥，返回错误
                    return Result<DelegationRole>(Error(
                        "role lists unknown key " + keyID + " as a signing key"
                    ));
                }
                pubKeys[keyID] = keyIt->second;
            }
            
            // 创建新的DelegationRole对象
            DelegationRole delegationRole;
            delegationRole.Name = role.Name;
            delegationRole.Paths = role.Paths;
            
            // 重新构建BaseRole，使用从Keys映射中找到的实际密钥
            std::vector<std::shared_ptr<crypto::PublicKey>> roleKeys;
            for (const auto& [keyId, key] : pubKeys) {
                roleKeys.push_back(key);
            }
            
            BaseRole baseRole(role.Name, role.BaseRoleInfo.Threshold(), roleKeys);
            delegationRole.BaseRoleInfo = baseRole;
            
            return Result<DelegationRole>(delegationRole);
        }
    }
    
    // 没有找到角色
    return Result<DelegationRole>(Error("Role not found: " + roleName));
}

// SignedSnapshot 实现
json SignedSnapshot::toJson() const {
    return Signed.toJson();
}

void SignedSnapshot::fromJson(const json& j) {
    Signed.fromJson(j);
}

json SignedSnapshot::toSignedJson() const {
    json j;
    j["signed"] = Signed.toJson();
    
    json signatures = json::array();
    for (const auto& sig : Signatures) {
        signatures.push_back(sig.toJson());
    }
    j["signatures"] = signatures;
    
    return j;
}

// SignedSnapshot ToSigned 方法 - 对应Go版本的ToSigned
Result<std::shared_ptr<notary::tuf::Signed>> SignedSnapshot::ToSigned() const {
    // 对内部Signed结构进行规范化JSON编码
    json signedJson = Signed.toJson();
    
    // 生成规范化的JSON字符串
    std::string canonicalJson = signedJson.dump(-1, ' ', false, json::error_handler_t::strict);
    
    // 创建新的Signed对象
    auto result = std::make_shared<notary::tuf::Signed>();
    
    // 拷贝已有签名
    result->Signatures = Signatures;
    
    // 存储规范化的JSON数据
    result->signedData = std::vector<uint8_t>(canonicalJson.begin(), canonicalJson.end());
    
    return Result<std::shared_ptr<notary::tuf::Signed>>(result);
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
            Signed.fromJson(j["signed"]);
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
void SignedSnapshot::AddMeta(const std::string& role, const FileMeta& meta) {
    Signed.Meta[role + ".json"] = meta;
    Dirty = true;
}

Result<FileMeta> SignedSnapshot::GetMeta(const std::string& role) const {
    std::string roleName = role + ".json";
    auto it = Signed.Meta.find(roleName);
    if (it != Signed.Meta.end()) {
        return Result<FileMeta>(it->second);
    }
    return Result<FileMeta>(Error("Meta not found for role: " + role));
}

void SignedSnapshot::DeleteMeta(const std::string& role) {
    std::string roleName = role + ".json";
    auto it = Signed.Meta.find(roleName);
    if (it != Signed.Meta.end()) {
        Signed.Meta.erase(it);
        Dirty = true;
    }
}

// SignedTimestamp 实现
json SignedTimestamp::toJson() const {
    return Signed.toJson();
}

void SignedTimestamp::fromJson(const json& j) {
    Signed.fromJson(j);
}

json SignedTimestamp::toSignedJson() const {
    json j;
    j["signed"] = Signed.toJson();
    
    json signatures = json::array();
    for (const auto& sig : Signatures) {
        signatures.push_back(sig.toJson());
    }
    j["signatures"] = signatures;
    
    return j;
}

// SignedTimestamp ToSigned 方法 - 对应Go版本的ToSigned
Result<std::shared_ptr<notary::tuf::Signed>> SignedTimestamp::ToSigned() const {
    // 对内部Signed结构进行规范化JSON编码
    json signedJson = Signed.toJson();
    
    // 生成规范化的JSON字符串
    std::string canonicalJson = signedJson.dump(-1, ' ', false, json::error_handler_t::strict);
    
    // 创建新的Signed对象
    auto result = std::make_shared<notary::tuf::Signed>();
    
    // 拷贝已有签名
    result->Signatures = Signatures;
    
    // 存储规范化的JSON数据
    result->signedData = std::vector<uint8_t>(canonicalJson.begin(), canonicalJson.end());
    
    return Result<std::shared_ptr<notary::tuf::Signed>>(result);
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
            Signed.fromJson(j["signed"]);
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
    auto it = Signed.Meta.find("snapshot.json");
    if (it != Signed.Meta.end()) {
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

// RestrictDelegationPathPrefixes辅助函数 - 对应Go版本的RestrictDelegationPathPrefixes
std::vector<std::string> RestrictDelegationPathPrefixes(const std::vector<std::string>& parentPaths, 
                                                        const std::vector<std::string>& delegationPaths) {
    std::vector<std::string> validPaths;
    
    if (delegationPaths.empty()) {
        return validPaths;
    }
    
    // 验证每个委托路径
    for (const auto& delgPath : delegationPaths) {
        bool isPrefixed = false;
        for (const auto& parentPath : parentPaths) {
            if (delgPath.find(parentPath) == 0) {  // 使用前缀匹配
                isPrefixed = true;
                break;
            }
        }
        // 如果委托路径没有匹配任何父路径的前缀，则无效
        if (isPrefixed) {
            validPaths.push_back(delgPath);
        }
    }
    
    return validPaths;
}

// IsParentOf实现 - 对应Go版本的DelegationRole.IsParentOf
bool DelegationRole::IsParentOf(const DelegationRole& child) const {
    // 通过委托名称确定传入的委托角色是否是此角色的直接子角色
    // 例如：targets/a 是 targets/a/b 的直接父角色，但 targets/a 不是 targets/a/b/c 的直接父角色
    std::string childNameStr = child.Name;
    std::string parentNameStr = this->Name;
    
    // 获取子角色的父目录
    size_t lastSlash = childNameStr.find_last_of('/');
    if (lastSlash == std::string::npos) {
        return false; // 子角色没有父目录
    }
    
    std::string childParentDir = childNameStr.substr(0, lastSlash);
    return childParentDir == parentNameStr;
}

// Restrict实现 - 对应Go版本的DelegationRole.Restrict
Result<DelegationRole> DelegationRole::Restrict(const DelegationRole& child) const {
    if (!IsParentOf(child)) {
        return Result<DelegationRole>(Error(
            this->Name + " is not a parent of " + child.Name
        ));
    }
    
    // 创建受限制的委托角色
    DelegationRole restrictedRole;
    restrictedRole.BaseRoleInfo = BaseRole(child.Name, child.BaseRoleInfo.Threshold(), child.BaseRoleInfo.Keys());
    restrictedRole.Name = child.Name;
    
    // 使用RestrictDelegationPathPrefixes限制路径
    restrictedRole.Paths = RestrictDelegationPathPrefixes(this->Paths, child.Paths);
    
    return Result<DelegationRole>(restrictedRole);
}

// Repo 实现
Repo::Repo(std::shared_ptr<crypto::CryptoService> cryptoService) 
    : cryptoService_(cryptoService) {
}

std::shared_ptr<SignedTargets> Repo::GetTargets(const std::string& role) const {
    auto it = targets_.find(role);
    if (it != targets_.end()) {
        return it->second;
    }
    return nullptr;
}

void Repo::SetTargets(std::shared_ptr<SignedTargets> targets, const std::string& role) {
    targets_[role] = targets;
}

// 初始化方法实现：暂时不考虑consitent
Result<std::shared_ptr<SignedRoot>> Repo::InitRoot(const BaseRole& root, const BaseRole& targets, 
                    const BaseRole& snapshot, const BaseRole& timestamp) {
    // 收集所有密钥
    std::map<std::string, std::shared_ptr<crypto::PublicKey>> keys;
    std::map<std::string, BaseRole> roles;
    
    auto addKeysFromRole = [&](const BaseRole& role, std::string roleName) {
        for (const auto& key : role.Keys()) {
            keys[key->ID()] = key;
        }
        roles[roleName] = role;
    };
    
    addKeysFromRole(root, ROOT_ROLE);
    addKeysFromRole(targets, TARGETS_ROLE);
    addKeysFromRole(snapshot, SNAPSHOT_ROLE);
    addKeysFromRole(timestamp, TIMESTAMP_ROLE);
    
    // 使用NewRoot辅助函数创建新的SignedRoot对象
    auto newRoot = NewRoot(keys, roles, false); // 暂时不支持consistent snapshot
    
    root_ = newRoot;
    originalRootRole_ = root;
    
    return Result<std::shared_ptr<SignedRoot>>(newRoot);
}

Result<std::shared_ptr<SignedTargets>> Repo::InitTargets(const std::string& role) {
    // 角色验证：检查是否是有效的targets角色
    if (!IsDelegation(role) && role != TARGETS_ROLE) {
        return Result<std::shared_ptr<SignedTargets>>(
            Error("Role is not a valid targets role name: " + role)
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
    auto targets = GetTargets(TARGETS_ROLE);
    if (!targets) {
        return Result<std::shared_ptr<SignedSnapshot>>(Error("Targets metadata not loaded"));
    }
    
    // 使用ToSigned方法获取签名对象
    auto rootSignedResult = root_->ToSigned();
    if (!rootSignedResult.ok()) {
        return Result<std::shared_ptr<SignedSnapshot>>(rootSignedResult.error());
    }
    
    auto targetsSignedResult = targets->ToSigned();
    if (!targetsSignedResult.ok()) {
        return Result<std::shared_ptr<SignedSnapshot>>(targetsSignedResult.error());
    }
    
    // 使用NewSnapshot辅助函数创建新的SignedSnapshot对象
    auto snapshotResult = NewSnapshot(rootSignedResult.value(), targetsSignedResult.value());
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
    
    // 使用ToSigned方法获取签名对象
    auto snapshotSignedResult = snapshot_->ToSigned();
    if (!snapshotSignedResult.ok()) {
        return Result<std::shared_ptr<SignedTimestamp>>(snapshotSignedResult.error());
    }
    
    // 使用NewTimestamp辅助函数创建新的SignedTimestamp对象
    auto timestampResult = NewTimestamp(snapshotSignedResult.value());
    if (!timestampResult.ok()) {
        return timestampResult;
    }
    
    timestamp_ = timestampResult.value();
    return timestampResult;
}

// 密钥管理方法实现
Error Repo::AddBaseKeys(const std::string& role, const std::vector<std::shared_ptr<crypto::PublicKey>>& keys) {
    if (!root_) {
        return Error("Root metadata not loaded");
    }
    
    for (const auto& key : keys) {
        // 添加密钥到根元数据
        root_->Signed.Keys[key->ID()] = key;
        // 添加密钥ID到角色
        root_->Signed.Roles[role].Keys().push_back(key);
    }
    
    root_->Dirty = true;
    markRoleDirty(role);
    return Error();
}

Error Repo::ReplaceBaseKeys(const std::string& role, const std::vector<std::shared_ptr<crypto::PublicKey>>& keys) {
    if (!root_) {
        return Error("Root metadata not loaded");
    }
    
    utils::GetLogger().Info("Starting ReplaceBaseKeys", utils::LogContext()
        .With("role", role)
        .With("newKeyCount", std::to_string(keys.size())));
    
    // 使用GetBaseRole方法获取角色，与Go版本保持一致 (对应Go的r, err := tr.GetBaseRole(role))
    auto baseRoleResult = GetBaseRole(role);
    if (!baseRoleResult.ok()) {
        return baseRoleResult.error();
    }
    
    auto baseRole = baseRoleResult.value();
    
    // 从BaseRole中提取密钥ID列表 (对应Go的r.ListKeyIDs()...)
    std::vector<std::string> oldKeyIDs;
    for (const auto& key : baseRole.Keys()) {
        oldKeyIDs.push_back(key->ID());
    }
    
    utils::GetLogger().Info("Found old keys to remove", utils::LogContext()
        .With("role", role)
        .With("oldKeyCount", std::to_string(oldKeyIDs.size())));
    
    // 移除旧密钥 (对应Go的tr.RemoveBaseKeys(role, r.ListKeyIDs()...))
    Error err = RemoveBaseKeys(role, oldKeyIDs);
    if (!err.ok()) {
        utils::GetLogger().Error("Failed to remove old keys", utils::LogContext()
            .With("role", role)
            .With("error", err.what()));
        return err;
    }
    
    utils::GetLogger().Info("Successfully removed old keys", utils::LogContext()
        .With("role", role));
    
    // 添加新密钥 (对应Go的return tr.AddBaseKeys(role, keys...))
    err = AddBaseKeys(role, keys);
    if (!err.ok()) {
        utils::GetLogger().Error("Failed to add new keys", utils::LogContext()
            .With("role", role)
            .With("error", err.what()));
        return err;
    }
    
    utils::GetLogger().Info("Successfully completed ReplaceBaseKeys", utils::LogContext()
        .With("role", role)
        .With("newKeyCount", std::to_string(keys.size())));
    
    return Error();
}

Error Repo::RemoveBaseKeys(const std::string& role, const std::vector<std::string>& keyIDs) {
    if (!root_) {
        return Error("Root metadata not loaded");
    }
    
    utils::GetLogger().Info("Starting RemoveBaseKeys", utils::LogContext()
        .With("role", role)
        .With("keyIDCount", std::to_string(keyIDs.size())));
    
    
    // 从角色中移除密钥ID
    auto& roleKeys = root_->Signed.Roles[role].Keys();
    size_t originalSize = roleKeys.size();
    
    roleKeys.erase(
        std::remove_if(roleKeys.begin(), roleKeys.end(),
            [&keyIDs](const std::shared_ptr<crypto::PublicKey>& key) {
                return std::find(keyIDs.begin(), keyIDs.end(), key->ID()) != keyIDs.end();
            }),
        roleKeys.end()
    );
    
    size_t newSize = roleKeys.size();
    utils::GetLogger().Info("Removed keys from role", utils::LogContext()
        .With("role", role)
        .With("originalKeyCount", std::to_string(originalSize))
        .With("newKeyCount", std::to_string(newSize))
        .With("removedCount", std::to_string(originalSize - newSize)));
    
    // 检查密钥是否仍被其他角色使用
    std::set<std::string> usedKeyIDs;
    for (const auto& [roleName, roleInfo] : root_->Signed.Roles) {
        if (roleName == role) continue; // 跳过当前角色
        for (const auto& key : roleInfo.Keys()) {
            usedKeyIDs.insert(key->ID());
        }
    }
    
    // 从根密钥中移除不再使用的密钥（除了root角色的密钥）
    if (role != ROOT_ROLE) {
        for (const auto& keyID : keyIDs) {
            if (usedKeyIDs.find(keyID) == usedKeyIDs.end()) {
                // 从全局密钥字典中移除密钥
                auto it = root_->Signed.Keys.find(keyID);
                if (it != root_->Signed.Keys.end()) {
                    root_->Signed.Keys.erase(it);
                    utils::GetLogger().Debug("Removed key from global keys", utils::LogContext()
                        .With("keyID", keyID));
                }
                
                // 关键修复：删除私钥文件 (对应Go版本的tr.cryptoService.RemoveKey(k))
                if (cryptoService_) {
                    auto removeErr = cryptoService_->RemoveKey(keyID);
                    if (!removeErr.ok()) {
                        utils::GetLogger().Warn("Failed to remove private key file", utils::LogContext()
                            .With("keyID", keyID)
                            .With("error", removeErr.what()));
                        // 不返回错误，因为主要目标是更新元数据
                        // 私钥文件删除失败只记录警告
                    } else {
                        utils::GetLogger().Info("Successfully removed private key file", utils::LogContext()
                            .With("keyID", keyID)
                            .With("role", role));
                    }
                }
            } else {
                utils::GetLogger().Debug("Key still in use by other roles, not removing from global keys", utils::LogContext()
                    .With("keyID", keyID));
            }
        }
    } else {
        utils::GetLogger().Debug("Root role keys are preserved during rotation", utils::LogContext()
            .With("role", role));
    }
    
    root_->Dirty = true;
    markRoleDirty(role);
    
    utils::GetLogger().Info("Successfully completed RemoveBaseKeys", utils::LogContext()
        .With("role", role));
    
    return Error();
}

// 角色管理方法实现
Result<BaseRole> Repo::GetBaseRole(const std::string& name) const {
    if (!root_) {
        return Result<BaseRole>(Error("Root metadata not loaded"));
    }
    
    return root_->BuildBaseRole(name);
}

Result<DelegationRole> Repo::GetDelegationRole(const std::string& name) const {
    // TODO: 实现委托角色查找逻辑
    // 需要遍历targets元数据中的委托信息
    return Result<DelegationRole>(Error("Delegation role lookup not implemented"));
}

std::vector<BaseRole> Repo::GetAllLoadedRoles() const {
    std::vector<BaseRole> roles;
    
    if (root_) {
        for (const auto& [roleName, role] : root_->Signed.Roles) {
            roles.push_back(role);
        }
    }
    
    return roles;
}

// 验证方法实现
Error Repo::VerifyCanSign(const std::string& roleName) const {
    auto roleResult = GetBaseRole(roleName);
    if (!roleResult.ok()) {
        return Error("Role does not exist: " + roleName);
    }
    
    const auto& role = roleResult.value();
    
    // 检查是否至少有一个可用的私钥
    for (const auto& key : role.Keys()) {
        auto privateKeyResult = cryptoService_->GetPrivateKey(key->ID());
        if (privateKeyResult.ok()) {
            return Error(); // 找到可用的私钥
        }
    }
    
    return Error("No signing keys available for role");
}


Error Repo::AddTargets(const std::string& role, const std::map<std::string, FileMeta>& targets) {
    // TODO: 验证是否可以签名该角色
    auto cantSignErr = Error(); //VerifyCanSign(role);
    bool needSign = false;
    
    // 检查角色的元数据是否存在
    auto targetsMetadata = GetTargets(role);
    if (!targetsMetadata) {
        // 如果不存在则创建
        utils::GetLogger().Info("TargetsMetadata not found for role", utils::LogContext()
            .With("role", role));
        auto initResult = InitTargets(role);
        if (!initResult.ok()) {
            return initResult.error();
        }
        targetsMetadata = GetTargets(role);
    }
    
    // 现在记录元数据（在确保非空之后）
    if (targetsMetadata) {
        utils::GetLogger().Info("targetsMetadata", utils::LogContext()
            .With("targetsMetadata", targetsMetadata->toJson().dump()));
    }
    
    std::map<std::string, FileMeta> addedTargets;
    
    // 定义添加目标的访问者函数
    auto addTargetVisitor = [&](const std::string& targetPath, const FileMeta& targetMeta) -> WalkVisitorFunc {
        return [&, targetPath, targetMeta](std::shared_ptr<SignedTargets> tgt, const DelegationRole& validRole) -> WalkResult {
            // 检查目标是否已经存在且相同
            auto existingMeta = tgt->GetMeta(targetPath);
            if (existingMeta) {
                utils::GetLogger().Info("existingMeta", utils::LogContext()
                    .With("existingMeta", existingMeta->toJson().dump()));
                utils::GetLogger().Info("targetMeta", utils::LogContext()
                    .With("targetMeta", targetMeta.toJson().dump()));
                if (existingMeta->equals(targetMeta)) {
                    // 目标已存在且相同，添加到成功列表
                    utils::GetLogger().Info("target already exists and is the same", utils::LogContext()
                        .With("targetPath", targetPath));
                    addedTargets[targetPath] = targetMeta;
                    return StopWalk{}; // StopWalk equivalent
                }
            } else {
                utils::GetLogger().Info("existingMeta is null", utils::LogContext()
                    .With("targetPath", targetPath));
                utils::GetLogger().Info("targetMeta", utils::LogContext()
                    .With("targetMeta", targetMeta.toJson().dump()));
            }
            
            needSign = true;
            if (cantSignErr.ok()) {
                utils::GetLogger().Info("add target to metadata", utils::LogContext()
                    .With("targetPath", targetPath));
                // 添加目标到元数据
                tgt->AddTarget(targetPath, targetMeta);
                // 添加到成功列表
                addedTargets[targetPath] = targetMeta;
            }
            return StopWalk{}; // StopWalk equivalent
        };
    };
    
    // 遍历所有目标并添加
    for (const auto& [path, target] : targets) {
        utils::GetLogger().Info("Begin walk targets", utils::LogContext()
            .With("path", path));
        auto walkErr = WalkTargets(path, role, addTargetVisitor(path, target));
        if (!walkErr.ok()) {
            return walkErr;
        }
       
        if (needSign && !cantSignErr.ok()) {
            return cantSignErr;
        }
    }
    utils::GetLogger().Info("End walk targets", utils::LogContext());
    
    // 检查是否所有目标都添加成功
    if (addedTargets.size() != targets.size()) {
        return Error("Could not add all targets");
    }
    
    return Error(); // 成功
}

Error Repo::RemoveTargets(const std::string& role, const std::vector<std::string>& targets) {
    // TODO: 暂时忽略 verifyCanSign 检查
    // auto cantSignErr = VerifyCanSign(role);
    // if (cantSignErr is InvalidRole) return cantSignErr;
    
    bool needSign = false;
    
    // 检查角色是否存在 (对应Go的_, ok := tr.Targets[role])
    auto roleIt = targets_.find(role);
    if (roleIt == targets_.end()) {
        // 如果角色不存在，工作已完成 (对应Go的if the role exists but metadata does not yet, then our work is done)
        return Error();
    }
    
    // 创建可复用的移除访问者函数 (对应Go的removeTargetVisitor，但移到循环外提高效率)
    auto createRemoveTargetVisitor = [&](const std::string& targetPath) -> WalkVisitorFunc {
        return [&, targetPath](std::shared_ptr<SignedTargets> tgt, 
                              const DelegationRole& validRole) -> WalkResult {
            if (!tgt) {
                return std::monostate{};
            }
            
            // 我们在遍历中已经验证了角色路径，所以只需修改元数据
            // 我们不检查目标路径与有效角色路径的匹配，因为可能处于无效状态需要修复
            // (对应Go的注释和逻辑)
            auto targetIt = tgt->Signed.targets.find(targetPath);
            if (targetIt != tgt->Signed.targets.end()) {
                // TODO: 这里应该检查 cantSignErr == nil，暂时忽略
                needSign = true;
                tgt->Signed.targets.erase(targetIt);
                tgt->Dirty = true;
            }
            
            return StopWalk{}; // 停止遍历 (对应Go的return StopWalk{})
        };
    };
    
    // 为每个目标路径执行删除操作
    for (const auto& targetPath : targets) {
        // 创建针对特定目标的访问者函数
        auto removeTargetVisitor = createRemoveTargetVisitor(targetPath);
        
        // 遍历目标 (对应Go的tr.WalkTargets("", role, removeTargetVisitor(path)))
        auto walkErr = WalkTargets("", role, removeTargetVisitor);
        if (!walkErr.ok()) {
            return walkErr;
        }
        
        // TODO: 这里应该检查 needSign && cantSignErr != nil，暂时忽略
        // if (needSign && cantSignErr != nil) return cantSignErr;
    }
    
    return Error(); // 成功
}

// 查询方法实现
FileMeta* Repo::TargetMeta(const std::string& role, const std::string& path) {
    // TODO: 实现目标元数据查找
    return nullptr;
}

std::vector<DelegationRole> Repo::TargetDelegations(const std::string& role, const std::string& path) const {
    // TODO: 实现目标委托查找
    return {};
}

// 遍历方法实现
Error Repo::WalkTargets(const std::string& targetPath, const std::string& rolePath, 
                       WalkVisitorFunc visitTargets, const std::vector<std::string>& skipRoles) {
    // 从基础targets角色开始，隐式具有""目标路径
    auto targetsRoleResult = GetBaseRole(TARGETS_ROLE);
    if (!targetsRoleResult.ok()) {
        return targetsRoleResult.error();
    }
    
    // 将targets角色作为委托角色处理，具有空路径
    std::vector<DelegationRole> roles;
    DelegationRole baseTargetsRole;
    baseTargetsRole.BaseRoleInfo = targetsRoleResult.value();
    baseTargetsRole.Name = TARGETS_ROLE;
    baseTargetsRole.Paths = {""};
    roles.push_back(baseTargetsRole);
    
    while (!roles.empty()) {
        auto role = roles.front();
        roles.erase(roles.begin());
        
        // 检查角色元数据
        auto signedTgt = GetTargets(role.Name);
        if (!signedTgt) {
            // 角色元数据在repo中不存在，继续下一个
            continue;
        }
        
        // 检查是否在所需角色子树的前缀，如果是则添加其委托角色子项并继续遍历
        std::string rolePathStr = rolePath;
        std::string roleNameStr = role.Name;
        if (rolePathStr.find(roleNameStr + "/") == 0) {
            auto validDelegations = signedTgt->GetValidDelegations(role);
            roles.insert(roles.end(), validDelegations.begin(), validDelegations.end());
            continue;
        }
        
        // 确定是否访问此角色：
        // 如果路径对指定的targetPath有效且角色为空或是子树中的路径
        // 同时检查是否选择在此遍历中跳过访问此角色
        bool shouldSkip = std::find(skipRoles.begin(), skipRoles.end(), role.Name) != skipRoles.end();
        
        if (isValidPath(targetPath, role) && isAncestorRole(role.Name, rolePath) && !shouldSkip) {
            // 如果有匹配的路径或角色名称，访问此目标并确定是否继续遍历
            auto result = visitTargets(signedTgt, role);
            
            if (std::holds_alternative<StopWalk>(result)) {
                // 如果访问者函数发出停止信号，返回nil完成遍历
                return Error();
            } else if (std::holds_alternative<Error>(result)) {
                // 传播访问者的任何错误
                return std::get<Error>(result);
            } else if (std::holds_alternative<std::monostate>(result)) {
                // 如果访问者函数发出继续信号，将此角色的委托添加到遍历中
                auto validDelegations = signedTgt->GetValidDelegations(role);
                roles.insert(roles.end(), validDelegations.begin(), validDelegations.end());
            }
        }
    }
    
    return Error();
}

bool isValidSnapshot(const Snapshot& snapshot) {
    // TODO: 实现snapshot结构验证
    return true;
}
bool isValidTimestamp(const Timestamp& timestamp) {
    // TODO: 实现timestamp结构验证
    return true;
}

// 委托管理方法实现
Error Repo::UpdateDelegationKeys(const std::string& roleName, const std::vector<std::shared_ptr<crypto::PublicKey>>& addKeys, 
                                 const std::vector<std::string>& removeKeys, int newThreshold) {
    // 验证是否为有效的委托角色 (对应Go的if !data.IsDelegation(roleName))
    if (!IsDelegation(roleName)) {
        return Error("not a valid delegated role: " + roleName);
    }
    
    // 获取父角色名称 (对应Go的parent := roleName.Parent())
    std::string parent = utils::getParentRole(roleName);
    
    utils::GetLogger().Info("UpdateDelegationKeys started", utils::LogContext()
        .With("roleName", roleName)
        .With("parent", parent)
        .With("addKeysCount", std::to_string(addKeys.size()))
        .With("removeKeysCount", std::to_string(removeKeys.size()))
        .With("newThreshold", std::to_string(newThreshold)));
    
    // 验证是否可以签名父角色 (对应Go的if err := tr.VerifyCanSign(parent); err != nil)
    auto canSignErr = VerifyCanSign(parent);
    if (!canSignErr.ok()) {
        utils::GetLogger().Error("Cannot sign parent role", utils::LogContext()
            .With("parent", parent)
            .With("error", canSignErr.what()));
        return canSignErr;
    }
    
    // 检查父角色的元数据 (对应Go的_, ok := tr.Targets[parent])
    auto parentTargets = GetTargets(parent);
    if (!parentTargets) {
        // 父角色文件可能还不存在 - 如果不存在则创建它 (对应Go的if !ok)
        utils::GetLogger().Info("Parent targets file does not exist, creating it", utils::LogContext()
            .With("parent", parent));
        
        auto initResult = InitTargets(parent);
        if (!initResult.ok()) {
            utils::GetLogger().Error("Failed to initialize parent targets", utils::LogContext()
                .With("parent", parent)
                .With("error", initResult.error().what()));
            return initResult.error();
        }
    }
    
    // 创建委托更新访问者函数 (对应Go的delegationUpdateVisitor)
    auto delegationUpdateVisitor = createDelegationUpdateVisitor(roleName, addKeys, removeKeys, 
                                                               {}, {}, false, newThreshold);
    
    // 走到这个委托的父级，因为那里存在其角色元数据
    // 我们不需要验证walker到达其期望角色，因为我们已经在VerifyCanSign中做了另一次遍历到父角色，
    // 并且可能创建了targets文件 (对应Go的注释和WalkTargets调用)
    auto walkErr = WalkTargets("", parent, delegationUpdateVisitor);
    if (!walkErr.ok()) {
        utils::GetLogger().Error("Failed to walk targets for delegation update", utils::LogContext()
            .With("roleName", roleName)
            .With("parent", parent)
            .With("error", walkErr.what()));
        return walkErr;
    }
    
    utils::GetLogger().Info("UpdateDelegationKeys completed successfully", utils::LogContext()
        .With("roleName", roleName)
        .With("parent", parent));
    
    return Error(); // 成功
}

Error Repo::PurgeDelegationKeys(const std::string& role, const std::vector<std::string>& removeKeys) {
    // 验证是否为有效的通配符委托角色 (对应Go的if !data.IsWildDelegation(role))
    if (!IsWildDelegation(role)) {
        return Error("only wildcard roles can be used in a purge: " + role);
    }
    
    utils::GetLogger().Info("PurgeDelegationKeys started", utils::LogContext()
        .With("role", role)
        .With("removeKeysCount", std::to_string(removeKeys.size()))
        .With("removeKeys", utils::vectorToString(removeKeys)));
    
    // 创建要移除的密钥ID映射 (对应Go的removeIDs := make(map[string]struct{}))
    std::set<std::string> removeIDs;
    for (const auto& id : removeKeys) {
        removeIDs.insert(id);
    }
    
    // 获取起始角色，即通配符角色的父角色 (对应Go的start := role.Parent())
    std::string start = utils::getParentRole(role);
    
    // TUF ID到规范ID的映射缓存 (对应Go的tufIDToCanon := make(map[string]string))
    std::map<std::string, std::string> tufIDToCanon;
    
    // 创建清理密钥的访问者函数 (对应Go的purgeKeys := func)
    auto purgeKeys = [&](std::shared_ptr<SignedTargets> tgt, const DelegationRole& validRole) -> WalkResult {
        if (!tgt) {
            return Error("SignedTargets is null");
        }
        
        utils::GetLogger().Debug("Processing purge for role", utils::LogContext()
            .With("validRole", validRole.Name)
            .With("delegationKeysCount", std::to_string(tgt->Signed.delegations.Keys.size())));
        
        std::vector<std::string> deleteCandidates;
        
        // 遍历委托中的所有密钥 (对应Go的for id, key := range tgt.Signed.Delegations.Keys)
        for (const auto& [id, key] : tgt->Signed.delegations.Keys) {
            std::string canonID;
            
            // 检查是否已缓存规范ID (对应Go的if canonID, ok = tufIDToCanon[id]; !ok)
            auto canonIt = tufIDToCanon.find(id);
            if (canonIt != tufIDToCanon.end()) {
                canonID = canonIt->second;
            } else {
                // 计算规范密钥ID (对应Go的canonID, err := utils.CanonicalKeyID(key))
                canonID = utils::CanonicalKeyID(key);
                if (canonID.empty()) {
                    return Error("Failed to compute canonical key ID for key: " + id);
                }
                tufIDToCanon[id] = canonID;
            }
            
            // 检查是否是要删除的密钥 (对应Go的if _, ok := removeIDs[canonID]; ok)
            if (removeIDs.find(canonID) != removeIDs.end()) {
                deleteCandidates.push_back(id);
                utils::GetLogger().Debug("Found key to purge", utils::LogContext()
                    .With("tufID", id)
                    .With("canonicalID", canonID));
            }
        }
        
        // 如果没有要删除的密钥，继续处理下一个角色 (对应Go的if len(deleteCandidates) == 0)
        if (deleteCandidates.empty()) {
            utils::GetLogger().Debug("No interesting keys found in this role", utils::LogContext()
                .With("validRole", validRole.Name));
            return std::monostate{}; // 继续遍历
        }
        
        // 现在我们知道有变更，检查是否能够签名 (对应Go的if err := tr.VerifyCanSign(validRole.Name); err != nil)
        auto canSignErr = VerifyCanSign(validRole.Name);
        if (!canSignErr.ok()) {
            utils::GetLogger().Warn("Role contains keys being purged but you do not have the necessary keys present to sign it", 
                utils::LogContext()
                    .With("role", validRole.Name)
                    .With("error", canSignErr.what()));
            return std::monostate{}; // 继续遍历，不做变更
        }
        
        utils::GetLogger().Info("Purging keys from role", utils::LogContext()
            .With("role", validRole.Name)
            .With("deleteKeysCount", std::to_string(deleteCandidates.size())));
        
        // 我们知道能够签名变更，删除密钥 (对应Go的for _, id := range deleteCandidates)
        for (const auto& id : deleteCandidates) {
            auto keyIt = tgt->Signed.delegations.Keys.find(id);
            if (keyIt != tgt->Signed.delegations.Keys.end()) {
                tgt->Signed.delegations.Keys.erase(keyIt);
                utils::GetLogger().Debug("Removed key from delegation keys", utils::LogContext()
                    .With("keyID", id));
            }
        }
        
        // 从所有角色中删除候选密钥 (对应Go的for _, role := range tgt.Signed.Delegations.Roles)
        for (auto& delegationRole : tgt->Signed.delegations.Roles) {
            auto& roleKeys = delegationRole.BaseRoleInfo.Keys();
            size_t originalSize = roleKeys.size();
            
            // 移除密钥 (对应Go的role.RemoveKeys(deleteCandidates))
            roleKeys.erase(
                std::remove_if(roleKeys.begin(), roleKeys.end(),
                    [&deleteCandidates](const std::shared_ptr<crypto::PublicKey>& key) {
                        return std::find(deleteCandidates.begin(), deleteCandidates.end(), key->ID()) != deleteCandidates.end();
                    }),
                roleKeys.end()
            );
            
            size_t newSize = roleKeys.size();
            if (originalSize != newSize) {
                utils::GetLogger().Debug("Removed keys from delegation role", utils::LogContext()
                    .With("delegationRole", delegationRole.Name)
                    .With("removedCount", std::to_string(originalSize - newSize)));
            }
            
            // 检查密钥数量是否低于阈值 (对应Go的if len(role.KeyIDs) < role.Threshold)
            if (static_cast<int>(roleKeys.size()) < delegationRole.BaseRoleInfo.Threshold()) {
                utils::GetLogger().Warn("Role has fewer keys than its threshold", utils::LogContext()
                    .With("role", delegationRole.Name)
                    .With("keyCount", std::to_string(roleKeys.size()))
                    .With("threshold", std::to_string(delegationRole.BaseRoleInfo.Threshold())));
            }
        }
        
        // 标记为dirty (对应Go的tgt.Dirty = true)
        tgt->Dirty = true;
        
        return std::monostate{}; // 继续遍历
    };
    
    // 执行遍历 (对应Go的return tr.WalkTargets("", start, purgeKeys))
    auto walkErr = WalkTargets("", start, purgeKeys);
    if (!walkErr.ok()) {
        utils::GetLogger().Error("Failed to walk targets for purging delegation keys", utils::LogContext()
            .With("role", role)
            .With("start", start)
            .With("error", walkErr.what()));
        return walkErr;
    }
    
    utils::GetLogger().Info("PurgeDelegationKeys completed successfully", utils::LogContext()
        .With("role", role)
        .With("start", start));
    
    return Error(); // 成功
}

Error Repo::UpdateDelegationPaths(const std::string& roleName, const std::vector<std::string>& addPaths, 
                                  const std::vector<std::string>& removePaths, bool clearPaths) {
    // 验证是否为有效的委托角色 (对应Go的if !data.IsDelegation(roleName))
    if (!IsDelegation(roleName)) {
        return Error("not a valid delegated role: " + roleName);
    }
    
    // 获取父角色名称 (对应Go的parent := roleName.Parent())
    std::string parent = utils::getParentRole(roleName);
    
    utils::GetLogger().Info("UpdateDelegationPaths started", utils::LogContext()
        .With("roleName", roleName)
        .With("parent", parent)
        .With("addPathsCount", std::to_string(addPaths.size()))
        .With("removePathsCount", std::to_string(removePaths.size()))
        .With("clearPaths", clearPaths ? "true" : "false"));
    
    // 验证是否可以签名父角色 (对应Go的if err := tr.VerifyCanSign(parent); err != nil)
    auto canSignErr = VerifyCanSign(parent);
    if (!canSignErr.ok()) {
        utils::GetLogger().Error("Cannot sign parent role", utils::LogContext()
            .With("parent", parent)
            .With("error", canSignErr.what()));
        return canSignErr;
    }
    
    // 检查父角色的元数据 (对应Go的_, ok := tr.Targets[parent])
    auto parentTargets = GetTargets(parent);
    if (!parentTargets) {
        // 如果父目标文件不存在，这是一个错误，因为必须存在委托才能仅编辑路径
        // (对应Go的if not, this is an error because a delegation must exist to edit only paths)
        std::string errorMsg = "no valid delegated role exists: " + roleName;
        utils::GetLogger().Error(errorMsg, utils::LogContext()
            .With("parent", parent)
            .With("roleName", roleName));
        return Error(errorMsg);
    }
    
    // 创建委托更新访问者函数，只更新路径，不添加或移除密钥
    // (对应Go的delegationUpdateVisitor(roleName, data.KeyList{}, []string{}, addPaths, removePaths, clearPaths, notary.MinThreshold))
    auto delegationUpdateVisitor = createDelegationUpdateVisitor(
        roleName, 
        {}, // 空密钥列表 - 不添加密钥
        {}, // 空移除密钥列表 - 不移除密钥
        addPaths, 
        removePaths, 
        clearPaths, 
        1 // MinThreshold - 最小阈值，但在路径更新时不会改变阈值
    );
    
    // 走到这个委托的父级，因为那里存在其角色元数据
    // 我们不需要验证walker到达其期望角色，因为我们已经在VerifyCanSign中做了另一次遍历到父角色
    // (对应Go的注释和WalkTargets调用)
    auto walkErr = WalkTargets("", parent, delegationUpdateVisitor);
    if (!walkErr.ok()) {
        utils::GetLogger().Error("Failed to walk targets for delegation paths update", utils::LogContext()
            .With("roleName", roleName)
            .With("parent", parent)
            .With("error", walkErr.what()));
        return walkErr;
    }
    
    utils::GetLogger().Info("UpdateDelegationPaths completed successfully", utils::LogContext()
        .With("roleName", roleName)
        .With("parent", parent));
    
    return Error(); // 成功
}

Error Repo::DeleteDelegation(const std::string& roleName) {
    // 验证是否为有效的委托角色 (对应Go的if !data.IsDelegation(roleName))
    if (!IsDelegation(roleName)) {
        return Error("not a valid delegated role: " + roleName);
    }
    
    // 获取父角色名称 (对应Go的parent := roleName.Parent())
    std::string parent = utils::getParentRole(roleName);
    
    utils::GetLogger().Info("DeleteDelegation started", utils::LogContext()
        .With("roleName", roleName)
        .With("parent", parent));
    
    // 验证是否可以签名父角色 (对应Go的if err := tr.VerifyCanSign(parent); err != nil)
    auto canSignErr = VerifyCanSign(parent);
    if (!canSignErr.ok()) {
        utils::GetLogger().Error("Cannot sign parent role", utils::LogContext()
            .With("parent", parent)
            .With("error", canSignErr.what()));
        return canSignErr;
    }
    
    // 从Targets映射和Snapshot中删除委托数据 - 如果它们不存在，这些是无操作
    // (对应Go的delete delegated data from Targets map and Snapshot - if they don't exist, these are no-op)
    auto targetsIt = targets_.find(roleName);
    if (targetsIt != targets_.end()) {
        targets_.erase(targetsIt);
        utils::GetLogger().Debug("Removed delegation from targets map", utils::LogContext()
            .With("roleName", roleName));
    }
    
    // 从快照中删除元数据 (对应Go的tr.Snapshot.DeleteMeta(roleName))
    if (snapshot_) {
        snapshot_->DeleteMeta(roleName);
        utils::GetLogger().Debug("Removed delegation meta from snapshot", utils::LogContext()
            .With("roleName", roleName));
    }
    
    // 获取父角色的targets (对应Go的p, ok := tr.Targets[parent])
    auto parentTargets = GetTargets(parent);
    if (!parentTargets) {
        // 如果没有父元数据（角色虽然存在），那么这就算完成了
        // (对应Go的if there is no parent metadata (the role exists though), then this is as good as done)
        utils::GetLogger().Info("Parent metadata does not exist, deletion considered complete", utils::LogContext()
            .With("parent", parent)
            .With("roleName", roleName));
        return Error(); // 成功
    }
    
    // 查找要删除的角色在委托列表中的索引 (对应Go的foundAt := utils.FindRoleIndex)
    int foundAt = -1;
    for (size_t i = 0; i < parentTargets->Signed.delegations.Roles.size(); ++i) {
        if (parentTargets->Signed.delegations.Roles[i].Name == roleName) {
            foundAt = static_cast<int>(i);
            break;
        }
    }
    
    if (foundAt >= 0) {
        utils::GetLogger().Debug("Found delegation role to delete", utils::LogContext()
            .With("roleName", roleName)
            .With("index", std::to_string(foundAt)));
        
        // 从委托角色列表中移除角色 (对应Go的slice out deleted role)
        auto& roles = parentTargets->Signed.delegations.Roles;
        
        // 创建新的角色列表，排除要删除的角色
        // (对应Go的roles = append(roles, p.Signed.Delegations.Roles[:foundAt]...)
        //     if foundAt+1 < len(p.Signed.Delegations.Roles) { roles = append(roles, p.Signed.Delegations.Roles[foundAt+1:]...) })
        std::vector<DelegationRole> newRoles;
        
        // 添加删除位置之前的角色
        for (int i = 0; i < foundAt; ++i) {
            newRoles.push_back(roles[i]);
        }
        
        // 添加删除位置之后的角色
        for (size_t i = foundAt + 1; i < roles.size(); ++i) {
            newRoles.push_back(roles[i]);
        }
        
        // 替换角色列表
        roles = std::move(newRoles);
        
        // 移除未使用的密钥 (对应Go的utils.RemoveUnusedKeys(p))
        removeUnusedKeys(parentTargets);
        
        // 标记为dirty (对应Go的p.Dirty = true)
        parentTargets->Dirty = true;
        
        utils::GetLogger().Info("Successfully removed delegation role", utils::LogContext()
            .With("roleName", roleName)
            .With("remainingRolesCount", std::to_string(roles.size())));
    } else {
        // 如果角色没有找到，它就算已经删除了 (对应Go的if the role wasn't found, it's a good as deleted)
        utils::GetLogger().Info("Delegation role not found in parent, considered already deleted", utils::LogContext()
            .With("roleName", roleName)
            .With("parent", parent));
    }
    
    utils::GetLogger().Info("DeleteDelegation completed successfully", utils::LogContext()
        .With("roleName", roleName)
        .With("parent", parent));
    
    return Error(); // 成功
}

// 元数据更新方法实现
Error Repo::UpdateSnapshot(const std::string& role, const std::shared_ptr<Signed>& s) {
    if (!snapshot_) {
        return Error("Snapshot metadata not loaded");
    }
    
    // 序列化Signed对象
    auto jsonData = s->Serialize();
    if (jsonData.empty()) {
        return Error("Failed to serialize signed data");
    }
    
    // 创建FileMeta
    auto metaResult = NewFileMeta(jsonData, {"sha256", "sha512"});
    if (!metaResult.ok()) {
        return Error("Failed to create file meta: " + metaResult.error().what());
    }
    
    // 更新snapshot的meta
    snapshot_->Signed.Meta[role + ".json"] = metaResult.value();
    snapshot_->Dirty = true;
    return Error();
}

Error Repo::UpdateTimestamp(const std::shared_ptr<Signed>& s) {
    if (!timestamp_) {
        return Error("Timestamp metadata not loaded");
    }
    
    // 序列化Signed对象
    auto jsonData = s->Serialize();
    if (jsonData.empty()) {
        return Error("Failed to serialize signed data");
    }
    
    // 创建FileMeta
    auto metaResult = NewFileMeta(jsonData, {"sha256", "sha512"});
    if (!metaResult.ok()) {
        return Error("Failed to create file meta: " + metaResult.error().what());
    }
    
    // 更新timestamp的meta（固定为snapshot.json）
    timestamp_->Signed.Meta["snapshot.json"] = metaResult.value();
    timestamp_->Dirty = true;
    return Error();
}

// 签名方法实现
Result<std::shared_ptr<Signed>> Repo::SignRoot(const std::chrono::time_point<std::chrono::system_clock>& expires) {
    if (!root_) {
        return Result<std::shared_ptr<Signed>>(Error("Root metadata not loaded"));
    }
    
    // 复制当前Root对象，避免直接修改
    auto rootBytes = root_->Serialize(); //
    if (rootBytes.empty()) {
        return Result<std::shared_ptr<Signed>>(Error("Failed to serialize current root"));
    }
    
    auto tempRoot = std::make_shared<SignedRoot>();
    if (!tempRoot->Deserialize(rootBytes)) {
        return Result<std::shared_ptr<Signed>>(Error("Failed to deserialize root copy"));
    }
    
    // 获取当前root role的密钥信息
    auto currRootResult = GetBaseRole(ROOT_ROLE);
    if (!currRootResult.ok()) {
        return Result<std::shared_ptr<Signed>>(currRootResult.error());
    }
    const auto& currRoot = currRootResult.value();
    
    std::vector<BaseRole> rolesToSignWith;
    
    // 检查是否为密钥轮换
    // 如果root role的密钥集或threshold发生变化，需要使用旧密钥对新root再签一遍
    if (!originalRootRole_.Equals(currRoot)) {
        rolesToSignWith.push_back(originalRootRole_);
    }
    
    // 更新过期时间和版本号
    tempRoot->Signed.Common.Expires = expires;
    tempRoot->Signed.Common.Version++;
    rolesToSignWith.push_back(currRoot);

    // 转换为Signed对象进行签名
    auto signedResult = tempRoot->ToSigned();
    if (!signedResult.ok()) {
        return Result<std::shared_ptr<Signed>>(signedResult.error());
    }
    
    // 进行签名
    auto signResult = sign(signedResult.value(), rolesToSignWith, {});
    if (!signResult.ok()) {
        return Result<std::shared_ptr<Signed>>(signResult.error());
    }
    
    // 更新root对象
    root_ = tempRoot;
    root_->Signatures = signResult.value()->Signatures;
    originalRootRole_ = currRoot;
    
    return signResult;
}

Result<std::shared_ptr<Signed>> Repo::SignTargets(const std::string& role, const std::chrono::time_point<std::chrono::system_clock>& expires) {
    auto targets = GetTargets(role);
    if (!targets) {
        return Result<std::shared_ptr<Signed>>(Error("SignTargets called with non-existent targets role"));
    }
    
    // 更新过期时间和版本号
    targets->Signed.Common.Expires = expires;
    targets->Signed.Common.Version++;
    
    // 转换为Signed对象
    auto signedResult = targets->ToSigned();
    if (!signedResult.ok()) {
        return Result<std::shared_ptr<Signed>>(signedResult.error());
    }
    
    // 获取角色信息
    BaseRole targetsRole;
    Error err;
    if (role == TARGETS_ROLE) {
        auto roleResult = GetBaseRole(role);
        if (!roleResult.ok()) {
            return Result<std::shared_ptr<Signed>>(roleResult.error());
        }
        targetsRole = roleResult.value();
    } else {
        // 委托角色处理
        auto delegationResult = GetDelegationRole(role);
        if (!delegationResult.ok()) {
            return Result<std::shared_ptr<Signed>>(delegationResult.error());
        }
        targetsRole = delegationResult.value().BaseRoleInfo;
    }
    
    // 进行签名
    auto signResult = sign(signedResult.value(), {targetsRole}, {});
    if (!signResult.ok()) {
        return Result<std::shared_ptr<Signed>>(signResult.error());
    }
    
    // 更新签名
    targets->Signatures = signResult.value()->Signatures;
    return signResult;
}

Result<std::shared_ptr<Signed>> Repo::SignSnapshot(const std::chrono::time_point<std::chrono::system_clock>& expires) {
    if (!snapshot_) {
        return Result<std::shared_ptr<Signed>>(Error("Snapshot metadata not loaded"));
    }
    
    // 更新snapshot基于当前的root和targets
    auto signedRootResult = root_->ToSigned();
    if (!signedRootResult.ok()) {
        return Result<std::shared_ptr<Signed>>(signedRootResult.error());
    }
    
    auto updateErr = UpdateSnapshot(ROOT_ROLE, signedRootResult.value());
    if (!updateErr.ok()) {
        return Result<std::shared_ptr<Signed>>(updateErr);
    }
    root_->Dirty = false; // root dirty until changes captured in snapshot
    
    // 更新所有targets
    for (auto& [role, targets] : targets_) {
        auto signedTargetsResult = targets->ToSigned();
        if (!signedTargetsResult.ok()) {
            return Result<std::shared_ptr<Signed>>(signedTargetsResult.error());
        }
        
        auto updateErr = UpdateSnapshot(role, signedTargetsResult.value());
        if (!updateErr.ok()) {
            return Result<std::shared_ptr<Signed>>(updateErr);
        }
        targets->Dirty = false;
    }
    
    // 更新过期时间和版本号
    snapshot_->Signed.Common.Expires = expires;
    snapshot_->Signed.Common.Version++;
    
    // 转换为Signed对象
    auto signedResult = snapshot_->ToSigned();
    if (!signedResult.ok()) {
        return Result<std::shared_ptr<Signed>>(signedResult.error());
    }
    
    // 获取snapshot角色
    auto snapshotRoleResult = GetBaseRole(SNAPSHOT_ROLE);
    if (!snapshotRoleResult.ok()) {
        return Result<std::shared_ptr<Signed>>(snapshotRoleResult.error());
    }
    
    // 进行签名
    auto signResult = sign(signedResult.value(), {snapshotRoleResult.value()}, {});
    if (!signResult.ok()) {
        return Result<std::shared_ptr<Signed>>(signResult.error());
    }
    
    // 更新签名
    snapshot_->Signatures = signResult.value()->Signatures;
    return signResult;
}

Result<std::shared_ptr<Signed>> Repo::SignTimestamp(const std::chrono::time_point<std::chrono::system_clock>& expires) {
    if (!timestamp_) {
        return Result<std::shared_ptr<Signed>>(Error("Timestamp metadata not loaded"));
    }
    
    // 更新timestamp基于当前的snapshot
    auto signedSnapshotResult = snapshot_->ToSigned();
    if (!signedSnapshotResult.ok()) {
        return Result<std::shared_ptr<Signed>>(signedSnapshotResult.error());
    }
    
    auto updateErr = UpdateTimestamp(signedSnapshotResult.value());
    if (!updateErr.ok()) {
        return Result<std::shared_ptr<Signed>>(updateErr);
    }
    
    // 更新过期时间和版本号
    timestamp_->Signed.Common.Expires = expires;
    timestamp_->Signed.Common.Version++;
    
    // 转换为Signed对象
    auto signedResult = timestamp_->ToSigned();
    if (!signedResult.ok()) {
        return Result<std::shared_ptr<Signed>>(signedResult.error());
    }
    
    // 获取timestamp角色
    auto timestampRoleResult = GetBaseRole(TIMESTAMP_ROLE);
    if (!timestampRoleResult.ok()) {
        return Result<std::shared_ptr<Signed>>(timestampRoleResult.error());
    }
    
    // 进行签名
    auto signResult = sign(signedResult.value(), {timestampRoleResult.value()}, {});
    if (!signResult.ok()) {
        return Result<std::shared_ptr<Signed>>(signResult.error());
    }
    
    // 更新签名
    timestamp_->Signatures = signResult.value()->Signatures;
    snapshot_->Dirty = false; // snapshot is dirty until changes have been captured in timestamp
    return signResult;
}

// 私有方法实现

// createDelegationUpdateVisitor 创建委托更新访问者函数 (对应Go的delegationUpdateVisitor)
WalkVisitorFunc Repo::createDelegationUpdateVisitor(
    const std::string& roleName,
    const std::vector<std::shared_ptr<crypto::PublicKey>>& addKeys,
    const std::vector<std::string>& removeKeys,
    const std::vector<std::string>& addPaths,
    const std::vector<std::string>& removePaths,
    bool clearAllPaths,
    int newThreshold) {
    
    return [=](std::shared_ptr<SignedTargets> tgt, const DelegationRole& validRole) -> WalkResult {
        if (!tgt) {
            return Error("SignedTargets is null");
        }
        
        utils::GetLogger().Debug("Processing delegation update", utils::LogContext()
            .With("roleName", roleName)
            .With("validRole", validRole.Name)
            .With("addKeysCount", std::to_string(addKeys.size()))
            .With("removeKeysCount", std::to_string(removeKeys.size())));
        
        // 验证在这个受限制的validRole下添加路径的变更，拒绝无效的路径添加
        // (对应Go的if len(addPaths) != len(data.RestrictDelegationPathPrefixes(validRole.Paths, addPaths)))
        auto restrictedPaths = RestrictDelegationPathPrefixes(validRole.Paths, addPaths);
        if (restrictedPaths.size() != addPaths.size()) {
            std::string errorMsg = "invalid paths to add to role: " + roleName;
            utils::GetLogger().Error(errorMsg, utils::LogContext()
                .With("validRolePaths", utils::vectorToString(validRole.Paths))
                .With("addPaths", utils::vectorToString(addPaths))
                .With("restrictedPaths", utils::vectorToString(restrictedPaths)));
            return Error(errorMsg);
        }
        
        // 尝试找到委托并使用我们的变更列表修改它 (对应Go的Try to find the delegation and amend it)
        DelegationRole* delgRole = nullptr;
        DelegationRole workingRole; // 工作副本
        
        for (auto& role : tgt->Signed.delegations.Roles) {
            if (role.Name == roleName) {
                utils::GetLogger().Debug("Found existing delegation role", utils::LogContext()
                    .With("roleName", roleName));
                
                // 制作副本并操作这个角色直到我们验证变更 (对应Go的Make a copy and operate on this role)
                workingRole = role; // 复制构造
                
                // 移除路径 (对应Go的delgRole.RemovePaths(removePaths))
                for (const auto& removePath : removePaths) {
                    auto it = std::find(workingRole.Paths.begin(), workingRole.Paths.end(), removePath);
                    if (it != workingRole.Paths.end()) {
                        workingRole.Paths.erase(it);
                    }
                }
                
                // 清除所有路径 (对应Go的if clearAllPaths)
                if (clearAllPaths) {
                    workingRole.Paths.clear();
                }
                
                // 添加路径 (对应Go的delgRole.AddPaths(addPaths))
                for (const auto& addPath : addPaths) {
                    if (std::find(workingRole.Paths.begin(), workingRole.Paths.end(), addPath) == workingRole.Paths.end()) {
                        workingRole.Paths.push_back(addPath);
                    }
                }
                
                // 移除密钥 (对应Go的delgRole.RemoveKeys(removeKeys))
                auto& roleKeys = workingRole.BaseRoleInfo.Keys();
                for (const auto& removeKeyID : removeKeys) {
                    roleKeys.erase(
                        std::remove_if(roleKeys.begin(), roleKeys.end(),
                            [&removeKeyID](const std::shared_ptr<crypto::PublicKey>& key) {
                                return key->ID() == removeKeyID;
                            }),
                        roleKeys.end()
                    );
                }
                
                delgRole = &workingRole;
                break;
            }
        }
        
        // 我们之前没有找到角色，所以创建它 (对应Go的We didn't find the role earlier, so create it)
        if (delgRole == nullptr) {
            utils::GetLogger().Debug("Creating new delegation role", utils::LogContext()
                .With("roleName", roleName)
                .With("newThreshold", std::to_string(newThreshold)));
            
            // 创建新角色 (对应Go的data.NewRole)
            std::vector<std::string> addKeyIDs;
            for (const auto& key : addKeys) {
                addKeyIDs.push_back(key->ID());
            }
            
            // 创建BaseRole
            BaseRole newBaseRole(roleName, newThreshold, addKeys);
            
            // 创建DelegationRole
            workingRole.Name = roleName;
            workingRole.BaseRoleInfo = newBaseRole;
            workingRole.Paths = addPaths;
            
            delgRole = &workingRole;
        }
        
        // 将密钥ID添加到角色，将密钥本身添加到父级 (对应Go的Add the key IDs to the role and the keys themselves to the parent)
        auto& roleKeys = delgRole->BaseRoleInfo.Keys();
        for (const auto& key : addKeys) {
            // 检查密钥是否已存在 (对应Go的if !utils.StrSliceContains(delgRole.KeyIDs, k.ID()))
            bool keyExists = false;
            for (const auto& existingKey : roleKeys) {
                if (existingKey->ID() == key->ID()) {
                    keyExists = true;
                    break;
                }
            }
            
            if (!keyExists) {
                roleKeys.push_back(key);
            }
        }
        
        // 确保我们仍然有一个有效的角色 (对应Go的Make sure we have a valid role still)
        if (static_cast<int>(roleKeys.size()) < delgRole->BaseRoleInfo.Threshold()) {
            utils::GetLogger().Warn("Role has fewer keys than its threshold", utils::LogContext()
                .With("roleName", delgRole->Name)
                .With("keyCount", std::to_string(roleKeys.size()))
                .With("threshold", std::to_string(delgRole->BaseRoleInfo.Threshold())));
        }
        
        // 注意：这个闭包在这点之后不能出错，因为我们已经承诺编辑repo对象中的SignedTargets元数据
        // 与更新此委托相关的任何错误必须在此点之前发生 (对应Go的注释)
        
        // 如果我们所有的变更都有效，我们应该编辑实际的SignedTargets以匹配我们的副本
        // (对应Go的If all of our changes were valid, we should edit the actual SignedTargets to match our copy)
        
        // 添加密钥到父级委托密钥映射 (对应Go的for _, k := range addKeys)
        for (const auto& key : addKeys) {
            tgt->Signed.delegations.Keys[key->ID()] = key;
        }
        
        // 查找并更新或添加角色 (对应Go的foundAt := utils.FindRoleIndex)
        bool found = false;
        for (size_t i = 0; i < tgt->Signed.delegations.Roles.size(); ++i) {
            if (tgt->Signed.delegations.Roles[i].Name == delgRole->Name) {
                tgt->Signed.delegations.Roles[i] = *delgRole;
                found = true;
                utils::GetLogger().Debug("Updated existing delegation role", utils::LogContext()
                    .With("roleName", delgRole->Name)
                    .With("index", std::to_string(i)));
                break;
            }
        }
        
        if (!found) {
            tgt->Signed.delegations.Roles.push_back(*delgRole);
            utils::GetLogger().Debug("Added new delegation role", utils::LogContext()
                .With("roleName", delgRole->Name));
        }
        
        // 标记为dirty (对应Go的tgt.Dirty = true)
        tgt->Dirty = true;
        
        // 移除未使用的密钥 (对应Go的utils.RemoveUnusedKeys(tgt))
        removeUnusedKeys(tgt);
        
        utils::GetLogger().Debug("Delegation update completed successfully", utils::LogContext()
            .With("roleName", roleName));
        
        return StopWalk{}; // 停止遍历 (对应Go的return StopWalk{})
    };
}

// removeUnusedKeys 移除未使用的密钥 (对应Go的utils.RemoveUnusedKeys)
void Repo::removeUnusedKeys(std::shared_ptr<SignedTargets> tgt) {
    if (!tgt) {
        return;
    }
    
    // 收集所有正在使用的密钥ID
    std::set<std::string> usedKeyIDs;
    for (const auto& role : tgt->Signed.delegations.Roles) {
        for (const auto& key : role.BaseRoleInfo.Keys()) {
            usedKeyIDs.insert(key->ID());
        }
    }
    
    // 移除未使用的密钥
    auto& keys = tgt->Signed.delegations.Keys;
    for (auto it = keys.begin(); it != keys.end();) {
        if (usedKeyIDs.find(it->first) == usedKeyIDs.end()) {
            utils::GetLogger().Debug("Removing unused delegation key", utils::LogContext()
                .With("keyID", it->first));
            it = keys.erase(it);
        } else {
            ++it;
        }
    }
}

void Repo::markRoleDirty(const std::string& role) {
    if (role == SNAPSHOT_ROLE) {
        if (snapshot_) {
            snapshot_->Dirty = true;
        }
    } else if (role == TARGETS_ROLE) {
        if (auto targets = GetTargets(TARGETS_ROLE)) {
            targets->Dirty = true;
        }
    } else if (role == TIMESTAMP_ROLE) {
        if (timestamp_) {
            timestamp_->Dirty = true;
        }
    }
}

Result<std::shared_ptr<Signed>> Repo::sign(std::shared_ptr<Signed> signedData, 
                                          const std::vector<BaseRole>& roles, 
                                          const std::vector<std::shared_ptr<crypto::PublicKey>>& optionalKeys) {
    if (!signedData) {
        return Result<std::shared_ptr<Signed>>(Error("Signed data is null"));
    }
    
    // 构建validKeys列表，包含optionalKeys
    std::vector<std::shared_ptr<crypto::PublicKey>> validKeys = optionalKeys;
    
    // 为每个角色进行签名
    for (const auto& role : roles) {
        // 获取当前role应使用的公钥（从role定义中获取）
        auto roleKeys = role.Keys();
        
        // 将roleKeys添加到validKeys中
        validKeys.insert(validKeys.end(), roleKeys.begin(), roleKeys.end());
        
        // 调用crypto::Sign函数进行签名
        // 将一组私钥应用到待签名的元数据上，并确保满足最小签名数要求，同时清理掉无效签名
        auto signError = crypto::Sign(cryptoService_, signedData, roleKeys, role.Threshold(), validKeys);
        if (!signError.ok()) {
            return Result<std::shared_ptr<Signed>>(signError);
        }
    }
    
    // 尝试用optionalKeys签名，但即使失败也不报错
    // 额外签名（兼容性）
    // - 尝试用optionalKeys签名，但即使失败也不报错
    // - 典型用途：密钥轮换过程旧key仍需签名一次，兼容旧客户端读取
    crypto::Sign(cryptoService_, signedData, optionalKeys, 0, validKeys);
    
    return Result<std::shared_ptr<Signed>>(signedData);
}

bool Repo::isValidPath(const std::string& candidatePath, const DelegationRole& delgRole) const {
    return candidatePath.empty() || delgRole.CheckPaths(candidatePath);
}

bool Repo::isAncestorRole(const std::string& candidateChild, const std::string& candidateAncestor) const {
    std::string childStr = candidateChild;
    std::string ancestorStr = candidateAncestor;
    
    // 如果ancestor为空，或者相等，或者child是ancestor的子角色
    return ancestorStr.empty() || 
           candidateAncestor == candidateChild || 
           childStr.find(ancestorStr + "/") == 0;
}

// 角色验证函数实现
bool IsDelegation(const std::string& role) {
    std::string strRole = role;
    std::string targetsBase = TARGETS_ROLE + "/";
    
    // 检查是否以"targets/"开头
    if (strRole.find(targetsBase) != 0) {
        return false;
    }
    
    // 检查字符是否在白名单中 (对应Go的delegationRegexp.MatchString)
    // Go的正则表达式: "^[-a-z0-9_/]+$"
    for (char c : strRole) {
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '/')) {
            return false;
        }
    }
    
    // 限制完整角色字符串长度为255字符 (对应Go的len(role) < 256)
    if (strRole.length() >= 256) {
        return false;
    }
    
    // 检查路径是否干净 (对应Go的path.Clean(strRole) == strRole)
    // 移除 ., .., 多余的斜杠和尾随斜杠
    std::string path = utils::cleanPath(strRole);
    if (path != strRole) {
        return false;
    }
    
    return true;
}

bool IsWildDelegation(const std::string& role) {
    std::string strRole = role;
    
    // 检查路径是否干净 (对应Go的path.Clean(role.String()) != role.String())
    if (utils::cleanPath(strRole) != strRole) {
        return false;
    }
    
    // 获取父角色 (对应Go的role.Parent())
    std::string base = utils::getParentRole(role);
    
    // 检查父角色是否是委托角色或者是CanonicalTargetsRole
    if (!(IsDelegation(base) || base == TARGETS_ROLE)) {
        return false;
    }
    
    // 检查是否以"/*"结尾 (对应Go的role[len(role)-2:] == "/*")
    if (strRole.length() < 2) {
        return false;
    }
    
    return strRole.substr(strRole.length() - 2) == "/*";
}

// TUF对象创建辅助函数实现
std::shared_ptr<SignedRoot> NewRoot(const std::map<std::string, std::shared_ptr<crypto::PublicKey>>& keys,
                                   const std::map<std::string, BaseRole>& roles, 
                                   bool consistent) {
    auto newRoot = std::make_shared<SignedRoot>();
    
    // 初始化Root结构体
    newRoot->Signed.Common.Type = "root";
    newRoot->Signed.Common.Version = 0; // Go版本中初始版本为0
    newRoot->Signed.Common.Expires = std::chrono::system_clock::now() + std::chrono::hours(24 * 365 * 10); // 10年过期
    
    // 设置密钥
    newRoot->Signed.Keys = keys;
    
    // 设置角色
    newRoot->Signed.Roles = roles;
    
    // 设置一致性快照标志
    newRoot->Signed.ConsistentSnapshot = consistent;
    
    // 初始化签名数组
    newRoot->Signatures.clear();
    
    // 标记为dirty
    newRoot->Dirty = true;
    
    return newRoot;
}

std::shared_ptr<SignedTargets> NewTargets() {
    auto newTargets = std::make_shared<SignedTargets>();
    
    // 初始化Targets结构体
    newTargets->Signed.Common.Type = "targets";
    newTargets->Signed.Common.Version = 0; // Go版本中初始版本为0
    newTargets->Signed.Common.Expires = std::chrono::system_clock::now() + std::chrono::hours(24 * 365); // 1年过期
    
    // 初始化targets为空
    newTargets->Signed.targets.clear();
    
    // 初始化delegations为空
    newTargets->Signed.delegations.Keys.clear();
    newTargets->Signed.delegations.Roles.clear();
    
    // 初始化签名数组
    newTargets->Signatures.clear();
    
    // 标记为dirty
    newTargets->Dirty = true;
    
    return newTargets;
}

Result<std::shared_ptr<SignedSnapshot>> NewSnapshot(const std::shared_ptr<Signed>& root,
                                                    const std::shared_ptr<Signed>& targets) {
    auto newSnapshot = std::make_shared<SignedSnapshot>();
    
    // 初始化Snapshot结构体
    newSnapshot->Signed.Common.Type = "snapshot";
    newSnapshot->Signed.Common.Version = 0; // Go版本中初始版本为0
    newSnapshot->Signed.Common.Expires = std::chrono::system_clock::now() + std::chrono::hours(24 * 365 * 3); // 3年过期
    
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
    newSnapshot->Signed.Meta["root.json"] = rootMetaResult.value();
    newSnapshot->Signed.Meta["targets.json"] = targetsMetaResult.value();
    
    // 初始化签名数组
    newSnapshot->Signatures.clear();
    
    // 标记为dirty
    newSnapshot->Dirty = true;
    
    return Result<std::shared_ptr<SignedSnapshot>>(newSnapshot);
}

Result<std::shared_ptr<SignedTimestamp>> NewTimestamp(const std::shared_ptr<Signed>& snapshot) {
    auto newTimestamp = std::make_shared<SignedTimestamp>();
    
    // 初始化Timestamp结构体
    newTimestamp->Signed.Common.Type = "timestamp";
    newTimestamp->Signed.Common.Version = 0; // Go版本中初始版本为0
    newTimestamp->Signed.Common.Expires = std::chrono::system_clock::now() + std::chrono::hours(24 * 14); // 14天过期
    
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
    newTimestamp->Signed.Meta["snapshot.json"] = snapshotMetaResult.value();
    
    // 初始化签名数组
    newTimestamp->Signatures.clear();
    
    // 标记为dirty
    newTimestamp->Dirty = true;
    
    return Result<std::shared_ptr<SignedTimestamp>>(newTimestamp);
}

// 检查哈希结构的有效性 - 对应Go版本的CheckValidHashStructures
Error CheckValidHashStructures(const std::map<std::string, std::vector<uint8_t>>& hashes) {
    int cnt = 0;
    
    for (const auto& [alg, hash] : hashes) {
        if (alg == "sha256") {
            if (hash.size() != SHA256_DIGEST_LENGTH) {
                return Error("Invalid sha256 checksum");
            }
            cnt++;
        } else if (alg == "sha512") {
            if (hash.size() != SHA512_DIGEST_LENGTH) {
                return Error("Invalid sha512 checksum");
            }
            cnt++;
        }
    }
    
    if (cnt == 0) {
        return Error("at least one supported hash needed");
    }
    
    return Error(); // 成功
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

// Signed 结构体方法实现
std::vector<uint8_t> Signed::Serialize() const {
    json j = toJson();
    
    std::string result = j.dump();
    return std::vector<uint8_t>(result.begin(), result.end());
}

bool Signed::Deserialize(const std::vector<uint8_t>& data) {
    try {
        std::string jsonStr(data.begin(), data.end());
        json j = json::parse(jsonStr);
        fromJson(j);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

json Signed::toJson() const {
    json j;
    j["signatures"] = json::array();
    for (const auto& sig : Signatures) {
        j["signatures"].push_back(sig.toJson());
    }
    
    // 将signedData作为原始JSON插入
    if (!signedData.empty()) {
        std::string jsonStr(signedData.begin(), signedData.end());
        j["signed"] = json::parse(jsonStr);
    }
    return j;
    // if (!signedData.empty()) {
    //     std::string jsonStr(signedData.begin(), signedData.end());
    //     return json::parse(jsonStr);
    // }
    // return json::object();
}

void Signed::fromJson(const json& j) {
    if (j.contains("signatures")) {
        Signatures.clear();
        for (const auto& sigJson : j["signatures"]) {
            Signature sig;
            sig.fromJson(sigJson);
            Signatures.push_back(sig);
        }
    }
    
    if (j.contains("signed")) {
        std::string signedStr = j["signed"].dump();
        signedData = std::vector<uint8_t>(signedStr.begin(), signedStr.end());
    }
    // std::string jsonStr = j.dump();
    // signedData = std::vector<uint8_t>(jsonStr.begin(), jsonStr.end());
}

// RootFromSigned fully unpacks a Signed object into a SignedRoot and ensures
// that it is a valid SignedRoot - 对应Go版本的data.RootFromSigned函数
Result<std::shared_ptr<SignedRoot>> RootFromSigned(std::shared_ptr<Signed> s) {
    if (!s) {
        utils::GetLogger().Error("RootFromSigned: Signed object is null");
        return Result<std::shared_ptr<SignedRoot>>(Error("signed object is null"));
    }
    
    // 检查signed data是否为空（对应Go版本的 if s.Signed == nil）
    if (s->signedData.empty()) {
        utils::GetLogger().Error("RootFromSigned: root file contained an empty payload");
        return Result<std::shared_ptr<SignedRoot>>(Error("root file contained an empty payload"));
    }
    
    utils::GetLogger().Debug("RootFromSigned: Parsing signed root data");
    
    try {
        // 创建Root对象并从JSON反序列化（对应Go版本的defaultSerializer.Unmarshal）
        Root r;
        json rootJson = json::parse(s->signedData.begin(), s->signedData.end());
        r.fromJson(rootJson);
        
        utils::GetLogger().Debug("RootFromSigned: Successfully parsed root structure");
        
        // 创建SignedRoot对象并复制签名（对应Go版本的copy(sigs, s.Signatures)）
        auto signedRoot = std::make_shared<SignedRoot>();
        signedRoot->Signed = std::move(r);
        
        // 复制签名列表
        signedRoot->Signatures.clear();
        signedRoot->Signatures.reserve(s->Signatures.size());
        for (const auto& sig : s->Signatures) {
            signedRoot->Signatures.push_back(sig);
        }
        
        utils::GetLogger().Debug("RootFromSigned: Successfully created SignedRoot with " + 
                               std::to_string(signedRoot->Signatures.size()) + " signatures");
        
        return Result<std::shared_ptr<SignedRoot>>(signedRoot);
        
    } catch (const json::exception& e) {
        std::string errorMsg = "Failed to parse root JSON: " + std::string(e.what());
        utils::GetLogger().Error("RootFromSigned: " + errorMsg);
        return Result<std::shared_ptr<SignedRoot>>(Error(errorMsg));
    } catch (const std::exception& e) {
        std::string errorMsg = "Failed to create SignedRoot: " + std::string(e.what());
        utils::GetLogger().Error("RootFromSigned: " + errorMsg);
        return Result<std::shared_ptr<SignedRoot>>(Error(errorMsg));
    }
}

} // namespace tuf
} // namespace notary 