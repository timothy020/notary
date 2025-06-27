#include "notary/client/repository.hpp"
#include "notary/changelist/changelist.hpp"
#include "notary/utils/logger.hpp"
#include "notary/utils/helpers.hpp"
#include <nlohmann/json.hpp>
#include <algorithm>

namespace notary {

using json = nlohmann::json;

namespace {
// 最小阈值常量 (对应Go的notary.MinThreshold)
const int MIN_THRESHOLD = 1;

// 检查是否是有效的委托角色名称 (对应Go的data.IsDelegation)
bool IsDelegation(const std::string& role) {
    // 委托角色名称通常包含"/"分隔符，且不是基础角色
    return role != ROOT_ROLE && 
           role != TARGETS_ROLE && 
           role != SNAPSHOT_ROLE && 
           role != TIMESTAMP_ROLE &&
           role.find('/') != std::string::npos;
}

// 检查是否是通配符委托角色名称 (对应Go的data.IsWildDelegation)  
bool IsWildDelegation(const std::string& role) {
    return role.length() > 0 && role.back() == '*';
}

// addChange函数实现 - 对应Go版本的addChange函数
// 这个函数在repository.cpp中也有实现，这里为了delegation.cpp独立性而重新实现
Error addChange(std::shared_ptr<changelist::Changelist> cl, 
               std::shared_ptr<changelist::Change> c, 
               const std::vector<std::string>& roles = {}) {
    std::vector<std::string> effectiveRoles;
    
    // 如果没有指定角色，默认使用targets角色 (对应Go的data.CanonicalTargetsRole)
    if (roles.empty()) {
        effectiveRoles.push_back("targets");
    } else {
        effectiveRoles = roles;
    }
    
    std::vector<std::shared_ptr<changelist::Change>> changes;
    
    // 为每个角色创建变更并验证角色有效性
    for (const auto& role : effectiveRoles) {
        // 确保只能将targets添加到CanonicalTargetsRole或委托角色
        // (对应Go的role != data.CanonicalTargetsRole && !data.IsDelegation(role) && !data.IsWildDelegation(role)检查)
        // 对于委托操作，我们放宽这个限制，允许委托角色
        if (c->Type() == changelist::TypeTargetsTarget &&
            role != "targets" && !IsDelegation(role) && !IsWildDelegation(role)) {
            return Error("Cannot add targets to role: " + role + " - invalid role for target addition");
        }
        
        // 创建角色特定的变更 (对应Go的changelist.NewTUFChange)
        auto roleChange = std::make_shared<changelist::TUFChange>(
            c->Action(),
            role,                    // 角色作为scope
            c->Type(),
            c->Path(),
            c->Content()
        );
        
        changes.push_back(roleChange);
    }
    
    // 添加所有变更到changelist (对应Go的for _, c := range changes循环)
    for (const auto& change : changes) {
        auto err = cl->Add(change);
        if (!err.ok()) {
            return err;
        }
    }
    
    return Error(); // 成功
}

} // namespace

// TUFDelegation结构体 - 对应Go的changelist.TUFDelegation
struct TUFDelegation {
    int NewThreshold = 0;                                    // 新阈值
    std::vector<std::shared_ptr<crypto::PublicKey>> AddKeys; // 要添加的密钥
    std::vector<std::string> RemoveKeys;                     // 要移除的密钥ID
    std::vector<std::string> AddPaths;                       // 要添加的路径
    std::vector<std::string> RemovePaths;                    // 要移除的路径  
    bool ClearAllPaths = false;                              // 是否清除所有路径

    // 序列化为JSON
    std::vector<uint8_t> Serialize() const {
        json j;
        
        if (NewThreshold > 0) {
            j["Threshold"] = NewThreshold;
        }
        
        if (!AddKeys.empty()) {
            j["addKeys"] = json::array();
            for (const auto& key : AddKeys) {
                json keyJson;
                keyJson["id"] = key->ID();
                keyJson["keytype"] = key->Algorithm();
                
                // 将公钥数据转换为Base64字符串
                auto publicData = key->Public();
                std::string publicBase64 = utils::Base64Encode(publicData);
                keyJson["public"] = publicBase64;
                
                j["addKeys"].push_back(keyJson);
            }
        }
        
        if (!RemoveKeys.empty()) {
            j["removeKeys"] = RemoveKeys;
        }
        
        if (!AddPaths.empty()) {
            j["addPaths"] = AddPaths;
        }
        
        if (!RemovePaths.empty()) {
            j["removePaths"] = RemovePaths;
        }
        
        if (ClearAllPaths) {
            j["clearAllPaths"] = true;
        }
        
        std::string jsonStr = j.dump();
        return std::vector<uint8_t>(jsonStr.begin(), jsonStr.end());
    }

    // 从JSON数据反序列化
    static std::pair<TUFDelegation, Error> Deserialize(const std::vector<uint8_t>& data) {
        TUFDelegation result;
        
        try {
            // 将二进制数据转换为字符串
            std::string jsonStr(data.begin(), data.end());
            
            // 解析JSON
            json j = json::parse(jsonStr);
            
            // 解析阈值
            if (j.contains("Threshold")) {
                result.NewThreshold = j["Threshold"].get<int>();
            }
            
            // 解析要添加的密钥
            if (j.contains("addKeys")) {
                for (const auto& keyJson : j["addKeys"]) {
                    std::string keyID = keyJson["id"].get<std::string>();
                    std::string keyType = keyJson["keytype"].get<std::string>();
                    std::string publicBase64 = keyJson["public"].get<std::string>();
                    
                    // Base64解码公钥数据
                    std::vector<uint8_t> publicData = utils::Base64Decode(publicBase64);
                    
                    // 使用工厂函数创建PublicKey对象
                    auto key = crypto::NewPublicKey(keyType, publicData);
                    if (!key) {
                        return {TUFDelegation(), Error("Failed to create public key")};
                    }
                    
                    result.AddKeys.push_back(key);
                }
            }
            
            // 解析要移除的密钥ID
            if (j.contains("removeKeys")) {
                result.RemoveKeys = j["removeKeys"].get<std::vector<std::string>>();
            }
            
            // 解析要添加的路径
            if (j.contains("addPaths")) {
                result.AddPaths = j["addPaths"].get<std::vector<std::string>>();
            }
            
            // 解析要移除的路径
            if (j.contains("removePaths")) {
                result.RemovePaths = j["removePaths"].get<std::vector<std::string>>();
            }
            
            // 解析是否清除所有路径
            if (j.contains("clearAllPaths")) {
                result.ClearAllPaths = j["clearAllPaths"].get<bool>();
            }
            
            return {result, Error()};
            
        } catch (const std::exception& e) {
            return {TUFDelegation(), Error(std::string("Failed to deserialize TUFDelegation: ") + e.what())};
        }
    }
};

// AddDelegation方法实现 - 对应Go的AddDelegation
Error Repository::AddDelegation(const std::string& name, 
                               const std::vector<std::shared_ptr<crypto::PublicKey>>& delegationKeys, 
                               const std::vector<std::string>& paths) {
    try {
        // 如果有委托密钥，先添加角色和密钥 (对应Go的if len(delegationKeys) > 0)
        if (!delegationKeys.empty()) {
            auto err = AddDelegationRoleAndKeys(name, delegationKeys);
            if (err.hasError()) {
                return err;
            }
        }
        
        // 如果有路径，添加路径 (对应Go的if len(paths) > 0)
        if (!paths.empty()) {
            auto err = AddDelegationPaths(name, paths);
            if (err.hasError()) {
                return err;
            }
        }
        
        return Error(); // 成功
        
    } catch (const std::exception& e) {
        return Error(std::string("Failed to add delegation: ") + e.what());
    }
}

// AddDelegationRoleAndKeys方法实现 - 对应Go的AddDelegationRoleAndKeys
Error Repository::AddDelegationRoleAndKeys(const std::string& name, 
                                          const std::vector<std::shared_ptr<crypto::PublicKey>>& delegationKeys) {
    try {
        // 验证是否是有效的委托角色名称 (对应Go的!data.IsDelegation(name))
        if (!IsDelegation(name)) {
            return Error("Invalid delegation role name: " + name);
        }
        
        // 记录调试信息 (对应Go的logrus.Debugf)
        utils::GetLogger().Debug("Adding delegation with threshold and keys", 
            utils::LogContext()
                .With("name", name)
                .With("threshold", std::to_string(MIN_THRESHOLD))
                .With("keyCount", std::to_string(delegationKeys.size())));
        
        // 创建TUFDelegation对象 (对应Go的changelist.TUFDelegation)
        TUFDelegation tdDelegation;
        tdDelegation.NewThreshold = MIN_THRESHOLD; // 默认阈值为1，因为我们目前不允许更大的阈值
        tdDelegation.AddKeys = delegationKeys;
        
        // 序列化为JSON (对应Go的json.Marshal(&changelist.TUFDelegation{...}))
        auto tdJSON = tdDelegation.Serialize();
        if (tdJSON.empty()) {
            return Error("Failed to serialize TUFDelegation");
        }
        
        // 创建变更模板 (对应Go的template := newCreateDelegationChange(name, tdJSON))
        auto templateChange = newCreateDelegationChange(name, tdJSON);
        
        // 添加变更到changelist (对应Go的addChange(r.changelist, template, name))
        return addChange(changelist_, templateChange, {name});
        
    } catch (const std::exception& e) {
        return Error(std::string("Failed to add delegation role and keys: ") + e.what());
    }
}

// AddDelegationPaths方法实现 - 对应Go的AddDelegationPaths
Error Repository::AddDelegationPaths(const std::string& name, const std::vector<std::string>& paths) {
    try {
        // 验证是否是有效的委托角色名称 (对应Go的!data.IsDelegation(name))
        if (!IsDelegation(name)) {
            return Error("Invalid delegation role name: " + name);
        }
        
        // 记录调试信息 (对应Go的logrus.Debugf)
        utils::GetLogger().Debug("Adding paths to delegation", 
            utils::LogContext()
                .With("name", name)
                .With("pathCount", std::to_string(paths.size())));
        
        // 创建TUFDelegation对象 (对应Go的changelist.TUFDelegation)
        TUFDelegation tdDelegation;
        tdDelegation.AddPaths = paths;
        
        // 序列化为JSON (对应Go的json.Marshal(&changelist.TUFDelegation{AddPaths: paths}))
        auto tdJSON = tdDelegation.Serialize();
        if (tdJSON.empty()) {
            return Error("Failed to serialize TUFDelegation");
        }
        
        // 创建变更模板 (对应Go的template := newCreateDelegationChange(name, tdJSON))
        auto templateChange = newCreateDelegationChange(name, tdJSON);
        
        // 添加变更到changelist (对应Go的addChange(r.changelist, template, name))
        return addChange(changelist_, templateChange, {name});
        
    } catch (const std::exception& e) {
        return Error(std::string("Failed to add delegation paths: ") + e.what());
    }
}

// RemoveDelegationKeysAndPaths方法实现 - 对应Go的RemoveDelegationKeysAndPaths
Error Repository::RemoveDelegationKeysAndPaths(const std::string& name, 
                                              const std::vector<std::string>& keyIDs, 
                                              const std::vector<std::string>& paths) {
    try {
        // 如果有路径，先移除路径 (对应Go的if len(paths) > 0)
        if (!paths.empty()) {
            auto err = RemoveDelegationPaths(name, paths);
            if (err.hasError()) {
                return err;
            }
        }
        
        // 如果有密钥ID，移除密钥 (对应Go的if len(keyIDs) > 0)
        if (!keyIDs.empty()) {
            auto err = RemoveDelegationKeys(name, keyIDs);
            if (err.hasError()) {
                return err;
            }
        }
        
        return Error(); // 成功
        
    } catch (const std::exception& e) {
        return Error(std::string("Failed to remove delegation keys and paths: ") + e.what());
    }
}

// RemoveDelegationRole方法实现 - 对应Go的RemoveDelegationRole
Error Repository::RemoveDelegationRole(const std::string& name) {
    try {
        // 验证是否是有效的委托角色名称 (对应Go的!data.IsDelegation(name))
        if (!IsDelegation(name)) {
            return Error("Invalid delegation role name: " + name);
        }
        
        // 记录调试信息 (对应Go的logrus.Debugf)
        utils::GetLogger().Debug("Removing delegation", 
            utils::LogContext().With("name", name));
        
        // 创建删除变更模板 (对应Go的template := newDeleteDelegationChange(name, nil))
        auto templateChange = newDeleteDelegationChange(name, {});
        
        // 添加变更到changelist (对应Go的addChange(r.changelist, template, name))
        return addChange(changelist_, templateChange, {name});
        
    } catch (const std::exception& e) {
        return Error(std::string("Failed to remove delegation role: ") + e.what());
    }
}

// RemoveDelegationPaths方法实现 - 对应Go的RemoveDelegationPaths
Error Repository::RemoveDelegationPaths(const std::string& name, const std::vector<std::string>& paths) {
    try {
        // 验证是否是有效的委托角色名称 (对应Go的!data.IsDelegation(name))
        if (!IsDelegation(name)) {
            return Error("Invalid delegation role name: " + name);
        }
        
        // 记录调试信息 (对应Go的logrus.Debugf)
        utils::GetLogger().Debug("Removing paths from delegation", 
            utils::LogContext()
                .With("name", name)
                .With("pathCount", std::to_string(paths.size())));
        
        // 创建TUFDelegation对象 (对应Go的changelist.TUFDelegation)
        TUFDelegation tdDelegation;
        tdDelegation.RemovePaths = paths;
        
        // 序列化为JSON (对应Go的json.Marshal(&changelist.TUFDelegation{RemovePaths: paths}))
        auto tdJSON = tdDelegation.Serialize();
        if (tdJSON.empty()) {
            return Error("Failed to serialize TUFDelegation");
        }
        
        // 创建更新变更模板 (对应Go的template := newUpdateDelegationChange(name, tdJSON))
        auto templateChange = newUpdateDelegationChange(name, tdJSON);
        
        // 添加变更到changelist (对应Go的addChange(r.changelist, template, name))
        return addChange(changelist_, templateChange, {name});
        
    } catch (const std::exception& e) {
        return Error(std::string("Failed to remove delegation paths: ") + e.what());
    }
}

// RemoveDelegationKeys方法实现 - 对应Go的RemoveDelegationKeys
Error Repository::RemoveDelegationKeys(const std::string& name, const std::vector<std::string>& keyIDs) {
    try {
        // 验证是否是有效的委托角色名称或通配符委托角色名称 (对应Go的!data.IsDelegation(name) && !data.IsWildDelegation(name))
        if (!IsDelegation(name) && !IsWildDelegation(name)) {
            return Error("Invalid delegation role name: " + name);
        }
        
        // 记录调试信息 (对应Go的logrus.Debugf)
        utils::GetLogger().Debug("Removing keys from delegation", 
            utils::LogContext()
                .With("name", name)
                .With("keyIDCount", std::to_string(keyIDs.size())));
        
        // 创建TUFDelegation对象 (对应Go的changelist.TUFDelegation)
        TUFDelegation tdDelegation;
        tdDelegation.RemoveKeys = keyIDs;
        
        // 序列化为JSON (对应Go的json.Marshal(&changelist.TUFDelegation{RemoveKeys: keyIDs}))
        auto tdJSON = tdDelegation.Serialize();
        if (tdJSON.empty()) {
            return Error("Failed to serialize TUFDelegation");
        }
        
        // 创建更新变更模板 (对应Go的template := newUpdateDelegationChange(name, tdJSON))
        auto templateChange = newUpdateDelegationChange(name, tdJSON);
        
        // 添加变更到changelist (对应Go的addChange(r.changelist, template, name))
        return addChange(changelist_, templateChange, {name});
        
    } catch (const std::exception& e) {
        return Error(std::string("Failed to remove delegation keys: ") + e.what());
    }
}

// ClearDelegationPaths方法实现 - 对应Go的ClearDelegationPaths
Error Repository::ClearDelegationPaths(const std::string& name) {
    try {
        // 验证是否是有效的委托角色名称 (对应Go的!data.IsDelegation(name))
        if (!IsDelegation(name)) {
            return Error("Invalid delegation role name: " + name);
        }
        
        // 记录调试信息 (对应Go的logrus.Debugf)
        utils::GetLogger().Debug("Removing all paths from delegation", 
            utils::LogContext().With("name", name));
        
        // 创建TUFDelegation对象 (对应Go的changelist.TUFDelegation)
        TUFDelegation tdDelegation;
        tdDelegation.ClearAllPaths = true;
        
        // 序列化为JSON (对应Go的json.Marshal(&changelist.TUFDelegation{ClearAllPaths: true}))
        auto tdJSON = tdDelegation.Serialize();
        if (tdJSON.empty()) {
            return Error("Failed to serialize TUFDelegation");
        }
        
        // 创建更新变更模板 (对应Go的template := newUpdateDelegationChange(name, tdJSON))
        auto templateChange = newUpdateDelegationChange(name, tdJSON);
        
        // 添加变更到changelist (对应Go的addChange(r.changelist, template, name))
        return addChange(changelist_, templateChange, {name});
        
    } catch (const std::exception& e) {
        return Error(std::string("Failed to clear delegation paths: ") + e.what());
    }
}

// newUpdateDelegationChange方法实现 - 对应Go的newUpdateDelegationChange
std::shared_ptr<changelist::TUFChange> Repository::newUpdateDelegationChange(
    const std::string& name, const std::vector<uint8_t>& content) {
    
    return std::make_shared<changelist::TUFChange>(
        changelist::ActionUpdate,        // action = "update"
        name,                           // scope = role name
        changelist::TypeTargetsDelegation, // type = "delegation"
        "",                             // path为空，委托没有路径
        content                         // content = JSON数据
    );
}

// newCreateDelegationChange方法实现 - 对应Go的newCreateDelegationChange
std::shared_ptr<changelist::TUFChange> Repository::newCreateDelegationChange(
    const std::string& name, const std::vector<uint8_t>& content) {
    
    return std::make_shared<changelist::TUFChange>(
        changelist::ActionCreate,        // action = "create"
        name,                           // scope = role name
        changelist::TypeTargetsDelegation, // type = "delegation"
        "",                             // path为空，委托没有路径
        content                         // content = JSON数据
    );
}

// newDeleteDelegationChange方法实现 - 对应Go的newDeleteDelegationChange
std::shared_ptr<changelist::TUFChange> Repository::newDeleteDelegationChange(
    const std::string& name, const std::vector<uint8_t>& content) {
    
    return std::make_shared<changelist::TUFChange>(
        changelist::ActionDelete,        // action = "delete"
        name,                           // scope = role name
        changelist::TypeTargetsDelegation, // type = "delegation"
        "",                             // path为空，委托没有路径
        content                         // content = JSON数据 (删除时通常为空)
    );
}

} // namespace notary
