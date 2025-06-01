#include "notary/utils/helpers.hpp"
#include "notary/tuf/repo.hpp"

namespace notary {
namespace utils {

// 获取角色的默认过期时间
std::chrono::system_clock::time_point getDefaultExpiry(RoleName role) {
    auto now = std::chrono::system_clock::now();
    switch (role) {
        case RoleName::RootRole:
            return now + std::chrono::hours(24 * 365 * 10); // 10年
        case RoleName::TargetsRole:
        case RoleName::SnapshotRole:
            return now + std::chrono::hours(24 * 365 * 3);  // 3年
        case RoleName::TimestampRole:
            return now + std::chrono::hours(24 * 14);       // 14天
        default:
            return now + std::chrono::hours(24 * 365);      // 1年
    }
}

std::vector<uint8_t> serializeCanonicalRole(std::shared_ptr<tuf::Repo> tufRepo, RoleName role, const std::vector<std::shared_ptr<crypto::PublicKey>>& extraSigningKeys) {
    if (!tufRepo) {
        return {};
    }
    
    try {
        // 获取默认过期时间
        auto now = std::chrono::system_clock::now();
        std::chrono::system_clock::time_point expires = getDefaultExpiry(role);
        
        Result<std::shared_ptr<tuf::Signed>> result;
        // 根据角色类型进行签名
        switch (role) {
            case RoleName::RootRole: {
                result = tufRepo->SignRoot(expires);
                break;
            }
            case RoleName::SnapshotRole: {
                result = tufRepo->SignSnapshot(expires);
                break;
            }
            case RoleName::TargetsRole: {
                result = tufRepo->SignTargets(role, expires);
                break;
            }
            default: {
                // 返回错误：不支持的role
                result = Error("Unsupported role");
                break;
            }
        }
        
        if (!result.ok()) {
            return {};
        }
        
        // 序列化为JSON
        return result.value()->Serialize();
        
    } catch (const std::exception& e) {
        std::cerr << "Error in serializeCanonicalRole: " << e.what() << std::endl;
        return {};
    }
}

// applyChangelist函数实现 (对应Go的applyChangelist函数)
Error applyChangelist(std::shared_ptr<tuf::Repo> repo, 
                        std::shared_ptr<tuf::Repo> invalid, 
                        std::shared_ptr<changelist::Changelist> cl) {
    if (!repo || !cl) {
        return Error("Invalid parameters: repo and changelist cannot be null");
    }
    
    try {
        // 创建迭代器 (对应Go的it, err := cl.NewIterator())
        auto iterator = cl->NewIterator();
        if (!iterator) {
            return Error("Failed to create changelist iterator");
        }
        
        int index = 0;
        
        // 使用迭代器遍历变更 (对应Go的for it.HasNext())
        while (iterator->HasNext()) {
            // 获取下一个变更 (对应Go的c, err := it.Next())
            // 注意：在C++版本中，我们假设Next()方法在出错时会抛出异常或返回nullptr
            // 这与Go版本的错误处理方式不同，但符合C++的惯例
            std::shared_ptr<changelist::Change> change;
            try {
                change = iterator->Next();
            } catch (const std::exception& e) {
                return Error(std::string("Failed to get next change from iterator: ") + e.what());
            }
            
            if (!change) {
                return Error("Iterator returned null change");
            }
            
            // 检查是否是委托角色 (对应Go的isDel := data.IsDelegation(c.Scope()) || data.IsWildDelegation(c.Scope()))
            std::string scope = change->Scope();
            bool isDel = tuf::IsDelegation(stringToRole(scope)) || tuf::IsWildDelegation(stringToRole(scope));
            
            Error err;
            
            // 根据scope分发处理 (对应Go的switch语句)
            if (scope == changelist::ScopeTargets || isDel) {
                err = applyTargetsChange(repo, invalid, change);
            } else if (scope == changelist::ScopeRoot) {
                err = applyRootChange(repo, change);
            } else {
                return Error("Scope not supported: " + scope);
            }
            
            if (!err.ok()) {
                utils::GetLogger().Debug("Error attempting to apply change", utils::LogContext()
                    .With("index", std::to_string(index))
                    .With("action", change->Action())
                    .With("scope", scope)
                    .With("path", change->Path())
                    .With("type", change->Type())
                    .With("error", err.what()));
                return err;
            }
            
            index++;
        }
        
        utils::GetLogger().Debug("Applied changes", utils::LogContext()
            .With("count", std::to_string(index)));
        
        return Error(); // 成功
        
    } catch (const std::exception& e) {
        return Error(std::string("Failed to apply changelist: ") + e.what());
    }
}

// applyTargetsChange函数实现 (对应Go的applyTargetsChange函数)
Error applyTargetsChange(std::shared_ptr<tuf::Repo> repo, 
                            std::shared_ptr<tuf::Repo> invalid, 
                            std::shared_ptr<changelist::Change> change) {
    if (!repo || !change) {
        return Error("Invalid parameters");
    }
    
    std::string type = change->Type();
    
    // 根据类型分发处理 (对应Go的switch c.Type())
    if (type == changelist::TypeTargetsTarget) {
        return changeTargetMeta(repo, change);
    } else if (type == changelist::TypeTargetsDelegation) {
        return changeTargetsDelegation(repo, change);
    } else if (type == changelist::TypeWitness) {
        return witnessTargets(repo, invalid, stringToRole(change->Scope()));
    } else {
        return Error("Only target meta and delegations changes supported");
    }
}

// changeTargetMeta函数实现 (对应Go的changeTargetMeta函数)
Error changeTargetMeta(std::shared_ptr<tuf::Repo> repo, 
                        std::shared_ptr<changelist::Change> change) {
    if (!repo || !change) {
        return Error("Invalid parameters");
    }
    
    std::string action = change->Action();
    std::string path = change->Path();
    RoleName scope = stringToRole(change->Scope());
    
    try {
        if (action == changelist::ActionCreate) {
            utils::GetLogger().Info("Changelist add", utils::LogContext()
                .With("path", path));
            
            // 解析FileMeta (对应Go的json.Unmarshal(c.Content(), meta))
            std::string contentStr(change->Content().begin(), change->Content().end());
            nlohmann::json metaJson = nlohmann::json::parse(contentStr);
            
            tuf::FileMeta meta;
            meta.fromJson(metaJson);

            utils::GetLogger().Info("FileMeta", utils::LogContext()
                .With("filemeta", meta.toJson().dump()));
            
            // 创建Files映射 (对应Go的files := data.Files{c.Path(): *meta})
            std::map<std::string, tuf::FileMeta> files;
            files[path] = meta;
            
            // 尝试添加目标到此角色 (对应Go的repo.AddTargets(c.Scope(), files))
            auto err = repo->AddTargets(scope, files);
            if (!err.ok()) {
                utils::GetLogger().Error("Couldn't add target", utils::LogContext()
                    .With("scope", change->Scope())
                    .With("error", err.what()));
                return err;
            }
            
        } else if (action == changelist::ActionDelete) {
            utils::GetLogger().Debug("Changelist remove", utils::LogContext()
                .With("path", path));
            
            // 尝试从此角色移除目标 (对应Go的repo.RemoveTargets(c.Scope(), c.Path()))
            auto err = repo->RemoveTargets(scope, {path});
            if (!err.ok()) {
                utils::GetLogger().Error("Couldn't remove target", utils::LogContext()
                    .With("scope", change->Scope())
                    .With("error", err.what()));
                return err;
            }
            
        } else {
            return Error("Action not yet supported: " + action);
        }
        
        return Error(); // 成功
        
    } catch (const std::exception& e) {
        return Error(std::string("Failed to change target meta: ") + e.what());
    }
}

// changeTargetsDelegation函数实现 (对应Go的changeTargetsDelegation函数)
Error changeTargetsDelegation(std::shared_ptr<tuf::Repo> repo, 
                                std::shared_ptr<changelist::Change> change) {
    // TODO: 实现委托变更逻辑
    // 这需要解析TUFDelegation结构并调用相应的repo方法
    return Error("Delegation changes not yet implemented");
}

// applyRootChange函数实现 (对应Go的applyRootChange函数)
Error applyRootChange(std::shared_ptr<tuf::Repo> repo, 
                        std::shared_ptr<changelist::Change> change) {
    if (!repo || !change) {
        return Error("Invalid parameters");
    }
    
    std::string type = change->Type();
    
    // 根据类型分发处理 (对应Go的switch c.Type())
    if (type == changelist::TypeBaseRole) {
        return applyRootRoleChange(repo, change);
    } else {
        return Error("Type of root change not yet supported: " + type);
    }
}

// applyRootRoleChange函数实现 (对应Go的applyRootRoleChange函数)
Error applyRootRoleChange(std::shared_ptr<tuf::Repo> repo, 
                            std::shared_ptr<changelist::Change> change) {
    if (!repo || !change) {
        return Error("Invalid parameters");
    }
    
    std::string action = change->Action();
    
    try {
        if (action == changelist::ActionCreate) {
            // 解析TUFRootData (对应Go的json.Unmarshal(c.Content(), d))
            const auto& contentBytes = change->Content();
            std::string contentStr(contentBytes.begin(), contentBytes.end());
            nlohmann::json rootDataJson = nlohmann::json::parse(contentStr);
            
            // 解析角色名 (对应Go的d.RoleName)
            if (!rootDataJson.contains("role") && !rootDataJson.contains("roleName")) {
                return Error("Missing role name in TUFRootData");
            }
            
            // 解析角色名和密钥列表 对应GO json.Unmarshal(c.Content(), d)
            std::string roleNameStr;
            std::vector<std::shared_ptr<crypto::PublicKey>> keys;
            if (rootDataJson.contains("role")) {
                roleNameStr = rootDataJson["role"];
            } else {
                roleNameStr = rootDataJson["roleName"];
            }
            
            RoleName roleName = stringToRole(roleNameStr);
            utils::GetLogger().Info("Applying root role change", utils::LogContext()
                .With("role", roleNameStr));
            
            // 解析密钥列表 (对应Go的d.Keys)
            if (!rootDataJson.contains("keys")) {
                return Error("Missing keys in TUFRootData");
            }
            
            const auto& keysJson = rootDataJson["keys"];
            
            if (keysJson.is_array()) {
                for (const auto& keyJson : keysJson) {
                    try {
                        // 解析密钥信息
                        std::string keyType;
                        std::vector<uint8_t> publicData;
                        
                        if (keyJson.contains("algorithm")) {
                            keyType = keyJson["algorithm"];
                        } else {
                            utils::GetLogger().Warn("Key missing algorithm/keytype field, skipping");
                            continue;
                        }
                        
                        if (keyJson.contains("public")) {
                            std::string publicStr = keyJson["public"];
                            publicData = std::vector<uint8_t>(publicStr.begin(), publicStr.end());
                        } else {
                            utils::GetLogger().Warn("Key missing public data, skipping");
                            continue;
                        }
                        
                        // 创建公钥对象
                        auto publicKey = crypto::NewPublicKey(keyType, publicData);
                        if (publicKey) {
                            keys.push_back(publicKey);
                        } else {
                            utils::GetLogger().Warn("Failed to create public key", utils::LogContext()
                                .With("keyType", keyType));
                        }
                        
                    } catch (const std::exception& e) {
                        utils::GetLogger().Warn("Error parsing key", utils::LogContext()
                            .With("error", e.what()));
                        continue;
                    }
                }
            } else {
                return Error("Keys field must be an array");
            }
            
            if (keys.empty()) {
                return Error("No valid keys found in TUFRootData");
            }
            
            // 调用repo的ReplaceBaseKeys方法 (对应Go的repo.ReplaceBaseKeys(d.RoleName, d.Keys...))
            auto err = repo->ReplaceBaseKeys(roleName, keys);
            if (!err.ok()) {
                return Error("Failed to replace base keys for role " + roleNameStr + ": " + err.what());
            }
            
            utils::GetLogger().Debug("Successfully replaced base keys", utils::LogContext()
                .With("role", roleNameStr)
                .With("keyCount", std::to_string(keys.size())));
            
            return Error(); // 成功
            
        } else {
            return Error("Action not yet supported for root: " + action);
        }
        
    } catch (const std::exception& e) {
        return Error(std::string("Failed to apply root role change: ") + e.what());
    }
}

// witnessTargets函数实现 (对应Go的witnessTargets函数)
Error witnessTargets(std::shared_ptr<tuf::Repo> repo, 
                        std::shared_ptr<tuf::Repo> invalid, 
                        RoleName scope) {
    // TODO: 实现witness逻辑
    // 这是一个复杂的功能，用于处理无效的目标见证
    return Error("Witness targets not yet implemented");
    }

}
}