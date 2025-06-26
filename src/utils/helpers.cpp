#include "notary/utils/helpers.hpp"
#include "notary/tuf/repo.hpp"
#include "notary/crypto/keys.hpp"
#include "notary/utils/tools.hpp"
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>

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
            // 解析TUFRootData - 直接使用changelist模块的TUFRootData反序列化
            // (对应Go的json.Unmarshal(c.Content(), &d))
            changelist::TUFRootData d;
            auto deserializeErr = d.Deserialize(change->Content());
            if (!deserializeErr.ok()) {
                return Error("Failed to deserialize TUFRootData: " + deserializeErr.what());
            }
            
            utils::GetLogger().Info("Applying root role change", utils::LogContext()
                .With("role", roleToString(d.roleName))
                .With("keyCount", std::to_string(d.keys.size())));
            
            // 直接调用repo的ReplaceBaseKeys方法 
            // (对应Go的return repo.ReplaceBaseKeys(d.RoleName, d.Keys...))
            auto err = repo->ReplaceBaseKeys(d.roleName, d.keys);
            if (!err.ok()) {
                return Error("Failed to replace base keys for role " + roleToString(d.roleName) + ": " + err.what());
            }
            
            utils::GetLogger().Debug("Successfully replaced base keys", utils::LogContext()
                .With("role", roleToString(d.roleName))
                .With("keyCount", std::to_string(d.keys.size())));
            
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

// 从角色列表中移除指定角色 (对应Go的RoleNameSliceRemove)
std::vector<RoleName> roleNameSliceRemove(const std::vector<RoleName>& roles, RoleName roleToRemove) {
    std::vector<RoleName> result;
    result.reserve(roles.size());
    
    for (const auto& role : roles) {
        if (role != roleToRemove) {
            result.push_back(role);
        }
    }
    
    return result;
}

// getAllPrivKeys函数实现 (对应Go的getAllPrivKeys函数)
Result<std::vector<std::shared_ptr<crypto::PrivateKey>>> getAllPrivKeys(
    const std::vector<std::string>& rootKeyIDs, 
    std::shared_ptr<crypto::CryptoService> cryptoService) {
    
    // 1. 验证加密服务是否可用 (对应Go的if cryptoService == nil)
    if (!cryptoService) {
        return Result<std::vector<std::shared_ptr<crypto::PrivateKey>>>(
            Error("no crypto service available to get private keys from"));
    }

    // 2. 从指定的rootKeyIDs获取私钥 (对应Go的for _, keyID := range rootKeyIDs)
    std::vector<std::shared_ptr<crypto::PrivateKey>> privKeys;
    privKeys.reserve(rootKeyIDs.size());
    
    for (const std::string& keyID : rootKeyIDs) {
        // 获取私钥 (对应Go的privKey, _, err := cryptoService.GetPrivateKey(keyID))
        auto privateKeyResult = cryptoService->GetPrivateKey(keyID);
        if (!privateKeyResult.ok()) {
            return Result<std::vector<std::shared_ptr<crypto::PrivateKey>>>(
                privateKeyResult.error());
        }
        
        auto [privKey, role] = privateKeyResult.value();
        privKeys.push_back(privKey);
    }
    
    // 3. 如果没有指定rootKeyIDs，则尝试获取或创建新的根密钥 (对应Go的if len(privKeys) == 0)
    if (privKeys.empty()) {
        std::string rootKeyID;
        
        // 3.1 获取现有的根密钥列表 (对应Go的rootKeyList := cryptoService.ListKeys(data.CanonicalRootRole))
        std::vector<std::string> rootKeyList = cryptoService->ListKeys(RoleName::RootRole);
        
        if (rootKeyList.empty()) {
            // 3.2 如果没有根密钥，创建一个新的ECDSA密钥 (对应Go的cryptoService.Create)
            auto createResult = cryptoService->Create(RoleName::RootRole, "", ECDSA_KEY);
            if (!createResult.ok()) {
                return Result<std::vector<std::shared_ptr<crypto::PrivateKey>>>(
                    createResult.error());
            }
            
            // 获取创建的公钥的ID (对应Go的rootKeyID = rootPublicKey.ID())
            rootKeyID = createResult.value()->ID();
            
        } else {
            // 3.3 如果有现有的根密钥，使用第一个 (对应Go的rootKeyID = rootKeyList[0])
            rootKeyID = rootKeyList[0];
        }
        
        // 3.4 获取对应的私钥 (对应Go的privKey, _, err := cryptoService.GetPrivateKey(rootKeyID))
        auto privateKeyResult = cryptoService->GetPrivateKey(rootKeyID);
        if (!privateKeyResult.ok()) {
            return Result<std::vector<std::shared_ptr<crypto::PrivateKey>>>(
                privateKeyResult.error());
        }
        
        auto [privKey, role] = privateKeyResult.value();
        privKeys.push_back(privKey);
    }
    
    return Result<std::vector<std::shared_ptr<crypto::PrivateKey>>>(privKeys);
}

// 检查是否接近过期 (对应Go的nearExpiry函数)
bool nearExpiry(const std::chrono::system_clock::time_point& expires) {
    auto plus6mo = std::chrono::system_clock::now() + std::chrono::hours(24 * 30 * 6); // 6个月
    return expires < plus6mo;
}

// warnRolesNearExpiry实现
// 对应Go版本的warnRolesNearExpiry函数
// 检查接近过期的角色并发出警告
void warnRolesNearExpiry(const std::shared_ptr<tuf::Repo>& repo) {
    if (!repo) {
        return; // 如果repo为空，直接返回
    }
    
    try {
        // 获取每个角色及其相应的signed common并调用nearExpiry检查
        
        // Root检查 (对应Go的if nearExpiry(r.Root.Signed.SignedCommon))
        auto root = repo->GetRoot();
        if (root && nearExpiry(root->Signed.Common.Expires)) {
            utils::GetLogger().Warn("root is nearing expiry, you should re-sign the role metadata");
        }
        
        // Targets和委托检查 (对应Go的for role, signedTOrD := range r.Targets)
        auto targetsMap = repo->GetTargets(); 
        for (const auto& [role, signedTargets] : targetsMap) {
            // signedTargets是*data.SignedTargets类型
            if (signedTargets && nearExpiry(signedTargets->Signed.Common.Expires)) {
                std::string roleStr = roleToString(role);
                utils::GetLogger().Warn(roleStr + " metadata is nearing expiry, you should re-sign the role metadata");
            }
        }
        
        // Snapshot检查 (对应Go的if nearExpiry(r.Snapshot.Signed.SignedCommon))
        auto snapshot = repo->GetSnapshot();
        if (snapshot && nearExpiry(snapshot->Signed.Common.Expires)) {
            utils::GetLogger().Warn("snapshot is nearing expiry, you should re-sign the role metadata");
        }
        
        // 不需要担心Timestamp，notary signer会用timestamp密钥重新签名
        // (对应Go的注释: do not need to worry about Timestamp, notary signer will re-sign with the timestamp key)
        
    } catch (const std::exception& e) {
        utils::GetLogger().Error("Failed to check role expiry", 
            utils::LogContext().With("error", e.what()));
    }
}

// rotateRemoteKey函数实现 - 对应Go版本的rotateRemoteKey函数
// 在远程存储中轮转私钥并返回公钥组件
Result<std::shared_ptr<crypto::PublicKey>> rotateRemoteKey(RoleName role, 
                                                          std::shared_ptr<storage::RemoteStore> remoteStore,
                                                          const std::string& gun) {
    try {
        if (!remoteStore) {
            return Error("Remote store not initialized");
        }
        
        utils::GetLogger().Info("Requesting remote key rotation", 
            utils::LogContext()
                .With("role", roleToString(role))
                .With("gun", gun));
        
        // 发送密钥轮转请求到远程服务器 (对应Go的rawPubKey, err := remote.RotateKey(role))
        // 首先尝试将RemoteStore转换为HttpStore以访问RotateKey方法
        auto httpStore = dynamic_cast<storage::HttpStore*>(remoteStore.get());
        if (!httpStore) {
            return Error("Remote store is not an HttpStore, cannot rotate key");
        }
        
        // 将角色名转换为字符串
        std::string roleStr = roleToString(role);
        auto rawPubKeyResult = httpStore->RotateKey(roleStr);
        if (!rawPubKeyResult.ok()) {
            return Error("Failed to rotate remote key for role " + roleStr + ": " + rawPubKeyResult.error().what());
        }
        
        // 获取原始公钥字节数据 (对应Go的rawPubKey)
        auto rawPubKey = rawPubKeyResult.value();
        
        utils::GetLogger().Debug("Received raw public key from server", 
            utils::LogContext()
                .With("role", roleToString(role))
                .With("dataSize", std::to_string(rawPubKey.size())));
        
        // 使用UnmarshalPublicKey解析公钥数据 (对应Go的pubKey, err := data.UnmarshalPublicKey(rawPubKey))
        auto pubKeyResult = crypto::UnmarshalPublicKey(rawPubKey);
        if (!pubKeyResult.ok()) {
            return Error("Failed to unmarshal public key: " + pubKeyResult.error().what());
        }
        
        auto pubKey = pubKeyResult.value();
        if (!pubKey) {
            return Error("Unmarshaled public key is null");
        }
        
        utils::GetLogger().Info("Successfully rotated remote key", 
            utils::LogContext()
                .With("role", roleToString(role))
                .With("newKeyID", pubKey->ID())
                .With("algorithm", pubKey->Algorithm())
                .With("gun", gun));
        
        // 返回公钥 (对应Go的return pubKey, nil)
        return pubKey;
        
    } catch (const std::exception& e) {
        return Error(std::string("Exception in rotateRemoteKey: ") + e.what());
    }
}

}
}