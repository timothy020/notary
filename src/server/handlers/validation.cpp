#include "notary/server/handlers/validation.hpp"
#include "notary/tuf/builder.hpp"
#include "notary/tuf/repo.hpp"
#include "notary/server/types.hpp"
#include "notary/server/server.hpp"
#include "notary/utils/logger.hpp"
#include <nlohmann/json.hpp>
#include <algorithm>
#include <stdexcept>

namespace notary {
namespace server {
namespace handlers {

using json = nlohmann::json;

// 主要验证函数 - 对应Go版本的validateUpdate
std::vector<MetaUpdate> validateUpdate(crypto::CryptoService* cryptoService, const std::string& gun, std::vector<MetaUpdate> updates, StorageService* store) {
    utils::GetLogger().Debug("开始验证元数据更新", 
        utils::LogContext()
            .With("gun", gun)
            .With("updates_count", std::to_string(updates.size())));

    // 一些委托的目标角色可能基于其他客户端所做的其他更新而无效
    // 我们将重建只包含实际应该更新的内容的更新切片
    std::vector<MetaUpdate> updatesToApply;
    updatesToApply.reserve(updates.size());

    // 创建角色映射
    std::map<std::string, MetaUpdate> roles;
    for (const auto& update : updates) {
        roles[update.role] = update;
    }

    // 创建RepoBuilder - 需要三个参数
    tuf::TrustPinConfig trustPin; // 空的trust pin配置
    // 注意：这里需要确保cryptoService的生命周期管理正确
    // 在实际使用中，应该传入shared_ptr而不是原始指针
    std::shared_ptr<crypto::CryptoService> sharedCrypto(cryptoService, [](crypto::CryptoService*){});
    auto builder = tuf::NewRepoBuilder(gun, sharedCrypto, trustPin);
    
    // 尝试从存储加载root
    try {
        loadFromStore(gun, ROOT_ROLE, builder.get(), store);
    } catch (const std::exception& e) {
        // 如果是"not found"错误则忽略，其他错误需要抛出
        std::string errorMsg = e.what();
        if (errorMsg.find("not found") == std::string::npos && 
            errorMsg.find("NOT_FOUND") == std::string::npos) {
            throw;
        }
    }

    // 处理root更新
    auto rootIt = roles.find(ROOT_ROLE);
    if (rootIt != roles.end()) {
        const auto& rootUpdate = rootIt->second;
        int currentRootVersion = builder->getLoadedVersion(ROOT_ROLE);
        
        if (rootUpdate.version != currentRootVersion && 
            rootUpdate.version != currentRootVersion + 1) {
            std::string msg = "Root modifications must increment the version. Current " + 
                             std::to_string(currentRootVersion) + ", new " + std::to_string(rootUpdate.version);
            throw std::runtime_error("Bad root: " + msg);
        }

        // 重新引导构建器
        builder = builder->bootstrapNewBuilder();
        
        // 加载新的root
        try {
            std::vector<uint8_t> rootData(rootUpdate.data.begin(), rootUpdate.data.end());
            auto err = builder->load(ROOT_ROLE, rootData, currentRootVersion, false);
            if (err.hasError()) {
                throw std::runtime_error("Bad root: " + err.what());
            }
        } catch (const std::exception& e) {
            throw std::runtime_error("Bad root: " + std::string(e.what()));
        }

        utils::GetLogger().Debug("成功验证root");
        updatesToApply.push_back(rootUpdate);
    } else if (!builder->isLoaded(ROOT_ROLE)) {
        throw std::runtime_error("Validation error: no pre-existing root and no root provided in update.");
    }

    // 加载和验证targets
    try {
        auto targetsToUpdate = loadAndValidateTargets(gun, builder.get(), roles, store);
        updatesToApply.insert(updatesToApply.end(), 
                             targetsToUpdate.begin(), targetsToUpdate.end());
        utils::GetLogger().Debug("成功验证targets");
    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to load and validate targets: " + std::string(e.what()));
    }

    // 此时，root和targets必须已经加载到repo中
    auto snapshotIt = roles.find(SNAPSHOT_ROLE);
    if (snapshotIt != roles.end()) {
        const auto& snapshotUpdate = snapshotIt->second;
        
        try {
            std::vector<uint8_t> snapshotData(snapshotUpdate.data.begin(), snapshotUpdate.data.end());
            auto err = builder->load(SNAPSHOT_ROLE, snapshotData, 1, false);
            if (err.hasError()) {
                throw std::runtime_error("Bad snapshot: " + err.what());
            }
        } catch (const std::exception& e) {
            throw std::runtime_error("Bad snapshot: " + std::string(e.what()));
        }
        
        utils::GetLogger().Debug("成功验证snapshot");
        updatesToApply.push_back(snapshotUpdate);
    } else {
        // 检查：
        //   - 我们有snapshot密钥
        //   - 它与root.json中签名的snapshot密钥匹配
        // 然后：
        //   - 生成新的snapshot
        //   - 将其添加到更新中
        try {
            auto snapshotUpdate = generateSnapshot(gun, builder.get(), store);
            updatesToApply.push_back(snapshotUpdate);
        } catch (const std::exception& e) {
            throw std::runtime_error("Failed to generate snapshot: " + std::string(e.what()));
        }
    }

    // 立即生成timestamp
    try {
        auto timestampUpdate = generateTimestamp(gun, builder.get(), store);
        updatesToApply.push_back(timestampUpdate);
    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to generate timestamp: " + std::string(e.what()));
    }

    utils::GetLogger().Info("成功验证所有元数据更新", 
        utils::LogContext()
            .With("gun", gun)
            .With("final_updates_count", std::to_string(updatesToApply.size())));

    return updatesToApply;
}

// 加载和验证目标角色 - 对应Go版本的loadAndValidateTargets
std::vector<MetaUpdate> loadAndValidateTargets(const std::string& gun, tuf::RepoBuilder* builder, const std::map<std::string, MetaUpdate>& roles, StorageService* store) {
    utils::GetLogger().Debug("开始加载和验证targets角色", 
        utils::LogContext().With("gun", gun));

    // 收集所有targets角色（包括委托）
    std::vector<std::string> targetsRoles;
    for (const auto& [role, update] : roles) {
        if (role == TARGETS_ROLE || 
            (update.roleName.find("targets/") == 0)) { // 委托targets角色
            targetsRoles.push_back(update.roleName);
        }
    }

    // 按路径段数排序，确保我们总是在更深的路径之前处理较浅的更新
    // （即我们将在targets/foo之前加载和验证targets）
    std::sort(targetsRoles.begin(), targetsRoles.end(), 
             [](const std::string& a, const std::string& b) {
                 // 计算路径段数（'/'的数量）
                 auto countSlashes = [](const std::string& s) {
                     return std::count(s.begin(), s.end(), '/');
                 };
                 int aSlashes = countSlashes(a);
                 int bSlashes = countSlashes(b);
                 if (aSlashes != bSlashes) {
                     return aSlashes < bSlashes;
                 }
                 return a < b; // 字典序作为次要排序
             });

    std::vector<MetaUpdate> updatesToApply;
    updatesToApply.reserve(targetsRoles.size());

    for (const std::string& roleStr : targetsRoles) {
        // 对于委托，我们必须加载所有祖先角色，从`targets`开始向下工作
        std::vector<std::string> parentsToLoad;
        std::string ancestorRole = roleStr;
        
        // 找到所有需要加载的父角色
        while (ancestorRole != "targets" && ancestorRole.find("targets/") == 0) {
            // 获取父角色
            size_t lastSlash = ancestorRole.find_last_of('/');
            if (lastSlash != std::string::npos) {
                ancestorRole = ancestorRole.substr(0, lastSlash);
                if (ancestorRole.empty()) {
                    ancestorRole = "targets";
                }
            } else {
                ancestorRole = "targets";
            }
            
            // 检查是否已加载
            std::string parentRole = (ancestorRole == "targets") ? TARGETS_ROLE : TARGETS_ROLE;
            if (!builder->isLoaded(parentRole)) {
                parentsToLoad.push_back(ancestorRole);
            }
            
            if (ancestorRole == "targets") {
                break;
            }
        }

        // 从最顶层开始加载父角色
        std::reverse(parentsToLoad.begin(), parentsToLoad.end());
        for (const std::string& parentRoleStr : parentsToLoad) {
            std::string parentRole = (parentRoleStr == "targets") ? TARGETS_ROLE : TARGETS_ROLE;
            try {
                loadFromStore(gun, parentRole, builder, store);
            } catch (const std::exception& e) {
                // 如果父角色不存在，继续尝试 - 加载角色最终会因为无效角色而失败
                std::string errorMsg = e.what();
                if (errorMsg.find("not found") == std::string::npos) {
                    throw;
                }
            }
        }

        // 加载当前角色
        auto roleIt = std::find_if(roles.begin(), roles.end(),
                                  [&roleStr](const auto& pair) {
                                      return pair.second.roleName == roleStr;
                                  });
        
        if (roleIt != roles.end()) {
            const auto& update = roleIt->second;
            
            try {
                std::string currentRole = (roleStr == "targets") ? TARGETS_ROLE : TARGETS_ROLE;
                std::vector<uint8_t> updateData(update.data.begin(), update.data.end());
                auto err = builder->load(currentRole, updateData, 1, false);
                if (err.hasError()) {
                    throw std::runtime_error("Load failed: " + err.what());
                }
            } catch (const std::exception& e) {
                utils::GetLogger().Error("加载targets角色失败", 
                    utils::LogContext()
                        .With("role", roleStr)
                        .With("error", e.what()));
                throw std::runtime_error("Bad targets: " + std::string(e.what()));
            }
            updatesToApply.push_back(update);
        }
    }

    return updatesToApply;
}

// 生成快照 - 对应Go版本的generateSnapshot
MetaUpdate generateSnapshot(const std::string& gun, tuf::RepoBuilder* builder, StorageService* store) {
    utils::GetLogger().Debug("开始生成snapshot", 
        utils::LogContext().With("gun", gun));

    std::string prevSnapshotData = "";
    
    // 尝试获取当前的snapshot
    try {
        MetadataRequest req;
        req.gun = gun;
        req.role = SNAPSHOT_ROLE;
        req.roleName = "snapshot";
        req.version = 0; // 获取最新版本
        
        auto result = store->GetMetadata(req);
        if (result.ok()) {
            prevSnapshotData = result.value().data;
        }
    } catch (const std::exception& e) {
        // 忽略错误，可能是第一次创建snapshot
        utils::GetLogger().Debug("获取现有snapshot失败，可能是首次创建", 
            utils::LogContext().With("error", e.what()));
    }

    // 生成新的snapshot
    try {
        auto snapshotResult = builder->generateSnapshot(nullptr);
        if (!snapshotResult.ok()) {
            auto& err = snapshotResult.error();
            std::string errorMsg = err.what();
            if (errorMsg.find("insufficient signatures") != std::string::npos ||
                errorMsg.find("no keys") != std::string::npos ||
                errorMsg.find("role threshold") != std::string::npos) {
                // 如果我们无法签名snapshot，那么我们没有snapshot的密钥，
                // 客户端应该提交snapshot
                throw std::runtime_error("Bad hierarchy: no snapshot was included in update and server does not hold current snapshot key for repository");
            } else {
                throw std::runtime_error("Validation error: " + errorMsg);
            }
        }
        
        auto [metaData, version] = snapshotResult.value();
        std::string metaStr(metaData.begin(), metaData.end());
        
        MetaUpdate update;
        update.role = SNAPSHOT_ROLE;
        update.roleName = "snapshot";
        update.version = version;
        update.data = metaStr;
        
        utils::GetLogger().Debug("成功生成snapshot", 
            utils::LogContext()
                .With("gun", gun)
                .With("version", std::to_string(version)));
        
        return update;
    } catch (const std::exception& e) {
        std::string errorMsg = e.what();
        if (errorMsg.find("insufficient signatures") != std::string::npos ||
            errorMsg.find("no keys") != std::string::npos ||
            errorMsg.find("role threshold") != std::string::npos) {
            // 如果我们无法签名snapshot，那么我们没有snapshot的密钥，
            // 客户端应该提交snapshot
            throw std::runtime_error("Bad hierarchy: no snapshot was included in update and server does not hold current snapshot key for repository");
        } else {
            throw std::runtime_error("Validation error: " + errorMsg);
        }
    }
}

// 生成时间戳 - 对应Go版本的generateTimestamp
MetaUpdate generateTimestamp(const std::string& gun, tuf::RepoBuilder* builder, StorageService* store) {
    utils::GetLogger().Debug("开始生成timestamp", 
        utils::LogContext().With("gun", gun));

    std::string prevTimestampData = "";
    
    // 尝试获取当前的timestamp
    try {
        MetadataRequest req;
        req.gun = gun;
        req.role = TIMESTAMP_ROLE;
        req.roleName = "timestamp";
        req.version = 0; // 获取最新版本
        
        auto result = store->GetMetadata(req);
        if (result.ok()) {
            prevTimestampData = result.value().data;
        }
    } catch (const std::exception& e) {
        // 忽略错误，可能是第一次创建timestamp
        utils::GetLogger().Debug("获取现有timestamp失败，可能是首次创建", 
            utils::LogContext().With("error", e.what()));
    }

    // 生成新的timestamp
    try {
        auto timestampResult = builder->generateTimestamp(nullptr);
        if (!timestampResult.ok()) {
            auto& err = timestampResult.error();
            std::string errorMsg = err.what();
            if (errorMsg.find("insufficient signatures") != std::string::npos ||
                errorMsg.find("no keys") != std::string::npos) {
                // 如果我们无法签名timestamp，那么我们没有timestamp的密钥，
                // 客户端搞砸了他们的root
                throw std::runtime_error("Bad root: no timestamp keys exist on the server");
            } else {
                throw std::runtime_error("Validation error: " + errorMsg);
            }
        }
        
        auto [metaData, version] = timestampResult.value();
        std::string metaStr(metaData.begin(), metaData.end());
        
        MetaUpdate update;
        update.role = TIMESTAMP_ROLE;
        update.roleName = "timestamp";
        update.version = version;
        update.data = metaStr;
        
        utils::GetLogger().Debug("成功生成timestamp", 
            utils::LogContext()
                .With("gun", gun)
                .With("version", std::to_string(version)));
        
        return update;
    } catch (const std::exception& e) {
        std::string errorMsg = e.what();
        if (errorMsg.find("insufficient signatures") != std::string::npos ||
            errorMsg.find("no keys") != std::string::npos) {
            // 如果我们无法签名timestamp，那么我们没有timestamp的密钥，
            // 客户端搞砸了他们的root
            throw std::runtime_error("Bad root: no timestamp keys exist on the server");
        } else {
            throw std::runtime_error("Validation error: " + errorMsg);
        }
    }
}

// 从存储加载元数据到构建器 - 对应Go版本的loadFromStore
void loadFromStore(const std::string& gun, const std::string& roleName, tuf::RepoBuilder* builder, StorageService* store) {
    try {
        MetadataRequest req;
        req.gun = gun;
        req.role = roleName;
        
        // 设置角色名称
        req.roleName = roleName;
        req.version = 0; // 获取最新版本
        
        auto result = store->GetMetadata(req);
        if (!result.ok()) {
            throw std::runtime_error("Metadata not found: " + result.error().what());
        }

        const std::string& metaJSON = result.value().data;
        std::vector<uint8_t> metaBytes(metaJSON.begin(), metaJSON.end());
        auto err = builder->load(roleName, metaBytes, 1, true);
        if (err.hasError()) {
            throw std::runtime_error("Load failed: " + err.what());
        }
        
    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to load from store: " + std::string(e.what()));
    }
}

} // namespace handlers
} // namespace server
} // namespace notary
