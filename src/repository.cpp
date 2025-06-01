#include "notary/repository.hpp"
#include "notary/tuf/repo.hpp"
#include "notary/tuf/builder.hpp"
#include "notary/utils/tools.hpp"
#include "notary/crypto/keys.hpp"
#include "notary/utils/helpers.hpp"
#include "notary/changelist/changelist.hpp"
#include "notary/storage/key_storage.hpp"
#include <algorithm>
#include <nlohmann/json.hpp>
#include <chrono>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <iomanip>
#include <sstream>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <ctime>
#include <uuid/uuid.h>
#include <iostream>

namespace notary {

using json = nlohmann::json;

// 使用标准filesystem命名空间
namespace fs = std::filesystem;

namespace {
// 检查角色是否可以由服务器管理
bool isValidServerManagedRole(RoleName role) {
    return role == RoleName::TimestampRole || role == RoleName::SnapshotRole;
}

// 检查角色是否是根角色
bool isRootRole(RoleName role) {
    return role == RoleName::RootRole;
}

// addChange函数实现 (对应Go的addChange函数)
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
        if (role != "targets" && !tuf::IsDelegation(stringToRole(role)) && !tuf::IsWildDelegation(stringToRole(role))) {
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


Repository::Repository(const GUN& gun, const std::string& trustDir, const std::string& serverURL)
    : gun_(gun)
    , trustDir_(trustDir)
    , serverURL_(serverURL)
    , changelist_(std::make_shared<changelist::FileChangelist>(trustDir+gun_+"/changelist"))
    , cache_(std::make_shared<storage::FileSystemStorage>(trustDir+gun_+"/tuf", ".json"))
    , remoteStore_(std::make_shared<storage::RemoteStore>(serverURL))
    {
    // 初始化cryptoService_
    // 定义一个简单的 PassRetriever，表示无密码
    auto passRetriever = [](const std::string& keyName,
                                  const std::string& alias,
                                  bool createNew,
                                  int attempts) -> std::tuple<std::string, bool, Error> {
        // 返回空密码（""），不放弃（false），无错误（Error()）
        return std::make_tuple("", false, Error());
    };
    std::unique_ptr<storage::GenericKeyStore> keyStores = notary::storage::GenericKeyStore::NewKeyFileStore(trustDir+"/private", passRetriever);
    cryptoService_ = std::make_shared<crypto::CryptoService>(std::vector<std::shared_ptr<storage::GenericKeyStore>>{std::move(keyStores)});
    
    // 初始化TUF Repo
    tufRepo_ = std::make_shared<tuf::Repo>(cryptoService_);
    invalidRepo_ = std::make_shared<tuf::Repo>(cryptoService_);
}

void Repository::SetPassphrase(const std::string& passphrase) {
    cryptoService_->SetDefaultPassphrase(passphrase);
}


Error Repository::Initialize(const std::vector<std::string>& rootKeyIDs,
                           const std::vector<RoleName>& serverManagedRoles) {
    // 验证服务器管理的角色
    std::vector<RoleName> remoteRoles = {RoleName::TimestampRole}; // timestamp总是由服务器管理
    std::vector<RoleName> localRoles = {RoleName::TargetsRole, RoleName::SnapshotRole};

    for (const auto& role : serverManagedRoles) {
        if (!isValidServerManagedRole(role)) {
            return Error("Invalid server managed role");
        }
        if (role == RoleName::SnapshotRole) {
            // 将snapshot从本地管理移到远程管理
            localRoles.erase(
                std::remove(localRoles.begin(), localRoles.end(), RoleName::SnapshotRole),
                localRoles.end()
            );
            remoteRoles.push_back(role);
        }
    }

    // 获取或创建根密钥
    std::vector<std::shared_ptr<crypto::PublicKey>> rootKeys;
    
    // 如果提供了根密钥ID，使用这些ID获取密钥
    if (!rootKeyIDs.empty()) {
        for (const auto& keyID : rootKeyIDs) {
            auto key = cryptoService_->GetKey(keyID);
            rootKeys.push_back(key);
        }
    } else {
        // 如果没有提供根密钥ID，自动创建一个新的根密钥
        auto publicKeyResult = cryptoService_->Create(RoleName::RootRole, gun_, ECDSA_KEY);
        if (!publicKeyResult.ok()) {
            return Error("Failed to create root key: " + publicKeyResult.error().what());
        }
        rootKeys.push_back(publicKeyResult.value());
    }
    
    // 确保至少有一个根密钥
    if (rootKeys.empty()) {
        return Error("No root keys available");
    }

    // 初始化角色
    auto [root, targets, snapshot, timestamp] = initializeRoles(rootKeys, localRoles, remoteRoles);

    // 初始化内存中的TUF Repo对象
    tufRepo_ = std::make_shared<tuf::Repo>(cryptoService_);
    
    // 初始化Repo中的角色
    auto rootResult = tufRepo_->InitRoot(root, targets, snapshot, timestamp);
    if (!rootResult.ok()) {
        return rootResult.error();
    }
    
    // 初始化Targets
    auto targetsResult = tufRepo_->InitTargets();
    if (!targetsResult.ok()) {
        return targetsResult.error();
    }
    
    // 初始化Snapshot
    auto snapshotResult = tufRepo_->InitSnapshot();
    if (!snapshotResult.ok()) {
        return snapshotResult.error();
    }
    
    // 初始化Timestamp
    auto timestampResult = tufRepo_->InitTimestamp();
    if (!timestampResult.ok()) {
        return timestampResult.error();
    }

    return saveMetadata(false);
    // 初始化TUF元数据
    // return initializeTUFMetadata(root, targets, snapshot, timestamp);
}

Error Repository::saveMetadata(bool ignoreSnapshot) {
    if (!tufRepo_) {
        return Error("TUF repository not initialized");
    }
    
    std::cout << "Saving changes to Trusted Collection." << std::endl;
    
    try {
        // 1. 序列化并保存root.json
        // 使用 serializeCanonicalRole() 对 root.json 进行规范签名与 JSON 序列化
        auto rootData = utils::serializeCanonicalRole(tufRepo_, RoleName::RootRole, {});
        if (rootData.empty()) {
            return Error("Failed to serialize root metadata");
        }
        
        // 调用 cache_->Set() 落盘到本地，key 是字符串 "root"，值是内容字节数组
        auto rootResult = cache_->Set(ROOT_ROLE, rootData);
        if (rootResult.hasError()) {
            return rootResult;
        }
        
        // 2. 序列化并保存所有targets文件
        std::map<RoleName, std::vector<uint8_t>> targetsToSave;
        
        // 遍历tufRepo中的所有targets角色
        auto targets = tufRepo_->GetTargets();
        // 遍历targets
        for (const auto& [role, targets] : targets) {
            // 签名targets角色
            auto signedTargetsResult = tufRepo_->SignTargets(role, utils::getDefaultExpiry(role));
            if (!signedTargetsResult.ok()) {
                return signedTargetsResult.error();
            }
            
            // 序列化为JSON
            auto targetsData = signedTargetsResult.value()->Serialize();
            if (!targetsData.empty()) {
                targetsToSave[role] = targetsData;
            }
        }
        
        // TODO: 添加对委托角色的支持
        // 这里需要遍历所有委托角色，类似Go版本中的 for t := range r.tufRepo.Targets
        
        // 保存所有targets文件 (对应Go的 for role, blob := range targetsToSave)
        for (const auto& [role, blob] : targetsToSave) {
            // 如果父目录不存在，cache.Set会创建它
            auto targetsResult = cache_->Set(roleToString(role), blob);
            if (targetsResult.hasError()) {
                return targetsResult;
            }
        }
        
        // 3. 如果不忽略snapshot，序列化并保存snapshot.json
        if (!ignoreSnapshot) {
            auto snapshotData = utils::serializeCanonicalRole(tufRepo_, RoleName::SnapshotRole, {});
            if (snapshotData.empty()) {
                return Error("Failed to serialize snapshot metadata");
            }
            
            auto snapshotResult = cache_->Set(SNAPSHOT_ROLE, snapshotData);
            if (snapshotResult.hasError()) {
                return snapshotResult;
            }
        }
        
        return Error(); // 成功
        
    } catch (const std::exception& e) {
        return Error("Failed to save metadata: " + std::string(e.what()));
    }
}

std::tuple<BaseRole, BaseRole, BaseRole, BaseRole> 
Repository::initializeRoles(const std::vector<std::shared_ptr<crypto::PublicKey>>& rootKeys,
                          const std::vector<RoleName>& localRoles,
                          const std::vector<RoleName>& remoteRoles) {
    // 创建根角色
    BaseRole root(RoleName::RootRole, 1, rootKeys);
    
    // 初始化其他角色的空密钥列表
    std::vector<std::shared_ptr<crypto::PublicKey>> emptyKeys;
    BaseRole targets(RoleName::TargetsRole, 0, emptyKeys);
    BaseRole snapshot(RoleName::SnapshotRole, 0, emptyKeys);
    BaseRole timestamp(RoleName::TimestampRole, 0, emptyKeys);

    // 创建本地角色密钥（不包括timestamp）
    for (const auto& role : localRoles) {
        if (role == RoleName::TimestampRole) {
            continue; // 跳过timestamp角色，它只从远程获取
        }
        
        auto publicKeyResult = cryptoService_->Create(role, gun_, ECDSA_KEY);
        if (!publicKeyResult.ok()) {
            continue; // 跳过失败的密钥创建
        }
        std::vector<std::shared_ptr<crypto::PublicKey>> roleKeys = {publicKeyResult.value()};
        
        if (role == RoleName::TargetsRole) {
            targets = BaseRole(role, 1, roleKeys);
        } else if (role == RoleName::SnapshotRole) {
            snapshot = BaseRole(role, 1, roleKeys);
        }
    }

    // 获取远程角色密钥
    for (const auto& role : remoteRoles) {
        auto keyResult = remoteStore_->GetKey(gun_.empty() ? "default" : gun_, 
                                          role == RoleName::TimestampRole ? "timestamp" : "snapshot");
        if (!keyResult.ok()) {
            std::cerr << "Failed to get remote key : " << keyResult.error().what() << std::endl;
            continue; // 跳过失败的密钥获取
        }
        
        // 从json中提取公钥信息
        auto keyJson = keyResult.value();
        std::cout << "远端获取到的keyJson: " << keyJson << std::endl;

        // 解码Base64公钥数据
        std::vector<uint8_t> derData = utils::Base64Decode(keyJson["keyval"]["public"]);
        
        // 从DER数据创建ECDSA公钥
        /**
         * DER (二进制数据)
         * ↓
         * d2i_EC_PUBKEY（反序列化）
         * ↓
         * EC_KEY*（OpenSSL对象）
         * ↓
         * i2d_EC_PUBKEY（再序列化）
         * ↓
         * vector<uint8_t> keyDer
         * ↓
         * crypto::ECDSAPublicKey(keyDer)
         * ↓
         * PublicKey 接口（适配）
         */
        const unsigned char* p = derData.data();
        EC_KEY* ecKey = d2i_EC_PUBKEY(nullptr, &p, derData.size());
        if (ecKey) {
            unsigned char* der = nullptr;
            int derLen = i2d_EC_PUBKEY(ecKey, &der);
            if (derLen > 0 && der) {
                std::vector<uint8_t> keyDer(der, der + derLen);
                OPENSSL_free(der);
                
                // 创建ECDSA公钥对象
                auto publicKey = std::make_shared<crypto::ECDSAPublicKey>(keyDer);
                
                if (publicKey) {
                    std::vector<std::shared_ptr<crypto::PublicKey>> roleKeys = {publicKey};
                    
                    if (role == RoleName::TimestampRole) {
                        timestamp = BaseRole(role, 1, roleKeys);
                    } else if (role == RoleName::SnapshotRole) {
                        snapshot = BaseRole(role, 1, roleKeys);
                    }
                }
            }
            EC_KEY_free(ecKey);
        }
    }

    return {root, targets, snapshot, timestamp};
}


// NewTarget is a helper method that returns a Target
Result<Target> Repository::NewTarget(const std::string& targetName, 
                                    const std::string& targetPath,
                                    const json& customData) {
    // 检查目标文件是否存在
    if (!fs::exists(targetPath)) {
        return Error(std::string("Target file not found: ") + targetPath);
    }
    
    // 读取文件内容
    std::ifstream file(targetPath, std::ios::binary | std::ios::ate);
    if (!file) {
        return Error(std::string("Failed to open target file: ") + targetPath);
    }
    
    // 获取文件大小
    auto size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    // 读取文件内容
    std::vector<uint8_t> fileData(size);
    if (!file.read(reinterpret_cast<char*>(fileData.data()), size)) {
        return Error(std::string("Failed to read target file: ") + targetPath);
    }
    
    // 使用NewFileMeta等价的逻辑计算哈希 (对应Go的data.NewFileMeta)
    // 默认使用NotaryDefaultHashes: SHA256和SHA512
    std::vector<std::string> hashAlgorithms = {"sha256", "sha512"};
    
    auto fileMetaResult = tuf::NewFileMeta(fileData, hashAlgorithms);
    if (!fileMetaResult.ok()) {
        return fileMetaResult.error();
    }
    
    auto fileMeta = fileMetaResult.value();
    
    // 创建目标对象 (对应Go的&Target{Name: targetName, Hashes: meta.Hashes, Length: meta.Length, Custom: targetCustom})
    Target target;
    target.name = targetName;
    target.hashes = fileMeta.Hashes;
    target.length = fileMeta.Length;
    target.custom = customData;
    
    return target;
}

Error Repository::AddTarget(const Target& target, const std::vector<std::string>& roles) {
    try {
        // 验证目标哈希是否存在 (对应Go的len(target.Hashes) == 0检查)
        if (target.hashes.empty()) {
            return Error("No hashes specified for target \"" + target.name + "\"");
        }
        
        // 记录调试信息 (对应Go的logrus.Debugf)
        utils::GetLogger().Debug("Adding target", utils::LogContext()
            .With("name", target.name)
            .With("length", std::to_string(target.length)));
        
        // 构造目标元数据 (对应Go的data.FileMeta{Length: target.Length, Hashes: target.Hashes, Custom: target.Custom})
        tuf::FileMeta meta;
        meta.Length = target.length;
        meta.Hashes = target.hashes;
        meta.Custom = target.custom;
        
        // 序列化元数据为JSON (对应Go的json.Marshal(meta))
        json metaJson = meta.toJson();
        std::string metaJsonStr = metaJson.dump();
        std::vector<uint8_t> content(metaJsonStr.begin(), metaJsonStr.end());
        
        // 创建变更模板 (对应Go的changelist.NewTUFChange)
        auto templateChange = std::make_shared<changelist::TUFChange>(
            changelist::ActionCreate,      // 创建操作
            "",                           // scope为空，对应Go版本
            changelist::TypeTargetsTarget, // 目标类型
            target.name,                  // 目标路径
            content                       // 元数据内容
        );
        
        // 使用addChange函数处理角色验证和变更创建 (对应Go的addChange函数调用)
        return addChange(changelist_, templateChange, roles);
        
    } catch (const std::exception& e) {
        return Error(std::string("Failed to add target: ") + e.what());
    }
}

Error Repository::applyChangelist() {
    try {
        auto changes = changelist_->List();
        if (changes.empty()) {
            return Error(); // 没有变更需要应用
        }
        
        // 获取当前targets元数据
        auto result = cache_->Get(TARGETS_ROLE);
        if (!result.ok()) {
            return Error("Could not load targets metadata");
        }
        
        // 将vector<uint8_t>转换为json
        std::string targetsStr(result.value().begin(), result.value().end());
        json targetsData;
        try {
            targetsData = json::parse(targetsStr);
        } catch (const std::exception& e) {
            return Error("Failed to parse targets metadata: " + std::string(e.what()));
        }
        
        bool targetsModified = false;
        
        // 应用每个变更
        for (const auto& change : changes) {
            // 目前只处理targets变更
            if (change->Type() == changelist::TypeTargetsTarget) {
                if (change->Action() == changelist::ActionCreate || 
                    change->Action() == changelist::ActionUpdate) {
                    // 解析元数据
                    std::string contentStr(change->Content().begin(), change->Content().end());
                    json targetMeta;
                    try {
                        targetMeta = json::parse(contentStr);
                    } catch (const std::exception& e) {
                        std::cerr << "Error parsing target metadata: " << e.what() << std::endl;
                        continue;
                    }
                    
                    // 添加到targets
                    if (!targetsData.contains("signed")) {
                        targetsData["signed"] = json::object();
                    }
                    if (!targetsData["signed"].contains("targets")) {
                        targetsData["signed"]["targets"] = json::object();
                    }
                    
                    targetsData["signed"]["targets"][change->Path()] = targetMeta;
                    targetsModified = true;
                } else if (change->Action() == changelist::ActionDelete) {
                    // 从targets中删除
                    if (targetsData.contains("signed") && 
                        targetsData["signed"].contains("targets") &&
                        targetsData["signed"]["targets"].contains(change->Path())) {
                        targetsData["signed"]["targets"].erase(change->Path());
                        targetsModified = true;
                    }
                }
            }
        }
        
        // 如果有修改，更新版本和过期时间，然后保存
        if (targetsModified) {
            // 更新元数据的version字段
            if (targetsData["signed"].contains("version")) {
                targetsData["signed"]["version"] = targetsData["signed"]["version"].get<int>() + 1;
            } else {
                targetsData["signed"]["version"] = 1;
            }
            
            // 更新元数据的expires字段
            auto expiry = utils::getDefaultExpiry(RoleName::TargetsRole);
            auto expiryTime = std::chrono::system_clock::to_time_t(expiry);
            std::stringstream ss;
            ss << std::put_time(std::gmtime(&expiryTime), "%Y-%m-%dT%H:%M:%SZ");
            targetsData["signed"]["expires"] = ss.str();
            
            // 保存更新后的元数据
            std::string updatedStr = targetsData.dump();
            std::vector<uint8_t> updatedData(updatedStr.begin(), updatedStr.end());
            auto err = cache_->Set(TARGETS_ROLE, updatedData);
            if (!err.ok()) {
                return Error(std::string("Failed to save target metadata: ") + err.what());
            }
        }
        
        return Error(); // 成功
    } catch (const std::exception& e) {
        return Error(std::string("Failed to apply changelist: ") + e.what());
    }
}

Error Repository::Publish() {
    try {
        bool initialPublish = false;
        
        // 更新TUF元数据 (对应Go的r.updateTUF(true))
        auto err = updateTUF(true);
        if (!err.ok()) {
            // 检查是否是仓库不存在的错误 (对应Go的ErrRepositoryNotExist检查)
            if (std::string(err.what()).find("Repository not found") != std::string::npos ||
                std::string(err.what()).find("repository does not exist") != std::string::npos) {
                
                // 尝试从本地缓存加载 (对应Go的r.bootstrapRepo())
                utils::GetLogger().Info("尝试从本地缓存加载", utils::LogContext().With("gun", gun_.empty() ? "default" : gun_));
                err = bootstrapRepo();
                if (!err.ok() && (std::string(err.what()).find("Metadata not found") != std::string::npos ||
                                 std::string(err.what()).find("not found") != std::string::npos)) {
                    
                    utils::GetLogger().Info("No TUF data found locally or remotely - initializing repository for the first time",
                        utils::LogContext().With("gun", gun_.empty() ? "default" : gun_));
                    
                    // 初始化仓库 (对应Go的r.Initialize(nil))
                    err = Initialize({});
                }
                
                if (!err.ok()) {
                    utils::GetLogger().Debug("Unable to load or initialize repository during first publish",
                        utils::LogContext().With("error", err.what()));
                    return err;
                }
                
                // 标记为首次发布 (对应Go的initialPublish = true)
                initialPublish = true;
            } else {
                // 无法更新，因此无法发布 (对应Go的"We could not update, so we cannot publish")
                utils::GetLogger().Error("Could not publish Repository since we could not update",
                    utils::LogContext().With("error", err.what()));
                return err;
            }
        }

        // 应用changelist到repo (对应Go的applyChangelist(r.tufRepo, r.invalid, cl))
        err = utils::applyChangelist(tufRepo_, invalidRepo_, changelist_);
        if (!err.ok()) {
            utils::GetLogger().Debug("Error applying changelist");
            return err;
        }
        
        // 准备需要更新的TUF文件 (对应Go的updatedFiles := make(map[data.RoleName][]byte))
        std::map<std::string, std::vector<uint8_t>> updatedFiles;
        
        // 检查并签署Root文件 (对应Go的signRootIfNecessary)
        err = signRootIfNecessary(updatedFiles, initialPublish);
        if (!err.ok()) {
            return err;
        }
        
        // 签署Targets文件 (对应Go的signTargets)
        err = signTargets(updatedFiles, initialPublish);
        if (!err.ok()) {
            return err;
        }
        
        // 处理Snapshot文件 (对应Go的snapshot处理逻辑)
        if (!tufRepo_ || !tufRepo_->GetSnapshot()) {
            // 如果没有snapshot文件，尝试初始化 (对应Go的r.tufRepo.InitSnapshot())
            if (tufRepo_) {
                auto initResult = tufRepo_->InitSnapshot();
                if (!initResult.ok()) {
                    return Error("Failed to initialize snapshot: " + initResult.error().what());
                }
            }
        }
        
        // 尝试序列化并签署snapshot (对应Go的serializeCanonicalRole)
        if (tufRepo_) {
            auto snapshotResult = utils::serializeCanonicalRole(tufRepo_, RoleName::SnapshotRole, {});
            if (!snapshotResult.empty()) {
                // 成功签署snapshot
                updatedFiles["snapshot"] = snapshotResult;
            } else {
                // 签署失败，假设服务器会签署 (对应Go的"Assuming that server should sign the snapshot")
                utils::GetLogger().Debug("Client does not have the key to sign snapshot. "
                    "Assuming that server should sign the snapshot.");
            }
        }
        
        // 推送更新到远程服务器 (对应Go的remote.SetMulti)
        if (remoteStore_) {
            // 准备批量上传的元数据map - 对应Go版本的SetMulti
            std::map<std::string, json> metasToUpload;
            
            for (const auto& [roleName, data] : updatedFiles) {
                // 将vector<uint8_t>转换为json对象
                try {
                    std::string jsonStr(data.begin(), data.end());
                    json jsonData = json::parse(jsonStr);
                    metasToUpload[roleName] = jsonData;
                } catch (const json::exception& e) {
                    return Error("Failed to parse metadata JSON for " + roleName + ": " + e.what());
                }
            }
            
            // 使用SetMulti一次性上传所有元数据，保持服务器一致性
            err = remoteStore_->SetMulti(gun_.empty() ? "default" : gun_, metasToUpload);
            if (!err.ok()) {
                return Error("Failed to publish metadata using SetMulti: " + err.what());
            }
            
            utils::GetLogger().Info("成功批量发布元数据", 
                utils::LogContext()
                    .With("gun", gun_.empty() ? "default" : gun_)
                    .With("files_count", std::to_string(metasToUpload.size())));
        }
        
        // 清除changelist (对应Go的r.changelist.Clear(""))
        err = changelist_->Clear("");
        if (!err.ok()) {
            // 这不是关键问题，但会导致奇怪的行为 (对应Go的警告日志)
            utils::GetLogger().Warn("Unable to clear changelist. You may want to manually delete the folder",
                utils::LogContext().With("location", changelist_->Location()));
        }
        
        return Error(); // 成功

        // // 应用changelist
        // err = applyChangelist();
        // if (!err.ok()) {
        //     return err;
        // }
        // // 清除changelist
        // err = changelist_->Clear("");
        // if (!err.ok()) {
        //     std::cerr << "Warning: Unable to clear changelist. You may want to manually delete the folder "
        //               << changelist_->Location() << std::endl;
        // }
        // // 获取所有需要推送的元数据
        // std::string gunStr = gun_.empty() ? "default" : gun_;
        // std::map<std::string, std::vector<uint8_t>> updatedFiles;
        // // 处理Root文件
        // auto rootResult = cache_->Get(ROOT_ROLE);
        // if (rootResult.ok()) {
        //     if (needsResigning(rootResult.value()) || initialPublish) {
        //         auto signedRoot = resignMetadata(rootResult.value(), "root");
        //         if (!signedRoot.ok()) {
        //             return Error(std::string("Failed to resign root metadata: ") + signedRoot.error().what());
        //         }
        //         updatedFiles["root"] = signedRoot.value();
        //     } else {
        //         // 直接使用vector<uint8_t>，不需要dump
        //         updatedFiles["root"] = rootResult.value();
        //     }
        // }
        // // 处理Targets文件
        // auto targetsResult = cache_->Get(TARGETS_ROLE);
        // if (targetsResult.ok()) {
        //     if (needsResigning(targetsResult.value()) || initialPublish) {
        //         auto signedTargets = resignMetadata(targetsResult.value(), "targets");
        //         if (!signedTargets.ok()) {
        //             return Error(std::string("Failed to resign targets metadata: ") + signedTargets.error().what());
        //         }
        //         updatedFiles["targets"] = signedTargets.value();
        //     } else {
        //         // 直接使用vector<uint8_t>，不需要dump
        //         updatedFiles["targets"] = targetsResult.value();
        //     }
        // }
        // // 处理Snapshot文件
        // auto snapshotResult = cache_->Get(SNAPSHOT_ROLE);
        // if (snapshotResult.ok()) {
        //     if (needsResigning(snapshotResult.value()) || initialPublish) {
        //         auto signedSnapshot = resignMetadata(snapshotResult.value(), "snapshot");
        //         if (!signedSnapshot.ok()) {
        //             std::cout << "Client does not have the key to sign snapshot. "
        //                       << "Assuming that server should sign the snapshot." << std::endl;
        //         } else {
        //             updatedFiles["snapshot"] = signedSnapshot.value();
        //         }
        //     } else {
        //         // 直接使用vector<uint8_t>，不需要dump
        //         updatedFiles["snapshot"] = snapshotResult.value();
        //     }
        // } else {
        //     // 如果没有snapshot文件，尝试初始化
        //     err = initializeSnapshot();
        //     if (!err.ok()) {
        //         std::cerr << "Failed to initialize snapshot: " << err.what() << std::endl;
        //         return err;
        //     }
        // }
        // // 推送到远程服务器
        // for (const auto& [role, data] : updatedFiles) {
        //     err = remoteStore_->SetRemote(gunStr, role, data);
        //     if (!err.ok()) {
        //         return Error(std::string("Failed to publish ") + role + " metadata: " + err.what());
        //     }
        // }
        // return Error(); // 成功
    } catch (const std::exception& e) {
        return Error(std::string("Failed to publish: ") + e.what());
    }
}

// 检查是否接近过期 (对应Go的nearExpiry函数)
bool nearExpiry(const std::chrono::system_clock::time_point& expires) {
    auto plus6mo = std::chrono::system_clock::now() + std::chrono::hours(24 * 30 * 6); // 6个月
    return expires < plus6mo;
}

// signRootIfNecessary函数实现 (对应Go的signRootIfNecessary函数)
Error Repository::signRootIfNecessary(std::map<std::string, std::vector<uint8_t>>& updates, bool initialPublish) {
    if (!tufRepo_) {
        return Error("TUF repository not initialized");
    }
    
    try {
        auto root = tufRepo_->GetRoot();
        if (!root) {
            return Error("Root metadata not found");
        }
        
        bool needsUpdate = false;
        
        // 检查是否接近过期 (对应Go的nearExpiry(repo.Root.Signed.SignedCommon))
        if (nearExpiry(root->Signed.Common.Expires)) {
            needsUpdate = true;
        }
        
        // 检查是否标记为dirty (对应Go的repo.Root.Dirty)
        if (root->Dirty) {
            needsUpdate = true;
        }
        
        if (needsUpdate) {
            // 序列化并签署root (对应Go的serializeCanonicalRole)
            auto rootJSON = utils::serializeCanonicalRole(tufRepo_, RoleName::RootRole, {});
            if (rootJSON.empty()) {
                return Error("Failed to serialize root metadata");
            }
            updates[ROOT_ROLE] = rootJSON;
        } else if (initialPublish) {
            // 首次发布时，即使不需要重新签名也要包含root (对应Go的repo.Root.MarshalJSON())
            auto rootJSON = root->Serialize();
            if (rootJSON.empty()) {
                return Error("Failed to marshal root metadata");
            }
            updates[ROOT_ROLE] = rootJSON;
        }
        
        return Error(); // 成功
        
    } catch (const std::exception& e) {
        return Error(std::string("Failed to sign root if necessary: ") + e.what());
    }
}

// signTargets函数实现 (对应Go的signTargets函数)
Error Repository::signTargets(std::map<std::string, std::vector<uint8_t>>& updates, bool initialPublish) {
    if (!tufRepo_) {
            return Error("TUF repository not initialized");
    }

    try {
        // 遍历所有targets文件 (对应Go的for roleName, roleObj := range repo.Targets)
        auto targets = tufRepo_->GetTargets();
        
        for (const auto& [roleName, roleObj] : targets) {
            bool needsUpdate = false;
            
            // 检查是否标记为dirty (对应Go的roleObj.Dirty)
            if (roleObj->Dirty) {
                needsUpdate = true;
            }
            
            // 如果是主targets角色且是首次发布 (对应Go的roleName == data.CanonicalTargetsRole && initialPublish)
            if (roleName == RoleName::TargetsRole && initialPublish) {
                needsUpdate = true;
            }
            
            if (needsUpdate) {
                // 序列化并签署targets (对应Go的serializeCanonicalRole)
                auto targetsJSON = utils::serializeCanonicalRole(tufRepo_, roleName, {});
                if (targetsJSON.empty()) {
                    return Error("Failed to serialize targets metadata for role: " + roleToString(roleName));
                }
                updates[TARGETS_ROLE] = targetsJSON;
            }
        }
        
        return Error(); // 成功
        
    } catch (const std::exception& e) {
        return Error(std::string("Failed to sign targets: ") + e.what());
    }
}

Error Repository::updateTUF(bool force) {
    try {
        std::string gunStr = gun_.empty() ? "default" : gun_;
        
        // 尝试从远程获取最新的元数据
        auto rootResult = remoteStore_->GetRemote(gunStr, "root");
        if (!rootResult.ok()) {
            utils::GetLogger().Info("Repository not found", utils::LogContext().With("gun", gunStr));
            return Error("Repository not found");
        }
        
        // 更新本地缓存
        auto err = cache_->Set(ROOT_ROLE, rootResult.value());
        if (!err.ok()) {
            return err;
        }
        
        // 获取并更新其他角色的元数据
        std::vector<std::string> roles = {"targets", "snapshot"};
        for (const auto& role : roles) {
            auto result = remoteStore_->GetRemote(gunStr, role);
            if (result.ok()) {
                std::string roleKey = role == "targets" ? TARGETS_ROLE : SNAPSHOT_ROLE;
                err = cache_->Set(roleKey, result.value());
                if (!err.ok()) {
                    return err;
                }
            }
        }
        
        return Error();
    } catch (const std::exception& e) {
        return Error(std::string("Failed to update TUF: ") + e.what());
    }
}

Error Repository::bootstrapRepo() {
    // 创建TrustPinConfig（空配置，类似Go版本的trustpinning.TrustPinConfig{}）
    tuf::TrustPinConfig trustPin;
    
    // 创建新的RepoBuilder
    auto builder = tuf::NewRepoBuilder(gun_, cryptoService_, trustPin);
    
    utils::GetLogger().Info("Loading trusted collection.");
    
    // 定义基础角色列表（对应Go版本的data.BaseRoles）
    std::vector<RoleName> baseRoles = {
        RoleName::RootRole,
        RoleName::TargetsRole,
        RoleName::SnapshotRole,
        RoleName::TimestampRole
    };
    
    // 遍历所有基础角色
    for (const auto& role : baseRoles) {
        std::string roleStr = roleToString(role);
        
        // 从cache获取角色的字节数据（对应Go版本的r.cache.GetSized）
        auto bytesResult = cache_->Get(roleStr);
        if (!bytesResult.ok()) {
            // 检查是否是未找到错误且角色是snapshot或timestamp
            // 类似Go版本：if _, ok := err.(store.ErrMetaNotFound); ok &&
            // (role == data.CanonicalSnapshotRole || role == data.CanonicalTimestampRole)
            if (role == RoleName::SnapshotRole || role == RoleName::TimestampRole) {
                // server snapshots和server timestamp管理是支持的，
                // 所以如果这些加载失败是可以的 - 特别是对于新仓库
                continue;
            }
            return Error("Failed to get metadata for role " + roleStr + ": " + bytesResult.error().what());
        }
        
        // 直接使用字节数据（对应Go版本的jsonBytes）
        const std::vector<uint8_t>& jsonBytes = bytesResult.value();
        
        // 调用builder的Load方法（对应Go版本的b.Load(role, jsonBytes, 1, true)）
        Error loadErr = builder->load(role, jsonBytes, 1, true);
        if (!loadErr.ok()) {
            return Error("Failed to load role " + roleStr + ": " + loadErr.what());
        }
    }
    
    // 完成构建（对应Go版本的b.Finish()）
    auto finishResult = builder->finish();
    if (!finishResult.ok()) {
        return Error("Failed to finish building repository: " + finishResult.error().what());
    }
    
    // 获取构建的仓库
    auto [tufRepo, invalidRepo] = finishResult.value();
    if (tufRepo) {
        tufRepo_ = tufRepo;
    }
    
    return Error();
}

} // namespace notary 