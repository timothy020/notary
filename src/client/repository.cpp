#include "notary/client/repository.hpp"
#include "notary/client/tufclient.hpp"
#include "notary/tuf/repo.hpp"
#include "notary/tuf/builder.hpp"
#include "notary/utils/tools.hpp"
#include "notary/crypto/keys.hpp"
#include "notary/crypto/certificate.hpp"
#include "notary/crypto/verify.hpp"
#include "notary/utils/x509.hpp"
#include "notary/utils/helpers.hpp"
#include "notary/changelist/changelist.hpp"
#include "notary/storage/keystore.hpp"
#include "notary/storage/httpstore.hpp"
#include "notary/passRetriever/passRetriever.hpp"
#include <set>
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
bool isValidServerManagedRole(const std::string& role) {
    return role == TIMESTAMP_ROLE || role == SNAPSHOT_ROLE;
}

// 检查角色是否是根角色
bool isRootRole(const std::string& role) {
    return role == ROOT_ROLE;
}

// checkRotationInput函数实现 - 对应Go版本的checkRotationInput函数
// 验证密钥轮转的输入参数是否有效
Error checkRotationInput(const std::string& role, bool serverManaged) {
    // 检查是否是有效的角色
    if (role != ROOT_ROLE && role != TARGETS_ROLE && 
        role != SNAPSHOT_ROLE && role != TIMESTAMP_ROLE) {
        return Error("Notary does not currently permit rotating the " + role + " key");
    }
    
    // 检查是否是委托角色
    if (tuf::IsDelegation(role)) {
        return Error("Notary does not currently permit rotating the " + role + " key");
    }
    
    // 目前支持远程管理的角色：timestamp和snapshot
    bool canBeRemoteKey = (role == TIMESTAMP_ROLE || role == SNAPSHOT_ROLE);
    
    // 目前支持本地管理的角色：root、targets和snapshot  
    bool canBeLocalKey = (role == ROOT_ROLE || role == TARGETS_ROLE || 
                         role == SNAPSHOT_ROLE);
    
    if (serverManaged && !canBeRemoteKey) {
        return Error("Invalid remote role: " + role + " cannot be server managed");
    }
    
    if (!serverManaged && !canBeLocalKey) {
        return Error("Invalid local role: " + role + " must be server managed");
    }
    
    return Error(); // 成功
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
        if (role != "targets" && !tuf::IsDelegation(role) && !tuf::IsWildDelegation(role)) {
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
    , changelist_(std::make_shared<changelist::FileChangelist>(trustDir+"/tuf/"+gun_+"/changelist"))
    , cache_(std::make_shared<storage::FileStore>(trustDir+"/tuf/"+gun_+"/metadata", ".json"))
    , remoteStore_(storage::HttpStore::NewNotaryServerStore(serverURL, gun))
    {
    // 初始化cryptoService_
    // 定义一个简单的 PassRetriever，表示无密码
    // auto passRetriever = [](const std::string& keyName,
    //                               const std::string& alias,
    //                               bool createNew,
    //                               int attempts) -> std::tuple<std::string, bool, Error> {
    //     // 返回空密码（""），不放弃（false），无错误（Error()）
    //     return std::make_tuple("", false, Error());
    // };
    auto passRetriever = passphrase::PromptRetriever();
    std::unique_ptr<storage::GenericKeyStore> keyStores = notary::storage::GenericKeyStore::NewKeyFileStore(trustDir+"/private", passRetriever);
    cryptoService_ = std::make_shared<crypto::CryptoService>(std::vector<std::shared_ptr<storage::GenericKeyStore>>{std::move(keyStores)});
    
    // 初始化TUF Repo
    tufRepo_ = std::make_shared<tuf::Repo>(cryptoService_);
    invalidRepo_ = std::make_shared<tuf::Repo>(cryptoService_);
}


Error Repository::Initialize(const std::vector<std::string>& rootKeyIDs,
                           const std::vector<std::shared_ptr<crypto::PublicKey>>& rootCerts,
                           const std::vector<std::string>& serverManagedRoles) {
    // 验证服务器管理的角色
    std::vector<std::string> remoteRoles = {TIMESTAMP_ROLE}; // timestamp总是由服务器管理
    std::vector<std::string> localRoles = {TARGETS_ROLE, SNAPSHOT_ROLE};

    for (const auto& role : serverManagedRoles) {
        if (!isValidServerManagedRole(role)) {
            return Error("Invalid server managed role");
        }
        if (role == SNAPSHOT_ROLE) {
            // 将snapshot从本地管理移到远程管理
            localRoles.erase(
                std::remove(localRoles.begin(), localRoles.end(), SNAPSHOT_ROLE),
                localRoles.end()
            );
            remoteRoles.push_back(role);
        }
    }

    // 获取根密钥 (对应Go版本的获取根密钥逻辑)
    // - 如果没有提供 rootCerts，则通过 createNewPublicKeyFromKeyIDs 方法生成新的公钥。
    // - 如果提供了 rootCerts，则通过 publicKeysOfKeyIDs 方法验证公钥和私钥是否匹配。
    std::vector<std::shared_ptr<crypto::PublicKey>> publicKeys;
    
    if (rootCerts.empty()) {
        // 使用createNewPublicKeyFromKeyIDs生成新公钥 (对应Go的r.createNewPublicKeyFromKeyIDs(rootKeyIDs))
        auto publicKeysResult = createNewPublicKeyFromKeyIDs(rootKeyIDs);
        if (!publicKeysResult.ok()) {
            return Error("Failed to create new public keys from key IDs: " + publicKeysResult.error().what());
        }
        publicKeys = publicKeysResult.value();
    } else {
        // 使用publicKeysOfKeyIDs验证公钥和私钥匹配 (对应Go的r.publicKeysOfKeyIDs(rootKeyIDs, rootCerts))
        auto publicKeysResult = publicKeysOfKeyIDs(rootKeyIDs, rootCerts);
        if (!publicKeysResult.ok()) {
            return Error("Failed to validate public keys of key IDs: " + publicKeysResult.error().what());
        }
        publicKeys = publicKeysResult.value();
    }
    
    // 确保至少有一个根密钥
    if (publicKeys.empty()) {
        return Error("No root keys available");
    }

    // 初始化角色
    auto [root, targets, snapshot, timestamp] = initializeRoles(publicKeys, localRoles, remoteRoles);

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
        auto rootData = utils::serializeCanonicalRole(tufRepo_, ROOT_ROLE, {});
        if (rootData.empty()) {
            return Error("Failed to serialize root metadata");
        }
        
        // 调用 cache_->Set() 落盘到本地，key 是字符串 "root"，值是内容字节数组
        auto rootResult = cache_->Set(ROOT_ROLE, rootData);
        if (rootResult.hasError()) {
            return rootResult;
        }
        
        // 2. 序列化并保存所有targets文件
        std::map<std::string, std::vector<uint8_t>> targetsToSave;
        
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
            auto targetsResult = cache_->Set(role, blob);
            if (targetsResult.hasError()) {
                return targetsResult;
            }
        }
        
        // 3. 如果不忽略snapshot，序列化并保存snapshot.json
        if (!ignoreSnapshot) {
            auto snapshotData = utils::serializeCanonicalRole(tufRepo_, SNAPSHOT_ROLE, {});
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
                          const std::vector<std::string>& localRoles,
                          const std::vector<std::string>& remoteRoles) {
    // 创建根角色
    BaseRole root(ROOT_ROLE, 1, rootKeys);
    
    // 初始化其他角色的空密钥列表
    std::vector<std::shared_ptr<crypto::PublicKey>> emptyKeys;
    BaseRole targets(TARGETS_ROLE, 0, emptyKeys);
    BaseRole snapshot(SNAPSHOT_ROLE, 0, emptyKeys);
    BaseRole timestamp(TIMESTAMP_ROLE, 0, emptyKeys);

    // 创建本地角色密钥（不包括timestamp）
    for (const auto& role : localRoles) {
        if (role == TIMESTAMP_ROLE) {
            continue; // 跳过timestamp角色，它只从远程获取
        }
        
        auto publicKeyResult = cryptoService_->Create(role, gun_, ECDSA_KEY);
        if (!publicKeyResult.ok()) {
            continue; // 跳过失败的密钥创建
        }
        std::vector<std::shared_ptr<crypto::PublicKey>> roleKeys = {publicKeyResult.value()};
        
        if (role == TARGETS_ROLE) {
            targets = BaseRole(role, 1, roleKeys);
        } else if (role == SNAPSHOT_ROLE) {
            snapshot = BaseRole(role, 1, roleKeys);
        }
    }

    // 获取远程角色密钥
    for (const auto& role : remoteRoles) {
        auto keyResult = remoteStore_->GetKey(role == TIMESTAMP_ROLE ? "timestamp" : "snapshot");
        if (!keyResult.ok()) {
            std::cerr << "Failed to get remote key : " << keyResult.error().what() << std::endl;
            continue; // 跳过失败的密钥获取
        }
        
        // 从字节数据解析JSON
        std::string keyJsonStr(keyResult.value().begin(), keyResult.value().end());
        json keyJson;
        try {
            keyJson = json::parse(keyJsonStr);
        } catch (const std::exception& e) {
            std::cerr << "Failed to parse key JSON: " << e.what() << std::endl;
            continue;
        }
        
        std::cout << "远端获取到的keyJson: " << keyJson.dump() << std::endl;

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
                    
                    if (role == TIMESTAMP_ROLE) {
                        timestamp = BaseRole(role, 1, roleKeys);
                    } else if (role == SNAPSHOT_ROLE) {
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
            auto expiry = utils::getDefaultExpiry(TARGETS_ROLE);
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
    Error err = publish(changelist_);
    if (!err.ok()) {
        return err;
    }
    // 清除changelist (对应Go的r.changelist.Clear(""))
    err = changelist_->Clear("");
    if (!err.ok()) {
        utils::GetLogger().Warn("Unable to clear changelist. You may want to manually delete the folder",
            utils::LogContext().With("location", changelist_->Location()));
    }
    return Error();
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
        if (utils::nearExpiry(root->Signed.Common.Expires)) {
            needsUpdate = true;
        }
        
        // 检查是否标记为dirty (对应Go的repo.Root.Dirty)
        if (root->Dirty) {
            needsUpdate = true;
        }
        
        if (needsUpdate) {
            // 序列化并签署root (对应Go的serializeCanonicalRole)
            utils::GetLogger().Info("signRootIfNecessary");
            auto rootJSON = utils::serializeCanonicalRole(tufRepo_, ROOT_ROLE, {});
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
            if (roleName == TARGETS_ROLE && initialPublish) {
                needsUpdate = true;
            }
            
            if (needsUpdate) {
                // 序列化并签署targets (对应Go的serializeCanonicalRole)
                auto targetsJSON = utils::serializeCanonicalRole(tufRepo_, roleName, {});
                if (targetsJSON.empty()) {
                    return Error("Failed to serialize targets metadata for role: " + roleName);
                }
                updates[TARGETS_ROLE] = targetsJSON;
            }
        }
        
        return Error(); // 成功
        
    } catch (const std::exception& e) {
        return Error(std::string("Failed to sign targets: ") + e.what());
    }
}

Error Repository::updateTUF(bool forWrite) {
    // 对应Go版本的updateTUF方法
    // 使用LoadTUFRepo来加载TUF仓库
    try {
        // 构建TUFLoadOptions (对应Go版本的TUFLoadOptions)
        client::TUFLoadOptions options;
        options.GUN = gun_;
        options.TrustPinning = tuf::TrustPinConfig{}; // 使用空的信任锚定配置
        options.CryptoService = cryptoService_;
        options.Cache = cache_;
        options.RemoteStore = remoteStore_;
        options.AlwaysCheckInitialized = forWrite; // 对应Go版本的forWrite参数
        
        // 调用LoadTUFRepo函数 (对应Go版本的LoadTUFRepo)
        auto repoResult = client::LoadTUFRepo(options);
        if (!repoResult.ok()) {
            return repoResult.error();
        }
        
        // 获取结果 (对应Go版本的repo, invalid, err := LoadTUFRepo(...))
        auto repos = repoResult.value();
        auto repo = std::get<0>(repos);
        auto invalid = std::get<1>(repos);
        
        // 设置TUF仓库 (对应Go版本的r.tufRepo = repo)
        tufRepo_ = repo;
        
        // 设置无效仓库 (对应Go版本的r.invalid = invalid)
        invalidRepo_ = invalid;
        
        return Error(); // 成功
        
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
    std::vector<std::string> baseRoles = {
        ROOT_ROLE,
        TARGETS_ROLE,
        SNAPSHOT_ROLE,
        TIMESTAMP_ROLE
    };
    
    // 遍历所有基础角色
    for (const auto& role : baseRoles) {
        std::string roleStr = role;
        
        // 从cache获取角色的字节数据（对应Go版本的r.cache.GetSized）
        auto bytesResult = cache_->Get(roleStr);
        if (!bytesResult.ok()) {
            // 检查是否是未找到错误且角色是snapshot或timestamp
            // 类似Go版本：if _, ok := err.(store.ErrMetaNotFound); ok &&
            // (role == data.CanonicalSnapshotRole || role == data.CanonicalTimestampRole)
            if (role == SNAPSHOT_ROLE || role == TIMESTAMP_ROLE) {
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

// GetTargetByName - 通过目标名称获取目标信息 (对应Go的GetTargetByName)
Result<Target> Repository::GetTargetByName(const std::string& targetName) {
    try {
        // 首先更新TUF元数据
        auto updateErr = updateTUF(false);
        if (!updateErr.ok()) {
            // 如果远程更新失败，尝试从本地缓存加载
            auto bootstrapErr = bootstrapRepo();
            if (!bootstrapErr.ok()) {
                return Error("Failed to load repository: " + updateErr.what() + " and " + bootstrapErr.what());
            }
        }
        
        if (!tufRepo_) {
            return Error("TUF repository not initialized");
        }
        
        // 用于存储查找结果的变量
        tuf::FileMeta resultMeta;
        bool foundTarget = false;
        
        // 定义访问者函数来查找指定的目标 (对应Go的getTargetVisitorFunc)
        tuf::WalkVisitorFunc getTargetVisitorFunc = [&](std::shared_ptr<tuf::SignedTargets> tgt, const tuf::DelegationRole& validRole) -> tuf::WalkResult {
            if (!tgt) {
                return std::monostate{}; // 返回nil等价物
            }
            
            // 在目标中查找指定名称的文件 (对应Go的tgt.Signed.Targets[name])
            auto targetIt = tgt->Signed.targets.find(targetName);
            if (targetIt != tgt->Signed.targets.end()) {
                // 找到目标，设置结果变量并停止遍历
                resultMeta = targetIt->second;
                foundTarget = true;
                return tuf::StopWalk{}; // 停止遍历
            }
            
            return std::monostate{}; // 继续遍历
        };
        
        // 执行遍历，从TargetsRole开始查找 (对应Go的r.tufRepo.WalkTargets)
        auto walkErr = tufRepo_->WalkTargets(targetName, TARGETS_ROLE, getTargetVisitorFunc);
        
        // 检查是否找到目标且没有错误
        if (!walkErr.ok()) {
            return Error("Error walking targets: " + walkErr.what());
        }
        
        if (!foundTarget) {
            return Error("Target not found: " + targetName);
        }
        
        // 构造Target对象
        Target target;
        target.name = targetName;
        target.hashes = resultMeta.Hashes;
        target.length = resultMeta.Length;
        target.custom = resultMeta.Custom;
        
        return target;
        
    } catch (const std::exception& e) {
        return Error("Failed to get target by name: " + std::string(e.what()));
    }
}

// 获取委托角色 (对应Go的GetDelegationRoles)
Result<std::vector<tuf::DelegationRole>> Repository::GetDelegationRoles() {
    try {
        // 首先更新TUF元数据 (对应Go的if err := r.updateTUF(false); err != nil)
        auto updateErr = updateTUF(false);
        if (!updateErr.ok()) {
            return Result<std::vector<tuf::DelegationRole>>(updateErr);
        }
        
        // 检查是否已加载targets角色 (对应Go的_, ok := r.tufRepo.Targets[data.CanonicalTargetsRole])
        auto targetsObj = tufRepo_->GetTargets(TARGETS_ROLE);
        if (!targetsObj) {
            return Result<std::vector<tuf::DelegationRole>>(
                Error("targets metadata not found"));
        }
        
        // 创建委托角色列表 (对应Go的allDelegations := []data.Role{})
        std::vector<tuf::DelegationRole> allDelegations;
        
        // 定义访问者函数来填充委托列表并将其密钥ID转换为规范ID
        // (对应Go的delegationCanonicalListVisitor)
        tuf::WalkVisitorFunc delegationCanonicalListVisitor = 
            [&allDelegations](std::shared_ptr<tuf::SignedTargets> tgt, const tuf::DelegationRole& validRole) -> tuf::WalkResult {
                if (!tgt) {
                    return std::monostate{}; // 继续遍历
                }
                
                // 获取当前目标的委托 (对应Go的tgt.Signed.Delegations)
                const auto& delegations = tgt->Signed.delegations;
                
                // 添加所有委托角色到列表 (对应Go的allDelegations = append(allDelegations, canonicalDelegations...))
                for (const auto& role : delegations.Roles) {
                    // 注意：这里我们直接添加DelegationRole，密钥ID已经在解析时转换为规范格式
                    allDelegations.push_back(role);
                }
                
                return std::monostate{}; // 继续遍历
            };
        
        // 使用WalkTargets遍历所有委托 (对应Go的err := r.tufRepo.WalkTargets("", "", delegationCanonicalListVisitor))
        auto walkErr = tufRepo_->WalkTargets("", "", delegationCanonicalListVisitor);
        if (!walkErr.ok()) {
            return Result<std::vector<tuf::DelegationRole>>(walkErr);
        }
        
        return Result<std::vector<tuf::DelegationRole>>(allDelegations);
        
    } catch (const std::exception& e) {
        return Result<std::vector<tuf::DelegationRole>>(Error("Failed to get delegation roles: " + std::string(e.what())));
    }
}

// 删除信任数据 (对应Go的DeleteTrustData)
Error Repository::DeleteTrustData(const std::string& baseDir, const GUN& gun, 
                                 const std::string& serverURL, bool deleteRemote) {
    // 构建本地仓库路径 (对应Go的filepath.Join(baseDir, tufDir, filepath.FromSlash(gun.String())))
    std::string localRepo = baseDir + "tuf/" + gun;
    utils::GetLogger().Info("删除路径", utils::LogContext().With("localRepo", localRepo));
    
    // 删除本地TUF仓库数据目录，包括本地TUF元数据文件和changelist信息
    // (对应Go的os.RemoveAll(localRepo))
    try {
        if (fs::exists(localRepo)) {
            fs::remove_all(localRepo);
            utils::GetLogger().Info("Local trust data deleted", 
                utils::LogContext()
                    .With("gun", gun)
                    .With("localPath", localRepo));
        }
    } catch (const std::exception& e) {
        return Error(std::string("Error clearing TUF repo data: ") + e.what());
    }
    
    // 如果需要删除远程数据 (对应Go的deleteRemote检查)
    if (deleteRemote && !serverURL.empty()) {
        utils::GetLogger().Info("Deleting remote trust data", 
            utils::LogContext()
                .With("gun", gun)
                .With("serverURL", serverURL));
        
        try {
            // 创建远程存储客户端 (对应Go的getRemoteStore)
            // 构建URL: baseURL + "/v2/" + gun.String() + "/_trust/tuf/"
            std::string remoteURL = serverURL + "/v2/" + gun + "/_trust/tuf/";
            auto remoteStore = storage::HttpStore::NewNotaryServerStore(serverURL, gun);
            
            // 删除远程数据 (对应Go的remote.RemoveAll())
            auto result = remoteStore->RemoveAll();
            if (!result.ok()) {
                utils::GetLogger().Error("Failed to delete remote trust data", 
                    utils::LogContext()
                        .With("gun", gun)
                        .With("serverURL", serverURL)
                        .With("error", result.what()));
                return result;
            }
            
            utils::GetLogger().Info("Remote trust data deleted successfully", 
                utils::LogContext()
                    .With("gun", gun)
                    .With("serverURL", serverURL));
                    
        } catch (const std::exception& e) {
            return Error(std::string("Unable to instantiate a remote store: ") + e.what());
        }
    }
    
    return Error(); // 成功
}

// 列出所有目标 (对应Go的ListTargets)
Result<std::vector<TargetWithRole>> Repository::ListTargets(const std::vector<std::string>& roles) {
    try {
        // 首先更新TUF元数据 (对应Go版本的updateTUF调用)
        auto updateErr = updateTUF(false);
        if (!updateErr.ok()) {
            // 如果远程更新失败，尝试从本地缓存加载
            auto bootstrapErr = bootstrapRepo();
            if (!bootstrapErr.ok()) {
                return Error("Failed to load repository: " + updateErr.what() + " and " + bootstrapErr.what());
            }
        }
        if (!tufRepo_) {
            return Error("TUF repository not initialized");
        }
        
        // 如果没有指定角色，默认使用targets角色 (对应Go的if len(roles) == 0)
        std::vector<std::string> effectiveRoles = roles;
        if (effectiveRoles.empty()) {
            effectiveRoles.push_back(TARGETS_ROLE);
        }
        
        // 用于存储目标的map，防止重复 (对应Go的targets := make(map[string]*TargetWithRole))
        std::map<std::string, TargetWithRole> targets;
        
        // 遍历每个角色 (对应Go的for _, role := range roles)
        for (const auto& role : effectiveRoles) {
            // 定义要跳过的角色数组 (对应Go的skipRoles := utils.RoleNameSliceRemove(roles, role))
            std::vector<std::string> skipRoles = utils::roleNameSliceRemove(effectiveRoles, role);
            
            // 定义访问者函数来按优先级顺序填充目标map (对应Go的listVisitorFunc)
            tuf::WalkVisitorFunc listVisitorFunc = [&](std::shared_ptr<tuf::SignedTargets> tgt, 
                                                      const tuf::DelegationRole& validRole) -> tuf::WalkResult {
                if (!tgt) {
                    return std::monostate{}; // 继续遍历
                }
                
                // 我们找到了目标，应该尝试将它们添加到目标map中
                // (对应Go的for targetName, targetMeta := range tgt.Signed.Targets)
                for (const auto& [targetName, targetMeta] : tgt->Signed.targets) {
                    // 按优先级处理，不覆盖之前设置的目标
                    // 并检查此路径对此角色是否有效 (对应Go的if _, ok := targets[targetName]; ok || !validRole.CheckPaths(targetName))
                    if (targets.find(targetName) != targets.end() || !validRole.CheckPaths(targetName)) {
                        continue;
                    }
                    
                    // 创建带角色的目标对象 (对应Go的targets[targetName] = &TargetWithRole{...})
                    TargetWithRole targetWithRole;
                    targetWithRole.target.name = targetName;
                    targetWithRole.target.hashes = targetMeta.Hashes;
                    targetWithRole.target.length = targetMeta.Length;
                    targetWithRole.target.custom = targetMeta.Custom;
                    targetWithRole.role = validRole.Name;
                    
                    targets[targetName] = targetWithRole;
                }
                
                return std::monostate{}; // 继续遍历
            };
            
            // 执行目标遍历 (对应Go的r.tufRepo.WalkTargets("", role, listVisitorFunc, skipRoles...))
            auto walkErr = tufRepo_->WalkTargets("", role, listVisitorFunc, skipRoles);
            if (!walkErr.ok()) {
                return Error("Error walking targets for role " + role + ": " + walkErr.what());
            }
        }
        
        // 将map转换为vector (对应Go的var targetList []*TargetWithRole; for _, v := range targets)
        std::vector<TargetWithRole> targetList;
        targetList.reserve(targets.size());
        
        for (const auto& [name, targetWithRole] : targets) {
            targetList.push_back(targetWithRole);
        }
        
        return targetList;
        
    } catch (const std::exception& e) {
        return Error("Failed to list targets: " + std::string(e.what()));
    }
}

// 移除目标文件 (对应Go的RemoveTarget)
Error Repository::RemoveTarget(const std::string& targetName, const std::vector<std::string>& roles) {
    try {
        // 记录调试信息 (对应Go的logrus.Debugf("Removing target \"%s\"", targetName))
        utils::GetLogger().Debug("Removing target", utils::LogContext()
            .With("targetName", targetName));
        
        // 创建删除操作的变更模板 (对应Go的changelist.NewTUFChange)
        // changelist.ActionDelete, "", changelist.TypeTargetsTarget, targetName, nil
        auto templateChange = std::make_shared<changelist::TUFChange>(
            changelist::ActionDelete,      // 删除操作
            "",                           // scope为空，对应Go版本
            changelist::TypeTargetsTarget, // 目标类型
            targetName,                   // 目标路径/名称
            std::vector<uint8_t>()        // 删除操作时内容为空 (对应Go的nil)
        );
        
        // 使用addChange函数处理角色验证和变更创建 (对应Go的addChange(r.changelist, template, roles...))
        return addChange(changelist_, templateChange, roles);
        
    } catch (const std::exception& e) {
        return Error(std::string("Failed to remove target: ") + e.what());
    }
}

// rootCertKey函数实现 - 对应Go版本的rootCertKey函数
// 根据给定的私钥和GUN生成根证书，并从证书中提取公钥
std::shared_ptr<crypto::PublicKey> rootCertKey(const std::string& gun, std::shared_ptr<crypto::PrivateKey> privKey) {
    if (!privKey) {
        utils::GetLogger().Error("Private key is null in rootCertKey");
        return nullptr;
    }
    
    // 硬编码策略：生成的证书在10年后过期 (对应Go版本的Hard-coded policy: the generated certificate expires in 10 years)
    auto startTime = std::chrono::system_clock::now();
    auto endTime = startTime + std::chrono::hours(24 * 365 * 10); // 10年 (对应Go版本的notary.Year*10)
    
    try {
        // 生成证书 (对应Go版本的cryptoservice.GenerateCertificate)
        auto cert = notary::crypto::GenerateCertificate(privKey, gun, startTime, endTime);
        if (!cert) {
            utils::GetLogger().Error("Failed to generate certificate", 
                utils::LogContext()
                    .With("gun", gun)
                    .With("privateKeyID", privKey->ID())
                    .With("algorithm", privKey->Algorithm()));
            return nullptr;
        }

        // 从生成的证书中提取X509公钥 (对应Go版本的utils.CertToKey(cert))
        auto x509PublicKey = notary::utils::CertToKey(*cert);
        if (!x509PublicKey) {
            utils::GetLogger().Error("Cannot generate public key from private key", 
                utils::LogContext()
                    .With("privateKeyID", privKey->ID())
                    .With("algorithm", privKey->Algorithm())
                    .With("gun", gun));
            return nullptr;
        }

        // 注意：证书公钥ID与原始私钥ID不一致是正常的，因为证书包含了额外信息
        utils::GetLogger().Info("Successfully generated root certificate and extracted public key", 
            utils::LogContext()
                .With("gun", gun)
                .With("privateKeyID", privKey->ID())
                .With("certificatePublicKeyID", x509PublicKey->ID())
                .With("algorithm", x509PublicKey->Algorithm()));

        return x509PublicKey;

    } catch (const std::exception& e) {
        utils::GetLogger().Error("Exception in rootCertKey", 
            utils::LogContext()
                .With("gun", gun)
                .With("keyID", privKey->ID())
                .With("error", e.what()));
        return nullptr;
    }
}

// createNewPublicKeyFromKeyIDs函数实现 - 对应Go版本的createNewPublicKeyFromKeyIDs函数
// 根据给定的密钥ID列表生成一组对应的公钥
// 这些密钥ID存在于仓库的CryptoService中
// 返回的公钥顺序与输入的keyIDs顺序一一对应
Result<std::vector<std::shared_ptr<crypto::PublicKey>>> Repository::createNewPublicKeyFromKeyIDs(
    const std::vector<std::string>& keyIDs) {
    
    try {
        // 初始化一个空的公钥向量 (对应Go的publicKeys := []data.PublicKey{})
        std::vector<std::shared_ptr<crypto::PublicKey>> publicKeys;
        
        // 从CryptoService中获取所有私钥 (对应Go的privKeys, err := getAllPrivKeys(keyIDs, r.GetCryptoService()))
        auto privKeysResult = utils::getAllPrivKeys(keyIDs, cryptoService_);
        if (!privKeysResult.ok()) {
            return Error("Failed to get private keys: " + privKeysResult.error().what());
        }
        
        auto privKeys = privKeysResult.value();
        
        // 预留空间以提高性能
        publicKeys.reserve(privKeys.size());
        
        // 遍历每个私钥，生成对应的根证书公钥 (对应Go的for _, privKey := range privKeys)
        for (const auto& privKey : privKeys) {
            // 根据GUN和私钥生成根证书公钥 (对应Go的rootKey, err := rootCertKey(r.gun, privKey))
            auto rootKey = rootCertKey(gun_.empty() ? "default" : gun_, privKey);
            if (!rootKey) {
                return Error("Failed to generate root certificate key for private key: " + privKey->ID());
            }
            
            // 将生成的公钥添加到结果向量中 (对应Go的publicKeys = append(publicKeys, rootKey))
            publicKeys.push_back(rootKey);
        }
        
        utils::GetLogger().Debug("Successfully created public keys from key IDs", 
            utils::LogContext()
                .With("keyIDCount", std::to_string(keyIDs.size()))
                .With("publicKeyCount", std::to_string(publicKeys.size()))
                .With("gun", gun_.empty() ? "default" : gun_));
        
        return publicKeys;
        
    } catch (const std::exception& e) {
        return Error(std::string("Exception in createNewPublicKeyFromKeyIDs: ") + e.what());
    }
}

// matchKeyIdsWithPubKeys函数实现 - 对应Go版本的matchKeyIdsWithPubKeys函数
// 验证私钥（通过其ID表示）和公钥形成匹配的密钥对
Error Repository::matchKeyIdsWithPubKeys(const std::vector<std::string>& ids, 
                                        const std::vector<std::shared_ptr<crypto::PublicKey>>& pubKeys) {
    // 检查输入参数有效性
    if (ids.size() != pubKeys.size()) {
        return Error("Number of key IDs and public keys must match");
    }
    
    try {
        // 遍历所有密钥ID和公钥对 (对应Go的for i := 0; i < len(ids); i++)
        for (size_t i = 0; i < ids.size(); i++) {
            const std::string& keyID = ids[i];
            auto pubKey = pubKeys[i];
            
            if (!pubKey) {
                return Error("Public key at index " + std::to_string(i) + " is null");
            }
            
            // 从CryptoService获取对应的私钥 (对应Go的privKey, _, err := r.GetCryptoService().GetPrivateKey(ids[i]))
            auto privateKeyResult = cryptoService_->GetPrivateKey(keyID);
            if (!privateKeyResult.ok()) {
                return Error("Could not get the private key matching id " + keyID + ": " + 
                           privateKeyResult.error().what());
            }
            
            auto [privKey, role] = privateKeyResult.value();
            if (!privKey) {
                return Error("Retrieved private key is null for ID: " + keyID);
            }
            
            // 验证私钥和公钥是否匹配 (对应Go的signed.VerifyPublicKeyMatchesPrivateKey(privKey, pubKey))
            auto verifyErr = crypto::VerifyPublicKeyMatchesPrivateKey(privKey, pubKey);
            if (verifyErr.hasError()) {
                return Error("Private key and public key do not match for ID " + keyID + ": " + 
                           verifyErr.what());
            }
            
            utils::GetLogger().Debug("Successfully verified key pair", 
                utils::LogContext()
                    .With("keyID", keyID)
                    .With("index", std::to_string(i)));
        }
        
        utils::GetLogger().Debug("All key pairs verified successfully", 
            utils::LogContext()
                .With("keyCount", std::to_string(ids.size())));
        
        return Error(); // 成功
        
    } catch (const std::exception& e) {
        return Error(std::string("Exception in matchKeyIdsWithPubKeys: ") + e.what());
    }
}

// publicKeysOfKeyIDs函数实现 - 对应Go版本的publicKeysOfKeyIDs函数
// 确认公钥和私钥（通过密钥ID）形成有效的、严格有序的密钥对
// (例如 keyIDs[0] 必须匹配 pubKeys[0]，keyIDs[1] 必须匹配 pubKeys[1]，以此类推)
// 或者在不匹配时抛出错误
Result<std::vector<std::shared_ptr<crypto::PublicKey>>> Repository::publicKeysOfKeyIDs(
    const std::vector<std::string>& keyIDs, 
    const std::vector<std::shared_ptr<crypto::PublicKey>>& pubKeys) {
    
    try {
        // 检查密钥ID和公钥数量是否匹配 (对应Go的if len(keyIDs) != len(pubKeys))
        if (keyIDs.size() != pubKeys.size()) {
            return Error("Require matching number of keyIDs and public keys but got " + 
                        std::to_string(keyIDs.size()) + " IDs and " + 
                        std::to_string(pubKeys.size()) + " public keys");
        }
        
        // 验证密钥ID和公钥是否匹配 (对应Go的matchKeyIdsWithPubKeys(r, keyIDs, pubKeys))
        auto matchErr = matchKeyIdsWithPubKeys(keyIDs, pubKeys);
        if (matchErr.hasError()) {
            return Error("Could not obtain public key from IDs: " + matchErr.what());
        }
        
        utils::GetLogger().Info("Successfully validated public keys of key IDs", 
            utils::LogContext()
                .With("keyIDCount", std::to_string(keyIDs.size()))
                .With("publicKeyCount", std::to_string(pubKeys.size()))
                .With("gun", gun_.empty() ? "default" : gun_));
        
        // 返回验证后的公钥列表 (对应Go的return pubKeys, nil)
        return pubKeys;
        
    } catch (const std::exception& e) {
        return Error(std::string("Exception in publicKeysOfKeyIDs: ") + e.what());
    }
}

// pubKeyListForRotation函数实现 - 对应Go版本的pubKeyListForRotation函数
// 给定一组新密钥和要轮转的角色，返回要使用的当前密钥列表
Result<std::vector<std::shared_ptr<crypto::PublicKey>>> Repository::pubKeyListForRotation(
    const std::string& role, bool serverManaged, const std::vector<std::string>& newKeys) {
    
    try {
        std::vector<std::shared_ptr<crypto::PublicKey>> pubKeyList;
        
        // 如果服务器管理要轮转的密钥，请求轮转并返回新密钥 (对应Go的if serverManaged)
        if (serverManaged) {
            utils::GetLogger().Debug("Rotating server-managed key", 
                utils::LogContext()
                    .With("role", role)
                    .With("gun", gun_));
            
            // 请求远程密钥轮转 (对应Go的rotateRemoteKey(role, remote))
            auto pubKeyResult = utils::rotateRemoteKey(role, remoteStore_, gun_);
            if (!pubKeyResult.ok()) {
                return Error("Unable to rotate remote key: " + pubKeyResult.error().what());
            }
            
            auto pubKey = pubKeyResult.value();
            pubKeyList.reserve(1);
            pubKeyList.push_back(pubKey);
            
            utils::GetLogger().Info("Successfully rotated server-managed key", 
                utils::LogContext()
                    .With("role", role)
                    .With("keyID", pubKey->ID()));
            
            return pubKeyList;
        }
        
        // 如果没有传入新密钥，我们生成一个 (对应Go的if len(newKeys) == 0)
        if (newKeys.empty()) {
            utils::GetLogger().Debug("Generating new key for rotation", 
                utils::LogContext()
                    .With("role", role)
                    .With("gun", gun_));
            
            pubKeyList.reserve(1);
            auto pubKeyResult = cryptoService_->Create(role, gun_, ECDSA_KEY);
            if (!pubKeyResult.ok()) {
                return Error("Unable to generate key: " + pubKeyResult.error().what());
            }
            
            auto pubKey = pubKeyResult.value();
            pubKeyList.push_back(pubKey);
            
            utils::GetLogger().Info("Successfully generated new key for rotation", 
                utils::LogContext()
                    .With("role", role)
                    .With("keyID", pubKey->ID()));
        }
        
        // 如果提供了要轮转到的密钥列表，我们添加这些密钥 (对应Go的if len(newKeys) > 0)
        if (!newKeys.empty()) {
            utils::GetLogger().Debug("Using provided keys for rotation", 
                utils::LogContext()
                    .With("role", role)
                    .With("keyCount", std::to_string(newKeys.size())));
            
            pubKeyList.clear(); // 清空之前可能生成的密钥
            pubKeyList.reserve(newKeys.size());
            
            for (const auto& keyID : newKeys) {
                // 从CryptoService获取密钥 (对应Go的r.GetCryptoService().GetKey(keyID))
                auto pubKey = cryptoService_->GetKey(keyID);
                if (!pubKey) {
                    return Error("Unable to find key: " + keyID);
                }
                
                pubKeyList.push_back(pubKey);
                
                utils::GetLogger().Debug("Added key to rotation list", 
                    utils::LogContext()
                        .With("keyID", keyID)
                        .With("algorithm", pubKey->Algorithm()));
            }
        }
        
        // 转换为证书（对于根密钥） (对应Go的pubKeysToCerts(role, pubKeyList))
        auto certsResult = pubKeysToCerts(role, pubKeyList);
        if (!certsResult.ok()) {
            return Error("Failed to convert public keys to certificates: " + certsResult.error().what());
        }
        
        auto certKeyList = certsResult.value();
        
        utils::GetLogger().Info("Successfully prepared key list for rotation", 
            utils::LogContext()
                .With("role", role)
                .With("keyCount", std::to_string(certKeyList.size()))
                .With("serverManaged", serverManaged ? "true" : "false"));
        
        return certKeyList;
        
    } catch (const std::exception& e) {
        return Error(std::string("Exception in pubKeyListForRotation: ") + e.what());
    }
}



// pubKeysToCerts函数实现 - 对应Go版本的pubKeysToCerts函数
// 将公钥转换为证书（对于根密钥）
Result<std::vector<std::shared_ptr<crypto::PublicKey>>> Repository::pubKeysToCerts(
    const std::string& role, const std::vector<std::shared_ptr<crypto::PublicKey>>& pubKeys) {
    
    try {
        // 如果不是根角色，直接返回原始公钥列表 (对应Go的if role != data.CanonicalRootRole)
        if (role != ROOT_ROLE) {
            utils::GetLogger().Debug("Role is not root, returning public keys as-is", 
                utils::LogContext()
                    .With("role", role)
                    .With("keyCount", std::to_string(pubKeys.size())));
            return pubKeys;
        }
        
        utils::GetLogger().Debug("Converting public keys to certificates for root role", 
            utils::LogContext()
                .With("keyCount", std::to_string(pubKeys.size())));
        
        std::vector<std::shared_ptr<crypto::PublicKey>> certKeys;
        certKeys.reserve(pubKeys.size());
        
        // 遍历每个公钥，为根角色生成对应的证书公钥 (对应Go的for _, pubKey := range pubKeys)
        for (const auto& pubKey : pubKeys) {
            if (!pubKey) {
                return Error("Public key is null in pubKeysToCerts");
            }
            
            // 获取对应的私钥 (对应Go的privKey, _, err := r.GetCryptoService().GetPrivateKey(pubKey.ID()))
            auto privateKeyResult = cryptoService_->GetPrivateKey(pubKey->ID());
            if (!privateKeyResult.ok()) {
                // 找不到私钥直接报错，与Go版本保持一致 (对应Go的if err != nil { return nil, err })
                return Error("Could not get the private key matching public key ID " + pubKey->ID() + ": " + privateKeyResult.error().what());
            }
            
            auto [privKey, keyRole] = privateKeyResult.value();
            if (!privKey) {
                return Error("Retrieved private key is null for ID: " + pubKey->ID());
            }
            
            // 使用rootCertKey函数生成证书公钥 (对应Go的rootCertKey(r.gun, privKey))
            auto certKey = rootCertKey(gun_.empty() ? "default" : gun_, privKey);
            if (!certKey) {
                return Error("Failed to generate certificate key for public key: " + pubKey->ID());
            }
            
            certKeys.push_back(certKey);
            
            utils::GetLogger().Debug("Successfully converted public key to certificate key", 
                utils::LogContext()
                    .With("originalKeyID", pubKey->ID())
                    .With("certificateKeyID", certKey->ID()));
        }
        
        utils::GetLogger().Info("Successfully converted public keys to certificates", 
            utils::LogContext()
                .With("originalKeyCount", std::to_string(pubKeys.size()))
                .With("certificateKeyCount", std::to_string(certKeys.size())));
        
        return certKeys;
        
    } catch (const std::exception& e) {
        return Error(std::string("Exception in pubKeysToCerts: ") + e.what());
    }
}

// rootFileKeyChange函数实现 - 对应Go版本的rootFileKeyChange函数 
// 为根文件创建密钥变更
Error Repository::rootFileKeyChange(std::shared_ptr<changelist::Changelist> cl, const std::string&role, 
                                   const std::string& action, const std::vector<std::shared_ptr<crypto::PublicKey>>& keyList) {
    try {
        // 创建TUFRootData元数据 (对应Go的meta := changelist.TUFRootData{RoleName: role, Keys: keyList})
        changelist::TUFRootData meta;
        meta.roleName = role;
        meta.keys = keyList;
        
        // 序列化元数据为JSON (对应Go的metaJSON, err := json.Marshal(meta))
        auto metaJSON = meta.Serialize();
        if (metaJSON.empty()) {
            return Error("Failed to serialize TUFRootData for role: " + role);
        }
        
        // 创建TUF变更对象 (对应Go的changelist.NewTUFChange)
        auto change = std::make_shared<changelist::TUFChange>(
            action,                          // action
            changelist::ScopeRoot,          // scope = "root"
            changelist::TypeBaseRole,       // type = "role"
            role,             // path = role.String()
            metaJSON                        // content = metaJSON
        );
        
        // 将变更添加到changelist中 (对应Go的return cl.Add(c))
        return cl->Add(change);
        
    } catch (const std::exception& e) {
        return Error(std::string("Failed to create root file key change: ") + e.what());
    }
}

// RotateKey函数实现 - 对应Go版本的RotateKey函数
// 移除角色关联的所有现有密钥，根据参数创建新密钥或委托服务器管理
// 这些变更会暂存在changelist中，直到调用publish
Error Repository::RotateKey(const std::string&role, bool serverManagesKey, const std::vector<std::string>& keyList) {
    // 验证输入参数 (对应Go的checkRotationInput(role, serverManagesKey))
    auto checkErr = checkRotationInput(role, serverManagesKey);
    if (checkErr.hasError()) {
        return checkErr;
    }
    
    // 获取用于轮转的公钥列表 (对应Go的pubKeyList, err := r.pubKeyListForRotation(role, serverManagesKey, keyList))
    auto pubKeysResult = pubKeyListForRotation(role, serverManagesKey, keyList);
    if (!pubKeysResult.ok()) {
        return pubKeysResult.error();
    }
    
    auto pubKeyList = pubKeysResult.value();
    
    // 创建内存changelist (对应Go的cl := changelist.NewMemChangelist())
    auto cl = std::make_shared<changelist::MemoryChangelist>();
    
    // 创建根文件密钥变更 (对应Go的r.rootFileKeyChange(cl, role, changelist.ActionCreate, pubKeyList))
    auto keyChangeErr = rootFileKeyChange(cl, role, "create", pubKeyList);
    if (keyChangeErr.hasError()) {
        return keyChangeErr;
    }
    
    // 发布变更 (对应Go的return r.publish(cl))
    return publish(cl);
}

// publish函数实现 - 对应Go版本的publish函数
// 使用提供的changelist发布变更到远程服务器
Error Repository::publish(std::shared_ptr<changelist::Changelist> cl) {
    try {
        bool initialPublish = false;
        
        // 更新TUF元数据 (对应Go的r.updateTUF(true))
        auto err = updateTUF(true);
        if (!err.ok()) {
            // 检查是否是仓库不存在的错误 (对应Go的ErrRepositoryNotExist检查)
            if (std::string(err.what()).find("does not exist") != std::string::npos) {
                
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
        err = utils::applyChangelist(tufRepo_, invalidRepo_, cl);
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
            try {
                auto snapshotResult = utils::serializeCanonicalRole(tufRepo_, SNAPSHOT_ROLE, {});
                if (!snapshotResult.empty()) {
                    // 成功签署snapshot
                    updatedFiles["snapshot"] = snapshotResult;
                    utils::GetLogger().Debug("Successfully signed snapshot locally");
                } else {
                    // 签署失败，假设服务器会签署 (对应Go的"Assuming that server should sign the snapshot")
                    utils::GetLogger().Debug("Client does not have the key to sign snapshot. "
                        "Assuming that server should sign the snapshot.");
                }
            } catch (const std::exception& e) {
                // 如果是其他类型的错误（非密钥不足），则传播错误
                return Error("Failed to serialize snapshot: " + std::string(e.what()));
            }
        }
        
        // 推送更新到远程服务器 (对应Go的remote.SetMulti)
        if (remoteStore_) {
            // 准备批量上传的元数据map - 对应Go版本的SetMulti
            // 需要验证和格式化数据，确保发送到服务器的是有效的JSON
            std::map<std::string, std::vector<uint8_t>> metasToUpload;
            
            for (const auto& [roleName, data] : updatedFiles) {
                // 验证vector<uint8_t>是否包含有效的JSON数据
                try {
                    std::string jsonStr(data.begin(), data.end());
                    json jsonData = json::parse(jsonStr);
                    
                    // 重新序列化以确保格式正确性（去除多余空格等）
                    std::string formattedJsonStr = jsonData.dump();
                    std::vector<uint8_t> formattedData(formattedJsonStr.begin(), formattedJsonStr.end());
                    
                    metasToUpload[roleName] = formattedData;
                    
                } catch (const json::exception& e) {
                    return Error("Failed to parse metadata JSON for " + roleName + ": " + e.what());
                }
            }
            
            // 使用SetMulti一次性上传所有元数据，保持服务器一致性
            err = remoteStore_->SetMulti(metasToUpload);
            if (!err.ok()) {
                return Error("Failed to publish metadata using SetMulti: " + err.what());
            }
            
            utils::GetLogger().Info("成功批量发布元数据", 
                utils::LogContext()
                    .With("gun", gun_.empty() ? "default" : gun_)
                    .With("files_count", std::to_string(metasToUpload.size())));
        }
        
        return Error(); // 成功
    } catch (const std::exception& e) {
        return Error(std::string("Failed to publish: ") + e.what());
    }
}

} // namespace notary 