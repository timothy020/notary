#include "notary/tuf/builder.hpp"
#include "notary/tuf/repo.hpp"
#include "notary/tuf/certs.hpp"
#include "notary/crypto/crypto_service.hpp"
#include "notary/crypto/verify.hpp"
#include "notary/utils/tools.hpp"
#include "notary/utils/helpers.hpp"
#include <algorithm>
#include <sstream>

namespace notary {
namespace tuf {

// ConsistentInfo 实现
bool ConsistentInfo::checksumKnown() const {
    // 空哈希，无大小：这是零值
    return !fileMeta_.Hashes.empty() || fileMeta_.Length != 0;
}

std::string ConsistentInfo::consistentName() const {
    // 返回角色的一致性名称 (rolename.sha256)
    auto it = fileMeta_.Hashes.find("sha256");
    if (it != fileMeta_.Hashes.end()) {
        std::string hashHex = utils::HexEncode(it->second);
        return roleToString(roleName_) + "." + hashHex;
    }
    return roleToString(roleName_);
}

int64_t ConsistentInfo::length() const {
    if (checksumKnown()) {
        return fileMeta_.Length;
    }
    return -1;
}

// FinishedBuilder 实现
Error FinishedBuilder::load(RoleName roleName, const std::vector<uint8_t>& content, 
                           int minVersion, bool allowExpired) {
    return Error("the builder has finished building and cannot accept any more input or produce any more output");
}

Error FinishedBuilder::loadRootForUpdate(const std::vector<uint8_t>& content, 
                                        int minVersion, bool isFinal) {
    return Error("the builder has finished building and cannot accept any more input or produce any more output");
}

Result<std::pair<std::vector<uint8_t>, int>> FinishedBuilder::generateSnapshot(
    std::shared_ptr<SignedSnapshot> prev) {
    return Result<std::pair<std::vector<uint8_t>, int>>(
        Error("the builder has finished building and cannot accept any more input or produce any more output"));
}

Result<std::pair<std::vector<uint8_t>, int>> FinishedBuilder::generateTimestamp(
    std::shared_ptr<SignedTimestamp> prev) {
    return Result<std::pair<std::vector<uint8_t>, int>>(
        Error("the builder has finished building and cannot accept any more output"));
}

Result<std::pair<std::shared_ptr<Repo>, std::shared_ptr<Repo>>> FinishedBuilder::finish() {
    return Result<std::pair<std::shared_ptr<Repo>, std::shared_ptr<Repo>>>(
        Error("the builder has finished building and cannot accept any more input or produce any more output"));
}

std::unique_ptr<RepoBuilder> FinishedBuilder::bootstrapNewBuilder() {
    return std::make_unique<FinishedBuilder>();
}

std::unique_ptr<RepoBuilder> FinishedBuilder::bootstrapNewBuilderWithNewTrustpin(
    const TrustPinConfig& trustpin) {
    return std::make_unique<FinishedBuilder>();
}

bool FinishedBuilder::isLoaded(RoleName roleName) const { return false; }

int FinishedBuilder::getLoadedVersion(RoleName roleName) const { return 0; }

ConsistentInfo FinishedBuilder::getConsistentInfo(RoleName roleName) const {
    return ConsistentInfo(roleName);
}

// RepoBuilderImpl 实现
RepoBuilderImpl::RepoBuilderImpl(const std::string& gun, 
                                std::shared_ptr<crypto::CryptoService> cs,
                                const TrustPinConfig& trustpin)
    : gun_(gun), trustpin_(trustpin) {
    repo_ = std::make_shared<Repo>(cs);
    invalidRoles_ = std::make_shared<Repo>(nullptr);
}

RepoBuilderImpl::RepoBuilderImpl(const std::string& gun,
                                std::shared_ptr<Repo> repo,
                                const TrustPinConfig& trustpin)
    : repo_(repo), gun_(gun), trustpin_(trustpin) {
    invalidRoles_ = std::make_shared<Repo>(nullptr);
}

bool RepoBuilderImpl::isLoaded(RoleName roleName) const {
    switch (roleName) {
        case RoleName::RootRole:
            return repo_->GetRoot() != nullptr;
        case RoleName::SnapshotRole:
            return repo_->GetSnapshot() != nullptr;
        case RoleName::TimestampRole:
            return repo_->GetTimestamp() != nullptr;
        case RoleName::TargetsRole:
            return repo_->GetTargets().find(roleName) != repo_->GetTargets().end();
        default:
            return repo_->GetTargets().find(roleName) != repo_->GetTargets().end();
    }
}

int RepoBuilderImpl::getLoadedVersion(RoleName roleName) const {
    switch (roleName) {
        case RoleName::RootRole:
            if (auto root = repo_->GetRoot()) {
                return root->Signed.Common.Version;
            }
            break;
        case RoleName::SnapshotRole:
            if (auto snapshot = repo_->GetSnapshot()) {
                return snapshot->Signed.Common.Version;
            }
            break;
        case RoleName::TimestampRole:
            if (auto timestamp = repo_->GetTimestamp()) {
                return timestamp->Signed.Common.Version;
            }
            break;
        default:
            {
                auto targets = repo_->GetTargets();
                auto it = targets.find(roleName);
                if (it != targets.end()) {
                    return it->second->Signed.Common.Version;
                }
            }
            break;
    }
    return 1; // 最小有效版本号
}

ConsistentInfo RepoBuilderImpl::getConsistentInfo(RoleName roleName) const {
    ConsistentInfo info(roleName); // 开始时文件元数据未知
    
    switch (roleName) {
        case RoleName::TimestampRole:
            // 我们不想获得一致的时间戳，但我们确实想限制其大小
            info.setFileMeta(FileMeta{.Length = 100 * 1024}); // 100KB 限制
            break;
        case RoleName::SnapshotRole:
            if (auto timestamp = repo_->GetTimestamp()) {
                auto it = timestamp->Signed.Meta.find(roleToString(roleName));
                if (it != timestamp->Signed.Meta.end()) {
                    info.setFileMeta(it->second);
                }
            }
            break;
        case RoleName::RootRole:
            if (bootstrappedRootChecksum_) {
                info.setFileMeta(*bootstrappedRootChecksum_);
            } else if (auto snapshot = repo_->GetSnapshot()) {
                auto it = snapshot->Signed.Meta.find(roleToString(roleName));
                if (it != snapshot->Signed.Meta.end()) {
                    info.setFileMeta(it->second);
                }
            }
            break;
        default:
            if (auto snapshot = repo_->GetSnapshot()) {
                auto it = snapshot->Signed.Meta.find(roleToString(roleName));
                if (it != snapshot->Signed.Meta.end()) {
                    info.setFileMeta(it->second);
                }
            }
            break;
    }
    
    return info;
}

Error RepoBuilderImpl::load(RoleName roleName, const std::vector<uint8_t>& content, 
                           int minVersion, bool allowExpired) {
    return loadOptions(roleName, content, minVersion, allowExpired, false, false);
}

Error RepoBuilderImpl::loadRootForUpdate(const std::vector<uint8_t>& content, 
                                        int minVersion, bool isFinal) {
    Error err = loadOptions(RoleName::RootRole, content, minVersion, !isFinal, !isFinal, true);
    if (err.hasError()) {
        return err;
    }
    
    if (!isFinal) {
        prevRoot_ = repo_->GetRoot();
    }
    return Error(); // 成功
}

Result<std::pair<std::vector<uint8_t>, int>> RepoBuilderImpl::generateSnapshot(
    std::shared_ptr<SignedSnapshot> prev) {
    // 1. 前置检查 - 对应Go版本的switch检查
    if (!repo_->GetCryptoService()) {
        return Result<std::pair<std::vector<uint8_t>, int>>(
            Error("cannot generate snapshot without a cryptoservice"));
    }
    
    if (isLoaded(RoleName::SnapshotRole)) {
        return Result<std::pair<std::vector<uint8_t>, int>>(
            Error("snapshot has already been loaded"));
    }
    
    if (isLoaded(RoleName::TimestampRole)) {
        return Result<std::pair<std::vector<uint8_t>, int>>(
            Error("cannot generate snapshot if timestamp has already been loaded"));
    }
    
    // 2. 检查前置条件 - 必须已加载root
    Error prereqErr = checkRoleLoaded(RoleName::RootRole);
    if (prereqErr.hasError()) {
        return Result<std::pair<std::vector<uint8_t>, int>>(prereqErr);
    }
    
    // 3. 处理prev参数
    if (!prev) {
        // 如果没有之前的snapshot，需要生成一个，因此targets必须已经加载
        Error targetsErr = checkRoleLoaded(RoleName::TargetsRole);
        if (targetsErr.hasError()) {
            return Result<std::pair<std::vector<uint8_t>, int>>(targetsErr);
        }
        
        // 初始化snapshot
        auto initResult = repo_->InitSnapshot();
        if (!initResult.ok()) {
            repo_->SetSnapshot(nullptr);
            return Result<std::pair<std::vector<uint8_t>, int>>(initResult.error());
        }
    } else {
        if (!isValidSnapshot(prev->Signed)) {
            return Result<std::pair<std::vector<uint8_t>, int>>(
                Error("invalid snapshot structure"));
        }
        repo_->SetSnapshot(prev);
    }
    
    // 4. 签名snapshot - 使用默认过期时间
    auto defaultExpires = utils::getDefaultExpiry(RoleName::SnapshotRole);
    auto signResult = repo_->SignSnapshot(defaultExpires);
    if (!signResult.ok()) {
        repo_->SetSnapshot(nullptr);
        return Result<std::pair<std::vector<uint8_t>, int>>(signResult.error());
    }
    
    auto signedObj = signResult.value();
    
    // 5. 序列化为JSON
    std::vector<uint8_t> sgndJSON;
    try {
        json j = signedObj->toJson();
        std::string jsonStr = j.dump();
        sgndJSON = std::vector<uint8_t>(jsonStr.begin(), jsonStr.end());
    } catch (const std::exception& e) {
        repo_->SetSnapshot(nullptr);
        return Result<std::pair<std::vector<uint8_t>, int>>(
            Error("Failed to marshal snapshot JSON: " + std::string(e.what())));
    }
    
    // 6. 清理loadedNotChecksummed - 对应Go版本的逻辑
    // loadedNotChecksummed应该当前包含等待校验和的root，
    // 因为它必须已经被加载。由于snapshot是使用已加载的root和targets数据生成的，
    // 从rb.loadedNotChecksummed中删除所有这些
    auto targets = repo_->GetTargets();
    for (const auto& [tgtName, _] : targets) {
        loadedNotChecksummed_.erase(tgtName);
    }
    loadedNotChecksummed_.erase(RoleName::RootRole);
    
    // timestamp还不能被加载，所以我们想缓存snapshot字节，
    // 这样当稍后生成或加载timestamp时就可以验证校验和
    loadedNotChecksummed_[RoleName::SnapshotRole] = sgndJSON;
    
    int version = repo_->GetSnapshot()->Signed.Common.Version;
    return Result<std::pair<std::vector<uint8_t>, int>>(
        std::make_pair(sgndJSON, version));
}

Result<std::pair<std::vector<uint8_t>, int>> RepoBuilderImpl::generateTimestamp(
    std::shared_ptr<SignedTimestamp> prev) {
    // 1. 前置检查 - 对应Go版本的switch检查
    if (!repo_->GetCryptoService()) {
        return Result<std::pair<std::vector<uint8_t>, int>>(
            Error("cannot generate timestamp without a cryptoservice"));
    }
    
    if (isLoaded(RoleName::TimestampRole)) {
        return Result<std::pair<std::vector<uint8_t>, int>>(
            Error("timestamp has already been loaded"));
    }
    
    // 2. SignTimestamp总是序列化已加载的snapshot并在数据中签名，
    // 所以我们必须始终首先加载snapshot
    std::vector<RoleName> prereqRoles = {RoleName::RootRole, RoleName::SnapshotRole};
    for (RoleName req : prereqRoles) {
        if (!isLoaded(req)) {
            return Result<std::pair<std::vector<uint8_t>, int>>(
                Error(roleToString(req) + " must be loaded first"));
        }
    }
    
    // 3. 处理prev参数
    if (!prev) {
        // 初始化timestamp
        auto initResult = repo_->InitTimestamp();
        if (!initResult.ok()) {
            repo_->SetTimestamp(nullptr);
            return Result<std::pair<std::vector<uint8_t>, int>>(initResult.error());
        }
    } else {
        if (!isValidTimestamp(prev->Signed)) {
            return Result<std::pair<std::vector<uint8_t>, int>>(
                Error("invalid timestamp structure"));
        }
        repo_->SetTimestamp(prev);
    }
    
    // 4. 签名timestamp - 使用默认过期时间
    auto defaultExpires = utils::getDefaultExpiry(RoleName::TimestampRole);
    auto signResult = repo_->SignTimestamp(defaultExpires);
    if (!signResult.ok()) {
        repo_->SetTimestamp(nullptr);
        return Result<std::pair<std::vector<uint8_t>, int>>(signResult.error());
    }
    
    auto signedObj = signResult.value();
    
    // 5. 序列化为JSON
    std::vector<uint8_t> sgndJSON;
    try {
        json j = signedObj->toJson();
        std::string jsonStr = j.dump();
        sgndJSON = std::vector<uint8_t>(jsonStr.begin(), jsonStr.end());
    } catch (const std::exception& e) {
        repo_->SetTimestamp(nullptr);
        return Result<std::pair<std::vector<uint8_t>, int>>(
            Error("Failed to marshal timestamp JSON: " + std::string(e.what())));
    }
    
    // 6. 清理loadedNotChecksummed - 对应Go版本的逻辑
    // snapshot应该已经被加载（并且没有校验和，因为timestamp不能被加载），
    // 所以它正在等待校验和。由于这个timestamp是使用等待校验和的snapshot生成的，
    // 我们可以从rb.loadedNotChecksummed中删除它。现在应该没有其他等待校验和的项目，
    // 因为加载/生成snapshot应该已经清除了`loadNotChecksummed`中的所有其他内容。
    loadedNotChecksummed_.erase(RoleName::SnapshotRole);
    
    int version = repo_->GetTimestamp()->Signed.Common.Version;
    return Result<std::pair<std::vector<uint8_t>, int>>(
        std::make_pair(sgndJSON, version));
}

Result<std::pair<std::shared_ptr<Repo>, std::shared_ptr<Repo>>> RepoBuilderImpl::finish() {
    return Result<std::pair<std::shared_ptr<Repo>, std::shared_ptr<Repo>>>(
        std::make_pair(repo_, invalidRoles_));
}

std::unique_ptr<RepoBuilder> RepoBuilderImpl::bootstrapNewBuilder() {
    auto newBuilder = std::make_unique<RepoBuilderImpl>(
        gun_,
        std::make_shared<Repo>(repo_->GetCryptoService()),
        trustpin_
    );
    
    // 设置引导值
    newBuilder->prevRoot_ = repo_->GetRoot();
    newBuilder->bootstrappedRootChecksum_ = nextRootChecksum_;
    
    return std::move(newBuilder);
}

std::unique_ptr<RepoBuilder> RepoBuilderImpl::bootstrapNewBuilderWithNewTrustpin(
    const TrustPinConfig& trustpin) {
    auto newBuilder = std::make_unique<RepoBuilderImpl>(
        gun_,
        std::make_shared<Repo>(repo_->GetCryptoService()),
        trustpin
    );
    
    // 设置引导值
    newBuilder->prevRoot_ = repo_->GetRoot();
    newBuilder->bootstrappedRootChecksum_ = nextRootChecksum_;
    
    return std::move(newBuilder);
}

// 私有辅助方法
Error RepoBuilderImpl::loadOptions(RoleName roleName, const std::vector<uint8_t>& content, 
                                  int minVersion, bool allowExpired, bool skipChecksum, bool allowLoaded) {
    // 验证角色名称
    if (!isValidRole(roleName)) {
        return Error("invalid role: " + roleToString(roleName));
    }
    
    // 检查是否已加载（除非允许重新加载）
    if (!allowLoaded && isLoaded(roleName)) {
        return Error(roleToString(roleName) + " has already been loaded");
    }
    
    // 检查前置条件
    Error err = checkPrereqsLoaded(roleName);
    if (err.hasError()) {
        return err;
    }
    
    // 根据角色类型加载不同的元数据
    switch (roleName) {
        case RoleName::RootRole:
            return loadRoot(content, minVersion, allowExpired, skipChecksum);
        case RoleName::SnapshotRole:
            return loadSnapshot(content, minVersion, allowExpired);
        case RoleName::TimestampRole:
            return loadTimestamp(content, minVersion, allowExpired);
        case RoleName::TargetsRole:
            return loadTargets(content, minVersion, allowExpired);
        default:
            return loadDelegation(roleName, content, minVersion, allowExpired);
    }
}

Error RepoBuilderImpl::checkPrereqsLoaded(RoleName roleName) {
    std::vector<RoleName> prereqRoles;
    
    switch (roleName) {
        case RoleName::RootRole:
            // root 没有前置条件
            break;
        case RoleName::TimestampRole:
        case RoleName::SnapshotRole:
        case RoleName::TargetsRole:
            prereqRoles.push_back(RoleName::RootRole);
            break;
        default: // 委托
            prereqRoles.push_back(RoleName::RootRole);
            prereqRoles.push_back(RoleName::TargetsRole);
            break;
    }
    
    for (RoleName req : prereqRoles) {
        if (!isLoaded(req)) {
            return Error(roleToString(req) + " must be loaded first");
        }
    }
    
    return Error(); // 成功
}

// 检查单个角色是否已加载
Error RepoBuilderImpl::checkRoleLoaded(RoleName singleRole) {
    if (!isLoaded(singleRole)) {
        return Error(roleToString(singleRole) + " must be loaded first");
    }
    return Error(); // 成功
}

bool RepoBuilderImpl::isValidRole(RoleName roleName) {
    // 简单的角色验证
    switch (roleName) {
        case RoleName::RootRole:
        case RoleName::TargetsRole:
        case RoleName::SnapshotRole:
        case RoleName::TimestampRole:
            return true;
        default:
            return false; // 暂时不支持委托角色
    }
}

Error RepoBuilderImpl::loadRoot(const std::vector<uint8_t>& content, int minVersion, 
                               bool allowExpired, bool skipChecksum) {
    RoleName roleName = RoleName::RootRole;

    // 1. 转换字节到Signed对象并检查校验和（如果不跳过）
    // 对应Go版本的：signedObj, err := rb.bytesToSigned(content, data.CanonicalRootRole, skipChecksum)
    auto signedResult = bytesToSigned(content, roleName, skipChecksum);
    if (!signedResult.ok()) {
        utils::GetLogger().Error("loadRoot: Failed to convert bytes to Signed object: " + signedResult.error().getMessage());
        return signedResult.error();
    }
    auto signedObj = signedResult.value();

    // 2. 使用trustpinning.ValidateRoot验证root（包括trust pinning验证）
    // 这是核心验证步骤，对应Go版本的：
    // signedRoot, err := trustpinning.ValidateRoot(rb.prevRoot, signedObj, rb.gun, rb.trustpin)
    auto signedRootResult = tuf::ValidateRoot(prevRoot_, signedObj, gun_, trustpin_);
    if (!signedRootResult.ok()) {
        utils::GetLogger().Error("loadRoot: ValidateRoot failed: " + signedRootResult.error().getMessage());
        return signedRootResult.error();
    }
    auto signedRoot = signedRootResult.value();

    // 3. 验证版本（对应Go版本的signed.VerifyVersion）
    Error versionErr = crypto::VerifyVersion(signedRoot->Signed.Common, minVersion);
    if (versionErr.hasError()) {
        utils::GetLogger().Error("loadRoot: Version verification failed: " + versionErr.getMessage());
        return versionErr;
    }

    // 4. 检查过期时间（必须放在最后，因为所有其他验证都应该通过）
    // 对应Go版本的：if !allowExpired { if err := signed.VerifyExpiry(...); err != nil }
    if (!allowExpired) {
        Error expiryErr = crypto::VerifyExpiry(signedRoot->Signed.Common, roleName);
        if (expiryErr.hasError()) {
            utils::GetLogger().Error("loadRoot: Expiry verification failed: " + expiryErr.getMessage());
            return expiryErr;
        }
    }

    // 5. 从验证过的root构建BaseRole（对应Go版本的signedRoot.BuildBaseRole(data.CanonicalRootRole)）
    auto rootRoleResult = signedRoot->BuildBaseRole(roleName);
    if (!rootRoleResult.ok()) {
        // 这不应该发生，因为root已经被验证过了
        utils::GetLogger().Error("loadRoot: Failed to build base role from validated root: " + rootRoleResult.error().getMessage());
        return rootRoleResult.error();
    }

    // 6. 设置到repo中（对应Go版本的rb.repo.Root = signedRoot）
    repo_->SetRoot(signedRoot);
    
    // 设置原始root角色用于轮换验证（对应Go版本的rb.repo.originalRootRole = rootRole）
    repo_->SetOriginalRootRole(rootRoleResult.value());

    utils::GetLogger().Info("loadRoot: Successfully loaded and validated root for GUN: " + gun_);
    return Error(); // 成功
}

Error RepoBuilderImpl::loadSnapshot(const std::vector<uint8_t>& content, int minVersion, 
                                   bool allowExpired) {
    RoleName roleName = RoleName::SnapshotRole;

    // 从root获取snapshot角色
    auto snapshotRoleResult = repo_->GetBaseRole(roleName);
    if (!snapshotRoleResult.ok()) {
        // 这不应该发生，因为它已经被验证过了
        return snapshotRoleResult.error();
    }

    // 转换字节到Signed对象并验证签名
    auto signedResult = bytesToSignedAndValidateSigs(snapshotRoleResult.value(), content);
    if (!signedResult.ok()) {
        return signedResult.error();
    }

    auto signedObj = signedResult.value();

    // 创建SignedSnapshot对象
    auto signedSnapshot = std::make_shared<SignedSnapshot>();
    
    // 从signedObj解析快照内容
    try {
        std::string jsonStr(signedObj->signedData.begin(), signedObj->signedData.end());
        json j = json::parse(jsonStr);
        
        // 解析到Snapshot结构
        signedSnapshot->Signed.fromJson(j);
        signedSnapshot->Signatures = signedObj->Signatures;
    } catch (const std::exception& e) {
        return Error("Failed to parse snapshot from signed: " + std::string(e.what()));
    }

    // 验证版本
    Error versionErr = crypto::VerifyVersion(signedSnapshot->Signed.Common, minVersion);
    if (versionErr.hasError()) {
        return versionErr;
    }

    // 检查过期时间（必须放在最后，因为所有其他验证都应该通过）
    if (!allowExpired) {
        Error expiryErr = crypto::VerifyExpiry(signedSnapshot->Signed.Common, roleName);
        if (expiryErr.hasError()) {
            return expiryErr;
        }
    }

    // 到这一点，剩下的唯一要验证的是现有的校验和 - 我们可以使用
    // 这个snapshot来引导下一个builder（如果需要的话） - 我们不需要做
    // 2值赋值，因为我们已经验证了signedSnapshot，它必须有root元数据
    auto rootMetaIt = signedSnapshot->Signed.Meta.find(roleToString(RoleName::RootRole));
    if (rootMetaIt != signedSnapshot->Signed.Meta.end()) {
        nextRootChecksum_ = std::make_shared<FileMeta>(rootMetaIt->second);
    }

    // 验证来自snapshot的校验和
    Error checksumErr = validateChecksumsFromSnapshot(signedSnapshot);
    if (checksumErr.hasError()) {
        return checksumErr;
    }

    repo_->SetSnapshot(signedSnapshot);
    return Error(); // 成功
}

Error RepoBuilderImpl::loadTimestamp(const std::vector<uint8_t>& content, int minVersion, 
                                    bool allowExpired) {
    RoleName roleName = RoleName::TimestampRole;

    // 从root获取timestamp角色
    auto timestampRoleResult = repo_->GetBaseRole(roleName);
    if (!timestampRoleResult.ok()) {
        // 这不应该发生，因为它已经被验证过了
        return timestampRoleResult.error();
    }

    // 转换字节到Signed对象并验证签名
    auto signedResult = bytesToSignedAndValidateSigs(timestampRoleResult.value(), content);
    if (!signedResult.ok()) {
        return signedResult.error();
    }

    auto signedObj = signedResult.value();

    // 创建SignedTimestamp对象
    auto signedTimestamp = std::make_shared<SignedTimestamp>();
    
    // 从signedObj解析时间戳内容
    try {
        std::string jsonStr(signedObj->signedData.begin(), signedObj->signedData.end());
        json j = json::parse(jsonStr);
        
        // 解析到Timestamp结构
        signedTimestamp->Signed.fromJson(j);
        signedTimestamp->Signatures = signedObj->Signatures;
    } catch (const std::exception& e) {
        return Error("Failed to parse timestamp from signed: " + std::string(e.what()));
    }

    // 验证版本
    Error versionErr = crypto::VerifyVersion(signedTimestamp->Signed.Common, minVersion);
    if (versionErr.hasError()) {
        return versionErr;
    }

    // 检查过期时间（必须放在最后，因为所有其他验证都应该通过）
    if (!allowExpired) {
        Error expiryErr = crypto::VerifyExpiry(signedTimestamp->Signed.Common, roleName);
        if (expiryErr.hasError()) {
            return expiryErr;
        }
    }

    // 验证来自timestamp的校验和
    Error checksumErr = validateChecksumsFromTimestamp(signedTimestamp);
    if (checksumErr.hasError()) {
        return checksumErr;
    }

    repo_->SetTimestamp(signedTimestamp);
    return Error(); // 成功
}

Error RepoBuilderImpl::loadTargets(const std::vector<uint8_t>& content, int minVersion, 
                                  bool allowExpired) {
    RoleName roleName = RoleName::TargetsRole;

    // 从root获取targets角色
    auto targetsRoleResult = repo_->GetBaseRole(roleName);
    if (!targetsRoleResult.ok()) {
        // 这不应该发生，因为它已经被验证过了
        return targetsRoleResult.error();
    }

    // 转换字节到Signed对象并验证签名
    auto signedResult = bytesToSignedAndValidateSigs(targetsRoleResult.value(), content);
    if (!signedResult.ok()) {
        return signedResult.error();
    }

    auto signedObj = signedResult.value();

    // 创建SignedTargets对象
    auto signedTargets = std::make_shared<SignedTargets>();
    
    // 从signedObj解析目标内容
    try {
        std::string jsonStr(signedObj->signedData.begin(), signedObj->signedData.end());
        json j = json::parse(jsonStr);
        
        // 解析到Targets结构
        signedTargets->Signed.fromJson(j);
        signedTargets->Signatures = signedObj->Signatures;
    } catch (const std::exception& e) {
        return Error("Failed to parse targets from signed: " + std::string(e.what()));
    }

    // 验证版本
    Error versionErr = crypto::VerifyVersion(signedTargets->Signed.Common, minVersion);
    if (versionErr.hasError()) {
        return versionErr;
    }

    // 检查过期时间（必须放在最后，因为所有其他验证都应该通过）
    if (!allowExpired) {
        Error expiryErr = crypto::VerifyExpiry(signedTargets->Signed.Common, roleName);
        if (expiryErr.hasError()) {
            return expiryErr;
        }
    }

    // 设置到repo
    signedTargets->Signatures = signedObj->Signatures;
    repo_->SetTargets(signedTargets, roleName);
    return Error(); // 成功
}

Error RepoBuilderImpl::loadDelegation(RoleName roleName, const std::vector<uint8_t>& content, 
                                     int minVersion, bool allowExpired) {
    // 获取委托角色 TODO: 未实现repo_->GetDelegationRole
    auto delegationRoleResult = repo_->GetDelegationRole(roleName);
    if (!delegationRoleResult.ok()) {
        return delegationRoleResult.error();
    }

    // bytesToSigned检查校验和
    auto signedResult = bytesToSigned(content, roleName, false);
    if (!signedResult.ok()) {
        return signedResult.error();
    }

    auto signedObj = signedResult.value();

    // 创建SignedTargets对象（委托也是targets类型）
    auto signedTargets = std::make_shared<SignedTargets>();
    
    // 从signedObj解析委托内容
    try {
        std::string jsonStr(signedObj->signedData.begin(), signedObj->signedData.end());
        json j = json::parse(jsonStr);
        
        // 解析到Targets结构
        signedTargets->Signed.fromJson(j);
        signedTargets->Signatures = signedObj->Signatures;
    } catch (const std::exception& e) {
        return Error("Failed to parse delegation targets from signed: " + std::string(e.what()));
    }

    // 验证版本
    Error versionErr = crypto::VerifyVersion(signedTargets->Signed.Common, minVersion);
    if (versionErr.hasError()) {
        // 不捕获到invalidRoles中，因为我们收到的角色是回滚
        return versionErr;
    }

    // 验证签名 - 委托角色从DelegationRole获取BaseRole
    BaseRole baseRole;
    baseRole.SetName(delegationRoleResult.value().Name);
    baseRole.SetKeys(delegationRoleResult.value().BaseRoleInfo.Keys());
    baseRole.SetThreshold(delegationRoleResult.value().BaseRoleInfo.Threshold());
    
    Error signatureErr = crypto::VerifySignatures(*signedObj, baseRole);
    if (signatureErr.hasError()) {
        invalidRoles_->SetTargets(signedTargets, roleName);
        return signatureErr;
    }

    // 检查过期时间（必须放在最后，因为所有其他验证都应该通过）
    if (!allowExpired) {
        Error expiryErr = crypto::VerifyExpiry(signedTargets->Signed.Common, roleName);
        if (expiryErr.hasError()) {
            invalidRoles_->SetTargets(signedTargets, roleName);
            return expiryErr;
        }
    }

    // 设置到repo
    signedTargets->Signatures = signedObj->Signatures;
    repo_->SetTargets(signedTargets, roleName);
    return Error(); // 成功
}

// RepoBuilderWrapper 实现
RepoBuilderWrapper::RepoBuilderWrapper(std::unique_ptr<RepoBuilder> builder)
    : builder_(std::move(builder)) {}

Error RepoBuilderWrapper::load(RoleName roleName, const std::vector<uint8_t>& content, 
                              int minVersion, bool allowExpired) {
    return builder_->load(roleName, content, minVersion, allowExpired);
}

Error RepoBuilderWrapper::loadRootForUpdate(const std::vector<uint8_t>& content, 
                                           int minVersion, bool isFinal) {
    return builder_->loadRootForUpdate(content, minVersion, isFinal);
}

Result<std::pair<std::vector<uint8_t>, int>> RepoBuilderWrapper::generateSnapshot(
    std::shared_ptr<SignedSnapshot> prev) {
    return builder_->generateSnapshot(prev);
}

Result<std::pair<std::vector<uint8_t>, int>> RepoBuilderWrapper::generateTimestamp(
    std::shared_ptr<SignedTimestamp> prev) {
    return builder_->generateTimestamp(prev);
}

Result<std::pair<std::shared_ptr<Repo>, std::shared_ptr<Repo>>> RepoBuilderWrapper::finish() {
    if (isFinished_) {
        return Result<std::pair<std::shared_ptr<Repo>, std::shared_ptr<Repo>>>(
            Error("the builder has finished building and cannot accept any more input or produce any more output"));
    }
    
    // 完成构建并替换为finished builder
    auto result = builder_->finish();
    builder_ = std::make_unique<FinishedBuilder>();
    isFinished_ = true;
    
    return result;
}

std::unique_ptr<RepoBuilder> RepoBuilderWrapper::bootstrapNewBuilder() {
    return builder_->bootstrapNewBuilder();
}

std::unique_ptr<RepoBuilder> RepoBuilderWrapper::bootstrapNewBuilderWithNewTrustpin(
    const TrustPinConfig& trustpin) {
    return builder_->bootstrapNewBuilderWithNewTrustpin(trustpin);
}

bool RepoBuilderWrapper::isLoaded(RoleName roleName) const {
    return builder_->isLoaded(roleName);
}

int RepoBuilderWrapper::getLoadedVersion(RoleName roleName) const {
    return builder_->getLoadedVersion(roleName);
}

ConsistentInfo RepoBuilderWrapper::getConsistentInfo(RoleName roleName) const {
    return builder_->getConsistentInfo(roleName);
}

// 工厂函数实现
std::unique_ptr<RepoBuilder> NewRepoBuilder(const std::string& gun, 
                                           std::shared_ptr<crypto::CryptoService> cs, 
                                           const TrustPinConfig& trustpin) {
    return NewBuilderFromRepo(gun, std::make_shared<Repo>(cs), trustpin);
}

std::unique_ptr<RepoBuilder> NewBuilderFromRepo(const std::string& gun,
                                               std::shared_ptr<Repo> repo,
                                               const TrustPinConfig& trustpin) {
    auto impl = std::make_unique<RepoBuilderImpl>(gun, repo, trustpin);
    return std::make_unique<RepoBuilderWrapper>(std::move(impl));
}

// RepoBuilderImpl 私有方法实现

Result<std::shared_ptr<Signed>> RepoBuilderImpl::bytesToSigned(const std::vector<uint8_t>& content, 
                                                               RoleName roleName, bool skipChecksum) {
    if (!skipChecksum) {
        Error err = validateChecksumFor(content, roleName);
        if (err.hasError()) {
            return Result<std::shared_ptr<Signed>>(err);
        }
    }

    // 解析JSON到Signed对象
    try {
        std::string jsonStr(content.begin(), content.end());
        json j = json::parse(jsonStr);
        
        auto signedObj = std::make_shared<Signed>();
        signedObj->fromJson(j);
        
        return Result<std::shared_ptr<Signed>>(signedObj);
    } catch (const std::exception& e) {
        return Result<std::shared_ptr<Signed>>(Error("Failed to parse JSON: " + std::string(e.what())));
    }
}

Result<std::shared_ptr<Signed>> RepoBuilderImpl::bytesToSignedAndValidateSigs(const BaseRole& role, 
                                                                             const std::vector<uint8_t>& content) {
    auto signedResult = bytesToSigned(content, role.Name(), false);
    if (!signedResult.ok()) {
        return signedResult;
    }
    
    auto signedObj = signedResult.value();
    
    // 验证签名 - 类似Go代码中的signed.VerifySignatures(signedObj, role)
    Error verifyErr = crypto::VerifySignatures(*signedObj, role);
    if (verifyErr.hasError()) {
        return Result<std::shared_ptr<Signed>>(verifyErr);
    }
    
    return signedResult;
}

Error RepoBuilderImpl::validateChecksumFor(const std::vector<uint8_t>& content, RoleName roleName) {
    // 对于root角色，如果有bootstrapped checksum，则首先验证它
    if (roleName == RoleName::RootRole && bootstrappedRootChecksum_) {
        Error err = utils::CheckHashes(content, roleToString(roleName), bootstrappedRootChecksum_->Hashes);
        if (err.hasError()) {
            return err;
        }
    }

    // 但我们也想缓存root内容，这样当snapshot加载时就会被验证
    // （以确保仓库中的所有内容都是自一致的）
    auto checksums = getChecksumsFor(roleName);
    if (checksums) { // 不同于空，在这种情况下哈希检查应该失败
        Error err = utils::CheckHashes(content, roleToString(roleName), *checksums);
        if (err.hasError()) {
            return err;
        }
    } else if (roleName != RoleName::TimestampRole) {
        // timestamp是唯一不需要校验和的角色，但对于其他所有内容，
        // 将内容缓存到尚未被snapshot/timestamp校验和的角色列表中
        loadedNotChecksummed_[roleName] = content;
    }

    return Error(); // 成功
}


std::shared_ptr<std::map<std::string, std::vector<uint8_t>>> RepoBuilderImpl::getChecksumsFor(RoleName role) const {
    std::map<std::string, std::vector<uint8_t>> hashes;
    
    switch (role) {
        case RoleName::TimestampRole:
            // timestamp角色没有校验和引用
            return nullptr;
        case RoleName::SnapshotRole:
            if (auto timestamp = repo_->GetTimestamp()) {
                auto it = timestamp->Signed.Meta.find(roleToString(role));
                if (it != timestamp->Signed.Meta.end()) {
                    hashes = it->second.Hashes;
                }
            } else {
                return nullptr;
            }
            break;
        default:
            // root、targets等角色从snapshot中获取校验和
            if (auto snapshot = repo_->GetSnapshot()) {
                auto it = snapshot->Signed.Meta.find(roleToString(role));
                if (it != snapshot->Signed.Meta.end()) {
                    hashes = it->second.Hashes;
                }
            } else {
                return nullptr;
            }
            break;
    }
    
    return std::make_shared<std::map<std::string, std::vector<uint8_t>>>(hashes);
}

Error RepoBuilderImpl::validateChecksumsFromTimestamp(std::shared_ptr<SignedTimestamp> ts) {
    if (!ts) {
        return Error("Timestamp is null");
    }
    
    // 检查是否有snapshot需要验证 - 与Go版本等价
    auto it = loadedNotChecksummed_.find(RoleName::SnapshotRole);
    if (it != loadedNotChecksummed_.end()) {
        // 到这一点，SignedTimestamp已经被验证，所以它必须有snapshot哈希
        auto snMetaIt = ts->Signed.Meta.find(roleToString(RoleName::SnapshotRole));
        if (snMetaIt != ts->Signed.Meta.end()) {
            Error err = utils::CheckHashes(it->second, roleToString(RoleName::SnapshotRole), snMetaIt->second.Hashes);
            if (err.hasError()) {
                return err;
            }
            // 删除已验证的条目
            loadedNotChecksummed_.erase(it);
        }
    }
    
    return Error(); // 成功
}

Error RepoBuilderImpl::validateChecksumsFromSnapshot(std::shared_ptr<SignedSnapshot> sn) {
    if (!sn) {
        return Error("Snapshot is null");
    }
    
    std::vector<RoleName> goodRoles;
    
    // 验证从snapshot加载的未校验和内容 - 与Go版本等价
    for (const auto& [roleName, loadedBytes] : loadedNotChecksummed_) {
        // 跳过snapshot和timestamp角色
        if (roleName == RoleName::SnapshotRole || roleName == RoleName::TimestampRole) {
            continue;
        }
        
        // 查找该角色在snapshot中的元数据
        auto metaIt = sn->Signed.Meta.find(roleToString(roleName));
        if (metaIt != sn->Signed.Meta.end()) {
            Error err = utils::CheckHashes(loadedBytes, roleToString(roleName), metaIt->second.Hashes);
            if (err.hasError()) {
                return err;
            }
            goodRoles.push_back(roleName);
        }
    }
    
    // 删除已验证的角色
    for (const auto& roleName : goodRoles) {
        loadedNotChecksummed_.erase(roleName);
    }
    
    return Error(); // 成功
}

// 从Root对象构建BaseRole - 对应Go版本的BuildBaseRole方法
Result<BaseRole> RepoBuilderImpl::buildBaseRoleFromRoot(std::shared_ptr<SignedRoot> signedRoot, RoleName roleName) {
    // 查找角色 - 直接使用RoleName作为键
    auto roleIt = signedRoot->Signed.Roles.find(roleName);
    if (roleIt == signedRoot->Signed.Roles.end()) {
        return Result<BaseRole>(Error("role not found in root: " + roleToString(roleName)));
    }
    
    // 在C++版本中，Roles已经是解析过的BaseRole对象，直接返回
    return Result<BaseRole>(roleIt->second);
}

} // namespace tuf
} // namespace notary
