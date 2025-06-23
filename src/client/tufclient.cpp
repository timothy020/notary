#include "notary/client/tufclient.hpp"
#include "notary/utils/logger.hpp"
#include "notary/utils/helpers.hpp"
#include "notary/storage/offlinestore.hpp"
#include "notary/storage/memorystore.hpp"
#include <nlohmann/json.hpp>
#include <regex>
#include <chrono>

namespace notary {
namespace client {

using json = nlohmann::json;

// 构造函数实现
TUFClient::TUFClient(std::shared_ptr<storage::RemoteStore> remote,
                     std::shared_ptr<storage::MetadataStore> cache,
                     std::shared_ptr<tuf::RepoBuilder> oldBuilder,
                     std::shared_ptr<tuf::RepoBuilder> newBuilder)
    : remote_(remote)
    , cache_(cache)
    , oldBuilder_(oldBuilder)
    , newBuilder_(newBuilder) {
}

// Update实现
// 按照TUF规范执行TUF仓库的更新
// Update() 函数的流程可以分为两个阶段：乐观的初次尝试，以及失败后的恢复性重试。
Result<std::tuple<std::shared_ptr<tuf::Repo>, std::shared_ptr<tuf::Repo>>> TUFClient::Update() {
    // TUF更新流程：
    // 1. 获取timestamp
    //   a. 如果timestamp错误（验证、过期等）下载新root并返回步骤1
    // 2. 检查本地snapshot是否是最新的
    //   a. 如果过期，获取更新的snapshot
    //     i. 如果snapshot错误，下载新root并返回步骤1
    // 3. 检查root是否与snapshot匹配
    //   a. 如果不匹配，下载新root并返回步骤1
    // 4. 迭代下载和搜索targets和委托以找到目标元数据
    
    utils::GetLogger().Debug("updating TUF client");
    
    auto updateErr = update();
    if (!updateErr.ok()) {
        utils::GetLogger().Debug("Error occurred. Root will be downloaded and another update attempted");
        utils::GetLogger().Debug("Resetting the TUF builder...");
        
        // 重置newBuilder
        newBuilder_ = newBuilder_->bootstrapNewBuilder();
        
        // 更新root
        auto updateRootErr = updateRoot();
        if (!updateRootErr.ok()) {
            utils::GetLogger().Debug("Client Update (Root): " + updateRootErr.what());
            return Result<std::tuple<std::shared_ptr<tuf::Repo>, std::shared_ptr<tuf::Repo>>>(updateRootErr);
        }
        
        // 如果我们再次出错，现在我们有最新的root，只是想要失败退出
        // 因为没有期望问题可以自动解决
        utils::GetLogger().Debug("retrying TUF client update");
        auto retryUpdateErr = update();
        if (!retryUpdateErr.ok()) {
            return Result<std::tuple<std::shared_ptr<tuf::Repo>, std::shared_ptr<tuf::Repo>>>(retryUpdateErr);
        }
    }
    
    // 调用newBuilder的Finish方法获取最终的仓库
    auto finishResult = newBuilder_->finish();
    if (!finishResult.ok()) {
        return Result<std::tuple<std::shared_ptr<tuf::Repo>, std::shared_ptr<tuf::Repo>>>(finishResult.error());
    }
    
    // 将pair转换为tuple
    auto repos = finishResult.value();
    auto repoTuple = std::make_tuple(repos.first, repos.second);
    
    return Result<std::tuple<std::shared_ptr<tuf::Repo>, std::shared_ptr<tuf::Repo>>>(repoTuple);
}

// tryLoadCacheThenRemote实现
// 对应Go版本的tryLoadCacheThenRemote方法
Result<std::vector<uint8_t>> TUFClient::tryLoadCacheThenRemote(const tuf::ConsistentInfo& consistentInfo) {
    // 1. 步骤一：先在自己的书架上找书
    // 尝试从本地缓存中，根据索引卡上的信息(角色名和预期大小)来获取书籍内容
    auto cachedResult = cache_->GetSized(roleToString(consistentInfo.getRoleName()), consistentInfo.length());
    
    // 2. 步骤二：如果书架上没有这本书(缓存未命中)
    if (!cachedResult.ok()) {
        // 直接告诉远程助理："我的书架上没有这本书，你去中央图书馆帮我拿一本新的。"
        // 空的vector表示我们手头没有任何旧版本可以参考
        utils::GetLogger().Info("no " + roleToString(consistentInfo.getRoleName()) + " in cache, must download");
        return tryLoadRemote(consistentInfo, std::vector<uint8_t>());
    }
    
    auto cachedData = cachedResult.value();
    
    // 3. 步骤三：如果书架上有这本书，检查它是否仍然有效
    // newBuilder是我们当前信任的"官方验证工具箱"
    // 我们用它来验证书架上的这本书是否符合最新的标准
    // false参数表示这是一个宽松验证，主要检查签名和版本，即使过期也可以
    auto loadErr = newBuilder_->load(consistentInfo.getRoleName(), cachedData, 1, false);
    if (loadErr.ok()) {
        // 如果验证通过，太好了！这本书是好的
        // 直接返回这本书的内容，无需联系中央图书馆，任务完成
        utils::GetLogger().Info("successfully verified cached " + roleToString(consistentInfo.getRoleName()));
        return Result<std::vector<uint8_t>>(cachedData);
    }
    
    // 4. 步骤四：如果书架上的书已经过时或损坏(验证失败)
    // 记录一条日志，说明本地的这本书不行了
    utils::GetLogger().Info("cached " + roleToString(consistentInfo.getRoleName()) + " is invalid (must download): " + loadErr.what());
    
    // 告诉远程助理："我书架上这本书有问题，你去中央图书馆帮我拿一本新的。
    // 为了防止他们给我一本更旧的，我把这本有问题的书也给你，你参考一下它的版本号。"
    // 这里传递cachedData是为了进行版本比较，防止回滚攻击
    return tryLoadRemote(consistentInfo, cachedData);
}

// tryLoadRemote实现
// 对应Go版本的tryLoadRemote方法
Result<std::vector<uint8_t>> TUFClient::tryLoadRemote(const tuf::ConsistentInfo& consistentInfo, 
                                                     const std::vector<uint8_t>& old) {
    // 1. 步骤一：从中央图书馆下载新书
    std::string consistentName = consistentInfo.consistentName(); // 获取带哈希或版本号的文件名
    auto downloadResult = remote_->GetSized(consistentName, consistentInfo.length());
    if (!downloadResult.ok()) {
        // 如果下载失败（比如网络不通），任务失败
        // 返回错误，并把手头那本旧的、有问题的书(old)也一并返回，
        // 让上层决定如何处理这个局面
        utils::GetLogger().Debug("error downloading " + consistentName + ": " + downloadResult.error().what());
        return Result<std::vector<uint8_t>>(downloadResult.error());
    }
    
    auto rawData = downloadResult.value();
    
    // 2. 步骤二：准备进行版本对比(防止回滚攻击的关键！)
    // oldBuilder是一个"临时记事本"或"草稿纸"
    // 我们尝试把手头这本旧书(old)的信息加载到这个记事本上
    // 即使加载失败也无所谓，它的唯一目的是尝试读取旧书的版本号
    oldBuilder_->load(consistentInfo.getRoleName(), old, 1, true);
    
    // 从记事本上获取旧书的版本号。如果旧书是空的或无法解析，
    // getLoadedVersion会返回一个默认的最低版本（比如1）
    int minVersion = oldBuilder_->getLoadedVersion(consistentInfo.getRoleName());
    
    // 3. 步骤三：验证新下载的书
    // 这是核心验证步骤！我们用我们信任的"官方验证工具箱"(newBuilder)
    // 来验证刚从中央图书馆下载回来的新书(rawData)
    // 关键参数minVersion：我们告诉验证工具，这本新书的版本号
    // **绝对不能低于**我们之前记录的旧书版本号minVersion
    // 这就防止了攻击者给我们一本伪造的、更旧的书（回滚攻击）
    auto verifyErr = newBuilder_->load(consistentInfo.getRoleName(), rawData, minVersion, false);
    if (!verifyErr.ok()) {
        // 如果验证失败（比如签名错误，或者版本号更旧），
        // 这是一个严重的安全问题。返回下载的书和错误
        utils::GetLogger().Debug("downloaded " + consistentName + " is invalid: " + verifyErr.what());
        return Result<std::vector<uint8_t>>(verifyErr);
    }
    
    // 4. 步骤四：成功后的收尾工作
    utils::GetLogger().Debug("successfully verified downloaded " + consistentName);
    
    // 将这本验证通过的新书，放到自己的书架上（写入缓存），以便下次使用
    auto cacheErr = cache_->Set(roleToString(consistentInfo.getRoleName()), rawData);
    if (!cacheErr.ok()) {
        // 即使写入缓存失败，也只是记录一条日志，不影响本次成功的结果
        utils::GetLogger().Debug("Unable to write " + roleToString(consistentInfo.getRoleName()) + " to cache: " + cacheErr.what());
    }
    
    // 返回这本全新的、可信的书
    return Result<std::vector<uint8_t>>(rawData);
}

// downloadTimestamp实现
// 对应Go版本的downloadTimestamp方法
// 时间戳是特殊的，我们总是尝试下载，只有在下载失败时才使用缓存（且缓存仍然有效）
Error TUFClient::downloadTimestamp() {
    utils::GetLogger().Debug("Loading timestamp...");
    
    RoleName role = RoleName::TimestampRole;
    auto consistentInfo = newBuilder_->getConsistentInfo(role);
    
    // 总是获取远程时间戳，因为它优于本地时间戳
    auto cachedResult = cache_->GetSized(TIMESTAMP_ROLE, MAX_TIMESTAMP_SIZE);
    std::vector<uint8_t> cachedTS;
    bool hasCachedData = false;
    
    if (cachedResult.ok()) {
        cachedTS = cachedResult.value();
        hasCachedData = true;
    }
    
    // 尝试从远程加载时间戳
    auto remoteResult = tryLoadRemote(consistentInfo, cachedTS);
    
    // 检查是否没有远程错误，或者是否是网络问题
    // 如果是验证错误，我们应该报错，以便下载新的root或失败更新
    if (remoteResult.ok()) {
        return Error(); // 成功
    }
    
    Error remoteErr = remoteResult.error();
    
    // 检查错误类型 - 对应Go版本的switch语句
    // TODO: 确认错误类型
    std::string errorMsg = remoteErr.what();
    bool isNetworkError = (errorMsg.find("not found") != std::string::npos ||
                          errorMsg.find("server unavailable") != std::string::npos ||
                          errorMsg.find("offline") != std::string::npos ||
                          errorMsg.find("network") != std::string::npos);
    
    if (!isNetworkError) {
        // 不是网络错误，直接返回错误
        return remoteErr;
    }
    
    // 由于是网络错误：获取缓存的时间戳（如果存在）
    if (!hasCachedData) {
        utils::GetLogger().Debug("no cached or remote timestamp available");
        return remoteErr;
    }
    
    utils::GetLogger().Warn("Error while downloading remote metadata, using cached timestamp - this might not be the latest version available remotely");
    
    // 使用缓存的时间戳
    auto loadErr = newBuilder_->load(role, cachedTS, 1, false);
    if (loadErr.ok()) {
        utils::GetLogger().Debug("successfully verified cached timestamp");
    }
    
    return loadErr;
}

// downloadSnapshot实现
// 对应Go版本的downloadSnapshot方法
Error TUFClient::downloadSnapshot() {
    utils::GetLogger().Debug("Loading snapshot...");
    
    RoleName role = RoleName::SnapshotRole;
    auto consistentInfo = newBuilder_->getConsistentInfo(role);
    
    // 快照元数据使用标准的"先缓存后远程"策略
    // 与时间戳不同，快照可以优先使用缓存
    auto result = tryLoadCacheThenRemote(consistentInfo);
    
    if (!result.ok()) {
        return result.error();
    }
    
    return Error(); // 成功
}

// getTargetsFile实现
// 对应Go版本的getTargetsFile方法
Result<std::vector<tuf::DelegationRole>> TUFClient::getTargetsFile(const tuf::DelegationRole& role, 
                                                                   const tuf::ConsistentInfo& consistentInfo) {
    utils::GetLogger().Debug("Loading " + roleToString(role.Name) + "...");
    
    // 使用标准的缓存优先策略下载targets文件
    auto rawResult = tryLoadCacheThenRemote(consistentInfo);
    if (!rawResult.ok()) {
        return Result<std::vector<tuf::DelegationRole>>(rawResult.error());
    }
    
    auto rawData = rawResult.value();
    
    // 解析JSON数据以获取SignedTargets结构
    // 注意：我们知道可以解析，因为如果tryLoadCacheThenRemote没有失败，
    // 那么原始数据已经被加载到builder中
    try {
        // 创建SignedTargets对象并反序列化
        auto signedTargets = std::make_shared<tuf::SignedTargets>();
        if (!signedTargets->Deserialize(rawData)) {
            Error parseError("Failed to deserialize SignedTargets");
            return Result<std::vector<tuf::DelegationRole>>(parseError);
        }
        
        // 直接调用SignedTargets的GetValidDelegations方法
        // 对应Go版本的tgs.GetValidDelegations(role)
        std::vector<tuf::DelegationRole> delegations = signedTargets->GetValidDelegations(role);
        
        return Result<std::vector<tuf::DelegationRole>>(delegations);
        
    } catch (const std::exception& e) {
        Error parseError("Failed to process targets data: " + std::string(e.what()));
        return Result<std::vector<tuf::DelegationRole>>(parseError);
    }
}

// downloadTargets实现
// 对应Go版本的downloadTargets方法
// 下载所有targets和委托targets，使用前序树遍历，因为需要先下载父节点以获取验证子节点的密钥
Error TUFClient::downloadTargets() {
    // 初始化待下载队列，从根targets角色开始
    std::vector<tuf::DelegationRole> toDownload;
    
    // 创建根targets角色 - 对应Go版本的data.DelegationRole
    tuf::DelegationRole rootTargets;
    rootTargets.Name = RoleName::TargetsRole;
    rootTargets.Paths = {""};  // 空路径表示根targets
    
    toDownload.push_back(rootTargets);
    
    // 前序遍历下载所有targets
    while (!toDownload.empty()) {
        // 从队列头部取出一个角色进行处理
        tuf::DelegationRole role = toDownload.front();
        toDownload.erase(toDownload.begin());
        
        // 获取该角色的一致性信息
        auto consistentInfo = newBuilder_->getConsistentInfo(role.Name);
        
        // 检查是否有该角色的校验和信息
        if (!consistentInfo.checksumKnown()) {
            utils::GetLogger().Debug("skipping " + roleToString(role.Name) + " because there is no checksum for it");
            continue;
        }
        
        // 下载并处理该targets文件
        auto childrenResult = getTargetsFile(role, consistentInfo);
        
        if (!childrenResult.ok()) {
            Error err = childrenResult.error();
            std::string errorMsg = err.what();
            
            // 检查错误类型 - 对应Go版本的switch语句
            // TODO：检查错误类型
            bool isExpiredOrThreshold = (errorMsg.find("expired") != std::string::npos ||
                                        errorMsg.find("threshold") != std::string::npos ||
                                        errorMsg.find("ErrExpired") != std::string::npos ||
                                        errorMsg.find("ErrRoleThreshold") != std::string::npos);
            
            if (isExpiredOrThreshold) {
                // 如果是根targets角色出现过期或阈值错误，必须返回错误
                if (role.Name == RoleName::TargetsRole) {
                    return err;
                }
                // 对于委托角色，只是警告并继续
                utils::GetLogger().Warn("Error getting " + roleToString(role.Name) + ": " + err.what());
            } else {
                // 其他类型的错误直接返回
                return err;
            }
        } else {
            // 成功获取子委托角色，添加到待下载队列的前面（前序遍历）
            auto children = childrenResult.value();
            toDownload.insert(toDownload.begin(), children.begin(), children.end());
        }
    }
    
    return Error(); // 成功
}

// downloadRoot实现
// 对应Go版本的downloadRoot方法
// 负责下载root.json文件
Result<std::vector<uint8_t>> TUFClient::downloadRoot() {
    utils::GetLogger().Debug("Loading root...");
    
    RoleName role = RoleName::RootRole;
    auto consistentInfo = newBuilder_->getConsistentInfo(role);
    
    // 我们不能在没有校验和的情况下读取root元数据的确切大小，
    // 因为这可能导致陷入TUF更新循环中，
    // 因为下载timestamp/snapshot元数据可能由于签名不匹配而失败
    if (!consistentInfo.checksumKnown()) {
        utils::GetLogger().Debug("Loading root with no expected checksum");
        
        // 获取缓存的root（如果存在），仅用于版本检查
        auto cachedResult = cache_->GetSized(ROOT_ROLE, -1);
        std::vector<uint8_t> cachedRoot;
        
        if (cachedResult.ok()) {
            cachedRoot = cachedResult.value();
        }
        // 优先下载新的root
        return tryLoadRemote(consistentInfo, cachedRoot);
    }
    
    // 如果有校验和信息，使用标准的"先缓存后远程"策略
    return tryLoadCacheThenRemote(consistentInfo);
}

// updateRootVersions实现
//  安全地将客户端的信任从一个旧版本的 root.json 文件，逐步、连续地更新到一个目标新版本。
// 从当前版本更新root到目标版本，支持密钥轮转
Error TUFClient::updateRootVersions(int fromVersion, int toVersion) {
    for (int v = fromVersion; v <= toVersion; v++) {
        utils::GetLogger().Debug("updating root from version " + std::to_string(fromVersion) + 
                                " to version " + std::to_string(toVersion) + 
                                ", currently fetching " + std::to_string(v));
        
        // 构造版本化的角色名称，格式："<version>.root"
        std::string versionedRole = std::to_string(v) + "." + ROOT_ROLE;
        
        // 从远程下载指定版本的root文件，-1表示不限制大小
        auto downloadResult = remote_->GetSized(versionedRole, -1);
        if (!downloadResult.ok()) {
            utils::GetLogger().Debug("error downloading " + versionedRole + ": " + downloadResult.error().what());
            return downloadResult.error();
        }
        
        auto rawData = downloadResult.value();
        
        // 加载root进行更新，支持密钥轮转
        // 参数说明：rawData - 原始数据，v - 版本号，false - 不是最终验证
        auto loadErr = newBuilder_->loadRootForUpdate(rawData, v, false);
        if (!loadErr.ok()) {
            utils::GetLogger().Debug("downloaded " + versionedRole + " is invalid: " + loadErr.what());
            return loadErr;
        }
        
        utils::GetLogger().Debug("successfully verified downloaded " + versionedRole);
    }
    
    return Error(); // 成功
}

// updateRoot实现
// 对应Go版本的updateRoot方法
// 检查是否有更新的root版本，并下载所有中间root文件以支持密钥轮转
Error TUFClient::updateRoot() {
    // 获取当前root版本
    auto currentRootConsistentInfo = oldBuilder_->getConsistentInfo(RoleName::RootRole);
    int currentVersion = oldBuilder_->getLoadedVersion(currentRootConsistentInfo.getRoleName());
    
    // 获取最新的root版本
    auto rawResult = downloadRoot();
    
    // 检查下载结果的错误类型
    if (!rawResult.ok()) {
        Error downloadErr = rawResult.error();
        std::string errorMsg = downloadErr.what();
        
        // 检查是否是root轮转失败错误
        // 轮转错误是可以接受的，因为我们还没有下载所有中间root文件
        // TODO：确认错误类型
        if (errorMsg.find("ErrRootRotationFail") != std::string::npos ||
            errorMsg.find("root rotation fail") != std::string::npos ||
            errorMsg.find("rotation") != std::string::npos) {
            // 轮转错误，继续处理
        } else {
            // 返回任何非轮转错误
            return downloadErr;
        }
    } else {
        // 没有错误更新root - 我们最多落后1个版本
        return Error(); // 成功
    }
    
    // 如果程序走到了这里，说明需要一次多版本的更新（例如从版本 3 更新到版本 5）。
    auto rawData = rawResult.ok() ? rawResult.value() : std::vector<uint8_t>();
    
    // 将当前版本加载到newBuilder中
    auto currentRawResult = cache_->GetSized(ROOT_ROLE, -1);
    if (!currentRawResult.ok()) {
        utils::GetLogger().Debug("error loading " + std::to_string(currentVersion) + "." + ROOT_ROLE + ": " + currentRawResult.error().what());
        return currentRawResult.error();
    }
    
    auto currentRaw = currentRawResult.value();
    auto loadCurrentErr = newBuilder_->loadRootForUpdate(currentRaw, currentVersion, false);
    if (!loadCurrentErr.ok()) {
        utils::GetLogger().Debug(std::to_string(currentVersion) + "." + ROOT_ROLE + " is invalid: " + loadCurrentErr.what());
        return loadCurrentErr;
    }
    
    // 如果没有新的raw数据，返回错误
    if (rawData.empty()) {
        return Error("No new root data available");
    }
    
    // 提取最新版本号
    try {
        json signedRoot = json::parse(rawData.begin(), rawData.end());
        
        // 检查signed字段
        if (!signedRoot.contains("signed")) {
            return Error("Invalid root format: missing signed field");
        }
        
        // 解析版本号
        auto signedData = signedRoot["signed"];
        if (!signedData.contains("version")) {
            return Error("Invalid root format: missing version field");
        }
        
        int newestVersion = signedData["version"].get<int>();
        
        // 从 current + 1 更新到 newest - 1（当前已加载，最新的在下面加载）
        if (currentVersion + 1 <= newestVersion - 1) {
            auto updateErr = updateRootVersions(currentVersion + 1, newestVersion - 1);
            if (!updateErr.ok()) {
                return updateErr;
            }
        }
        
        // 已经下载了最新版本，对照 newest - 1 进行验证
        auto loadNewestErr = newBuilder_->loadRootForUpdate(rawData, newestVersion, true);
        if (!loadNewestErr.ok()) {
            utils::GetLogger().Debug("downloaded " + std::to_string(newestVersion) + "." + ROOT_ROLE + " is invalid: " + loadNewestErr.what());
            return loadNewestErr;
        }
        
        utils::GetLogger().Debug("successfully verified downloaded " + std::to_string(newestVersion) + "." + ROOT_ROLE);
        
        // 将最新版本写入缓存
        auto setCacheErr = cache_->Set(ROOT_ROLE, rawData);
        if (!setCacheErr.ok()) {
            utils::GetLogger().Debug("unable to write " + std::to_string(newestVersion) + "." + ROOT_ROLE + " to cache: " + setCacheErr.what());
        }
        
        utils::GetLogger().Debug("finished updating root files");
        return Error(); // 成功
        
    } catch (const json::exception& e) {
        return Error("Failed to parse root JSON: " + std::string(e.what()));
    } catch (const std::exception& e) {
        return Error("Failed to process root data: " + std::string(e.what()));
    }
}

// update实现
// 对应Go版本的update方法
// TUF客户端的核心更新逻辑
Error TUFClient::update() {
    // 1. 下载timestamp
    auto timestampErr = downloadTimestamp();
    if (!timestampErr.ok()) {
        return timestampErr;
    }
    utils::GetLogger().Info("Client Update (Timestamp): Success");
    
    // 2. 下载snapshot
    auto snapshotErr = downloadSnapshot();
    if (!snapshotErr.ok()) {
        return snapshotErr;
    }
    utils::GetLogger().Info("Client Update (Snapshot): Success");
    // 3. 总是需要至少顶层targets
    auto targetsErr = downloadTargets();
    if (!targetsErr.ok()) {
        return targetsErr;
    }
    utils::GetLogger().Info("Client Update Success");
    
    return Error(); // 成功
}

// bootstrapClient实现
// 对应Go版本的bootstrapClient函数
// 尝试引导root.json作为仓库的信任锚点
// 得到的是最新的root.json，比如3.root.json，如果此时本地还是1.root.json
// 后续的updateRoot会下载2.root.json
Result<std::unique_ptr<TUFClient>> bootstrapClient(const TUFLoadOptions& options) {
    int minVersion = 1;
    
    // 磁盘上的旧root不应针对任何信任锚定配置进行验证
    // 因为如果我们有旧root，它本身就是锚定信任的东西
    tuf::TrustPinConfig emptyTrustPin; // 空的信任锚定配置
    auto oldBuilder = tuf::NewRepoBuilder(options.GUN, options.CryptoService, emptyTrustPin);
    
    // 默认情况下，我们希望对下载的任何新root使用信任锚定配置
    auto newBuilder = tuf::NewRepoBuilder(options.GUN, options.CryptoService, options.TrustPinning);
    
    // 首先尝试从缓存读取root。我们将信任此root，直到在更新期间检测到问题，
    // 这将导致我们下载新root并执行轮转。
    // 如果我们有旧root且有效，则覆盖newBuilder为已预加载旧root的构建器，
    // 或使用旧root进行信任引导的构建器。
    auto cachedRootResult = options.Cache->GetSized(ROOT_ROLE, -1); // NoSizeLimit equivalent
    if (cachedRootResult.ok()) {
        auto rootJSON = cachedRootResult.value();
        
        // 如果无法加载缓存的root，硬失败，因为这是我们锚定信任的方式
        auto loadOldErr = oldBuilder->load(RoleName::RootRole, rootJSON, minVersion, true);
        if (!loadOldErr.ok()) {
            return Result<std::unique_ptr<TUFClient>>(loadOldErr);
        }
        
        // 重置newBuilder，使用空的信任锚定配置，校验缓存root的有效期
        newBuilder = tuf::NewRepoBuilder(options.GUN, options.CryptoService, emptyTrustPin);
        
        auto loadNewErr = newBuilder->load(RoleName::RootRole, rootJSON, minVersion, false);
        if (!loadNewErr.ok()) {
            // 好的，旧root已过期 - 我们想下载新的。但我们想使用旧root来验证新root，
            // 所以使用旧构建器引导新构建器，但使用信任锚定来验证新root
            minVersion = oldBuilder->getLoadedVersion(RoleName::RootRole);
            newBuilder = oldBuilder->bootstrapNewBuilderWithNewTrustpin(options.TrustPinning);
        }
    }
    if (!newBuilder->isLoaded(RoleName::RootRole) || options.AlwaysCheckInitialized) {
        // remoteErr为nil且我们无法从缓存加载root，或者特别检查仓库的初始化。
        
        // 如果远程存储成功设置，尝试从远程获取root
        // 我们没有任何本地数据来确定root的大小，所以尝试最大值（虽然限制在100MB）
        auto tmpJSONResult = options.RemoteStore->GetSized(ROOT_ROLE, -1); // NoSizeLimit equivalent
        if (!tmpJSONResult.ok()) {
            // 我们在缓存中没有root，也无法从服务器加载
            // 除了错误，我们无能为力
            return Result<std::unique_ptr<TUFClient>>(tmpJSONResult.error());
        }
        
        auto tmpJSON = tmpJSONResult.value();
        
        if (!newBuilder->isLoaded(RoleName::RootRole)) {
            // 如果无法从缓存加载，我们总是想使用下载的root
            auto loadErr = newBuilder->load(RoleName::RootRole, tmpJSON, minVersion, false);
            if (!loadErr.ok()) {
                return Result<std::unique_ptr<TUFClient>>(loadErr);
            }
            
            auto setCacheErr = options.Cache->Set(ROOT_ROLE, tmpJSON);
            if (!setCacheErr.ok()) {
                // 如果无法写入缓存，我们仍应继续，只是记录错误
                utils::GetLogger().Error("could not save root to cache: " + setCacheErr.what());
            }
        }
    }
    
    // 我们只有在remoteErr != nil（因此我们不下载任何新root）且磁盘上没有root时才能到达这里
    if (!newBuilder->isLoaded(RoleName::RootRole)) {
        return Result<std::unique_ptr<TUFClient>>(
            Error("Repository not initialized")
        );
    }
    
    // 创建TUFClient对象
    auto client = std::make_unique<TUFClient>(
        options.RemoteStore,
        options.Cache,
        std::shared_ptr<tuf::RepoBuilder>(oldBuilder.release()),
        std::shared_ptr<tuf::RepoBuilder>(newBuilder.release())
    );
    
    return Result<std::unique_ptr<TUFClient>>(std::move(client));
}

// LoadTUFRepo实现
// 对应Go版本的LoadTUFRepo函数
// 引导信任锚点（root.json）从缓存（如果提供）在从远程（如果提供）更新仓库的所有元数据之前
// 它从缓存、远程存储或两者加载TUF仓库
Result<std::tuple<std::shared_ptr<tuf::Repo>, std::shared_ptr<tuf::Repo>>> LoadTUFRepo(const TUFLoadOptions& options) {
    // 复制options以便修改，设置一些合理的默认值，因此不一定需要提供所有内容
    TUFLoadOptions modifiedOptions = options;
    
    // 设置默认的RemoteStore（如果未提供）
    if (!modifiedOptions.RemoteStore) {
        modifiedOptions.RemoteStore = std::make_shared<storage::OfflineStore>();
        utils::GetLogger().Warn("RemoteStore not provided, using null store");
    }
    
    // 设置默认的Cache（如果未提供）
    if (!modifiedOptions.Cache) {
        modifiedOptions.Cache = std::make_shared<storage::MemoryStore>();
        utils::GetLogger().Warn("Cache not provided, using null store");
    }
    
    // 设置默认的CryptoService（如果未提供）
    if (!modifiedOptions.CryptoService) {
        modifiedOptions.CryptoService = crypto::EmptyService;
        utils::GetLogger().Warn("CryptoService not provided, using null service");
    }
    
    // 调用 bootstrapClient 方法，引导 TUF 客户端：
    // - 加载或下载 root.json 作为信任锚点。
    // - 如果 root.json 不存在，返回 ErrRepositoryNotExist 错误。
    // - 如果发生其他错误，直接返回。
    auto clientResult = bootstrapClient(modifiedOptions);
    if (!clientResult.ok()) {
        Error err = clientResult.error();
        std::string errorMsg = err.what();
        
        // 检查是否是ErrMetaNotFound错误（对应Go版本的store.ErrMetaNotFound）
        // 在C++版本中，我们通过错误消息来识别错误类型
        if (errorMsg.find("not found") != std::string::npos || 
            errorMsg.find("ErrMetaNotFound") != std::string::npos) {
            // 获取远程地址
            std::string remote = modifiedOptions.RemoteStore ? 
                modifiedOptions.RemoteStore->Location() : "unknown";
            
            // 返回ErrRepositoryNotExist错误
            return Result<std::tuple<std::shared_ptr<tuf::Repo>, std::shared_ptr<tuf::Repo>>>(
                ErrRepositoryNotExist(remote, modifiedOptions.GUN)
            );
        }
        
        // 返回其他错误
        return Result<std::tuple<std::shared_ptr<tuf::Repo>, std::shared_ptr<tuf::Repo>>>(err);
    }
    auto&& client = clientResult.value();
    
    // 调用 Update 方法更新 TUF 仓库的元数据：
    // 下载并验证 timestamp.json、snapshot.json 和 targets.json。
    // 如果 root.json 不存在，返回 ErrRepositoryNotExist 错误。
    // 如果发生其他错误，直接返回。
    auto updateResult = client->Update();
    if (!updateResult.ok()) {
        Error err = updateResult.error();
        std::string errorMsg = err.what();
        
        // 检查是否是元数据未找到错误且与root角色相关
        // notFound.Resource may include a version or checksum so when the role is root,
        // it will be root, <version>.root or root.<checksum>.
        if (errorMsg.find("not found") != std::string::npos || 
            errorMsg.find("ErrMetaNotFound") != std::string::npos) {
            
            // 使用正则表达式检查资源是否与root角色相关
            // 对应Go版本的regexp.MatchString(`\.?`+data.CanonicalRootRole.String()+`\.?`, notFound.Resource)
            // TODO：确认错误类型
            std::regex rootPattern(R"(\.?root\.?)");
            if (std::regex_search(errorMsg, rootPattern)) {
                // 获取远程地址
                std::string remote = modifiedOptions.RemoteStore ? 
                    modifiedOptions.RemoteStore->Location() : "unknown";
                
                // 返回ErrRepositoryNotExist错误
                return Result<std::tuple<std::shared_ptr<tuf::Repo>, std::shared_ptr<tuf::Repo>>>(
                    ErrRepositoryNotExist(remote, modifiedOptions.GUN)
                );
            }
        }
        
        // 返回其他错误
        return Result<std::tuple<std::shared_ptr<tuf::Repo>, std::shared_ptr<tuf::Repo>>>(err);
    }
    
    // 获取更新结果
    auto repos = updateResult.value();
    auto repo = std::get<0>(repos);
    auto invalid = std::get<1>(repos);
    
    // 检查接近过期的角色并发出警告
    utils::warnRolesNearExpiry(repo);
    
    return Result<std::tuple<std::shared_ptr<tuf::Repo>, std::shared_ptr<tuf::Repo>>>(repos);
}

} // namespace client
} // namespace notary