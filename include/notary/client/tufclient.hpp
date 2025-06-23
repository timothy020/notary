#pragma once

#include "notary/storage/store.hpp"
#include "notary/tuf/builder.hpp"
#include "notary/tuf/repo.hpp"
#include "notary/types.hpp"
#include "notary/utils/logger.hpp"
#include "notary/crypto/crypto_service.hpp"
#include "notary/tuf/trustpinning.hpp"
#include <memory>
#include <tuple>
#include <nlohmann/json.hpp>

// 前向声明
using json = nlohmann::json;

namespace notary {
namespace client {

// TUF加载选项 - 对应Go版本的TUFLoadOptions
struct TUFLoadOptions {
    std::string GUN;                                           // 全球唯一名称
    tuf::TrustPinConfig TrustPinning;                         // 信任锚定配置  
    std::shared_ptr<crypto::CryptoService> CryptoService;     // 密码服务
    std::shared_ptr<storage::MetadataStore> Cache;            // 缓存存储
    std::shared_ptr<storage::RemoteStore> RemoteStore;        // 远程存储
    bool AlwaysCheckInitialized = false;                      // 总是检查初始化状态
};

// 仓库未初始化错误
class ErrRepoNotInitialized : public std::exception {
public:
    ErrRepoNotInitialized(const std::string& remote = "", const std::string& gun = "")
        : remote_(remote), gun_(gun) {
        message_ = "Repository " + gun + " is not initialized at " + remote;
    }
    
    const char* what() const noexcept override {
        return message_.c_str();
    }
    
private:
    std::string remote_;
    std::string gun_;
    std::string message_;
};

// 前向声明
class TUFClient;

// TUFClient是原始TUF仓库的可用性包装器
// 对应Go版本的tufClient struct
class TUFClient {
public:
    // 构造函数
    TUFClient(std::shared_ptr<storage::RemoteStore> remote,
              std::shared_ptr<storage::MetadataStore> cache,
              std::shared_ptr<tuf::RepoBuilder> oldBuilder,
              std::shared_ptr<tuf::RepoBuilder> newBuilder);

    // 更新TUF仓库，按照TUF规范执行更新
    // 对应Go版本的Update方法
    Result<std::tuple<std::shared_ptr<tuf::Repo>, std::shared_ptr<tuf::Repo>>> Update();

private:
    // 内部更新方法
    Error update();
    
    // 更新根证书
    Error updateRoot();
    
    // 更新根证书版本
    Error updateRootVersions(int fromVersion, int toVersion);
    
    // 下载时间戳
    Error downloadTimestamp();
    
    // 下载快照
    Error downloadSnapshot();
    
    // 下载目标文件
    Error downloadTargets();
    
    // 获取目标文件
    Result<std::vector<tuf::DelegationRole>> getTargetsFile(const tuf::DelegationRole& role, 
                                                            const tuf::ConsistentInfo& ci);
    
    // 下载根证书
    Result<std::vector<uint8_t>> downloadRoot();
    
    // 先尝试从缓存加载，然后从远程加载
    // 对应Go版本的tryLoadCacheThenRemote方法
    Result<std::vector<uint8_t>> tryLoadCacheThenRemote(const tuf::ConsistentInfo& consistentInfo);
    
    // 尝试从远程加载
    // 对应Go版本的tryLoadRemote方法
    Result<std::vector<uint8_t>> tryLoadRemote(const tuf::ConsistentInfo& consistentInfo, 
                                             const std::vector<uint8_t>& old);

private:
    std::shared_ptr<storage::RemoteStore> remote_;     // 远程存储
    std::shared_ptr<storage::MetadataStore> cache_;    // 本地缓存
    std::shared_ptr<tuf::RepoBuilder> oldBuilder_;     // 旧的构建器
    std::shared_ptr<tuf::RepoBuilder> newBuilder_;     // 新的构建器
};

// bootstrapClient函数声明
// 对应Go版本的bootstrapClient函数
// 尝试引导root.json作为仓库的信任锚点
Result<std::unique_ptr<TUFClient>> bootstrapClient(const TUFLoadOptions& options);

// ErrRepositoryNotExist错误 - 对应Go版本的ErrRepositoryNotExist
class ErrRepositoryNotExist : public Error {
public:
    std::string remote;
    std::string gun;
    
    ErrRepositoryNotExist(const std::string& remote, const std::string& gun)
        : Error("Repository " + gun + " does not exist at " + remote)
        , remote(remote)
        , gun(gun) {
    }
};

// LoadTUFRepo 引导信任锚点（root.json）从缓存（如果提供）
// 在从远程（如果提供）更新仓库的所有元数据之前
// 它从缓存、远程存储或两者加载TUF仓库
// 对应Go版本的LoadTUFRepo函数
Result<std::tuple<std::shared_ptr<tuf::Repo>, std::shared_ptr<tuf::Repo>>> LoadTUFRepo(const TUFLoadOptions& options);

} // namespace client
} // namespace notary