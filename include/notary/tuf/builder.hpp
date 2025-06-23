#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <exception>
#include "notary/types.hpp"
#include "notary/tuf/repo.hpp"
#include "notary/tuf/trustpinning.hpp"

// 前向声明避免循环依赖
namespace notary {
namespace crypto {
    class CryptoService;
}
}

namespace notary {
namespace tuf {

// 构建器完成错误 - 当构建器已完成构建后调用任何函数时返回
class BuildDoneException : public std::exception {
public:
    const char* what() const noexcept override {
        return "the builder has finished building and cannot accept any more input or produce any more output";
    }
};

// 无效构建器输入错误 - 当RepoBuilder.Load被调用时传入错误类型的元数据
class InvalidBuilderInputException : public std::exception {
public:
    explicit InvalidBuilderInputException(const std::string& message) : message_(message) {}
    const char* what() const noexcept override { return message_.c_str(); }
    const std::string& getMessage() const { return message_; }
    
private:
    std::string message_;
};

// 一致性信息 - 角色的一致性名称和大小，或仅角色名称和-1（如果角色的文件元数据未知）
class ConsistentInfo {
public:
    // 构造函数
    ConsistentInfo() = default;
    explicit ConsistentInfo(RoleName roleName) : roleName_(roleName) {}
    ConsistentInfo(RoleName roleName, const FileMeta& fileMeta) 
        : roleName_(roleName), fileMeta_(fileMeta) {}
    
    // 访问器
    RoleName getRoleName() const { return roleName_; }
    const FileMeta& getFileMeta() const { return fileMeta_; }
    
    // 设置器
    void setRoleName(RoleName roleName) { roleName_ = roleName; }
    void setFileMeta(const FileMeta& fileMeta) { fileMeta_ = fileMeta; }
    
    // 确定是否知道足够信息来提供大小和一致性名称
    bool checksumKnown() const;
    
    // 根据此一致性信息返回角色的一致性名称 (rolename.sha256)
    std::string consistentName() const;
    
    // 根据此一致性信息返回角色的预期长度 - 如果不知道校验和信息，大小为-1
    int64_t length() const;

private:
    RoleName roleName_ = RoleName::RootRole;
    FileMeta fileMeta_;
};

// RepoBuilder接口 - 构建tuf.Repo的对象接口
class RepoBuilder {
public:
    virtual ~RepoBuilder() = default;
    
    // 加载元数据
    virtual Error load(RoleName roleName, const std::vector<uint8_t>& content, 
                      int minVersion, bool allowExpired) = 0;
    
    // 加载根元数据以进行更新
    virtual Error loadRootForUpdate(const std::vector<uint8_t>& content, 
                                   int minVersion, bool isFinal) = 0;
    
    // 生成快照
    virtual Result<std::pair<std::vector<uint8_t>, int>> generateSnapshot(
        std::shared_ptr<SignedSnapshot> prev = nullptr) = 0;
    
    // 生成时间戳
    virtual Result<std::pair<std::vector<uint8_t>, int>> generateTimestamp(
        std::shared_ptr<SignedTimestamp> prev = nullptr) = 0;
    
    // 完成构建并返回最终和无效的仓库
    virtual Result<std::pair<std::shared_ptr<Repo>, std::shared_ptr<Repo>>> finish() = 0;
    
    // 引导新构建器
    virtual std::unique_ptr<RepoBuilder> bootstrapNewBuilder() = 0;
    
    // 使用新的trust pin配置引导新构建器
    virtual std::unique_ptr<RepoBuilder> bootstrapNewBuilderWithNewTrustpin(
        const TrustPinConfig& trustpin) = 0;
    
    // 信息函数
    virtual bool isLoaded(RoleName roleName) const = 0;
    virtual int getLoadedVersion(RoleName roleName) const = 0;
    virtual ConsistentInfo getConsistentInfo(RoleName roleName) const = 0;
};

// 已完成构建器 - 拒绝任何更多输入或输出
class FinishedBuilder : public RepoBuilder {
public:
    Error load(RoleName roleName, const std::vector<uint8_t>& content, 
              int minVersion, bool allowExpired) override;
    
    Error loadRootForUpdate(const std::vector<uint8_t>& content, 
                           int minVersion, bool isFinal) override;
    
    Result<std::pair<std::vector<uint8_t>, int>> generateSnapshot(
        std::shared_ptr<SignedSnapshot> prev = nullptr) override;
    
    Result<std::pair<std::vector<uint8_t>, int>> generateTimestamp(
        std::shared_ptr<SignedTimestamp> prev = nullptr) override;
    
    Result<std::pair<std::shared_ptr<Repo>, std::shared_ptr<Repo>>> finish() override;
    
    std::unique_ptr<RepoBuilder> bootstrapNewBuilder() override;
    
    std::unique_ptr<RepoBuilder> bootstrapNewBuilderWithNewTrustpin(
        const TrustPinConfig& trustpin) override;
    
    bool isLoaded(RoleName roleName) const override;
    int getLoadedVersion(RoleName roleName) const override;
    ConsistentInfo getConsistentInfo(RoleName roleName) const override;
};

// 实际的仓库构建器实现
class RepoBuilderImpl : public RepoBuilder {
public:
    // 构造函数
    RepoBuilderImpl(const std::string& gun, 
                   std::shared_ptr<crypto::CryptoService> cs,
                   const TrustPinConfig& trustpin);
    
    // 从现有仓库引导的构造函数
    RepoBuilderImpl(const std::string& gun,
                   std::shared_ptr<Repo> repo,
                   const TrustPinConfig& trustpin);
    
    // 实现RepoBuilder接口
    Error load(RoleName roleName, const std::vector<uint8_t>& content, 
              int minVersion, bool allowExpired) override;
    
    Error loadRootForUpdate(const std::vector<uint8_t>& content, 
                           int minVersion, bool isFinal) override;
    
    Result<std::pair<std::vector<uint8_t>, int>> generateSnapshot(
        std::shared_ptr<SignedSnapshot> prev = nullptr) override;
    
    Result<std::pair<std::vector<uint8_t>, int>> generateTimestamp(
        std::shared_ptr<SignedTimestamp> prev = nullptr) override;
    
    Result<std::pair<std::shared_ptr<Repo>, std::shared_ptr<Repo>>> finish() override;
    
    std::unique_ptr<RepoBuilder> bootstrapNewBuilder() override;
    
    std::unique_ptr<RepoBuilder> bootstrapNewBuilderWithNewTrustpin(
        const TrustPinConfig& trustpin) override;
    
    bool isLoaded(RoleName roleName) const override;
    int getLoadedVersion(RoleName roleName) const override;
    ConsistentInfo getConsistentInfo(RoleName roleName) const override;

    // Root验证相关方法
    Result<BaseRole> buildBaseRoleFromRoot(std::shared_ptr<SignedRoot> signedRoot, RoleName roleName);
    
    // 检查方法
    Error checkRoleLoaded(RoleName singleRole);
    
private:
    // 私有成员变量
    std::shared_ptr<Repo> repo_;
    std::shared_ptr<Repo> invalidRoles_;
    
    // 根信任锚定验证所需
    std::string gun_;
    TrustPinConfig trustpin_;
    
    // 以防我们在快照和时间戳之前加载根和/或目标（或快照而不是时间戳），
    // 以便我们知道当带有校验和的数据进来时要验证什么
    std::map<RoleName, std::vector<uint8_t>> loadedNotChecksummed_;
    
    // 验证新根的引导值
    std::shared_ptr<SignedRoot> prevRoot_;
    std::shared_ptr<FileMeta> bootstrappedRootChecksum_;
    
    // 用于引导下一个构建器
    std::shared_ptr<FileMeta> nextRootChecksum_;
    
    // 私有辅助方法
    Error checkPrereqsLoaded(RoleName roleName);
    bool isValidRole(RoleName roleName);
    Error loadOptions(RoleName roleName, const std::vector<uint8_t>& content, 
                     int minVersion, bool allowExpired, bool skipChecksum, bool allowLoaded);
    
    // 各种角色的加载方法
    Error loadRoot(const std::vector<uint8_t>& content, int minVersion, 
                  bool allowExpired, bool skipChecksum);
    Error loadTimestamp(const std::vector<uint8_t>& content, int minVersion, bool allowExpired);
    Error loadSnapshot(const std::vector<uint8_t>& content, int minVersion, bool allowExpired);
    Error loadTargets(const std::vector<uint8_t>& content, int minVersion, bool allowExpired);
    Error loadDelegation(RoleName roleName, const std::vector<uint8_t>& content, 
                        int minVersion, bool allowExpired);
    
    // 校验和验证方法
    Error validateChecksumsFromTimestamp(std::shared_ptr<SignedTimestamp> ts);
    Error validateChecksumsFromSnapshot(std::shared_ptr<SignedSnapshot> sn);
    Error validateChecksumFor(const std::vector<uint8_t>& content, RoleName roleName);
    
    // 字节转换和验证方法
    Result<std::shared_ptr<Signed>> bytesToSigned(const std::vector<uint8_t>& content, 
                                                  RoleName roleName, bool skipChecksum);
    Result<std::shared_ptr<Signed>> bytesToSignedAndValidateSigs(const BaseRole& role, 
                                                                const std::vector<uint8_t>& content);
    
    // 获取校验和方法
    std::shared_ptr<std::map<std::string, std::vector<uint8_t>>> getChecksumsFor(RoleName role) const;
};

// 构建器包装器 - 嵌入repoBuilder，但一旦调用Finish，就用finishedBuilder替换嵌入的对象
class RepoBuilderWrapper : public RepoBuilder {
public:
    explicit RepoBuilderWrapper(std::unique_ptr<RepoBuilder> builder);
    
    // 实现RepoBuilder接口，大部分委托给内部构建器
    Error load(RoleName roleName, const std::vector<uint8_t>& content, 
              int minVersion, bool allowExpired) override;
    
    Error loadRootForUpdate(const std::vector<uint8_t>& content, 
                           int minVersion, bool isFinal) override;
    
    Result<std::pair<std::vector<uint8_t>, int>> generateSnapshot(
        std::shared_ptr<SignedSnapshot> prev = nullptr) override;
    
    Result<std::pair<std::vector<uint8_t>, int>> generateTimestamp(
        std::shared_ptr<SignedTimestamp> prev = nullptr) override;
    
    Result<std::pair<std::shared_ptr<Repo>, std::shared_ptr<Repo>>> finish() override;
    
    std::unique_ptr<RepoBuilder> bootstrapNewBuilder() override;
    
    std::unique_ptr<RepoBuilder> bootstrapNewBuilderWithNewTrustpin(
        const TrustPinConfig& trustpin) override;
    
    bool isLoaded(RoleName roleName) const override;
    int getLoadedVersion(RoleName roleName) const override;
    ConsistentInfo getConsistentInfo(RoleName roleName) const override;

private:
    std::unique_ptr<RepoBuilder> builder_;
    bool isFinished_ = false;
};

// 工厂函数

// NewRepoBuilder是获取预构建RepoBuilder的唯一方法
std::unique_ptr<RepoBuilder> NewRepoBuilder(const std::string& gun, 
                                           std::shared_ptr<crypto::CryptoService> cs, 
                                           const TrustPinConfig& trustpin);

// NewBuilderFromRepo允许我们从现有仓库数据引导构建器
// 您可能不应该在测试代码之外使用这个！！！
std::unique_ptr<RepoBuilder> NewBuilderFromRepo(const std::string& gun, 
                                               std::shared_ptr<Repo> repo, 
                                               const TrustPinConfig& trustpin);

} // namespace tuf
} // namespace notary

