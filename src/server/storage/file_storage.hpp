#pragma once

#include <string>
#include <mutex>
#include <filesystem>
#include "notary/server/server.hpp"
#include "notary/types.hpp"

namespace notary {
namespace server {
namespace storage {

// 文件系统存储服务
class FileStorageService : public StorageService {
public:
    explicit FileStorageService(const std::string& baseDir);
    
    // 获取元数据
    Result<Metadata> GetMetadata(const MetadataRequest& request) override;
    
    // 存储元数据
    Result<bool> StoreMetadata(const std::string& gun, const std::string& role, 
                       const std::string& roleName, const std::string& data) override;
    
    // 删除GUN相关的所有元数据
    Result<bool> DeleteGUN(const std::string& gun) override;

private:
    std::string baseDir_;
    std::mutex mutex_; // 用于操作线程安全
    
    // 计算文件校验和
    std::string calculateChecksum(const std::string& data) const;
    
    // 构建元数据文件路径
    std::string buildMetadataPath(const std::string& gun, const std::string& role, 
                                  int version = 0, const std::string& checksum = "") const;
                                  
    // 获取角色的最新版本号
    Result<int> getLatestVersion(const std::string& gun, const std::string& role) const;
    
    // 确保目录存在
    void ensureDirectoryExists(const std::string& path) const;
};

} // namespace storage
} // namespace server
} // namespace notary 