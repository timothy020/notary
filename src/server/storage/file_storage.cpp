#include "file_storage.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <regex>
#include <openssl/sha.h>
#include "notary/utils/logger.hpp"
#include "notary/types.hpp"

namespace fs = std::filesystem;

// 声明使用的命名空间，避免歧义
using notary::Error;
using notary::Result;

namespace notary {
namespace server {
namespace storage {

FileStorageService::FileStorageService(const std::string& baseDir) : baseDir_(baseDir) {
    ensureDirectoryExists(baseDir_);
    utils::GetLogger().Info("初始化文件存储服务", 
        utils::LogContext().With("baseDir", baseDir_));
}

Result<Metadata> FileStorageService::GetMetadata(const MetadataRequest& request) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    try {
        std::string rolePath;
        if (request.checksum.empty() && request.version == 0) {
            // 获取最新版本
            auto versionResult = getLatestVersion(request.gun, request.roleName);
            if (!versionResult.ok()) {
                return Result<Metadata>(versionResult.error());
            }
            int latestVersion = versionResult.value();
            rolePath = buildMetadataPath(request.gun, request.roleName, latestVersion);
        } else if (!request.checksum.empty()) {
            // 通过校验和查找
            rolePath = buildMetadataPath(request.gun, request.roleName, 0, request.checksum);
        } else {
            // 通过版本查找
            rolePath = buildMetadataPath(request.gun, request.roleName, request.version);
        }
        
        if (!fs::exists(rolePath)) {
            return Result<Metadata>(notary::Error("Metadata not found: " + rolePath));
        }
        
        // 读取文件内容
        std::ifstream file(rolePath, std::ios::binary);
        if (!file) {
            return Result<Metadata>(notary::Error("Cannot open file: " + rolePath));
        }
        
        std::stringstream buffer;
        buffer << file.rdbuf();
        std::string data = buffer.str();
        
        // 计算校验和
        std::string checksum = calculateChecksum(data);
        
        // 获取版本（从文件名）
        int version = request.version;
        if (version == 0 && !request.checksum.empty()) {
            // 通过校验和查找时需要从文件名提取版本
            fs::path path(rolePath);
            std::string filename = path.filename().string();
            std::regex versionRegex(R"((\d+)\.(.+)\.json)");
            std::smatch matches;
            if (std::regex_search(filename, matches, versionRegex)) {
                version = std::stoi(matches[1].str());
            }
        }
        
        Metadata metadata;
        metadata.data = data;
        metadata.checksum = checksum;
        metadata.version = version;
        
        // 获取文件最后修改时间作为timestamp
        try {
            auto fileTime = fs::last_write_time(rolePath);
            // C++17/C++20的fs::file_time_type转换到system_clock时间点有所不同
            // 这里我们简单使用当前时间，在实际实现中应正确转换文件时间
            metadata.timestamp = std::chrono::system_clock::now();
        } catch (const std::exception& e) {
            utils::GetLogger().Warn("无法获取文件修改时间",
                utils::LogContext()
                    .With("path", rolePath)
                    .With("error", e.what()));
            // 使用当前时间作为备选
            metadata.timestamp = std::chrono::system_clock::now();
        }
        
        utils::GetLogger().Debug("获取元数据成功",
            utils::LogContext()
                .With("gun", request.gun)
                .With("role", request.roleName)
                .With("version", std::to_string(version))
                .With("checksum", checksum));
        
        return Result<Metadata>(metadata);
    } catch (const std::exception& e) {
        utils::GetLogger().Error("获取元数据失败",
            utils::LogContext()
                .With("gun", request.gun)
                .With("role", request.roleName)
                .With("error", e.what()));
        return Result<Metadata>(notary::Error(e.what()));
    }
}

Result<bool> FileStorageService::StoreMetadata(const std::string& gun, const std::string& role, 
                                      const std::string& roleName, const std::string& data) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    try {
        // 获取最新版本号
        auto versionResult = getLatestVersion(gun, roleName);
        int newVersion = 1; // 默认从1开始
        if (versionResult.ok()) {
            newVersion = versionResult.value() + 1;
        }
        
        // 计算校验和
        std::string checksum = calculateChecksum(data);
        
        // 确保目录存在
        std::string dirPath = baseDir_ + gun + "/";
        ensureDirectoryExists(dirPath);
        
        // 保存版本文件
        std::string versionPath = buildMetadataPath(gun, roleName, newVersion);
        std::ofstream versionFile(versionPath, std::ios::binary);
        if (!versionFile) {
            return Result<bool>(notary::Error("Cannot create version file: " + versionPath));
        }
        versionFile.write(data.data(), data.size());
        versionFile.close();
        
        // 保存校验和文件
        std::string checksumPath = buildMetadataPath(gun, roleName, 0, checksum);
        std::ofstream checksumFile(checksumPath, std::ios::binary);
        if (!checksumFile) {
            // 回滚版本文件
            fs::remove(versionPath);
            return Result<bool>(notary::Error("Cannot create checksum file: " + checksumPath));
        }
        checksumFile.write(data.data(), data.size());
        checksumFile.close();
        
        // 创建或更新当前版本链接
        std::string currentPath = dirPath + "/" + roleName + ".json";
        if (fs::exists(currentPath)) {
            fs::remove(currentPath);
        }
        
        // 创建硬链接指向最新版本
        fs::create_hard_link(versionPath, currentPath);
        
        utils::GetLogger().Info("存储元数据成功",
            utils::LogContext()
                .With("gun", gun)
                .With("role", roleName)
                .With("version", std::to_string(newVersion))
                .With("checksum", checksum));
        
        return Result<bool>(true);
    } catch (const std::exception& e) {
        utils::GetLogger().Error("存储元数据失败",
            utils::LogContext()
                .With("gun", gun)
                .With("role", roleName)
                .With("error", e.what()));
        return Result<bool>(notary::Error(e.what()));
    }
}

Result<bool> FileStorageService::DeleteGUN(const std::string& gun) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    try {
        std::string gunPath = baseDir_ + "/" + gun;
        if (!fs::exists(gunPath)) {
            return Result<bool>(true); // 已经不存在，视为成功
        }
        
        // 递归删除目录
        fs::remove_all(gunPath);
        
        utils::GetLogger().Info("删除GUN成功",
            utils::LogContext().With("gun", gun));
        
        return Result<bool>(true);
    } catch (const std::exception& e) {
        utils::GetLogger().Error("删除GUN失败",
            utils::LogContext()
                .With("gun", gun)
                .With("error", e.what()));
        return Result<bool>(notary::Error(e.what()));
    }
}

std::string FileStorageService::calculateChecksum(const std::string& data) const {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data.c_str(), data.size());
    SHA256_Final(hash, &sha256);
    
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

std::string FileStorageService::buildMetadataPath(const std::string& gun, const std::string& role, 
                                              int version, const std::string& checksum) const {
    std::string basePath = baseDir_  + gun + "/";
    
    if (!checksum.empty()) {
        return basePath + role + "." + checksum + ".json";
    } else if (version > 0) {
        return basePath + std::to_string(version) + "." + role + ".json";
    } else {
        return basePath + role + ".json";
    }
}

Result<int> FileStorageService::getLatestVersion(const std::string& gun, const std::string& role) const {
    std::string dirPath = baseDir_ + gun + "/";
    if (!fs::exists(dirPath)) {
        return Result<int>(notary::Error("Directory not found: " + dirPath));
    }
    
    int latestVersion = 0;
    std::regex versionRegex("(\\d+)\\." + role + "\\.json");
    
    for (const auto& entry : fs::directory_iterator(dirPath)) {
        if (!entry.is_regular_file()) continue;
        
        std::string filename = entry.path().filename().string();
        std::smatch matches;
        if (std::regex_match(filename, matches, versionRegex)) {
            int version = std::stoi(matches[1].str());
            if (version > latestVersion) {
                latestVersion = version;
            }
        }
    }
    
    if (latestVersion == 0) {
        return Result<int>(notary::Error("No versions found for " + gun + "/" + role));
    }
    
    return Result<int>(latestVersion);
}

void FileStorageService::ensureDirectoryExists(const std::string& path) const {
    if (!fs::exists(path)) {
        fs::create_directories(path);
    }
}

} // namespace storage
} // namespace server
} // namespace notary 