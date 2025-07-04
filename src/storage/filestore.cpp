#include "notary/storage/filestore.hpp"
#ifdef _WIN32
#include <direct.h>
#define MKDIR(path) _mkdir(path)
#else
#include <sys/types.h>
#include <sys/stat.h>
#define MKDIR(path) mkdir(path, 0755)
#endif

namespace notary {
namespace storage {

// 检查目录是否存在
bool dirExists(const std::string& path) {
    struct stat info;
    if (stat(path.c_str(), &info) != 0) {
        return false;
    }
    return (info.st_mode & S_IFDIR) != 0;
}

// 创建目录
bool createDir(const std::string& path) {
    return MKDIR(path.c_str()) == 0;
}

// 递归创建目录
bool createDirRecursive(const std::string& path) {
    if (path.empty()) {
        return false;
    }
    
    if (dirExists(path)) {
        return true;
    }
    
    std::string parentPath;
    size_t pos = path.find_last_of('/');
    if (pos != std::string::npos) {
        parentPath = path.substr(0, pos);
        if (!parentPath.empty() && !dirExists(parentPath)) {
            if (!createDirRecursive(parentPath)) {
                return false;
            }
        }
    }
    
    return createDir(path);
}

// FileStore 实现
FileStore::FileStore(const std::string& baseDir, const std::string& ext) : baseDir_(baseDir), ext_(ext) {
    // 确保基础目录存在
    if (!dirExists(baseDir_)) {
        createDirRecursive(baseDir_);
    }
}

Result<std::vector<uint8_t>> FileStore::Get(const std::string& name) {
    std::string filePath = baseDir_ + "/" + name + ext_;
    
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        return Result<std::vector<uint8_t>>(Error("File not found: " + filePath));
    }
    
    // 获取文件大小
    file.seekg(0, std::ios::end);
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);
    
    // 读取文件内容
    std::vector<uint8_t> data(fileSize);
    file.read(reinterpret_cast<char*>(data.data()), fileSize);
    
    if (!file) {
        return Result<std::vector<uint8_t>>(Error("Failed to read file: " + filePath));
    }
    
    return Result<std::vector<uint8_t>>(std::move(data));
}

// GetSized 返回给定名称的元数据，最多读取size字节
// 如果size为NO_SIZE_LIMIT，对应"无限制"，但我们在MAX_DOWNLOAD_SIZE处截断
// 如果文件大小超过size，返回错误（恶意服务器攻击保护）
Result<std::vector<uint8_t>> FileStore::GetSized(const std::string& name, int64_t size) {
    std::string filePath = baseDir_ + "/" + name + ext_;
    
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        return Result<std::vector<uint8_t>>(Error("File not found: " + name));
    }
    
    // 如果size为NO_SIZE_LIMIT，使用MAX_DOWNLOAD_SIZE限制
    if (size == NO_SIZE_LIMIT) {
        size = MAX_DOWNLOAD_SIZE;
    }
    
    // 获取文件大小
    file.seekg(0, std::ios::end);
    int64_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);
    
    // 检查文件大小是否超过限制
    if (fileSize > size) {
        return Result<std::vector<uint8_t>>(Error("File too large, potential malicious server attack"));
    }
    
    // 读取文件内容，限制为size字节
    int64_t readSize = std::min(fileSize, size);
    std::vector<uint8_t> data(readSize);
    file.read(reinterpret_cast<char*>(data.data()), readSize);
    
    if (!file) {
        return Result<std::vector<uint8_t>>(Error("Failed to read file: " + filePath));
    }
    
    return Result<std::vector<uint8_t>>(std::move(data));
}

// SetMulti 在一次操作中设置多个角色的元数据
Error FileStore::SetMulti(const std::map<std::string, std::vector<uint8_t>>& data) {
    // 遍历map，对每个键值对调用Set方法
    for (const auto& pair : data) {
        Error err = Set(pair.first, pair.second);
        if (err.hasError()) {
            return err; // 如果任何Set操作失败，立即返回错误
        }
    }
    return Error(); // 成功
}

Error FileStore::Set(const std::string& name, const std::vector<uint8_t>& data) {
    std::string filePath = baseDir_ + "/" + name + ext_;
    
    // 确保父目录存在
    std::filesystem::path path(filePath);
    std::string parentDir = path.parent_path().string();
    if (!parentDir.empty() && !dirExists(parentDir)) {
        if (!createDirRecursive(parentDir)) {
            return Error("Failed to create parent directory: " + parentDir);
        }
    }
    
    std::ofstream file(filePath, std::ios::binary);
    if (!file) {
        return Error("Failed to create file: " + filePath);
    }
    
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    
    if (!file) {
        return Error("Failed to write file: " + filePath);
    }
    
    return Error(); // 成功
}

Error FileStore::Remove(const std::string& name) {
    std::string filePath = baseDir_ + "/" + name + ext_;
    
    try {
        if (std::filesystem::exists(filePath)) {
            std::filesystem::remove(filePath);
        }
        return Error(); // 成功
    } catch (const std::exception& e) {
        return Error("Failed to remove file: " + filePath + ", error: " + e.what());
    }
}

// RemoveAll 通过删除基础目录来清空现有的文件存储
Error FileStore::RemoveAll() {
    try {
        if (std::filesystem::exists(baseDir_)) {
            std::filesystem::remove_all(baseDir_);
        }
        return Error(); // 成功
    } catch (const std::exception& e) {
        return Error("Failed to remove all files in directory: " + baseDir_ + ", error: " + e.what());
    }
}

std::vector<std::string> FileStore::ListFiles() {
    std::vector<std::string> files;
    
    try {
        if (!std::filesystem::exists(baseDir_)) {
            return files;
        }
        
        for (const auto& entry : std::filesystem::recursive_directory_iterator(
                baseDir_, 
                std::filesystem::directory_options::skip_permission_denied)) {
            
            try {
                // 忽略目录
                if (entry.is_directory()) {
                    continue;
                }
                
                // 忽略符号链接
                if (entry.is_symlink()) {
                    continue;
                }
                
                // 只处理常规文件
                if (!entry.is_regular_file()) {
                    continue;
                }
                
                std::string fileName = entry.path().filename().string();
                
                // 检查文件是否匹配扩展名模式 (*ext_)
                if (!ext_.empty()) {
                    if (fileName.length() < ext_.length() || 
                        fileName.substr(fileName.length() - ext_.length()) != ext_) {
                        continue; // 不匹配扩展名，跳过
                    }
                }
                
                // 计算相对路径
                std::filesystem::path relativePath = std::filesystem::relative(entry.path(), baseDir_);
                std::string relativePathStr = relativePath.string();
                
                // 去掉扩展名（如果有）
                if (!ext_.empty() && relativePathStr.length() >= ext_.length()) {
                    relativePathStr = relativePathStr.substr(0, relativePathStr.length() - ext_.length());
                }
                
                files.push_back(relativePathStr);
                
            } catch (const std::exception& e) {
                // 忽略单个文件的错误，继续处理其他文件
                // 这与Go版本的行为一致
                continue;
            }
        }
    } catch (const std::exception& e) {
        utils::GetLogger().Error("Failed to list files in: " + baseDir_ + ", error: " + e.what());
    }
    
    return files;
}

std::string FileStore::Location() const {
    return baseDir_;
}


} // namespace storage
} // namespace notary