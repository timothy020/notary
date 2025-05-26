#include "notary/storage/storage.hpp"
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

// FileSystemStorage 实现
FileSystemStorage::FileSystemStorage(const std::string& baseDir, const std::string& ext) : baseDir_(baseDir), ext_(ext) {
    // 确保基础目录存在
    if (!dirExists(baseDir_)) {
        createDirRecursive(baseDir_);
    }
}

Result<std::vector<uint8_t>> FileSystemStorage::Get(const std::string& name) {
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

Error FileSystemStorage::Set(const std::string& name, const std::vector<uint8_t>& data) {
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

Error FileSystemStorage::Remove(const std::string& name) {
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

std::vector<std::string> FileSystemStorage::ListFiles() {
    std::vector<std::string> files;
    
    try {
        if (!std::filesystem::exists(baseDir_)) {
            return files;
        }
        
        for (const auto& entry : std::filesystem::recursive_directory_iterator(baseDir_)) {
            if (entry.is_regular_file()) {
                std::string relativePath = std::filesystem::relative(entry.path(), baseDir_).string();
                files.push_back(relativePath);
            }
        }
    } catch (const std::exception& e) {
        utils::GetLogger().Error("Failed to list files in: " + baseDir_ + ", error: " + e.what());
    }
    
    return files;
}

std::string FileSystemStorage::Location() const {
    return baseDir_;
}

// MemoryStorage 实现
Result<std::vector<uint8_t>> MemoryStorage::Get(const std::string& name) {
    auto it = storage_.find(name);
    if (it == storage_.end()) {
        return Result<std::vector<uint8_t>>(Error("Key not found: " + name));
    }
    return Result<std::vector<uint8_t>>(it->second);
}

Error MemoryStorage::Set(const std::string& name, const std::vector<uint8_t>& data) {
    storage_[name] = data;
    return Error(); // 成功
}

Error MemoryStorage::Remove(const std::string& name) {
    storage_.erase(name);
    return Error(); // 成功
}

std::vector<std::string> MemoryStorage::ListFiles() {
    std::vector<std::string> files;
    for (const auto& pair : storage_) {
        files.push_back(pair.first);
    }
    return files;
}

std::string MemoryStorage::Location() const {
    return "memory";
}



} // namespace storage
} // namespace notary