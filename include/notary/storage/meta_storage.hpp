#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <functional>
#include "notary/types.hpp"
#include "notary/utils/logger.hpp"
#include "notary/utils/tools.hpp"
#include <fstream>
#include <filesystem>

namespace notary {
namespace storage {

// 存储后端接口
class Storage {
public:
    virtual ~Storage() = default;
    
    // 获取文件内容
    virtual Result<std::vector<uint8_t>> Get(const std::string& name) = 0;
    
    // 保存文件内容
    virtual Error Set(const std::string& name, const std::vector<uint8_t>& data) = 0;
    
    // 删除文件
    virtual Error Remove(const std::string& name) = 0;
    
    // 列出所有文件
    virtual std::vector<std::string> ListFiles() = 0;
    
    // 获取存储位置描述
    virtual std::string Location() const = 0;
};

// 文件系统存储实现
class FileSystemStorage : public Storage {
public:
    explicit FileSystemStorage(const std::string& baseDir, const std::string& ext);
    
    Result<std::vector<uint8_t>> Get(const std::string& name) override;
    Error Set(const std::string& name, const std::vector<uint8_t>& data) override;
    Error Remove(const std::string& name) override;
    std::vector<std::string> ListFiles() override;
    std::string Location() const override;

private:
    std::string baseDir_;
    std::string ext_;
};

// 内存存储实现
class MemoryStorage : public Storage {
public:
    MemoryStorage() = default;
    
    Result<std::vector<uint8_t>> Get(const std::string& name) override;
    Error Set(const std::string& name, const std::vector<uint8_t>& data) override;
    Error Remove(const std::string& name) override;
    std::vector<std::string> ListFiles() override;
    std::string Location() const override;

private:
    std::map<std::string, std::vector<uint8_t>> storage_;
};

// 辅助函数
bool dirExists(const std::string& path);
bool createDir(const std::string& path);
bool createDirRecursive(const std::string& path);

} // namespace storage
} // namespace notary