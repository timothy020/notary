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
#include "notary/storage/store.hpp"

namespace notary {
namespace storage {

// 文件系统存储实现
class FileStore : public MetadataStore {
public:
    explicit FileStore(const std::string& baseDir, const std::string& ext);
    
    Result<std::vector<uint8_t>> Get(const std::string& name) override;
    Error Set(const std::string& name, const std::vector<uint8_t>& data) override;
    Error Remove(const std::string& name) override;
    std::vector<std::string> ListFiles() override;
    std::string Location() const override;

private:
    std::string baseDir_;
    std::string ext_;
};

// 辅助函数
bool dirExists(const std::string& path);
bool createDir(const std::string& path);
bool createDirRecursive(const std::string& path);

} // namespace storage
} // namespace notary