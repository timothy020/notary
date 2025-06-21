#pragma once

#include <string>
#include <vector>
#include "notary/types.hpp"

namespace notary {
namespace storage {

// 存储后端接口
class MetadataStore {
public:
    virtual ~MetadataStore() = default;
    
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


} // namespace storage
} // namespace notary