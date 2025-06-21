#pragma once

#include <string>
#include <vector>
#include <map>
#include "notary/types.hpp"

namespace notary {
namespace storage {

// 存储后端接口
class MetadataStore {
public:
    virtual ~MetadataStore() = default;

    // 获取文件内容
    virtual Result<std::vector<uint8_t>> Get(const std::string& name) = 0;

    // 获取文件内容
    virtual Result<std::vector<uint8_t>> GetSized(const std::string& name, int64_t size) = 0;
    
    // 保存文件内容
    virtual Error Set(const std::string& name, const std::vector<uint8_t>& data) = 0;
    
    // 保存多个文件内容
    virtual Error SetMulti(const std::map<std::string, std::vector<uint8_t>>& data) = 0;
    
    // 删除文件
    virtual Error Remove(const std::string& name) = 0;

    // 删除所有文件内容
    virtual Error RemoveAll() = 0;

    // 列出所有文件
    virtual std::vector<std::string> ListFiles() = 0;
    
    // 获取存储位置描述
    virtual std::string Location() const = 0;
};

class PublicKeyStore {
public:
    virtual ~PublicKeyStore() = default;

    virtual Result<std::vector<uint8_t>> GetKey(const std::string& name) = 0;
};

class RemoteStore : public MetadataStore, public PublicKeyStore {
public:
    virtual ~RemoteStore() = default;
};


} // namespace storage
} // namespace notary