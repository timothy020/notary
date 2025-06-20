#pragma once

#include <string>
#include <nlohmann/json.hpp>
#include "notary/types.hpp"

namespace notary {
namespace storage {

using json = nlohmann::json;


class RemoteStore {
public:
    RemoteStore(const std::string& serverURL, 
               const std::string& metaExtension = "json",
               const std::string& keyExtension = "key");
    
    // 从远程获取元数据
    Result<json> GetSized(const std::string& gun,
                         const std::string& role,
                         int64_t size = -1);
    
    // 从远程获取密钥
    Result<json> GetKey(const std::string& gun,
                      const std::string& role);
    
    // 发布元数据到远程
    Error Set(const std::string& gun,
                   const std::string& role,
                   const json& data);
    
    // 批量发布多个元数据到远程 - 对应Go版本的SetMulti
    Error SetMulti(const std::string& gun,
                  const std::map<std::string, json>& metas);

    // 删除单个元数据文件 - 始终返回错误，因为不允许远程删除单个文件
    Error Remove(const std::string& name);
    
    // 删除GUN的所有远程元数据 - 对应Go版本的RemoveAll
    Result<bool> RemoveAll() const;
    
    // 返回存储位置的可读名称 - 对应Go版本的Location
    std::string Location() const;

private:
    std::string serverURL_;
    std::string metaExtension_;
    std::string keyExtension_;
};

} // namespace storage
} // namespace notary 