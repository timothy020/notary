#pragma once

#include <string>
#include <nlohmann/json.hpp>
#include "notary/types.hpp"

namespace notary {
namespace storage {

using json = nlohmann::json;

class MetadataStore {
public:
    explicit MetadataStore(const std::string& trustDir);
    
    // 保存元数据
    Error Set(const std::string& gun, 
             const std::string& role, 
             const json& data);
    
    // 获取元数据
    Result<json> Get(const std::string& gun, 
                    const std::string& role);
    
    // 删除元数据
    Error Remove(const std::string& gun, 
                const std::string& role);
    
    // 列出所有元数据
    std::vector<std::string> List(const std::string& gun);
    
private:
    std::string getMetadataPath(const std::string& gun,
                               const std::string& role) const;
    
private:
    std::string trustDir_;
};

class RemoteStore {
public:
    RemoteStore(const std::string& serverURL);
    
    // 从远程获取元数据
    Result<json> GetRemote(const std::string& gun,
                         const std::string& role);
    
    // 发布元数据到远程
    Error SetRemote(const std::string& gun,
                   const std::string& role,
                   const json& data);
    
private:
    std::string serverURL_;
};

} // namespace storage
} // namespace notary 