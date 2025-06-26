#pragma once

#include <string>
#include <nlohmann/json.hpp>
#include "notary/types.hpp"
#include "notary/storage/store.hpp"

namespace notary {
namespace storage {

using json = nlohmann::json;


class HttpStore : public RemoteStore {
public:
    // 构造函数 - 对应Go版本的NewHTTPStore
    HttpStore(const std::string& baseURL, 
               const std::string& metaPrefix = "",
               const std::string& metaExtension = "json",
               const std::string& keyExtension = "key");
    
    // 实现MetadataStore接口
    Result<std::vector<uint8_t>> Get(const std::string& name) override;
    Result<std::vector<uint8_t>> GetSized(const std::string& name, int64_t size) override;
    Error Set(const std::string& name, const std::vector<uint8_t>& data) override;
    Error SetMulti(const std::map<std::string, std::vector<uint8_t>>& data) override;
    Error Remove(const std::string& name) override;
    Error RemoveAll() override;
    std::vector<std::string> ListFiles() override;
    std::string Location() const override;
    
    // 实现PublicKeyStore接口
    Result<std::vector<uint8_t>> GetKey(const std::string& name) override;
    
    // 实现密钥轮转接口 - 对应Go版本的rotateKey
    Result<std::vector<uint8_t>> RotateKey(const std::string& role);
    
    // 辅助工厂方法 - 对应Go版本的NewNotaryServerStore
    static std::unique_ptr<HttpStore> NewNotaryServerStore(const std::string& serverURL, const std::string& gun);

private:
    // URL构建辅助方法 - 对应Go版本的buildMetaURL, buildKeyURL, buildURL
    std::string buildMetaURL(const std::string& name) const;
    std::string buildKeyURL(const std::string& name) const;
    std::string buildURL(const std::string& uri) const;

private:
    std::string baseURL_;        // 基础URL，对应Go版本的baseURL
    std::string metaPrefix_;     // 元数据前缀路径，对应Go版本的metaPrefix
    std::string metaExtension_;  // 元数据扩展名，对应Go版本的metaExtension
    std::string keyExtension_;   // 密钥扩展名，对应Go版本的keyExtension
};

} // namespace storage
} // namespace notary 