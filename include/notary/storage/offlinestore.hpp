#pragma once

#include "notary/storage/store.hpp"
#include "notary/types.hpp"

namespace notary {
namespace storage {

// ErrOffline错误类，用于表示客户端处于离线状态
class ErrOffline : public Error {
public:
    ErrOffline() : Error("client is offline") {}
};

// OfflineStore用作nil store的占位符，对所有操作都返回ErrOffline
// 对应Go版本的OfflineStore struct
class OfflineStore : public RemoteStore {
public:
    OfflineStore() = default;
    virtual ~OfflineStore() = default;

    // 实现MetadataStore接口 - 所有方法都返回ErrOffline
    Result<std::vector<uint8_t>> Get(const std::string& name) override;
    Result<std::vector<uint8_t>> GetSized(const std::string& name, int64_t size) override;
    Error Set(const std::string& name, const std::vector<uint8_t>& data) override;
    Error SetMulti(const std::map<std::string, std::vector<uint8_t>>& data) override;
    Error Remove(const std::string& name) override;
    Error RemoveAll() override;
    std::vector<std::string> ListFiles() override;
    std::string Location() const override;
    
    // 实现PublicKeyStore接口 - 返回ErrOffline
    Result<std::vector<uint8_t>> GetKey(const std::string& name) override;
};

} // namespace storage
} // namespace notary
