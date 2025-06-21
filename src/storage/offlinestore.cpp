#include "notary/storage/offlinestore.hpp"

namespace notary {
namespace storage {

// 静态ErrOffline实例，用于返回错误
static ErrOffline offline_error;

// 实现MetadataStore接口方法

Result<std::vector<uint8_t>> OfflineStore::Get(const std::string& name) {
    return Result<std::vector<uint8_t>>(offline_error);
}

Result<std::vector<uint8_t>> OfflineStore::GetSized(const std::string& name, int64_t size) {
    return Result<std::vector<uint8_t>>(offline_error);
}

Error OfflineStore::Set(const std::string& name, const std::vector<uint8_t>& data) {
    return offline_error;
}

Error OfflineStore::SetMulti(const std::map<std::string, std::vector<uint8_t>>& data) {
    return offline_error;
}

Error OfflineStore::Remove(const std::string& name) {
    return offline_error;
}

Error OfflineStore::RemoveAll() {
    return offline_error;
}

std::vector<std::string> OfflineStore::ListFiles() {
    // 离线存储没有文件列表，返回空向量
    return std::vector<std::string>();
}

std::string OfflineStore::Location() const {
    // 对应Go版本返回"offline"
    return "offline";
}

// 实现PublicKeyStore接口方法

Result<std::vector<uint8_t>> OfflineStore::GetKey(const std::string& name) {
    return Result<std::vector<uint8_t>>(offline_error);
}

} // namespace storage
} // namespace notary 