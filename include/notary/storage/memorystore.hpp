#pragma once

#include "notary/storage/store.hpp"
#include <map>

namespace notary {
namespace storage {

// 内存存储实现
class MemoryStore : public MetadataStore {
public:
    MemoryStore() = default;
    
    Result<std::vector<uint8_t>> Get(const std::string& name) override;
    Result<std::vector<uint8_t>> GetSized(const std::string& name, int64_t size) override;
    Error Set(const std::string& name, const std::vector<uint8_t>& data) override;
    Error SetMulti(const std::map<std::string, std::vector<uint8_t>>& data) override;
    Error Remove(const std::string& name) override;
    Error RemoveAll() override;
    std::vector<std::string> ListFiles() override;
    std::string Location() const override;

private:
    std::map<std::string, std::vector<uint8_t>> storage_;
};

} // namespace storage
} // namespace notary