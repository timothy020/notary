#include "notary/storage/memorystore.hpp"

namespace notary {
namespace storage {

// MemoryStore 实现
Result<std::vector<uint8_t>> MemoryStore::Get(const std::string& name) {
    auto it = storage_.find(name);
    if (it == storage_.end()) {
        return Result<std::vector<uint8_t>>(Error("Key not found: " + name));
    }
    return Result<std::vector<uint8_t>>(it->second);
}

Error MemoryStore::Set(const std::string& name, const std::vector<uint8_t>& data) {
    storage_[name] = data;
    return Error(); // 成功
}

Error MemoryStore::Remove(const std::string& name) {
    storage_.erase(name);
    return Error(); // 成功
}

std::vector<std::string> MemoryStore::ListFiles() {
    std::vector<std::string> files;
    for (const auto& pair : storage_) {
        files.push_back(pair.first);
    }
    return files;
}

std::string MemoryStore::Location() const {
    return "memory";
}

} // namespace storage
} // namespace notary